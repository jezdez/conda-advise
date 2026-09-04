from __future__ import annotations

import os
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass

import pytest
from conda.models.records import PackageRecord

import conda_advise.network as network
from conda_advise.models import CoverageStatus, FailureReason
from conda_advise.scanner import scan_records


@dataclass
class FakeResponse:
    payload: dict[str, object]
    status_code: int = 200

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self) -> dict[str, object]:
        return self.payload


class FakeSession:
    def __init__(self, route, calls) -> None:
        self.route = route
        self.calls = calls

    def request(self, method, url, **options):
        self.calls.append((method, url, options.get("json"), options.get("timeout")))
        return self.route(method, url, options.get("json"))


def install_service(monkeypatch, route):
    calls = []
    monkeypatch.setattr(
        network,
        "get_session",
        lambda url: FakeSession(route, calls),
    )
    return calls


def make_record(
    *,
    name: str = "demo",
    version: str = "1.0",
    subdir: str = "noarch",
    url: str | None = None,
) -> PackageRecord:
    return PackageRecord(
        name=name,
        version=version,
        build="py_0",
        build_number=0,
        subdir=subdir,
        channel="conda-forge",
        url=url or "https://conda.anaconda.org/conda-forge/noarch/demo-1.0-py_0.conda",
        fn="demo-1.0-py_0.conda",
        sha256="a" * 64,
    )


def make_records(count: int) -> tuple[PackageRecord, ...]:
    return tuple(
        PackageRecord(
            name=f"demo-{index}",
            version="1.0",
            build="py_0",
            build_number=0,
            channel="conda-forge",
            subdir="noarch",
            fn=f"demo-{index}-1.0-py_0.conda",
            url=(
                "https://conda.anaconda.org/conda-forge/noarch/"
                f"demo-{index}-1.0-py_0.conda"
            ),
            sha256=f"{index + 1:064x}",
        )
        for index in range(count)
    )


def osv_route(method, url, payload):
    if "/hash-v0/" in url:
        return FakeResponse(
            {"pypi_normalized_names": ["demo"], "versions": {"demo": "1.0"}}
        )
    if url.endswith("/v1/querybatch"):
        return FakeResponse(
            {
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-aaaa-bbbb-cccc",
                                "modified": "2026-01-01T00:00:00Z",
                            }
                        ]
                    }
                ]
            }
        )
    if "/v1/vulns/" in url:
        return FakeResponse(
            {
                "id": "GHSA-aaaa-bbbb-cccc",
                "aliases": ["CVE-2026-0001"],
                "modified": "2026-01-01T00:00:00Z",
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
                    }
                ],
            }
        )
    if "known_exploited_vulnerabilities" in url:
        return FakeResponse(
            {"count": 1, "vulnerabilities": [{"cveID": "CVE-2026-0001"}]}
        )
    raise AssertionError(f"unexpected request: {method} {url} {payload}")


def test_scan_records_orchestrates_provider_kev_and_report(
    monkeypatch, tmp_path
) -> None:
    calls = install_service(monkeypatch, osv_route)

    report = scan_records(
        [make_record()],
        cache_path=tmp_path / "cache.sqlite3",
        target="/env",
    )

    assert report.target == "/env"
    assert report.summary.mapped == 1
    assert report.summary.qualifying_matches == 1
    assert report.findings[0].id == "CVE-2026-0001"
    assert report.findings[0].kev
    assert not report.has_incomplete
    assert all(timeout for _, _, _, timeout in calls)


def test_complete_empty_scan_does_not_attempt_kev(monkeypatch, tmp_path) -> None:
    def route(method, url, payload):
        if "/hash-v0/" in url:
            return FakeResponse(
                {"pypi_normalized_names": ["demo"], "versions": {"demo": "1.0"}}
            )
        if url.endswith("/v1/querybatch"):
            return FakeResponse({"results": [{"vulns": []}]})
        raise AssertionError(f"unexpected request: {method} {url} {payload}")

    calls = install_service(monkeypatch, route)
    report = scan_records([make_record()], cache_path=tmp_path / "cache.sqlite3")

    assert report.findings == ()
    assert report.failures == ()
    assert not report.has_incomplete
    assert not any("known_exploited" in url for _, url, _, _ in calls)


def test_finding_without_cve_alias_does_not_attempt_kev(monkeypatch, tmp_path) -> None:
    def route(method, url, payload):
        if "/hash-v0/" in url:
            return FakeResponse(
                {"pypi_normalized_names": ["demo"], "versions": {"demo": "1.0"}}
            )
        if url.endswith("/v1/querybatch"):
            return FakeResponse(
                {
                    "results": [
                        {
                            "vulns": [
                                {
                                    "id": "GHSA-aaaa-bbbb-cccc",
                                    "modified": "2026-01-01T00:00:00Z",
                                }
                            ]
                        }
                    ]
                }
            )
        if "/v1/vulns/" in url:
            return FakeResponse(
                {
                    "id": "GHSA-aaaa-bbbb-cccc",
                    "modified": "2026-01-01T00:00:00Z",
                }
            )
        raise AssertionError(f"unexpected request: {method} {url} {payload}")

    calls = install_service(monkeypatch, route)

    report = scan_records(
        [make_record()],
        cache_path=tmp_path / "cache.sqlite3",
    )

    assert [finding.id for finding in report.findings] == ["GHSA-aaaa-bbbb-cccc"]
    assert report.failures == ()
    assert not any("known_exploited" in url for _, url, _, _ in calls)


def test_private_record_is_never_sent(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        network,
        "get_session",
        lambda url: pytest.fail(f"private record triggered request to {url}"),
    )

    report = scan_records(
        [make_record(url="https://private.example/secret/noarch/demo.conda")],
        cache_path=tmp_path / "cache.sqlite3",
    )

    assert report.coverage[0].status is CoverageStatus.NOT_CHECKED
    assert report.coverage[0].reason is FailureReason.UNSUPPORTED_ORIGIN


def test_malformed_record_digests_are_missing_and_never_sent(
    monkeypatch, tmp_path
) -> None:
    record = PackageRecord(
        name="demo",
        version="1.0",
        build="py_0",
        build_number=0,
        channel="conda-forge",
        subdir="noarch",
        fn="demo-1.0-py_0.conda",
        url="https://conda.anaconda.org/conda-forge/noarch/demo-1.0-py_0.conda",
        sha256="g" * 64,
        md5="not-an-md5",
    )
    monkeypatch.setattr(
        network,
        "get_session",
        lambda url: pytest.fail(f"malformed digest triggered request to {url}"),
    )

    report = scan_records([record], cache_path=tmp_path / "cache.sqlite3")

    assert report.subjects[0].sha256 is None
    assert report.subjects[0].md5 is None
    assert report.coverage[0].status is CoverageStatus.NOT_CHECKED
    assert report.coverage[0].reason is FailureReason.MISSING_SHA256


def test_unrecognized_record_is_never_sent(monkeypatch, tmp_path) -> None:
    record = make_record(name="Invalid Package Name")
    monkeypatch.setattr(
        network,
        "get_session",
        lambda url: pytest.fail(f"unrecognized record triggered request to {url}"),
    )

    report = scan_records([record], cache_path=tmp_path / "cache.sqlite3")

    assert report.coverage[0].status is CoverageStatus.NOT_CHECKED
    assert report.coverage[0].reason is FailureReason.UNRECOGNIZED_RECORD
    assert report.summary.not_checked == 1


def test_credentials_never_reach_output_cache_or_requests(
    monkeypatch, tmp_path
) -> None:
    calls = install_service(monkeypatch, osv_route)
    cache_path = tmp_path / "cache.sqlite3"
    secret_url = (
        "https://user:password@conda.anaconda.org/t/tk-secret/conda-forge/noarch/"
        "demo.conda?token=query-secret#fragment-secret"
    )

    report = scan_records([make_record(url=secret_url)], cache_path=cache_path)
    with closing(sqlite3.connect(cache_path)) as connection:
        cache_contents = repr(
            connection.execute("SELECT * FROM cache_entries").fetchall()
        )
    combined = repr(report.to_dict()) + repr(calls) + cache_contents

    for secret in ("user", "password", "tk-secret", "query-secret", "fragment-secret"):
        assert secret not in combined


def test_fresh_cache_supports_a_complete_offline_scan(monkeypatch, tmp_path) -> None:
    cache_path = tmp_path / "cache.sqlite3"
    install_service(monkeypatch, osv_route)
    first = scan_records([make_record()], cache_path=cache_path)

    monkeypatch.setattr(
        network,
        "get_session",
        lambda url: pytest.fail(f"offline scan attempted {url}"),
    )
    second = scan_records([make_record()], offline=True, cache_path=cache_path)

    assert second.findings == first.findings
    assert not second.has_incomplete


def test_missing_kev_enrichment_makes_matching_report_incomplete(
    monkeypatch, tmp_path
) -> None:
    def route(method, url, payload):
        if "known_exploited_vulnerabilities" in url:
            return FakeResponse({}, status_code=503)
        return osv_route(method, url, payload)

    install_service(monkeypatch, route)

    report = scan_records([make_record()], cache_path=tmp_path / "cache.sqlite3")

    assert report.findings
    assert report.has_incomplete
    assert report.failures[-1].source == "kev"


def test_offline_cache_miss_is_incomplete_without_network(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(
        network,
        "get_session",
        lambda url: pytest.fail(f"offline scan attempted {url}"),
    )

    report = scan_records(
        [make_record()],
        offline=True,
        cache_path=tmp_path / "cache.sqlite3",
    )

    assert report.coverage[0].status is CoverageStatus.INCOMPLETE
    assert report.coverage[0].reason is FailureReason.OFFLINE_CACHE_MISS
    assert report.has_incomplete


def test_cold_scan_of_100_link_records(monkeypatch, tmp_path) -> None:
    def route(method, url, payload):
        if "/hash-v0/" in url:
            digest = url.rsplit("/", 1)[-1]
            name = f"demo-{int(digest, 16) - 1}"
            return FakeResponse(
                {"pypi_normalized_names": [name], "versions": {name: "1.0"}}
            )
        if url.endswith("/v1/querybatch"):
            assert isinstance(payload, dict)
            queries = payload["queries"]
            assert isinstance(queries, list)
            return FakeResponse({"results": [{"vulns": []} for _ in queries]})
        raise AssertionError(f"unexpected request: {method} {url} {payload}")

    calls = install_service(monkeypatch, route)
    records = make_records(100)

    started = time.perf_counter()
    report = scan_records(
        records,
        cache_path=tmp_path / "cache.sqlite3",
        timeout_seconds=30.0,
    )
    elapsed = time.perf_counter() - started

    assert len(report.subjects) == 100
    assert report.summary.checked == 100
    assert report.summary.mapped == 100
    assert not report.has_incomplete
    assert len(calls) == 101
    if os.environ.get("_CONDA_ADVISE_ENFORCE_PERFORMANCE_TARGETS") == "1":
        assert elapsed < 5.0, f"cold scan took {elapsed:.3f} seconds"
