from __future__ import annotations

import time
from dataclasses import replace
from datetime import datetime, timezone

import conda_advise.providers.common as common
from conda_advise.cache import AdvisoryCache
from conda_advise.models import CoverageStatus, EvidenceType, FailureReason, Subject
from conda_advise.network import JsonResponse
from conda_advise.providers.basilisk import scan_basilisk


def make_subject() -> Subject:
    return Subject(
        name="demo",
        version="1.0",
        build="py_0",
        build_number=0,
        subdir="noarch",
        channel="conda-forge",
        url="https://conda.anaconda.org/conda-forge/noarch/demo.conda",
        filename="demo.conda",
        sha256="a" * 64,
    )


def test_basilisk_uses_conda_purl_and_upstream_version_evidence(
    monkeypatch, tmp_path
) -> None:
    requests = []

    def fetch(items, **options):
        request = items[0]
        requests.append(request)
        assert "conda-mapping" not in request.url
        assert "api.osv.dev" not in request.url
        if request.method == "POST":
            assert request.payload == {
                "queries": [{"package": {"purl": "pkg:conda/conda-forge/demo@1.0"}}]
            }
            return {
                request.key: JsonResponse(
                    request.key,
                    {"results": [{"vulns": [{"id": "CVE-2026-1", "modified": "one"}]}]},
                    200,
                )
            }
        return {
            request.key: JsonResponse(
                request.key,
                {"id": "CVE-2026-1", "modified": "one"},
                200,
            )
        }

    monkeypatch.setattr(common, "fetch_json", fetch)
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        result = scan_basilisk(
            [make_subject()],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
            basilisk_url="http://localhost:8765",
        )

    assert len(requests) == 2
    assert result.findings[0].evidence[0].type is EvidenceType.UPSTREAM_VERSION
    assert result.findings[0].evidence[0].component_purl is None
    assert result.findings[0].source_records[0].url == (
        "http://localhost:8765/v1/vulns/CVE-2026-1"
    )
    assert result.coverage[0].status is CoverageStatus.COMPLETE


def test_basilisk_rejects_unexpected_pagination(monkeypatch, tmp_path) -> None:
    def fetch(items, **options):
        request = items[0]
        return {
            request.key: JsonResponse(
                request.key,
                {
                    "results": [
                        {
                            "vulns": [],
                            "next_page_token": "unsupported",
                        }
                    ]
                },
                200,
            )
        }

    monkeypatch.setattr(common, "fetch_json", fetch)
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        result = scan_basilisk(
            [make_subject()],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
        )

    assert result.coverage[0].status is CoverageStatus.INCOMPLETE
    assert result.coverage[0].reason is FailureReason.INVALID_RESPONSE


def test_basilisk_deduplicates_versions_but_covers_each_artifact(
    monkeypatch, tmp_path
) -> None:
    batches = []

    def fetch(items, **options):
        request = items[0]
        batches.append(request.payload)
        return {
            request.key: JsonResponse(
                request.key,
                {"results": [{"vulns": []}]},
                200,
            )
        }

    monkeypatch.setattr(common, "fetch_json", fetch)
    first = make_subject()
    second = replace(first, build="py_1", sha256="b" * 64)
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        result = scan_basilisk(
            [first, second],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
        )

    assert len(batches) == 1
    assert len(batches[0]["queries"]) == 1
    assert {item.subject for item in result.coverage} == {
        first.identifier,
        second.identifier,
    }


def test_basilisk_separates_configured_endpoint_caches(monkeypatch, tmp_path) -> None:
    calls = []

    def fetch(items, **options):
        request = items[0]
        calls.append(request.url)
        advisory_id = "CVE-2026-1" if ":8001/" in request.url else "CVE-2026-2"
        if request.method == "POST":
            payload = {"results": [{"vulns": [{"id": advisory_id, "modified": "one"}]}]}
        else:
            payload = {"id": advisory_id, "modified": "one"}
        return {request.key: JsonResponse(request.key, payload, 200)}

    monkeypatch.setattr(common, "fetch_json", fetch)
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        scan_basilisk(
            [make_subject()],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
            basilisk_url="http://localhost:8001",
        )
        second = scan_basilisk(
            [make_subject()],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
            basilisk_url="http://localhost:8002",
        )

    assert len(calls) == 4
    assert second.findings[0].id == "CVE-2026-2"


def test_basilisk_cached_coverage_retains_oldest_provider_timestamp(tmp_path) -> None:
    subject = make_subject()
    purl = "pkg:conda/conda-forge/demo@1.0"
    query_time = time.time() - 20
    detail_time = query_time + 10
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        cache.put(
            "basilisk.query:https://api.basilisk.prefix.dev",
            purl,
            {"vulns": [{"id": "CVE-2026-1", "modified": "one"}]},
            positive=True,
            now=query_time,
        )
        cache.put(
            "basilisk.detail:https://api.basilisk.prefix.dev",
            "CVE-2026-1\x1fone",
            {"id": "CVE-2026-1", "modified": "one"},
            positive=True,
            now=detail_time,
        )
        result = scan_basilisk(
            [subject],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=True,
            refresh=False,
        )

    expected = (
        datetime.fromtimestamp(query_time, timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    assert result.coverage[0].checked_at == expected
