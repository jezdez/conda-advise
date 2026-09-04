from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest

import conda_advise.providers.common as common
import conda_advise.providers.osv as osv
from conda_advise.cache import AdvisoryCache
from conda_advise.components.parselmouth import ComponentResult
from conda_advise.models import (
    Component,
    Coverage,
    CoverageStatus,
    EvidenceType,
    FailureReason,
    ProviderName,
    Severity,
    Subject,
)
from conda_advise.network import JsonResponse


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


def install_components(monkeypatch, subject: Subject) -> None:
    component = Component("demo", "1.0", "pkg:pypi/demo@1.0")
    result = ComponentResult(
        components={subject.identifier: (component,)},
        coverage=(
            Coverage(
                subject.identifier,
                ProviderName.OSV,
                CoverageStatus.COMPLETE,
                None,
                "2026-01-01T00:00:00Z",
            ),
        ),
        failures=(),
    )
    monkeypatch.setattr(osv, "discover_components", lambda *args, **kwargs: result)


def test_osv_follows_pagination_merges_aliases_and_preserves_endpoint(
    monkeypatch, tmp_path
) -> None:
    subject = make_subject()
    install_components(monkeypatch, subject)
    batches = []

    def fetch(requests, **options):
        request = requests[0]
        if request.method == "POST":
            batches.append(request.payload)
            token = request.payload["queries"][0].get("page_token")
            if token is None:
                return {
                    request.key: JsonResponse(
                        request.key,
                        {
                            "results": [
                                {
                                    "vulns": [{"id": "GHSA-a", "modified": "one"}],
                                    "next_page_token": "next",
                                }
                            ]
                        },
                        200,
                    )
                }
            return {
                request.key: JsonResponse(
                    request.key,
                    {"results": [{"vulns": [{"id": "PYSEC-1", "modified": "two"}]}]},
                    200,
                )
            }
        return {
            item.key: JsonResponse(
                item.key,
                {
                    "id": (advisory_id := item.url.rsplit("/", 1)[-1]),
                    "aliases": ["CVE-2026-1"],
                    "modified": "one" if advisory_id == "GHSA-a" else "two",
                    "affected": [
                        {
                            "package": {"ecosystem": "PyPI", "name": "demo"},
                            "ranges": [
                                {"type": "ECOSYSTEM", "events": [{"fixed": "2.0"}]}
                            ],
                        }
                    ],
                },
                200,
            )
            for item in requests
        }

    monkeypatch.setattr(common, "fetch_json", fetch)
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        result = osv.scan_osv(
            [subject],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
            osv_url="http://localhost:8765",
        )

    assert len(batches) == 2
    assert len(result.findings) == 1
    assert result.findings[0].id == "CVE-2026-1"
    assert result.findings[0].fixes == ("2.0",)
    assert result.findings[0].evidence[0].type is EvidenceType.ARTIFACT_COMPONENT
    assert all(
        record.url.startswith("http://localhost:8765/v1/vulns/")
        for record in result.findings[0].source_records
    )


def test_osv_excludes_withdrawn_details_and_keeps_unknown_severity(
    monkeypatch, tmp_path
) -> None:
    subject = make_subject()
    install_components(monkeypatch, subject)

    def fetch(requests, **options):
        request = requests[0]
        if request.method == "POST":
            return {
                request.key: JsonResponse(
                    request.key,
                    {
                        "results": [
                            {
                                "vulns": [
                                    {"id": "CVE-2026-1", "modified": "one"},
                                    {"id": "CVE-2026-2", "modified": "two"},
                                ]
                            }
                        ]
                    },
                    200,
                )
            }
        responses = {}
        for item in requests:
            advisory_id = item.url.rsplit("/", 1)[-1]
            payload = {"id": advisory_id, "modified": "two"}
            if advisory_id == "CVE-2026-1":
                payload = {
                    "id": advisory_id,
                    "modified": "one",
                    "withdrawn": "later",
                }
            responses[item.key] = JsonResponse(item.key, payload, 200)
        return responses

    monkeypatch.setattr(common, "fetch_json", fetch)
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        result = osv.scan_osv(
            [subject],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
        )

    assert [finding.id for finding in result.findings] == ["CVE-2026-2"]
    assert result.findings[0].severity is Severity.UNKNOWN


@pytest.mark.parametrize("withdrawn", [True, ""], ids=["boolean", "empty"])
def test_osv_rejects_malformed_withdrawn_values(
    monkeypatch, tmp_path, withdrawn: object
) -> None:
    subject = make_subject()
    install_components(monkeypatch, subject)

    def fetch(requests, **options):
        request = requests[0]
        if request.method == "POST":
            payload = {
                "results": [{"vulns": [{"id": "CVE-2026-1", "modified": "one"}]}]
            }
        else:
            payload = {
                "id": "CVE-2026-1",
                "modified": "one",
                "withdrawn": withdrawn,
            }
        return {request.key: JsonResponse(request.key, payload, 200)}

    monkeypatch.setattr(common, "fetch_json", fetch)
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        result = osv.scan_osv(
            [subject],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
        )

    assert result.findings == ()
    assert result.coverage[0].status is CoverageStatus.INCOMPLETE
    assert result.coverage[0].reason is FailureReason.INVALID_RESPONSE


def test_osv_marks_findings_stale_when_component_mapping_is_stale(
    monkeypatch, tmp_path
) -> None:
    subject = make_subject()
    component = Component("demo", "1.0", "pkg:pypi/demo@1.0")
    monkeypatch.setattr(
        osv,
        "discover_components",
        lambda *args, **kwargs: ComponentResult(
            components={subject.identifier: (component,)},
            coverage=(
                Coverage(
                    subject.identifier,
                    ProviderName.OSV,
                    CoverageStatus.COMPLETE,
                    None,
                    "2026-01-01T00:00:00Z",
                    stale=True,
                ),
            ),
            failures=(),
        ),
    )

    def fetch(requests, **options):
        request = requests[0]
        if request.method == "POST":
            payload = {
                "results": [{"vulns": [{"id": "CVE-2026-1", "modified": "one"}]}]
            }
        else:
            payload = {"id": "CVE-2026-1", "modified": "one"}
        return {request.key: JsonResponse(request.key, payload, 200)}

    monkeypatch.setattr(common, "fetch_json", fetch)
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        result = osv.scan_osv(
            [subject],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
        )

    assert result.coverage[0].stale
    assert result.findings[0].stale


def test_osv_refresh_replaces_cached_matches_and_invalid_batches_are_incomplete(
    monkeypatch, tmp_path
) -> None:
    subject = make_subject()
    install_components(monkeypatch, subject)
    mode = "positive"

    def fetch(requests, **options):
        request = requests[0]
        if request.method == "GET":
            return {
                request.key: JsonResponse(
                    request.key,
                    {"id": "CVE-2026-1", "modified": "one"},
                    200,
                )
            }
        if mode == "positive":
            payload = {
                "results": [{"vulns": [{"id": "CVE-2026-1", "modified": "one"}]}]
            }
        elif mode == "empty":
            payload = {"results": [{"vulns": []}]}
        else:
            payload = {"unexpected": []}
        return {request.key: JsonResponse(request.key, payload, 200)}

    monkeypatch.setattr(common, "fetch_json", fetch)
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        first = osv.scan_osv(
            [subject],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
        )
        assert first.findings
        mode = "empty"
        second = osv.scan_osv(
            [subject],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=True,
        )
        mode = "invalid"
        third = osv.scan_osv(
            [subject],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=True,
        )

    assert second.findings == ()
    assert second.coverage[0].status is CoverageStatus.COMPLETE
    assert third.coverage[0].status is CoverageStatus.INCOMPLETE
    assert third.coverage[0].reason is FailureReason.INVALID_RESPONSE


@pytest.mark.parametrize(
    "cached_detail",
    [
        {"malformed": True},
        {"id": "CVE-2026-2", "modified": "one"},
        {"id": "CVE-2026-1", "modified": "two"},
    ],
    ids=["missing-id", "wrong-id", "wrong-modified"],
)
def test_osv_rejects_invalid_cached_advisory_details(
    monkeypatch,
    tmp_path,
    cached_detail: dict[str, object],
) -> None:
    subject = make_subject()
    install_components(monkeypatch, subject)
    cache_path = tmp_path / "cache.sqlite3"
    with AdvisoryCache(cache_path) as cache:
        cache.put(
            "osv.query:https://api.osv.dev",
            "pkg:pypi/demo@1.0",
            {"vulns": [{"id": "CVE-2026-1", "modified": "one"}]},
            positive=True,
        )
        cache.put(
            "osv.detail:https://api.osv.dev",
            "CVE-2026-1\x1fone",
            cached_detail,
            positive=True,
        )
        result = osv.scan_osv(
            [subject],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=True,
            refresh=False,
        )

    assert result.findings == ()
    assert result.coverage[0].status is CoverageStatus.INCOMPLETE
    assert result.coverage[0].reason is FailureReason.INVALID_RESPONSE
    assert result.failures[0].reason is FailureReason.INVALID_RESPONSE


@pytest.mark.parametrize(
    ("payload", "positive"),
    [
        ({"malformed": True}, True),
        ({"vulns": []}, True),
        ({"vulns": [{"id": "CVE-2026-1", "modified": "one"}]}, False),
    ],
    ids=["malformed", "positive-empty", "negative-nonempty"],
)
def test_osv_rejects_invalid_cached_query_results(
    monkeypatch,
    tmp_path,
    payload: dict[str, object],
    positive: bool,
) -> None:
    subject = make_subject()
    install_components(monkeypatch, subject)
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        cache.put(
            "osv.query:https://api.osv.dev",
            "pkg:pypi/demo@1.0",
            payload,
            positive=positive,
        )
        result = osv.scan_osv(
            [subject],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=True,
            refresh=False,
        )

    assert result.findings == ()
    assert result.coverage[0].status is CoverageStatus.INCOMPLETE
    assert result.coverage[0].reason is FailureReason.INVALID_RESPONSE


@pytest.mark.parametrize(
    "summary",
    [
        {"id": "", "modified": "one"},
        {"id": "CVE-2026-1", "modified": ""},
        {"id": "\ud800", "modified": "one"},
        {"id": "CVE-2026-1", "modified": "\ud800"},
    ],
    ids=["empty-id", "empty-modified", "invalid-id-unicode", "invalid-time-unicode"],
)
def test_osv_rejects_invalid_summary_text(
    monkeypatch,
    tmp_path,
    summary: dict[str, object],
) -> None:
    subject = make_subject()
    install_components(monkeypatch, subject)

    def fetch(requests, **options):
        request = requests[0]
        assert request.method == "POST"
        return {
            request.key: JsonResponse(
                request.key,
                {"results": [{"vulns": [summary]}]},
                200,
            )
        }

    monkeypatch.setattr(common, "fetch_json", fetch)
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        result = osv.scan_osv(
            [subject],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
        )

    assert result.findings == ()
    assert result.coverage[0].status is CoverageStatus.INCOMPLETE
    assert result.coverage[0].reason is FailureReason.INVALID_RESPONSE


def test_osv_coverage_uses_oldest_required_provider_timestamp(
    monkeypatch,
    tmp_path,
) -> None:
    subject = make_subject()
    component = Component("demo", "1.0", "pkg:pypi/demo@1.0")
    mapping_time = (
        datetime(2030, 1, 1, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    )
    monkeypatch.setattr(
        osv,
        "discover_components",
        lambda *args, **kwargs: ComponentResult(
            components={subject.identifier: (component,)},
            coverage=(
                Coverage(
                    subject.identifier,
                    ProviderName.OSV,
                    CoverageStatus.COMPLETE,
                    None,
                    mapping_time,
                ),
            ),
            failures=(),
        ),
    )
    query_time = time.time() - 20
    detail_time = query_time + 10
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        cache.put(
            "osv.query:https://api.osv.dev",
            component.purl,
            {"vulns": [{"id": "CVE-2026-1", "modified": "one"}]},
            positive=True,
            now=query_time,
        )
        cache.put(
            "osv.detail:https://api.osv.dev",
            "CVE-2026-1\x1fone",
            {"id": "CVE-2026-1", "modified": "one"},
            positive=True,
            now=detail_time,
        )
        result = osv.scan_osv(
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
