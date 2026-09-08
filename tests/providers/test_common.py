from __future__ import annotations

import time

import pytest

import conda_advise.providers.common as common
from conda_advise.cache import AdvisoryCache
from conda_advise.models import (
    Evidence,
    EvidenceType,
    FailureReason,
    ProviderName,
    Subject,
)
from conda_advise.network import JsonResponse
from conda_advise.providers.common import AdvisoryQuery, QueryBinding, query_advisories


@pytest.fixture
def query():
    subject = Subject(
        "demo",
        "1",
        "0",
        0,
        "noarch",
        "conda-forge",
        "https://conda.anaconda.org/conda-forge/noarch/demo.conda",
        "demo.conda",
    )
    return AdvisoryQuery(
        "pkg:pypi/demo@1",
        {"package": {"name": "demo", "ecosystem": "PyPI"}, "version": "1"},
        (
            QueryBinding(
                subject,
                Evidence(
                    EvidenceType.ARTIFACT_COMPONENT,
                    ProviderName.OSV,
                    "a" * 64,
                    "pkg:pypi/demo@1",
                ),
            ),
        ),
    )


@pytest.mark.parametrize(
    "case",
    ["allowed", "summaries", "pages", "repeated-token", "details"],
    ids=["allowed", "summary-limit", "page-limit", "repeated-token", "detail-limit"],
)
def test_advisory_expansion_limits_preserve_incomplete_coverage(
    monkeypatch, tmp_path, query, case
) -> None:
    monkeypatch.setattr(common, "MAX_SUMMARIES_PER_QUERY", 2)
    monkeypatch.setattr(common, "MAX_PAGES_PER_QUERY", 2)
    monkeypatch.setattr(common, "MAX_DETAILS_PER_SCAN", 1 if case == "details" else 2)
    calls = []

    def fetch(requests, **kwargs):
        calls.extend(requests)
        result = {}
        for request in requests:
            if request.method == "POST":
                item = {
                    "vulns": [
                        {"id": f"id-{index}", "modified": "one"}
                        for index in range(3 if case == "summaries" else 2)
                    ]
                }
                if case in {"pages", "repeated-token"}:
                    item = {
                        "vulns": [],
                        "next_page_token": "repeat"
                        if case == "repeated-token"
                        else f"page-{len(calls)}",
                    }
                payload = {"results": [item]}
            else:
                payload = {"id": request.url.rsplit("/", 1)[-1], "modified": "one"}
            result[request.key] = JsonResponse(request.key, payload, 200)
        return result

    monkeypatch.setattr(common, "fetch_json", fetch)
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        result = query_advisories(
            [query],
            provider=ProviderName.OSV,
            cache=cache,
            deadline=time.monotonic() + 5,
            offline=False,
            refresh=False,
            base_url="https://example.invalid",
        )
        assert result.states[query.key].complete is (case == "allowed")
        if case != "allowed":
            assert result.states[query.key].reason is FailureReason.INVALID_RESPONSE
        if case in {"summaries", "pages", "repeated-token"}:
            assert cache.get("osv.query:https://example.invalid", query.key) is None
            assert all(request.method == "POST" for request in calls)
        assert len([request for request in calls if request.method == "POST"]) <= 2
        assert (
            len([request for request in calls if request.method == "GET"])
            <= common.MAX_DETAILS_PER_SCAN
        )


@pytest.mark.parametrize("cached", [False, True], ids=["online", "offline"])
def test_summary_budget_applies_across_queries(
    monkeypatch, tmp_path, query, cached
) -> None:
    monkeypatch.setattr(common, "MAX_SUMMARIES_PER_SCAN", 3)
    second = AdvisoryQuery("second", query.request, query.bindings)
    payload = {
        "vulns": [{"id": "one", "modified": "1"}, {"id": "two", "modified": "1"}]
    }

    def fetch(requests, **kwargs):
        return {
            request.key: JsonResponse(request.key, {"results": [payload, payload]}, 200)
            for request in requests
        }

    monkeypatch.setattr(common, "fetch_json", fetch)
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        if cached:
            for item in (query, second):
                cache.put(
                    "osv.query:https://example.invalid",
                    item.key,
                    payload,
                    positive=True,
                )
        result = query_advisories(
            [query, second],
            provider=ProviderName.OSV,
            cache=cache,
            deadline=time.monotonic() + 5,
            offline=cached,
            refresh=False,
            base_url="https://example.invalid",
        )
    assert not result.states[second.key].complete
    assert result.states[second.key].reason is FailureReason.INVALID_RESPONSE


@pytest.mark.parametrize(
    ("token", "positive", "complete"),
    [
        ("", False, True),
        (123, True, False),
        ("  ", True, False),
        ("next-page", True, False),
        ("next-page", False, False),
    ],
    ids=[
        "complete-empty-result",
        "invalid-token-type",
        "invalid-token-text",
        "partial-positive-result",
        "partial-negative-result",
    ],
)
def test_cached_queries_require_valid_complete_pagination(
    monkeypatch, tmp_path, query, token, positive, complete
) -> None:
    payload = {
        "vulns": [{"id": "one", "modified": "1"}] if positive else [],
        "next_page_token": token,
    }
    monkeypatch.setattr(
        common,
        "fetch_json",
        lambda requests, **options: pytest.fail("offline query requested the network"),
    )
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        cache.put(
            "osv.query:https://example.invalid", query.key, payload, positive=positive
        )
        result = query_advisories(
            [query],
            provider=ProviderName.OSV,
            cache=cache,
            deadline=time.monotonic() + 5,
            offline=True,
            refresh=False,
            base_url="https://example.invalid",
        )

    assert result.states[query.key].complete is complete
    assert not result.matches
    if complete:
        assert not result.failures
    else:
        assert result.states[query.key].reason is FailureReason.INVALID_RESPONSE
        assert result.failures[0].reason is FailureReason.INVALID_RESPONSE


def test_failed_query_preserves_stale_positive_matches(
    monkeypatch, tmp_path, query
) -> None:
    payload = {"vulns": [{"id": "one", "modified": "1"}]}
    calls = []

    def fetch(requests, **options):
        responses = {}
        calls.extend(request.method for request in requests)
        for request in requests:
            if request.method == "POST":
                responses[request.key] = JsonResponse(
                    request.key, None, 503, FailureReason.REQUEST_FAILED
                )
            else:
                responses[request.key] = JsonResponse(
                    request.key, {"id": "one", "modified": "1"}, 200
                )
        return responses

    monkeypatch.setattr(common, "fetch_json", fetch)
    fetched_at = time.time() - 2
    source = "osv.query:https://example.invalid"
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        cache.put(
            source,
            query.key,
            payload,
            positive=True,
            now=fetched_at,
            ttl=1,
            stale_positive_ttl=86_400,
        )
        result = query_advisories(
            [query],
            provider=ProviderName.OSV,
            cache=cache,
            deadline=time.monotonic() + 5,
            offline=False,
            refresh=False,
            base_url="https://example.invalid",
        )
        cached = cache.get(source, query.key)

    assert calls == ["POST", "GET"]
    assert len(result.matches) == 1
    assert result.matches[0].payload["id"] == "one"
    assert result.matches[0].stale
    assert not result.states[query.key].complete
    assert result.states[query.key].reason is FailureReason.REQUEST_FAILED
    assert result.states[query.key].stale
    assert result.states[query.key].checked_at == fetched_at
    assert len(result.failures) == 1
    assert result.failures[0].reason is FailureReason.REQUEST_FAILED
    assert cached is not None
    assert cached.payload == payload
    assert cached.fetched_at == fetched_at
