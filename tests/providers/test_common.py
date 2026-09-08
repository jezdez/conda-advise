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
