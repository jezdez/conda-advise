from __future__ import annotations

import time

import pytest

import conda_advise.kev as kev
from conda_advise.cache import AdvisoryCache
from conda_advise.models import FailureReason, ProviderName
from conda_advise.network import JsonResponse


def test_load_kev_caches_valid_catalog(monkeypatch, tmp_path) -> None:
    payload = {"count": 1, "vulnerabilities": [{"cveID": "CVE-2026-0001"}]}
    monkeypatch.setattr(
        kev,
        "fetch_json",
        lambda requests, **options: {
            requests[0].key: JsonResponse(requests[0].key, payload, 200)
        },
    )

    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        result = kev.load_kev(
            provider=ProviderName.OSV,
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
        )
        cached = cache.get(f"kev:{kev.DEFAULT_KEV_URL}", "catalog")

    assert result.cves == frozenset({"CVE-2026-0001"})
    assert result.failures == ()
    assert cached is not None


def test_missing_and_stale_kev_data_affect_completeness(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        kev,
        "fetch_json",
        lambda requests, **options: {
            requests[0].key: JsonResponse(
                requests[0].key,
                None,
                503,
                FailureReason.REQUEST_FAILED,
                "failed",
            )
        },
    )
    path = tmp_path / "cache.sqlite3"
    with AdvisoryCache(path) as cache:
        missing = kev.load_kev(
            provider=ProviderName.OSV,
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
        )
        cache.put(
            f"kev:{kev.DEFAULT_KEV_URL}",
            "catalog",
            {"count": 1, "vulnerabilities": [{"cveID": "CVE-2026-0001"}]},
            positive=True,
            now=time.time() - 2,
            ttl=1,
            stale_positive_ttl=10,
        )
        stale = kev.load_kev(
            provider=ProviderName.OSV,
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=True,
            refresh=False,
        )

    assert missing.failures[0].affects_completeness
    assert stale.cves == frozenset({"CVE-2026-0001"})
    assert stale.stale
    assert stale.failures[0].affects_completeness


def test_invalid_cached_kev_catalog_is_not_used_offline(tmp_path) -> None:
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        cache.put(
            f"kev:{kev.DEFAULT_KEV_URL}",
            "catalog",
            {"count": 0, "vulnerabilities": []},
            positive=True,
        )

        result = kev.load_kev(
            provider=ProviderName.OSV,
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=True,
            refresh=False,
        )

    assert result.cves == frozenset()
    assert not result.stale
    assert result.failures[0].reason is FailureReason.INVALID_RESPONSE


@pytest.mark.parametrize(
    "payload",
    [
        {"vulnerabilities": [{"cveID": "CVE-2026-0001"}]},
        {"count": 2, "vulnerabilities": [{"cveID": "CVE-2026-0001"}]},
        {"count": True, "vulnerabilities": [{"cveID": "CVE-2026-0001"}]},
        {"count": 1, "vulnerabilities": [{"invalid": True}]},
        {"count": 1, "vulnerabilities": [{"cveID": "CVE-2026-1"}]},
    ],
    ids=["missing-count", "truncated", "boolean-count", "missing-cve", "invalid-cve"],
)
def test_invalid_kev_catalog_does_not_replace_cache(
    monkeypatch, tmp_path, payload
) -> None:
    monkeypatch.setattr(
        kev,
        "fetch_json",
        lambda requests, **options: {
            requests[0].key: JsonResponse(requests[0].key, payload, 200)
        },
    )
    cache_source = f"kev:{kev.DEFAULT_KEV_URL}"
    cached_payload = {
        "count": 1,
        "vulnerabilities": [{"cveID": "CVE-2025-0001"}],
    }
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        cache.put(cache_source, "catalog", cached_payload, positive=True)
        result = kev.load_kev(
            provider=ProviderName.OSV,
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=True,
        )
        cached = cache.get(cache_source, "catalog")

    assert result.cves == frozenset({"CVE-2025-0001"})
    assert result.stale
    assert result.failures[0].reason is FailureReason.INVALID_RESPONSE
    assert cached is not None
    assert cached.payload == cached_payload
