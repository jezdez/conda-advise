from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .models import FailureReason, ProviderFailure
from .network import JsonRequest, fetch_json
from .provenance import validate_endpoint

if TYPE_CHECKING:
    from .cache import AdvisoryCache
    from .models import ProviderName

DEFAULT_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


@dataclass(frozen=True, slots=True)
class KevResult:
    cves: frozenset[str]
    stale: bool
    failures: tuple[ProviderFailure, ...] = ()


def load_kev(
    *,
    provider: ProviderName,
    cache: AdvisoryCache,
    deadline: float,
    offline: bool,
    refresh: bool,
    url: str = DEFAULT_KEV_URL,
) -> KevResult:
    endpoint = validate_endpoint(url)
    cache_source = f"kev:{endpoint}"
    cached = cache.get(cache_source, "catalog")
    cached_cves = _parse_kev(cached.payload) if cached is not None else None
    if cached is not None and not refresh and (not cached.stale or offline):
        if cached.positive and cached_cves:
            return KevResult(
                cached_cves,
                stale=cached.stale,
                failures=(
                    (_failure(provider, FailureReason.OFFLINE_CACHE_MISS),)
                    if cached.stale
                    else ()
                ),
            )
    if offline:
        reason = (
            FailureReason.INVALID_RESPONSE
            if cached is not None
            else FailureReason.OFFLINE_CACHE_MISS
        )
        return KevResult(
            frozenset(),
            stale=False,
            failures=(_failure(provider, reason),),
        )
    response = fetch_json(
        [JsonRequest("catalog", "GET", endpoint)],
        deadline=deadline,
        max_workers=1,
    )["catalog"]
    if response.succeeded:
        assert response.payload is not None
        cves = _parse_kev(response.payload)
        if cves:
            cache.put(cache_source, "catalog", response.payload, positive=True)
            return KevResult(cves, stale=False)
        reason = FailureReason.INVALID_RESPONSE
    else:
        reason = response.reason or FailureReason.REQUEST_FAILED
    if cached is not None and cached.positive and cached_cves:
        return KevResult(
            cached_cves,
            stale=True,
            failures=(_failure(provider, reason),),
        )
    return KevResult(
        frozenset(),
        stale=False,
        failures=(_failure(provider, reason),),
    )


def _parse_kev(payload: object) -> frozenset[str] | None:
    if not isinstance(payload, dict):
        return None
    count = payload.get("count")
    vulnerabilities = payload.get("vulnerabilities")
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or not isinstance(vulnerabilities, list)
        or count != len(vulnerabilities)
    ):
        return None
    cves: set[str] = set()
    for item in vulnerabilities:
        if not isinstance(item, dict):
            return None
        cve = item.get("cveID")
        if not isinstance(cve, str) or _CVE_ID.fullmatch(cve) is None:
            return None
        cves.add(cve)
    return frozenset(cves) if len(cves) == count and cves else None


def _failure(provider: ProviderName, reason: FailureReason) -> ProviderFailure:
    return ProviderFailure(
        provider=provider,
        source="kev",
        reason=reason,
        message="KEV enrichment is unavailable",
    )
