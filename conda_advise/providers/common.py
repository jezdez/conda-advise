from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import quote

from ..matching import AdvisoryMatch
from ..models import FailureReason, ProviderFailure, ProviderName
from ..network import JsonRequest, JsonResponse, fetch_json
from ..provenance import is_valid_text, validate_endpoint

if TYPE_CHECKING:
    from ..cache import AdvisoryCache, CacheEntry
    from ..models import Evidence, Subject


@dataclass(frozen=True, slots=True)
class QueryBinding:
    subject: Subject
    evidence: Evidence
    stale: bool = False


@dataclass(frozen=True, slots=True)
class AdvisoryQuery:
    key: str
    request: dict[str, object]
    bindings: tuple[QueryBinding, ...]


@dataclass(frozen=True, slots=True)
class QueryState:
    reason: FailureReason | None = None
    stale: bool = False
    checked_at: float | None = None

    @property
    def complete(self) -> bool:
        return self.reason is None


@dataclass(frozen=True, slots=True)
class AdvisoryQueryResult:
    matches: tuple[AdvisoryMatch, ...]
    states: dict[str, QueryState]
    failures: tuple[ProviderFailure, ...]


def query_advisories(
    queries: list[AdvisoryQuery],
    *,
    provider: ProviderName,
    cache: AdvisoryCache,
    deadline: float,
    offline: bool,
    refresh: bool,
    base_url: str,
) -> AdvisoryQueryResult:
    endpoint = validate_endpoint(base_url)
    query_source = f"{provider.value}.query:{endpoint}"
    detail_source = f"{provider.value}.detail:{endpoint}"
    query_by_key = {query.key: query for query in queries}
    summaries: dict[str, list[dict[str, object]]] = {}
    states: dict[str, QueryState] = {}
    fallbacks: dict[str, CacheEntry] = {}
    pending: list[AdvisoryQuery] = []
    failures: list[ProviderFailure] = []

    for query in query_by_key.values():
        cached = cache.get(query_source, query.key)
        cached_summaries = (
            _parse_cached_summaries(cached) if cached is not None else None
        )
        if cached is not None and not refresh and (not cached.stale or offline):
            if cached_summaries is not None:
                summaries[query.key] = cached_summaries
                states[query.key] = QueryState(
                    stale=cached.stale,
                    checked_at=cached.fetched_at,
                )
                continue
        if cached is not None and cached.positive and cached_summaries is not None:
            fallbacks[query.key] = cached
        if offline:
            _use_query_fallback(
                query,
                cached,
                summaries,
                states,
                failures,
                provider,
                (
                    FailureReason.INVALID_RESPONSE
                    if cached is not None and cached_summaries is None
                    else FailureReason.OFFLINE_CACHE_MISS
                ),
            )
        else:
            pending.append(query)

    for offset in range(0, len(pending), 1000):
        batch = pending[offset : offset + 1000]
        received, response = _fetch_query_pages(
            batch,
            provider=provider,
            endpoint=endpoint,
            deadline=deadline,
        )
        if received is not None:
            fetched_at = time.time()
            for query in batch:
                query_summaries = received[query.key]
                summaries[query.key] = query_summaries
                states[query.key] = QueryState(checked_at=fetched_at)
                cache.put(
                    query_source,
                    query.key,
                    {"vulns": query_summaries},
                    positive=bool(query_summaries),
                    now=fetched_at,
                )
            continue
        reason = response.reason or FailureReason.INVALID_RESPONSE
        for query in batch:
            _use_query_fallback(
                query,
                fallbacks.get(query.key),
                summaries,
                states,
                failures,
                provider,
                reason,
            )

    detail_requirements: dict[tuple[str, str], set[str]] = {}
    for query_key, items in summaries.items():
        for summary in items:
            advisory_id = summary["id"]
            modified = summary["modified"]
            assert isinstance(advisory_id, str)
            assert isinstance(modified, str)
            detail_requirements.setdefault((advisory_id, modified), set()).add(
                query_key
            )

    details: dict[tuple[str, str], dict[str, object]] = {}
    detail_stale: dict[tuple[str, str], bool] = {}
    detail_fallbacks: dict[tuple[str, str], CacheEntry] = {}
    detail_pending: list[tuple[str, str]] = []
    for detail_key in detail_requirements:
        cache_key = _detail_cache_key(*detail_key)
        cached = cache.get(detail_source, cache_key)
        cached_valid = (
            cached is not None
            and cached.positive
            and isinstance(cached.payload, dict)
            and _valid_detail(cached.payload, *detail_key)
        )
        if cached is not None and not refresh and (not cached.stale or offline):
            if cached_valid:
                assert isinstance(cached.payload, dict)
                details[detail_key] = cached.payload
                detail_stale[detail_key] = cached.stale
                _update_detail_states(
                    detail_key,
                    detail_requirements,
                    states,
                    stale=cached.stale,
                    checked_at=cached.fetched_at,
                )
                continue
        if cached_valid:
            assert cached is not None
            detail_fallbacks[detail_key] = cached
        if offline:
            _use_detail_fallback(
                detail_key,
                cached,
                details,
                detail_stale,
                detail_requirements,
                query_by_key,
                states,
                failures,
                provider,
                (
                    FailureReason.INVALID_RESPONSE
                    if cached is not None and cached.positive and not cached_valid
                    else FailureReason.OFFLINE_CACHE_MISS
                ),
            )
        else:
            detail_pending.append(detail_key)

    detail_responses = (
        fetch_json(
            [
                JsonRequest(
                    key=_detail_cache_key(advisory_id, modified),
                    method="GET",
                    url=f"{endpoint}/v1/vulns/{quote(advisory_id, safe='')}",
                )
                for advisory_id, modified in detail_pending
            ],
            deadline=deadline,
            max_workers=20,
        )
        if detail_pending
        else {}
    )
    for detail_key in detail_pending:
        cache_key = _detail_cache_key(*detail_key)
        response = detail_responses[cache_key]
        if response.succeeded and _valid_detail(response.payload, *detail_key):
            assert response.payload is not None
            fetched_at = time.time()
            details[detail_key] = response.payload
            detail_stale[detail_key] = False
            cache.put(
                detail_source,
                cache_key,
                response.payload,
                positive=True,
                now=fetched_at,
            )
            _update_detail_states(
                detail_key,
                detail_requirements,
                states,
                checked_at=fetched_at,
            )
            continue
        reason = response.reason or FailureReason.INVALID_RESPONSE
        _use_detail_fallback(
            detail_key,
            detail_fallbacks.get(detail_key),
            details,
            detail_stale,
            detail_requirements,
            query_by_key,
            states,
            failures,
            provider,
            reason,
        )

    matches: list[AdvisoryMatch] = []
    for detail_key, query_keys in detail_requirements.items():
        payload = details.get(detail_key)
        if payload is None:
            continue
        advisory_id = quote(detail_key[0], safe="")
        source_url = f"{endpoint}/v1/vulns/{advisory_id}"
        for query_key in query_keys:
            query = query_by_key[query_key]
            for binding in query.bindings:
                matches.append(
                    AdvisoryMatch(
                        subject=binding.subject,
                        provider=provider,
                        payload=payload,
                        evidence=binding.evidence,
                        queried_purl=query.key,
                        source_url=source_url,
                        stale=(
                            binding.stale
                            or states[query_key].stale
                            or detail_stale[detail_key]
                        ),
                    )
                )
    return AdvisoryQueryResult(tuple(matches), states, tuple(dict.fromkeys(failures)))


def _fetch_query_pages(
    queries: list[AdvisoryQuery],
    *,
    provider: ProviderName,
    endpoint: str,
    deadline: float,
) -> tuple[dict[str, list[dict[str, object]]] | None, JsonResponse]:
    results = {query.key: [] for query in queries}
    page = [(query, None) for query in queries]
    page_number = 0
    last_response = JsonResponse("batch", {}, 200)
    while page:
        body_queries: list[dict[str, object]] = []
        for query, token in page:
            request = dict(query.request)
            if token:
                request["page_token"] = token
            body_queries.append(request)
        request_key = f"batch:{page_number}:{','.join(query.key for query, _ in page)}"
        response = fetch_json(
            [
                JsonRequest(
                    key=request_key,
                    method="POST",
                    url=f"{endpoint}/v1/querybatch",
                    payload={"queries": body_queries},
                )
            ],
            deadline=deadline,
            max_workers=1,
        )[request_key]
        last_response = response
        parsed = _parse_batch_response(response, len(page))
        if parsed is None:
            return None, response
        next_page: list[tuple[AdvisoryQuery, str | None]] = []
        for (query, _), (vulns, token) in zip(page, parsed, strict=True):
            results[query.key].extend(vulns)
            if token:
                if provider is ProviderName.BASILISK:
                    return None, JsonResponse(
                        response.key,
                        None,
                        response.status_code,
                        FailureReason.INVALID_RESPONSE,
                        "Basilisk returned unsupported pagination",
                    )
                next_page.append((query, token))
        page = next_page
        page_number += 1
    for query_key, summaries in results.items():
        unique = {
            (summary["id"], summary["modified"]): summary for summary in summaries
        }
        results[query_key] = list(unique.values())
    return results, last_response


def _parse_batch_response(
    response: JsonResponse,
    expected: int,
) -> list[tuple[list[dict[str, object]], str | None]] | None:
    if not response.succeeded or response.payload is None:
        return None
    raw_results = response.payload.get("results")
    if not isinstance(raw_results, list) or len(raw_results) != expected:
        return None
    parsed: list[tuple[list[dict[str, object]], str | None]] = []
    for raw_result in raw_results:
        if not isinstance(raw_result, dict):
            return None
        raw_vulns = raw_result.get("vulns", [])
        if not isinstance(raw_vulns, list):
            return None
        vulns: list[dict[str, object]] = []
        for raw_vuln in raw_vulns:
            if not isinstance(raw_vuln, dict):
                return None
            advisory_id = raw_vuln.get("id")
            modified = raw_vuln.get("modified")
            if not is_valid_text(advisory_id) or not is_valid_text(modified):
                return None
            vulns.append({"id": advisory_id, "modified": modified})
        token = raw_result.get("next_page_token")
        if token is not None and not isinstance(token, str):
            return None
        parsed.append((vulns, token))
    return parsed


def _parse_cached_summaries(cached: CacheEntry) -> list[dict[str, object]] | None:
    if not isinstance(cached.payload, dict):
        return None
    parsed = _parse_batch_response(
        JsonResponse("cache", {"results": [cached.payload]}, 200), 1
    )
    if parsed is None:
        return None
    summaries = parsed[0][0]
    if cached.positive is not bool(summaries):
        return None
    return summaries


def _use_query_fallback(
    query: AdvisoryQuery,
    cached: CacheEntry | None,
    summaries: dict[str, list[dict[str, object]]],
    states: dict[str, QueryState],
    failures: list[ProviderFailure],
    provider: ProviderName,
    reason: FailureReason,
) -> None:
    parsed = _parse_cached_summaries(cached) if cached is not None else None
    if cached is not None and cached.positive and parsed is not None:
        summaries[query.key] = parsed
        states[query.key] = QueryState(
            reason,
            stale=cached.stale,
            checked_at=cached.fetched_at,
        )
    else:
        states[query.key] = QueryState(reason)
    for binding in query.bindings:
        failures.append(
            ProviderFailure(
                provider=provider,
                source=provider.value,
                reason=reason,
                message="advisory query is incomplete",
                subject=binding.subject.identifier,
            )
        )


def _use_detail_fallback(
    detail_key: tuple[str, str],
    cached: CacheEntry | None,
    details: dict[tuple[str, str], dict[str, object]],
    detail_stale: dict[tuple[str, str], bool],
    detail_requirements: dict[tuple[str, str], set[str]],
    query_by_key: dict[str, AdvisoryQuery],
    states: dict[str, QueryState],
    failures: list[ProviderFailure],
    provider: ProviderName,
    reason: FailureReason,
) -> None:
    cached_valid = (
        cached is not None
        and cached.positive
        and isinstance(cached.payload, dict)
        and _valid_detail(cached.payload, *detail_key)
    )
    if cached_valid:
        assert cached is not None
        assert isinstance(cached.payload, dict)
        details[detail_key] = cached.payload
        detail_stale[detail_key] = cached.stale
    _update_detail_states(
        detail_key,
        detail_requirements,
        states,
        reason=reason,
        stale=bool(cached_valid and cached.stale),
        checked_at=cached.fetched_at if cached_valid and cached is not None else None,
    )
    for query_key in detail_requirements[detail_key]:
        for binding in query_by_key[query_key].bindings:
            failures.append(
                ProviderFailure(
                    provider=provider,
                    source=provider.value,
                    reason=reason,
                    message="advisory detail is incomplete",
                    subject=binding.subject.identifier,
                )
            )


def _update_detail_states(
    detail_key: tuple[str, str],
    detail_requirements: dict[tuple[str, str], set[str]],
    states: dict[str, QueryState],
    *,
    reason: FailureReason | None = None,
    stale: bool = False,
    checked_at: float | None = None,
) -> None:
    for query_key in detail_requirements[detail_key]:
        previous = states[query_key]
        timestamps = tuple(
            value for value in (previous.checked_at, checked_at) if value is not None
        )
        states[query_key] = QueryState(
            reason=previous.reason or reason,
            stale=previous.stale or stale,
            checked_at=min(timestamps) if timestamps else None,
        )


def _valid_detail(
    payload: dict[str, object] | None,
    expected_id: str,
    expected_modified: str,
) -> bool:
    withdrawn = payload.get("withdrawn") if payload is not None else None
    return (
        payload is not None
        and payload.get("id") == expected_id
        and payload.get("modified") == expected_modified
        and (withdrawn is None or is_valid_text(withdrawn))
    )


def _detail_cache_key(advisory_id: str, modified: str) -> str:
    return f"{advisory_id}\x1f{modified}"
