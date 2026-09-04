from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from ..components.parselmouth import DEFAULT_PARSELMOUTH_URL, discover_components
from ..matching import build_findings
from ..models import (
    Coverage,
    CoverageStatus,
    Evidence,
    EvidenceType,
    ProviderName,
    ProviderResult,
    utc_timestamp,
)
from .common import AdvisoryQuery, QueryBinding, query_advisories

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ..cache import AdvisoryCache
    from ..models import Subject

DEFAULT_OSV_URL = "https://api.osv.dev"


def scan_osv(
    subjects: Sequence[Subject],
    *,
    cache: AdvisoryCache,
    deadline: float,
    offline: bool,
    refresh: bool,
    osv_url: str = DEFAULT_OSV_URL,
    parselmouth_url: str = DEFAULT_PARSELMOUTH_URL,
) -> ProviderResult:
    discovered = discover_components(
        subjects,
        cache=cache,
        deadline=deadline,
        offline=offline,
        refresh=refresh,
        base_url=parselmouth_url,
    )
    subjects_by_id = {subject.identifier: subject for subject in subjects}
    discovery_stale = {item.subject: item.stale for item in discovered.coverage}
    query_data: dict[str, tuple[dict[str, object], list[QueryBinding]]] = {}
    for subject_id, components in discovered.components.items():
        subject = subjects_by_id[subject_id]
        for component in components:
            request: dict[str, object] = {
                "package": {"ecosystem": "PyPI", "name": component.name},
                "version": component.version,
            }
            binding = QueryBinding(
                subject=subject,
                evidence=Evidence(
                    type=EvidenceType.ARTIFACT_COMPONENT,
                    provider=ProviderName.OSV,
                    artifact_sha256=subject.sha256,
                    component_purl=component.purl,
                ),
                stale=discovery_stale.get(subject.identifier, False),
            )
            query_key = component.purl
            if query_key not in query_data:
                query_data[query_key] = (request, [])
            query_data[query_key][1].append(binding)
    queries = [
        AdvisoryQuery(key, request, tuple(bindings))
        for key, (request, bindings) in query_data.items()
    ]
    queried = query_advisories(
        queries,
        provider=ProviderName.OSV,
        cache=cache,
        deadline=deadline,
        offline=offline,
        refresh=refresh,
        base_url=osv_url,
    )
    keys_by_subject: dict[str, list[str]] = {}
    for query in queries:
        for binding in query.bindings:
            keys_by_subject.setdefault(binding.subject.identifier, []).append(query.key)
    coverage: list[Coverage] = []
    for item in discovered.coverage:
        if item.status is not CoverageStatus.COMPLETE:
            coverage.append(item)
            continue
        states = [queried.states[key] for key in keys_by_subject.get(item.subject, [])]
        failed = next((state for state in states if not state.complete), None)
        checked_at = _oldest_timestamp(
            item.checked_at,
            *(state.checked_at for state in states),
        )
        coverage.append(
            Coverage(
                subject=item.subject,
                provider=ProviderName.OSV,
                status=(
                    CoverageStatus.INCOMPLETE
                    if failed is not None
                    else CoverageStatus.COMPLETE
                ),
                reason=failed.reason if failed is not None else None,
                checked_at=checked_at,
                stale=item.stale or any(state.stale for state in states),
            )
        )
    return ProviderResult(
        coverage=tuple(coverage),
        findings=build_findings(list(queried.matches)),
        failures=discovered.failures + queried.failures,
    )


def _oldest_timestamp(value: str | None, *timestamps: float | None) -> str | None:
    values = [timestamp for timestamp in timestamps if timestamp is not None]
    if value is not None:
        try:
            values.append(
                datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
            )
        except ValueError:
            return value
    if not values:
        return None
    return utc_timestamp(min(values))
