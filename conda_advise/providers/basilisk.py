from __future__ import annotations

from typing import TYPE_CHECKING

from packageurl import PackageURL

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

DEFAULT_BASILISK_URL = "https://api.basilisk.prefix.dev"


def scan_basilisk(
    subjects: Sequence[Subject],
    *,
    cache: AdvisoryCache,
    deadline: float,
    offline: bool,
    refresh: bool,
    basilisk_url: str = DEFAULT_BASILISK_URL,
) -> ProviderResult:
    query_data: dict[str, tuple[dict[str, object], list[QueryBinding]]] = {}
    for subject in subjects:
        purl = PackageURL(
            type="conda",
            namespace="conda-forge",
            name=subject.name,
            version=subject.version,
        ).to_string()
        request: dict[str, object] = {"package": {"purl": purl}}
        binding = QueryBinding(
            subject=subject,
            evidence=Evidence(
                type=EvidenceType.UPSTREAM_VERSION,
                provider=ProviderName.BASILISK,
                artifact_sha256=subject.sha256,
            ),
        )
        if purl not in query_data:
            query_data[purl] = (request, [])
        query_data[purl][1].append(binding)
    queries = [
        AdvisoryQuery(key, request, tuple(bindings))
        for key, (request, bindings) in query_data.items()
    ]
    queried = query_advisories(
        queries,
        provider=ProviderName.BASILISK,
        cache=cache,
        deadline=deadline,
        offline=offline,
        refresh=refresh,
        base_url=basilisk_url,
    )
    coverage: list[Coverage] = []
    for query in queries:
        state = queried.states[query.key]
        for binding in query.bindings:
            coverage.append(
                Coverage(
                    subject=binding.subject.identifier,
                    provider=ProviderName.BASILISK,
                    status=(
                        CoverageStatus.COMPLETE
                        if state.complete
                        else CoverageStatus.INCOMPLETE
                    ),
                    reason=state.reason,
                    checked_at=(
                        utc_timestamp(state.checked_at)
                        if state.checked_at is not None
                        else None
                    ),
                    stale=state.stale,
                )
            )
    return ProviderResult(
        coverage=tuple(coverage),
        findings=build_findings(list(queried.matches)),
        failures=queried.failures,
    )
