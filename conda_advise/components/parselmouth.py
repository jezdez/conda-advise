from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import quote

from packageurl import PackageURL

from ..models import (
    Component,
    Coverage,
    CoverageStatus,
    FailureReason,
    ProviderFailure,
    ProviderName,
    utc_timestamp,
)
from ..network import JsonRequest, fetch_json
from ..provenance import is_valid_text, validate_endpoint

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ..cache import AdvisoryCache, CacheEntry
    from ..models import Subject

DEFAULT_PARSELMOUTH_URL = "https://conda-mapping.prefix.dev"


@dataclass(frozen=True, slots=True)
class ComponentResult:
    components: dict[str, tuple[Component, ...]]
    coverage: tuple[Coverage, ...]
    failures: tuple[ProviderFailure, ...]


def discover_components(
    subjects: Sequence[Subject],
    *,
    cache: AdvisoryCache,
    deadline: float,
    offline: bool,
    refresh: bool,
    base_url: str = DEFAULT_PARSELMOUTH_URL,
) -> ComponentResult:
    endpoint = validate_endpoint(base_url)
    cache_source = f"parselmouth:{endpoint}"
    components: dict[str, tuple[Component, ...]] = {}
    coverage: list[Coverage] = []
    failures: list[ProviderFailure] = []
    pending: dict[str, list[Subject]] = {}
    fallback: dict[str, CacheEntry] = {}

    for subject in subjects:
        if not subject.sha256:
            coverage.append(
                _coverage(
                    subject,
                    CoverageStatus.NOT_CHECKED,
                    FailureReason.MISSING_SHA256,
                )
            )
            continue
        cached = cache.get(cache_source, subject.sha256)
        if cached is not None and not refresh and (not cached.stale or offline):
            _use_cached(subject, cached, components, coverage, failures)
            continue
        if cached is not None and cached.positive:
            fallback[subject.sha256] = cached
        if offline:
            if cached is not None and cached.positive:
                _use_stale(
                    subject,
                    cached,
                    components,
                    coverage,
                    failures,
                    FailureReason.OFFLINE_CACHE_MISS,
                )
            else:
                _offline_miss(subject, coverage, failures)
            continue
        pending.setdefault(subject.sha256, []).append(subject)

    responses = (
        fetch_json(
            [
                JsonRequest(
                    key=sha256,
                    method="GET",
                    url=f"{endpoint}/hash-v0/{quote(sha256, safe='')}",
                )
                for sha256 in pending
            ],
            deadline=deadline,
            max_workers=20,
        )
        if pending
        else {}
    )
    for sha256, grouped_subjects in pending.items():
        response = responses[sha256]
        if response.not_found:
            cache.put(cache_source, sha256, {}, positive=False)
            for subject in grouped_subjects:
                coverage.append(
                    _coverage(
                        subject,
                        CoverageStatus.NOT_CHECKED,
                        FailureReason.COMPONENT_NOT_MAPPED,
                    )
                )
            continue
        if response.succeeded:
            assert response.payload is not None
            parsed = _parse_mapping(response.payload)
            if parsed is None:
                for subject in grouped_subjects:
                    stale = fallback.get(sha256)
                    if stale is not None:
                        _use_stale(
                            subject,
                            stale,
                            components,
                            coverage,
                            failures,
                            FailureReason.INVALID_RESPONSE,
                        )
                    else:
                        coverage.append(
                            _coverage(
                                subject,
                                CoverageStatus.INCOMPLETE,
                                FailureReason.INVALID_RESPONSE,
                            )
                        )
                        failures.append(
                            ProviderFailure(
                                provider=ProviderName.OSV,
                                source="parselmouth",
                                reason=FailureReason.INVALID_RESPONSE,
                                message="component mapping has an invalid shape",
                                subject=subject.identifier,
                            )
                        )
                continue
            cache.put(cache_source, sha256, response.payload, positive=bool(parsed))
            for subject in grouped_subjects:
                if parsed:
                    components[subject.identifier] = parsed
                    coverage.append(_coverage(subject, CoverageStatus.COMPLETE, None))
                else:
                    coverage.append(
                        _coverage(
                            subject,
                            CoverageStatus.NOT_CHECKED,
                            FailureReason.NO_COMPONENTS,
                        )
                    )
            continue
        stale = fallback.get(sha256)
        for subject in grouped_subjects:
            if stale is not None:
                _use_stale(
                    subject,
                    stale,
                    components,
                    coverage,
                    failures,
                    response.reason or FailureReason.REQUEST_FAILED,
                )
            else:
                reason = response.reason or FailureReason.REQUEST_FAILED
                coverage.append(_coverage(subject, CoverageStatus.INCOMPLETE, reason))
                failures.append(
                    ProviderFailure(
                        provider=ProviderName.OSV,
                        source="parselmouth",
                        reason=reason,
                        message=response.message or "component lookup failed",
                        subject=subject.identifier,
                    )
                )
    return ComponentResult(components, tuple(coverage), tuple(failures))


def _parse_mapping(payload: dict[str, object]) -> tuple[Component, ...] | None:
    if "pypi_normalized_names" not in payload or "versions" not in payload:
        return None
    names = payload.get("pypi_normalized_names")
    versions = payload.get("versions")
    if names is None and versions is None:
        return ()
    if not isinstance(names, list) or not isinstance(versions, dict):
        return None
    if any(not is_valid_text(name) for name in names):
        return None
    if any(not is_valid_text(name) for name in versions):
        return None
    if len(names) != len(set(names)) or set(names) != set(versions):
        return None
    result: list[Component] = []
    for name_value in names:
        assert isinstance(name_value, str)
        version_value = versions.get(name_value)
        if not is_valid_text(version_value):
            return None
        name = _normalize_pypi_name(name_value)
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
            return None
        try:
            purl = PackageURL(
                type="pypi",
                name=name,
                version=version_value,
            ).to_string()
        except (TypeError, UnicodeError, ValueError):
            return None
        result.append(Component(name=name, version=version_value, purl=purl))
    return tuple(sorted(set(result), key=lambda item: (item.name, item.version)))


def _use_cached(
    subject: Subject,
    cached: CacheEntry,
    components: dict[str, tuple[Component, ...]],
    coverage: list[Coverage],
    failures: list[ProviderFailure],
) -> None:
    if not isinstance(cached.payload, dict):
        coverage.append(
            _coverage(
                subject,
                CoverageStatus.INCOMPLETE,
                FailureReason.INVALID_RESPONSE,
                checked_at=utc_timestamp(cached.fetched_at),
            )
        )
        failures.append(
            ProviderFailure(
                provider=ProviderName.OSV,
                source="parselmouth",
                reason=FailureReason.INVALID_RESPONSE,
                message="cached component mapping has an invalid shape",
                subject=subject.identifier,
            )
        )
        return
    if not cached.positive and not cached.payload:
        coverage.append(
            _coverage(
                subject,
                CoverageStatus.NOT_CHECKED,
                FailureReason.COMPONENT_NOT_MAPPED,
                checked_at=utc_timestamp(cached.fetched_at),
            )
        )
        return
    parsed = _parse_mapping(cached.payload)
    if parsed is None:
        coverage.append(
            _coverage(
                subject,
                CoverageStatus.INCOMPLETE,
                FailureReason.INVALID_RESPONSE,
                checked_at=utc_timestamp(cached.fetched_at),
            )
        )
        failures.append(
            ProviderFailure(
                provider=ProviderName.OSV,
                source="parselmouth",
                reason=FailureReason.INVALID_RESPONSE,
                message="cached component mapping has an invalid shape",
                subject=subject.identifier,
            )
        )
        return
    if parsed:
        if not cached.positive:
            coverage.append(
                _coverage(
                    subject,
                    CoverageStatus.INCOMPLETE,
                    FailureReason.INVALID_RESPONSE,
                    checked_at=utc_timestamp(cached.fetched_at),
                )
            )
            failures.append(
                ProviderFailure(
                    provider=ProviderName.OSV,
                    source="parselmouth",
                    reason=FailureReason.INVALID_RESPONSE,
                    message="cached component status does not match its data",
                    subject=subject.identifier,
                )
            )
            return
        components[subject.identifier] = parsed
        coverage.append(
            _coverage(
                subject,
                CoverageStatus.COMPLETE,
                None,
                checked_at=utc_timestamp(cached.fetched_at),
                stale=cached.stale,
            )
        )
        return
    coverage.append(
        _coverage(
            subject,
            CoverageStatus.NOT_CHECKED,
            FailureReason.NO_COMPONENTS,
            checked_at=utc_timestamp(cached.fetched_at),
        )
    )


def _use_stale(
    subject: Subject,
    cached: CacheEntry,
    components: dict[str, tuple[Component, ...]],
    coverage: list[Coverage],
    failures: list[ProviderFailure],
    reason: FailureReason,
) -> None:
    parsed = (
        _parse_mapping(cached.payload) if isinstance(cached.payload, dict) else None
    )
    if parsed:
        components[subject.identifier] = parsed
    coverage.append(
        _coverage(
            subject,
            CoverageStatus.INCOMPLETE,
            reason,
            checked_at=utc_timestamp(cached.fetched_at),
            stale=True,
        )
    )
    failures.append(
        ProviderFailure(
            provider=ProviderName.OSV,
            source="parselmouth",
            reason=reason,
            message="using stale component mapping",
            subject=subject.identifier,
        )
    )


def _offline_miss(
    subject: Subject,
    coverage: list[Coverage],
    failures: list[ProviderFailure],
) -> None:
    coverage.append(
        _coverage(
            subject,
            CoverageStatus.INCOMPLETE,
            FailureReason.OFFLINE_CACHE_MISS,
        )
    )
    failures.append(
        ProviderFailure(
            provider=ProviderName.OSV,
            source="parselmouth",
            reason=FailureReason.OFFLINE_CACHE_MISS,
            message="component mapping is not cached",
            subject=subject.identifier,
        )
    )


def _coverage(
    subject: Subject,
    status: CoverageStatus,
    reason: FailureReason | None,
    *,
    checked_at: str | None = None,
    stale: bool = False,
) -> Coverage:
    return Coverage(
        subject=subject.identifier,
        provider=ProviderName.OSV,
        status=status,
        reason=reason,
        checked_at=checked_at or utc_timestamp(time.time()),
        stale=stale,
    )


def _normalize_pypi_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()
