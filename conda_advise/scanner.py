from __future__ import annotations

import sqlite3
import time
from typing import TYPE_CHECKING

from .cache import AdvisoryCache
from .components.parselmouth import DEFAULT_PARSELMOUTH_URL
from .kev import DEFAULT_KEV_URL, load_kev
from .matching import mark_kev
from .models import (
    AdvisoryReport,
    Coverage,
    CoverageStatus,
    FailureReason,
    ProviderFailure,
    ProviderName,
    Severity,
    utc_timestamp,
)
from .provenance import (
    DEFAULT_CONDA_FORGE_ORIGINS,
    is_allowed_origin,
    is_recognized_subject,
    subject_from_record,
)
from .providers.basilisk import DEFAULT_BASILISK_URL, scan_basilisk
from .providers.osv import DEFAULT_OSV_URL, scan_osv

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from pathlib import Path

    from conda.models.records import PackageRecord

    from .models import Subject


def scan_records(
    records: Iterable[PackageRecord],
    *,
    provider: str | ProviderName = ProviderName.OSV,
    offline: bool = False,
    refresh: bool = False,
    minimum_severity: str | Severity = Severity.HIGH,
    timeout_seconds: float = 5.0,
    origins: Sequence[str] = DEFAULT_CONDA_FORGE_ORIGINS,
    osv_url: str = DEFAULT_OSV_URL,
    parselmouth_url: str = DEFAULT_PARSELMOUTH_URL,
    basilisk_url: str = DEFAULT_BASILISK_URL,
    kev_url: str = DEFAULT_KEV_URL,
    cache_path: Path | None = None,
    target: str | None = None,
) -> AdvisoryReport:
    selected_provider = ProviderName(provider)
    threshold = Severity.parse(minimum_severity)
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    if refresh and offline:
        raise ValueError("refresh cannot be combined with offline mode")
    deadline = time.monotonic() + timeout_seconds
    generated_at = utc_timestamp()
    subjects_by_id: dict[str, Subject] = {}
    for record in records:
        subject = subject_from_record(record)
        subjects_by_id.setdefault(subject.identifier, subject)
    subjects = tuple(subjects_by_id.values())
    eligible: list[Subject] = []
    coverage: list[Coverage] = []
    for subject in subjects:
        if not is_recognized_subject(subject):
            coverage.append(
                Coverage(
                    subject=subject.identifier,
                    provider=selected_provider,
                    status=CoverageStatus.NOT_CHECKED,
                    reason=FailureReason.UNRECOGNIZED_RECORD,
                    checked_at=generated_at,
                )
            )
        elif is_allowed_origin(subject.url, origins):
            eligible.append(subject)
        else:
            coverage.append(
                Coverage(
                    subject=subject.identifier,
                    provider=selected_provider,
                    status=CoverageStatus.NOT_CHECKED,
                    reason=FailureReason.UNSUPPORTED_ORIGIN,
                    checked_at=generated_at,
                )
            )

    cache_failures: tuple[ProviderFailure, ...] = ()
    try:
        cache = AdvisoryCache(cache_path, deadline=deadline)
    except (OSError, sqlite3.DatabaseError):
        cache = AdvisoryCache(":memory:", deadline=deadline)
        cache_failures = (
            ProviderFailure(
                provider=selected_provider,
                source="cache",
                reason=FailureReason.CACHE_FAILED,
                message="persistent cache is unavailable",
                affects_completeness=False,
            ),
        )
    try:
        if selected_provider is ProviderName.OSV:
            provider_result = scan_osv(
                eligible,
                cache=cache,
                deadline=deadline,
                offline=offline,
                refresh=refresh,
                osv_url=osv_url,
                parselmouth_url=parselmouth_url,
            )
        else:
            provider_result = scan_basilisk(
                eligible,
                cache=cache,
                deadline=deadline,
                offline=offline,
                refresh=refresh,
                basilisk_url=basilisk_url,
            )
        findings = provider_result.findings
        kev_failures: tuple[ProviderFailure, ...] = ()
        if any(
            identifier.startswith("CVE-")
            for finding in findings
            for identifier in (finding.id, *finding.aliases)
        ):
            kev = load_kev(
                provider=selected_provider,
                cache=cache,
                deadline=deadline,
                offline=offline,
                refresh=refresh,
                url=kev_url,
            )
            findings = mark_kev(findings, set(kev.cves), stale=kev.stale)
            kev_failures = kev.failures
    finally:
        cache.close()

    coverage.extend(provider_result.coverage)
    order = {subject.identifier: index for index, subject in enumerate(subjects)}
    coverage.sort(key=lambda item: order[item.subject])
    return AdvisoryReport(
        schema_version=1,
        generated_at=generated_at,
        target=target or "",
        provider=selected_provider,
        minimum_severity=threshold,
        subjects=subjects,
        coverage=tuple(coverage),
        findings=findings,
        failures=(cache_failures + provider_result.failures + kev_failures),
    )
