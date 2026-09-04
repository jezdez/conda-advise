from __future__ import annotations

import re
from dataclasses import dataclass, replace
from math import isfinite
from typing import TYPE_CHECKING

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError
from packageurl import PackageURL

from .models import (
    Finding,
    Severity,
    SeverityVector,
    SourceRecord,
)

if TYPE_CHECKING:
    from typing import Any

    from .models import Evidence, ProviderName, Subject


@dataclass(frozen=True, slots=True)
class AdvisoryMatch:
    subject: Subject
    provider: ProviderName
    payload: dict[str, object]
    evidence: Evidence
    queried_purl: str
    source_url: str
    stale: bool = False


def build_findings(matches: list[AdvisoryMatch]) -> tuple[Finding, ...]:
    active = [
        match for match in matches if _string(match.payload.get("withdrawn")) is None
    ]
    parents: dict[str, str] = {}

    def find(item: str) -> str:
        parents.setdefault(item, item)
        while parents[item] != item:
            parents[item] = parents[parents[item]]
            item = parents[item]
        return item

    def union(left: str, right: str) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parents[max(left_root, right_root)] = min(left_root, right_root)

    for match in active:
        advisory_id = _string(match.payload.get("id"))
        if not advisory_id:
            continue
        find(advisory_id)
        for alias in _strings(match.payload.get("aliases")):
            union(advisory_id, alias)

    grouped: dict[tuple[str, str], list[AdvisoryMatch]] = {}
    for match in active:
        advisory_id = _string(match.payload.get("id"))
        if advisory_id:
            grouped.setdefault(
                (match.subject.identifier, find(advisory_id)), []
            ).append(match)

    findings: list[Finding] = []
    for (subject_id, _), group in grouped.items():
        identifiers = {
            identifier
            for match in group
            for identifier in (
                _string(match.payload.get("id")),
                *_strings(match.payload.get("aliases")),
            )
            if identifier
        }
        display_id = _display_id(identifiers)
        source_records = _source_records(group)
        vectors = tuple(
            vector
            for source_record in source_records
            for vector in source_record.severity
        )
        scores = tuple(
            vector.base_score for vector in vectors if vector.base_score is not None
        )
        score = max(scores) if scores else None
        severity = max(
            (
                Severity.from_score(score, cvss_type=vector.type)
                for vector in vectors
                if vector.base_score == score
            ),
            key=lambda item: item.rank,
            default=Severity.UNKNOWN,
        )
        if score is None:
            severity = max(
                (_fallback_severity(match) for match in group),
                key=lambda item: item.rank,
                default=Severity.UNKNOWN,
            )
        evidences = tuple(
            sorted(
                {match.evidence for match in group},
                key=lambda item: (
                    item.type.value,
                    item.provider.value,
                    item.component_purl or "",
                ),
            )
        )
        fixes = tuple(
            sorted({fix for record in source_records for fix in record.fixes})
        )
        summary = next(
            (
                value
                for match in group
                if (value := _string(match.payload.get("summary")))
            ),
            None,
        )
        findings.append(
            Finding(
                subject=subject_id,
                id=display_id,
                aliases=tuple(sorted(identifiers - {display_id})),
                summary=summary,
                severity=severity,
                score=score,
                fixes=fixes,
                evidence=evidences,
                source_records=source_records,
                stale=any(match.stale for match in group),
            )
        )
    return tuple(sorted(findings, key=lambda item: (item.subject, item.id)))


def mark_kev(
    findings: tuple[Finding, ...],
    known_exploited: set[str],
    *,
    stale: bool = False,
) -> tuple[Finding, ...]:
    marked: list[Finding] = []
    for finding in findings:
        kev = any(
            identifier in known_exploited
            for identifier in (finding.id, *finding.aliases)
        )
        marked.append(
            replace(
                finding,
                kev=kev,
                stale=finding.stale or (kev and stale),
            )
        )
    return tuple(marked)


def _source_records(group: list[AdvisoryMatch]) -> tuple[SourceRecord, ...]:
    records: dict[tuple[ProviderName, str, str | None], SourceRecord] = {}
    for match in group:
        advisory_id = _string(match.payload.get("id"))
        if not advisory_id:
            continue
        modified = _string(match.payload.get("modified"))
        source = SourceRecord(
            provider=match.provider,
            id=advisory_id,
            modified=modified,
            published=_string(match.payload.get("published")),
            withdrawn=_string(match.payload.get("withdrawn")),
            url=match.source_url,
            severity=_severity_vectors(match),
            fixes=_fixed_versions(match),
            data=match.payload,
        )
        key = (match.provider, advisory_id, modified)
        previous = records.get(key)
        if previous is not None:
            source = replace(
                source,
                severity=tuple(
                    sorted(
                        {*previous.severity, *source.severity},
                        key=lambda item: (item.type, item.score, item.source or ""),
                    )
                ),
                fixes=tuple(sorted({*previous.fixes, *source.fixes})),
            )
        records[key] = source
    return tuple(
        sorted(records.values(), key=lambda item: (item.provider.value, item.id))
    )


def _severity_vectors(match: AdvisoryMatch) -> tuple[SeverityVector, ...]:
    candidates: list[object] = []
    candidates.extend(_list(match.payload.get("severity")))
    for affected in _matching_affected(match):
        candidates.extend(_list(affected.get("severity")))
    result: list[SeverityVector] = []
    seen: set[tuple[str, str, str | None]] = set()
    for item in candidates:
        if not isinstance(item, dict):
            continue
        severity_type = _string(item.get("type"))
        score = _string(item.get("score"))
        source = _string(item.get("source"))
        if not severity_type or not score:
            continue
        key = (severity_type, score, source)
        if key in seen:
            continue
        seen.add(key)
        result.append(
            SeverityVector(
                type=severity_type,
                score=score,
                source=source,
                base_score=_base_score(severity_type, score),
            )
        )
    return tuple(result)


def _base_score(severity_type: str, value: str) -> float | None:
    if not severity_type.startswith(("CVSS_V2", "CVSS_V3", "CVSS_V4")):
        return None
    try:
        score = float(value)
    except ValueError:
        pass
    else:
        return score if isfinite(score) and 0 <= score <= 10 else None
    try:
        if severity_type.startswith("CVSS_V2"):
            score = float(CVSS2(value).scores()[0])
        elif severity_type.startswith("CVSS_V3"):
            score = float(CVSS3(value).scores()[0])
        elif severity_type.startswith("CVSS_V4"):
            score = float(CVSS4(value).scores()[0])
        else:
            return None
    except (CVSSError, ValueError, TypeError):
        return None
    return score if isfinite(score) and 0 <= score <= 10 else None


def _fallback_severity(match: AdvisoryMatch) -> Severity:
    labels: list[str] = []
    database_specific = match.payload.get("database_specific")
    if isinstance(database_specific, dict):
        value = database_specific.get("severity")
        if isinstance(value, str):
            labels.append(value)
    for affected in _matching_affected(match):
        for key in ("ecosystem_specific", "database_specific"):
            specific = affected.get(key)
            if isinstance(specific, dict):
                value = specific.get("severity")
                if isinstance(value, str):
                    labels.append(value)
    values = []
    for label in labels:
        try:
            values.append(Severity.parse(label))
        except ValueError:
            continue
    return max(values, key=lambda item: item.rank, default=Severity.UNKNOWN)


def _fixed_versions(match: AdvisoryMatch) -> tuple[str, ...]:
    result: set[str] = set()
    for affected in _matching_affected(match):
        for range_item in _dicts(affected.get("ranges")):
            if range_item.get("type") == "GIT":
                continue
            for event in _dicts(range_item.get("events")):
                fixed = _string(event.get("fixed"))
                if fixed:
                    result.add(fixed)
        database_specific = affected.get("database_specific")
        if not isinstance(database_specific, dict):
            continue
        basilisk = database_specific.get("basilisk")
        if not isinstance(basilisk, dict):
            continue
        for fix in _dicts(basilisk.get("reported_fixes")):
            version = _string(fix.get("reported_fix"))
            if version:
                result.add(version)
    return tuple(sorted(result))


def _matching_affected(match: AdvisoryMatch) -> tuple[dict[str, Any], ...]:
    try:
        query = PackageURL.from_string(match.queried_purl)
    except ValueError:
        return ()
    return tuple(
        affected
        for affected in _dicts(match.payload.get("affected"))
        if _same_package(affected.get("package"), query)
    )


def _same_package(value: object, query: PackageURL) -> bool:
    if not isinstance(value, dict):
        return False
    candidate_purl = _string(value.get("purl"))
    if candidate_purl is not None:
        try:
            candidate = PackageURL.from_string(candidate_purl)
        except ValueError:
            return False
        return (
            candidate.type.casefold() == query.type.casefold()
            and (candidate.namespace or "").casefold()
            == (query.namespace or "").casefold()
            and _normalized_package_name(candidate.type, candidate.name)
            == _normalized_package_name(query.type, query.name)
        )
    ecosystem = _string(value.get("ecosystem"))
    name = _string(value.get("name"))
    expected_ecosystem = "conda-forge" if query.type == "conda" else query.type
    return (
        ecosystem is not None
        and name is not None
        and ecosystem.casefold() == expected_ecosystem.casefold()
        and _normalized_package_name(query.type, name)
        == _normalized_package_name(query.type, query.name)
    )


def _normalized_package_name(package_type: str, name: str) -> str:
    normalized = name.casefold()
    if package_type.casefold() == "pypi":
        return re.sub(r"[-_.]+", "-", normalized)
    return normalized


def _display_id(identifiers: set[str]) -> str:
    for prefix in ("CVE-", "GHSA-"):
        values = sorted(item for item in identifiers if item.startswith(prefix))
        if values:
            return values[0]
    return min(identifiers)


def _dicts(value: object) -> list[dict[str, Any]]:
    return [item for item in _list(value) if isinstance(item, dict)]


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _strings(value: object) -> tuple[str, ...]:
    return tuple(item for item in _list(value) if isinstance(item, str) and item)


def _string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None
