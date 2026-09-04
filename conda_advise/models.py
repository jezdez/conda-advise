from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from math import isfinite
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any


class ProviderName(str, Enum):
    OSV = "osv"
    BASILISK = "basilisk"


class EvidenceType(str, Enum):
    ARTIFACT_COMPONENT = "artifact_component"
    UPSTREAM_VERSION = "upstream_version"


class CoverageStatus(str, Enum):
    COMPLETE = "complete"
    NOT_CHECKED = "not_checked"
    INCOMPLETE = "incomplete"


class Severity(str, Enum):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.UNKNOWN: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    @classmethod
    def from_score(
        cls,
        score: float | None,
        *,
        cvss_type: str | None = None,
    ) -> Severity:
        if score is None or score <= 0:
            return cls.UNKNOWN
        if score < 4:
            return cls.LOW
        if score < 7:
            return cls.MEDIUM
        if score < 9 or (cvss_type is not None and cvss_type.startswith("CVSS_V2")):
            return cls.HIGH
        return cls.CRITICAL

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        if isinstance(value, cls):
            return value
        normalized = value.lower()
        if normalized == "moderate":
            normalized = "medium"
        return cls(normalized)


class FailureReason(str, Enum):
    UNSUPPORTED_ORIGIN = "unsupported_origin"
    UNRECOGNIZED_RECORD = "unrecognized_record"
    MISSING_SHA256 = "missing_sha256"
    COMPONENT_NOT_MAPPED = "component_not_mapped"
    NO_COMPONENTS = "no_components"
    OFFLINE_CACHE_MISS = "offline_cache_miss"
    REQUEST_FAILED = "request_failed"
    INVALID_RESPONSE = "invalid_response"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    CACHE_FAILED = "cache_failed"


@dataclass(frozen=True, slots=True)
class Subject:
    name: str
    version: str
    build: str
    build_number: int
    subdir: str
    channel: str
    url: str
    filename: str
    sha256: str | None = None
    md5: str | None = None

    @property
    def identifier(self) -> str:
        if self.sha256:
            return f"sha256:{self.sha256}"
        return ":".join(
            ("conda", self.channel, self.subdir, self.name, self.version, self.build)
        )

    def to_dict(self) -> dict[str, object]:
        result = _to_jsonable(self)
        assert isinstance(result, dict)
        return {"id": self.identifier, **result}


@dataclass(frozen=True, slots=True)
class Component:
    name: str
    version: str
    purl: str


@dataclass(frozen=True, slots=True)
class SeverityVector:
    type: str
    score: str
    source: str | None
    base_score: float | None


@dataclass(frozen=True, slots=True)
class SourceRecord:
    provider: ProviderName
    id: str
    modified: str | None
    published: str | None
    withdrawn: str | None
    url: str
    severity: tuple[SeverityVector, ...]
    fixes: tuple[str, ...]
    data: dict[str, object]


@dataclass(frozen=True, slots=True)
class Evidence:
    type: EvidenceType
    provider: ProviderName
    artifact_sha256: str | None
    component_purl: str | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    subject: str
    id: str
    aliases: tuple[str, ...]
    summary: str | None
    severity: Severity
    score: float | None
    fixes: tuple[str, ...]
    evidence: tuple[Evidence, ...]
    source_records: tuple[SourceRecord, ...]
    kev: bool = False
    stale: bool = False

    def qualifies(self, minimum_severity: str | Severity) -> bool:
        minimum = Severity.parse(minimum_severity)
        return self.kev or self.severity.rank >= minimum.rank


@dataclass(frozen=True, slots=True)
class Coverage:
    subject: str
    provider: ProviderName
    status: CoverageStatus
    reason: FailureReason | None
    checked_at: str | None
    stale: bool = False


@dataclass(frozen=True, slots=True)
class ProviderFailure:
    provider: ProviderName
    source: str
    reason: FailureReason
    message: str
    subject: str | None = None
    affects_completeness: bool = True


@dataclass(frozen=True, slots=True)
class ReportSummary:
    checked: int
    mapped: int
    unmapped: int
    not_checked: int
    incomplete: int
    total_matches: int
    qualifying_matches: int


@dataclass(frozen=True, slots=True)
class AdvisoryReport:
    schema_version: int
    generated_at: str
    target: str
    provider: ProviderName
    minimum_severity: Severity
    subjects: tuple[Subject, ...]
    coverage: tuple[Coverage, ...]
    findings: tuple[Finding, ...]
    failures: tuple[ProviderFailure, ...] = ()

    @property
    def qualifying_findings(self) -> tuple[Finding, ...]:
        return tuple(
            finding
            for finding in self.findings
            if finding.qualifies(self.minimum_severity)
        )

    @property
    def has_incomplete(self) -> bool:
        return any(
            item.status is CoverageStatus.INCOMPLETE for item in self.coverage
        ) or any(failure.affects_completeness for failure in self.failures)

    @property
    def summary(self) -> ReportSummary:
        complete = {
            item.subject
            for item in self.coverage
            if item.status is CoverageStatus.COMPLETE
        }
        unmapped = {
            item.subject
            for item in self.coverage
            if item.status is CoverageStatus.NOT_CHECKED
            and item.reason
            in {
                FailureReason.COMPONENT_NOT_MAPPED,
                FailureReason.NO_COMPONENTS,
            }
        }
        not_checked = {
            item.subject
            for item in self.coverage
            if item.status is CoverageStatus.NOT_CHECKED
            and item.subject not in unmapped
        }
        incomplete = {
            item.subject
            for item in self.coverage
            if item.status is CoverageStatus.INCOMPLETE
        }
        mapped = (
            {
                item.subject
                for item in self.coverage
                if item.status is CoverageStatus.COMPLETE
                and item.reason
                not in {
                    FailureReason.COMPONENT_NOT_MAPPED,
                    FailureReason.NO_COMPONENTS,
                }
            }
            if self.provider is ProviderName.OSV
            else set()
        )
        return ReportSummary(
            checked=len(complete),
            mapped=len(mapped),
            unmapped=len(unmapped),
            not_checked=len(not_checked),
            incomplete=len(incomplete),
            total_matches=len(self.findings),
            qualifying_matches=len(self.qualifying_findings),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "target": self.target,
            "provider": self.provider.value,
            "provider_experimental": self.provider is ProviderName.BASILISK,
            "minimum_severity": self.minimum_severity.value,
            "subjects": [subject.to_dict() for subject in self.subjects],
            "coverage": [_to_jsonable(item) for item in self.coverage],
            "findings": [_to_jsonable(item) for item in self.findings],
            "failures": [_to_jsonable(item) for item in self.failures],
            "summary": _to_jsonable(self.summary),
        }


@dataclass(frozen=True, slots=True)
class ProviderResult:
    coverage: tuple[Coverage, ...]
    findings: tuple[Finding, ...]
    failures: tuple[ProviderFailure, ...] = ()


def is_json_value(value: object) -> bool:
    if value is None or isinstance(value, (bool, int, str)):
        return True
    if isinstance(value, float):
        return isfinite(value)
    if isinstance(value, list):
        return all(is_json_value(item) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and is_json_value(item) for key, item in value.items()
        )
    return False


def utc_timestamp(value: float | None = None) -> str:
    instant = (
        datetime.now(timezone.utc)
        if value is None
        else datetime.fromtimestamp(value, timezone.utc)
    )
    return instant.isoformat().replace("+00:00", "Z")


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _to_jsonable(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, dict):
        return {str(key): _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_jsonable(item) for item in value]
    return value
