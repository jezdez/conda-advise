"""Human and JSON reporting for advisory scans."""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from typing import TYPE_CHECKING
from unicodedata import category

from .models import CoverageStatus, EvidenceType, ProviderName
from .provenance import subject_from_record

if TYPE_CHECKING:
    from collections.abc import Iterable
    from typing import TextIO

    from conda.models.records import PackageRecord

    from .models import AdvisoryReport, Finding, Severity


def report_exit_code(report: AdvisoryReport) -> int:
    """Return the stable command exit code for a completed scan."""
    if report.has_incomplete:
        return 2
    if report.qualifying_findings:
        return 1
    return 0


def render_report(
    report: AdvisoryReport,
    *,
    json_output: bool,
    stream: TextIO | None = None,
) -> None:
    """Write one complete manual scan report."""
    output = stream or sys.stdout
    if json_output:
        payload = report.to_dict()
        print(
            json.dumps(payload, allow_nan=False, indent=2, sort_keys=True),
            file=output,
        )
        return

    print(_render_human(report), file=output)


def render_error(
    message: str,
    *,
    json_output: bool,
    target: str | None = None,
    stream: TextIO | None = None,
) -> None:
    """Write a command error without mixing human text into JSON output."""
    message = message.strip() or "unexpected command failure"
    output = stream or (sys.stdout if json_output else sys.stderr)
    if json_output:
        payload: dict[str, object] = {
            "schema_version": 1,
            "error": {"message": message},
        }
        if target is not None:
            payload["target"] = target
        print(
            json.dumps(payload, allow_nan=False, indent=2, sort_keys=True),
            file=output,
        )
    else:
        print(f"conda-advise: {_terminal_text(message)}", file=output)


def render_hook_summary(report: AdvisoryReport) -> str:
    """Return a concise post-solve diagnostic, or an empty string."""
    affected = len({finding.subject for finding in report.qualifying_findings})
    incomplete = report.summary.incomplete
    provider = (
        "experimental basilisk"
        if report.provider is ProviderName.BASILISK
        else report.provider.value
    )
    coverage_source = (
        " from experimental basilisk"
        if report.provider is ProviderName.BASILISK
        else ""
    )
    if affected:
        noun = "package" if affected == 1 else "packages"
        verb = "has" if affected == 1 else "have"
        message = (
            f"conda-advise: {affected} {noun} {verb} advisory matches at or above "
            f"{report.minimum_severity.value} or listed in CISA KEV "
            f"from {provider}."
        )
        if incomplete:
            incomplete_noun = "package" if incomplete == 1 else "packages"
            message += f" Coverage is incomplete for {incomplete} {incomplete_noun}."
        elif report.has_incomplete:
            message += " Advisory coverage is also incomplete."
        return message + " Run 'conda advise' for details."
    if incomplete:
        noun = "package" if incomplete == 1 else "packages"
        return (
            f"conda-advise: advisory coverage{coverage_source} is incomplete for "
            f"{incomplete} {noun}."
        )
    if report.has_incomplete:
        return f"conda-advise: advisory coverage{coverage_source} is incomplete."
    return ""


def apply_metadata_tags(
    report: AdvisoryReport,
    records: Iterable[PackageRecord],
) -> int:
    """Annotate matching link records with their highest qualifying severity."""
    subject_ids = {subject.identifier for subject in report.subjects}
    highest: dict[str, Severity] = {}
    for finding in report.qualifying_findings:
        severity = finding.severity
        previous = highest.get(finding.subject)
        if previous is None or severity.rank > previous.rank:
            highest[finding.subject] = severity

    tagged = 0
    for record in records:
        subject_id = subject_from_record(record).identifier
        if (
            subject_id not in subject_ids
            or (severity := highest.get(subject_id)) is None
        ):
            continue
        metadata = record.metadata
        metadata.difference_update(
            {item for item in metadata if item.startswith("[advisory:")}
        )
        metadata.add(f"[advisory:{severity.value}]")
        tagged += 1
    return tagged


def _render_human(report: AdvisoryReport) -> str:
    subjects = {subject.identifier: subject for subject in report.subjects}
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in report.findings:
        grouped[finding.subject].append(finding)

    lines = [
        f"Conda advisory report for {report.target}",
        f"Provider: {report.provider.value}",
    ]
    if report.provider is ProviderName.BASILISK:
        lines.append("Basilisk is an experimental Prefix.dev provider.")

    for subject_id in sorted(grouped):
        subject = subjects.get(subject_id)
        if subject is None:
            heading = subject_id
        else:
            heading = (
                f"{subject.name} {subject.version} {subject.build} "
                f"({subject.channel}/{subject.subdir})"
            )
        lines.extend(("", heading))
        for finding in sorted(grouped[subject_id], key=lambda item: item.id):
            qualifiers = [finding.severity.value]
            if finding.score is not None:
                qualifiers.append(f"CVSS {finding.score:g}")
            if finding.kev:
                qualifiers.append("CISA KEV")
            if finding.stale:
                qualifiers.append("stale")
            lines.append(f"  {finding.id} [{', '.join(qualifiers)}]")
            if finding.summary:
                lines.append(f"    {finding.summary}")
            aliases = tuple(alias for alias in finding.aliases if alias != finding.id)
            if aliases:
                lines.append(f"    Aliases: {', '.join(aliases)}")
            if finding.fixes:
                lines.append(f"    Upstream fixes: {', '.join(finding.fixes)}")
            for evidence in sorted(
                finding.evidence,
                key=lambda item: (item.type.value, item.component_purl or ""),
            ):
                if evidence.type is EvidenceType.ARTIFACT_COMPONENT:
                    lines.append(
                        f"    Evidence: artifact component {evidence.component_purl}"
                    )
                else:
                    lines.append("    Evidence: upstream version match")
            sources = sorted(
                {
                    f"{item.provider.value}:{item.id} {item.url}"
                    for item in finding.source_records
                }
            )
            if sources:
                lines.append(f"    Sources: {', '.join(sources)}")

    coverage_items = tuple(
        item
        for item in report.coverage
        if item.status is not CoverageStatus.COMPLETE or item.stale
    )
    if coverage_items:
        lines.extend(("", "Coverage:"))
        for item in sorted(coverage_items, key=lambda entry: entry.subject):
            subject = subjects.get(item.subject)
            name = subject.name if subject is not None else item.subject
            detail = item.status.value
            if item.reason is not None:
                detail += f" ({item.reason.value})"
            if item.stale:
                detail += ", stale"
            lines.append(f"  {name}: {detail}")

    if report.failures:
        lines.extend(("", "Provider failures:"))
        for failure in sorted(
            report.failures,
            key=lambda item: (item.source, item.subject or "", item.reason.value),
        ):
            subject = f" for {failure.subject}" if failure.subject else ""
            description = f"{failure.reason.value}: {failure.message}"
            lines.append(f"  {failure.source}{subject}: {description}")

    summary = report.summary
    lines.extend(
        (
            "",
            (
                f"Checked {summary.checked} of {len(report.subjects)} artifacts. "
                f"Mapped {summary.mapped}, unmapped {summary.unmapped}, "
                f"not checked {summary.not_checked}, "
                f"incomplete {summary.incomplete}."
            ),
        )
    )
    if not report.findings:
        lines.append("No matching advisories were found in the configured provider.")
    else:
        total_noun = "match" if len(report.findings) == 1 else "matches"
        lines.append(
            f"Found {len(report.findings)} {total_noun}, "
            f"{summary.qualifying_matches} at or above "
            f"{report.minimum_severity.value} or listed in CISA KEV."
        )
    if report.has_incomplete:
        lines.append(
            "The scan is incomplete. Packages with missing coverage remain unknown."
        )
    return "\n".join(_terminal_text(line) for line in lines)


def _terminal_text(value: object) -> str:
    result: list[str] = []
    for character in str(value):
        if category(character).startswith("C"):
            width = 4 if ord(character) <= 0xFFFF else 8
            result.append(f"\\u{ord(character):0{width}x}")
        else:
            result.append(character)
    return "".join(result)
