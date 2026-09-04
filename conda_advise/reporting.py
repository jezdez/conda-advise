"""Human and JSON reporting for advisory scans."""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from typing import TYPE_CHECKING
from unicodedata import category

from rich import box
from rich.console import Console, Group
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from .models import CoverageStatus, EvidenceType, ProviderName
from .provenance import subject_from_record

if TYPE_CHECKING:
    from collections.abc import Iterable
    from typing import TextIO

    from conda.models.records import PackageRecord
    from rich.console import RenderableType

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

    console = Console(
        file=output,
        highlight=False,
        markup=False,
        force_terminal=output.isatty(),
    )
    console.print(_render_human(report))


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
        console = Console(
            file=output,
            highlight=False,
            markup=False,
            force_terminal=output.isatty(),
        )
        error = Text("conda-advise: ", style="bold cyan")
        error.append("Error: ", style="bold red")
        error.append(_terminal_text(message))
        console.print(error, soft_wrap=True)


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


def _render_human(report: AdvisoryReport) -> Group:
    subjects = {subject.identifier: subject for subject in report.subjects}
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in report.findings:
        grouped[finding.subject].append(finding)

    renderables: list[RenderableType] = [
        Text("Conda advisory report", style="bold cyan")
    ]
    metadata = Table.grid(padding=(0, 2))
    metadata.add_column(style="bold", no_wrap=True)
    metadata.add_column(overflow="fold")
    metadata.add_row("Target:", Text(_terminal_text(report.target)))
    metadata.add_row("Provider:", Text(report.provider.value))
    renderables.append(metadata)
    if report.provider is ProviderName.BASILISK:
        status = Text("Experimental provider: ", style="bold yellow")
        status.append("Basilisk is an experimental Prefix.dev provider.")
        renderables.append(status)

    if grouped:
        renderables.extend((Text(), Text("Advisory matches", style="bold")))
    for subject_id in sorted(grouped):
        if subject := subjects.get(subject_id):
            heading = Text(_terminal_text(subject.name), style="bold")
            heading.append(
                _terminal_text(
                    f" {subject.version} {subject.build} "
                    f"({subject.channel}/{subject.subdir})"
                )
            )
        else:
            heading = Text(_terminal_text(subject_id), style="bold")
        tree = Tree(heading, guide_style="dim")
        for finding in sorted(grouped[subject_id], key=lambda item: item.id):
            qualifiers = [finding.severity.value]
            if finding.score is not None:
                qualifiers.append(f"CVSS {finding.score:g}")
            if finding.kev:
                qualifiers.append("CISA KEV")
            if finding.stale:
                qualifiers.append("stale")
            label = Text(_terminal_text(finding.id), style="bold")
            label.append(" [")
            for index, qualifier in enumerate(qualifiers):
                if index:
                    label.append(", ")
                style = {
                    "unknown": "dim",
                    "low": "cyan",
                    "medium": "yellow",
                    "high": "bold red",
                    "critical": "bold white on red",
                    "CISA KEV": "bold magenta",
                    "stale": "yellow",
                }.get(qualifier, "")
                label.append(qualifier, style=style)
            label.append("]")
            advisory = tree.add(label)
            if finding.summary:
                summary = Text("Summary: ", style="bold")
                summary.append(_terminal_text(finding.summary))
                advisory.add(summary)
            aliases = tuple(alias for alias in finding.aliases if alias != finding.id)
            if aliases:
                alias_text = Text("Aliases: ", style="bold")
                alias_text.append(_terminal_text(", ".join(aliases)))
                advisory.add(alias_text)
            if finding.fixes:
                fixes = Text("Upstream fixes: ", style="bold")
                fixes.append(_terminal_text(", ".join(finding.fixes)))
                advisory.add(fixes)
            for evidence in sorted(
                finding.evidence,
                key=lambda item: (item.type.value, item.component_purl or ""),
            ):
                evidence_text = Text("Evidence: ", style="bold")
                if evidence.type is EvidenceType.ARTIFACT_COMPONENT:
                    evidence_text.append(
                        _terminal_text(f"artifact component {evidence.component_purl}")
                    )
                else:
                    evidence_text.append("upstream version match")
                advisory.add(evidence_text)
            sources = sorted(
                {
                    f"{item.provider.value}:{item.id} {item.url}"
                    for item in finding.source_records
                }
            )
            if sources:
                source_text = Text("Sources: ", style="bold")
                source_text.append(_terminal_text(", ".join(sources)))
                advisory.add(source_text)
        renderables.extend((Text(), tree))

    coverage_items = tuple(
        item
        for item in report.coverage
        if item.status is not CoverageStatus.COMPLETE or item.stale
    )
    if coverage_items:
        coverage_table = Table(
            title="Coverage",
            title_justify="left",
            box=box.SIMPLE_HEAD,
            header_style="bold",
        )
        coverage_table.add_column("Package", overflow="fold")
        coverage_table.add_column("Status", overflow="fold")
        coverage_table.add_column("Reason", overflow="fold")
        coverage_table.add_column("Freshness", overflow="fold")
        for item in sorted(coverage_items, key=lambda entry: entry.subject):
            subject = subjects.get(item.subject)
            name = subject.name if subject is not None else item.subject
            status_style = {
                CoverageStatus.COMPLETE: "cyan",
                CoverageStatus.NOT_CHECKED: "yellow",
                CoverageStatus.INCOMPLETE: "bold red",
            }[item.status]
            coverage_table.add_row(
                Text(_terminal_text(name)),
                Text(item.status.value, style=status_style),
                Text(item.reason.value if item.reason is not None else "-"),
                Text("stale", style="yellow") if item.stale else Text("current"),
            )
        renderables.extend((Text(), coverage_table))

    if report.failures:
        failure_table = Table(
            title="Provider failures",
            title_justify="left",
            box=box.SIMPLE_HEAD,
            header_style="bold",
        )
        failure_table.add_column("Source", overflow="fold")
        failure_table.add_column("Package", overflow="fold")
        failure_table.add_column("Failure", overflow="fold")
        for failure in sorted(
            report.failures,
            key=lambda item: (item.source, item.subject or "", item.reason.value),
        ):
            description = f"{failure.reason.value}: {failure.message}"
            failure_table.add_row(
                Text(_terminal_text(failure.source)),
                Text(_terminal_text(failure.subject or "-")),
                Text(_terminal_text(description), style="red"),
            )
        renderables.extend((Text(), failure_table))

    summary = report.summary
    renderables.extend(
        (
            Text(),
            Text("Scan summary", style="bold"),
            Text(f"Checked {summary.checked} of {len(report.subjects)} artifacts."),
            Text(
                f"Mapped {summary.mapped}, unmapped {summary.unmapped}, "
                f"not checked {summary.not_checked}, incomplete {summary.incomplete}."
            ),
        )
    )
    if not report.findings:
        renderables.append(
            Text("No matching advisories were found in the configured provider.")
        )
    else:
        total_noun = "match" if len(report.findings) == 1 else "matches"
        result = Text(
            f"Found {len(report.findings)} {total_noun}, "
            f"{summary.qualifying_matches} at or above "
        )
        result.append(report.minimum_severity.value, style="bold")
        result.append(" or listed in CISA KEV.")
        renderables.append(result)
    if report.has_incomplete:
        renderables.append(
            Text(
                "Incomplete scan: Packages with missing coverage remain unknown.",
                style="bold yellow",
            )
        )
    return Group(*renderables)


def _terminal_text(value: object) -> str:
    result: list[str] = []
    for character in str(value):
        if category(character).startswith("C"):
            width = 4 if ord(character) <= 0xFFFF else 8
            result.append(f"\\u{ord(character):0{width}x}")
        else:
            result.append(character)
    return "".join(result)
