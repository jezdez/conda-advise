"""Tests for advisory report rendering."""

from __future__ import annotations

import io
import json
from dataclasses import replace
from pathlib import Path

import pytest
from conda.models.records import PackageRecord
from jsonschema import Draft202012Validator

from conda_advise.models import (
    AdvisoryReport,
    Coverage,
    CoverageStatus,
    Evidence,
    EvidenceType,
    FailureReason,
    Finding,
    ProviderFailure,
    ProviderName,
    Severity,
    Subject,
)
from conda_advise.reporting import (
    apply_metadata_tags,
    render_error,
    render_hook_summary,
    render_hook_warning,
    render_report,
    report_exit_code,
)


class TerminalStream(io.StringIO):
    """In-memory text stream that behaves like an interactive terminal."""

    def isatty(self) -> bool:
        return True


def make_report(
    *,
    findings: tuple[Finding, ...] = (),
    status: CoverageStatus = CoverageStatus.COMPLETE,
    reason: FailureReason | None = None,
) -> AdvisoryReport:
    subject = Subject(
        name="demo",
        version="1.0",
        build="py_0",
        build_number=0,
        subdir="noarch",
        channel="conda-forge",
        url="https://conda.anaconda.org/conda-forge/noarch/demo-1.0-py_0.conda",
        filename="demo-1.0-py_0.conda",
        sha256="a" * 64,
    )
    return AdvisoryReport(
        schema_version=1,
        generated_at="2026-09-04T12:00:00Z",
        target="/old-target",
        provider=ProviderName.OSV,
        minimum_severity=Severity.HIGH,
        subjects=(subject,),
        coverage=(
            Coverage(
                subject=subject.identifier,
                provider=ProviderName.OSV,
                status=status,
                reason=reason,
                checked_at="2026-09-04T12:00:00Z",
            ),
        ),
        findings=findings,
    )


def make_finding(
    severity: Severity = Severity.HIGH,
    *,
    kev: bool = False,
) -> Finding:
    return Finding(
        subject=f"sha256:{'a' * 64}",
        id="CVE-2026-0001",
        aliases=("CVE-2026-0001", "GHSA-abcd-efgh-ijkl"),
        summary="Example advisory",
        severity=severity,
        score=7.5 if severity is Severity.HIGH else None,
        fixes=("1.1",),
        evidence=(
            Evidence(
                type=EvidenceType.ARTIFACT_COMPONENT,
                provider=ProviderName.OSV,
                artifact_sha256="a" * 64,
                component_purl="pkg:pypi/demo@1.0",
            ),
        ),
        source_records=(),
        kev=kev,
    )


@pytest.mark.parametrize(
    ("report", "expected"),
    [
        (make_report(), 0),
        (make_report(findings=(make_finding(),)), 1),
        (make_report(status=CoverageStatus.INCOMPLETE), 2),
    ],
    ids=["no-match", "qualifying-match", "incomplete"],
)
def test_report_exit_code(report: AdvisoryReport, expected: int) -> None:
    assert report_exit_code(report) == expected


def test_kev_finding_qualifies_below_threshold() -> None:
    report = make_report(findings=(make_finding(Severity.UNKNOWN, kev=True),))

    report = replace(report, minimum_severity=Severity.CRITICAL)

    assert report_exit_code(report) == 1


def test_unmapped_artifact_does_not_force_incomplete_exit() -> None:
    report = make_report(
        status=CoverageStatus.NOT_CHECKED,
        reason=FailureReason.COMPONENT_NOT_MAPPED,
    )

    assert report.summary.unmapped == 1
    assert report.summary.not_checked == 0
    assert report_exit_code(report) == 0


def test_basilisk_complete_coverage_is_not_component_mapping() -> None:
    report = replace(make_report(), provider=ProviderName.BASILISK)

    assert report.summary.checked == 1
    assert report.summary.mapped == 0


def test_render_report_emits_one_json_document_with_selected_target() -> None:
    stream = io.StringIO()
    report = replace(
        make_report(findings=(make_finding(),)),
        target="/target",
    )

    render_report(
        report,
        json_output=True,
        stream=stream,
    )

    payload = json.loads(stream.getvalue())
    assert payload["schema_version"] == 1
    assert payload["target"] == "/target"
    assert payload["provider"] == "osv"
    assert payload["provider_experimental"] is False
    assert payload["findings"][0]["evidence"][0]["type"] == "artifact_component"


def test_render_report_keeps_json_output_exactly_unchanged() -> None:
    stream = TerminalStream()
    report = replace(make_report(findings=(make_finding(),)), target="/target")
    expected = json.dumps(
        report.to_dict(),
        allow_nan=False,
        indent=2,
        sort_keys=True,
    )

    render_report(report, json_output=True, stream=stream)

    assert stream.getvalue() == expected + "\n"
    assert "\x1b" not in stream.getvalue()


def test_render_report_rejects_nonfinite_json_numbers() -> None:
    stream = io.StringIO()
    finding = replace(make_finding(), score=float("nan"))

    with pytest.raises(ValueError, match="Out of range float values"):
        render_report(
            replace(make_report(findings=(finding,)), target="/target"),
            json_output=True,
            stream=stream,
        )

    assert stream.getvalue() == ""


def test_render_report_distinguishes_component_evidence() -> None:
    stream = io.StringIO()

    render_report(
        replace(make_report(findings=(make_finding(),)), target="/target"),
        json_output=False,
        stream=stream,
    )

    output = stream.getvalue()
    assert "artifact component pkg:pypi/demo@1.0" in output
    assert "No matching advisories" not in output
    assert "Found 1 match, 1 at or above high" in output
    assert "Mapped 1, unmapped 0, not checked 0, incomplete 0" in output


def test_human_report_styles_interactive_terminal_output(monkeypatch) -> None:
    monkeypatch.setenv("TERM", "xterm-256color")
    stream = TerminalStream()

    render_report(
        replace(make_report(findings=(make_finding(),)), target="/target"),
        json_output=False,
        stream=stream,
    )

    output = stream.getvalue()
    assert "\x1b[" in output
    assert "Advisory matches" in output
    assert "high" in output
    assert "CISA KEV" in output


def test_human_report_is_unstyled_for_nonterminal_output() -> None:
    stream = io.StringIO()
    finding = replace(
        make_finding(),
        summary="Literal [bold red]provider text[/bold red]",
    )

    render_report(
        replace(make_report(findings=(finding,)), target="/target"),
        json_output=False,
        stream=stream,
    )

    output = stream.getvalue()
    assert "\x1b" not in output
    assert "Literal [bold red]provider text[/bold red]" in output
    assert "high" in output


def test_nonterminal_report_preserves_long_values_without_ellipsis() -> None:
    long_target = "/target/" + "target-segment-" * 12 + "target-end"
    long_package = "package-" + "Q" * 180 + "-package-end"
    long_failure = "provider-value-" + "Z" * 180 + "-failure-end"
    report = make_report(
        status=CoverageStatus.INCOMPLETE,
        reason=FailureReason.REQUEST_FAILED,
    )
    subject = replace(report.subjects[0], name=long_package)
    report = replace(
        report,
        target=long_target,
        subjects=(subject,),
        failures=(
            ProviderFailure(
                provider=ProviderName.OSV,
                source="provider-source",
                reason=FailureReason.REQUEST_FAILED,
                message=long_failure,
            ),
        ),
    )
    stream = io.StringIO()

    render_report(report, json_output=False, stream=stream)

    output = stream.getvalue()
    output_without_layout_whitespace = "".join(output.split())
    assert "…" not in output
    assert long_target in output_without_layout_whitespace
    assert "package-" in output
    assert "-package-end" in output_without_layout_whitespace
    assert output.count("Q") == 180
    assert "provider-value-" in output
    assert "-failure-end" in output_without_layout_whitespace
    assert output.count("Z") == 180


def test_basilisk_is_marked_experimental_in_every_output_mode() -> None:
    finding = replace(
        make_finding(),
        evidence=(
            Evidence(
                type=EvidenceType.UPSTREAM_VERSION,
                provider=ProviderName.BASILISK,
                artifact_sha256="a" * 64,
            ),
        ),
    )
    report = replace(
        make_report(findings=(finding,)),
        provider=ProviderName.BASILISK,
    )
    human = io.StringIO()
    structured = io.StringIO()

    render_report(report, json_output=False, stream=human)
    render_report(report, json_output=True, stream=structured)

    assert "experimental Prefix.dev provider" in human.getvalue()
    assert "experimental basilisk" in render_hook_summary(report)
    assert json.loads(structured.getvalue())["provider_experimental"] is True


def test_render_empty_report_does_not_claim_packages_are_unaffected() -> None:
    stream = io.StringIO()

    render_report(
        replace(make_report(), target="/target"),
        json_output=False,
        stream=stream,
    )

    output = stream.getvalue().lower()
    assert "no matching advisories were found in the configured provider" in output
    assert "safe" not in output
    assert "unaffected" not in output


def test_render_error_keeps_json_machine_readable() -> None:
    stream = io.StringIO()

    render_error("invalid target", json_output=True, target="/missing", stream=stream)

    assert json.loads(stream.getvalue()) == {
        "schema_version": 1,
        "target": "/missing",
        "error": {"message": "invalid target"},
    }


def test_render_error_styles_only_interactive_terminal_output(monkeypatch) -> None:
    monkeypatch.setenv("TERM", "xterm-256color")
    terminal = TerminalStream()
    redirected = io.StringIO()

    render_error("invalid [bold]target[/bold]", json_output=False, stream=terminal)
    render_error("invalid [bold]target[/bold]", json_output=False, stream=redirected)

    assert "\x1b[" in terminal.getvalue()
    assert "Error:" in terminal.getvalue()
    assert "[bold]target[/bold]" in terminal.getvalue()
    assert redirected.getvalue() == (
        "conda-advise: Error: invalid [bold]target[/bold]\n"
    )


def test_render_error_normalizes_empty_exceptions_to_schema_valid_json() -> None:
    stream = io.StringIO()
    schema_path = (
        Path(__file__).parents[1] / "schema" / "conda-advise-report-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    render_error(" \n", json_output=True, stream=stream)

    payload = json.loads(stream.getvalue())
    Draft202012Validator(schema).validate(payload)
    assert payload["error"]["message"] == "unexpected command failure"


def test_human_report_escapes_terminal_control_characters() -> None:
    stream = io.StringIO()
    finding = replace(
        make_finding(),
        summary="ordinary\x1b[31m red\nspoofed line\u202e",
    )

    render_report(
        replace(make_report(findings=(finding,)), target="/target"),
        json_output=False,
        stream=stream,
    )

    output = stream.getvalue()
    assert "ordinary\\u001b[31m red\\u000aspoofed line\\u202e" in output
    assert "\x1b" not in output


def test_apply_metadata_tags_keeps_only_highest_qualifying_tag() -> None:
    record = PackageRecord(
        name="demo",
        version="1.0",
        build="py_0",
        build_number=0,
        channel="conda-forge",
        subdir="noarch",
        fn="demo-1.0-py_0.conda",
        url="https://conda.anaconda.org/conda-forge/noarch/demo-1.0-py_0.conda",
        sha256="a" * 64,
    )
    record.metadata.update({"existing", "[advisory:low]"})
    report = make_report(
        findings=(make_finding(Severity.HIGH), make_finding(Severity.CRITICAL))
    )

    count = apply_metadata_tags(report, (record,))

    assert count == 1
    assert record.metadata == {"existing", "[advisory:critical]"}


def test_render_hook_summary_is_silent_for_complete_empty_report() -> None:
    assert render_hook_summary(make_report()) == ""


def test_render_hook_summary_uses_singular_grammar() -> None:
    summary = render_hook_summary(make_report(findings=(make_finding(),)))

    assert "1 package has advisory matches" in summary


def test_render_hook_warning_is_silent_for_complete_empty_report() -> None:
    stream = TerminalStream()

    render_hook_warning(make_report(), stream=stream)

    assert stream.getvalue() == ""


def test_render_hook_warning_preserves_redirected_summary() -> None:
    report = make_report(findings=(make_finding(),))
    stream = io.StringIO()

    render_hook_warning(report, stream=stream)

    assert stream.getvalue() == f"{render_hook_summary(report)}\n"


def test_render_hook_warning_uses_plain_output_for_global_json_mode() -> None:
    report = make_report(findings=(make_finding(),))
    stream = TerminalStream()

    render_hook_warning(report, stream=stream, rich_output=False)

    assert stream.getvalue() == f"{render_hook_summary(report)}\n"


@pytest.mark.parametrize(
    ("report", "expected_title", "expected_text"),
    [
        (
            make_report(findings=(make_finding(),)),
            "CONDA ADVISORY WARNING",
            "1 package has advisory matches",
        ),
        (
            make_report(status=CoverageStatus.INCOMPLETE),
            "CONDA ADVISORY COVERAGE INCOMPLETE",
            "advisory coverage is incomplete",
        ),
    ],
    ids=["advisory-match", "coverage-only"],
)
def test_render_hook_warning_labels_interactive_state(
    monkeypatch,
    report: AdvisoryReport,
    expected_title: str,
    expected_text: str,
) -> None:
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.delenv("NO_COLOR", raising=False)
    stream = TerminalStream()

    render_hook_warning(report, stream=stream)

    output = stream.getvalue()
    assert "\x1b[" in output
    assert expected_title in output
    assert expected_text in output
    assert "+" in output


def test_render_hook_warning_honors_no_color(monkeypatch) -> None:
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("NO_COLOR", "1")
    stream = TerminalStream()

    render_hook_warning(
        make_report(findings=(make_finding(),)),
        stream=stream,
    )

    output = stream.getvalue()
    assert "CONDA ADVISORY WARNING" in output
    assert "30;43m" not in output
    assert "33m" not in output
