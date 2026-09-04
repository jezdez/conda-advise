"""Tests for the ``conda advise`` command."""

from __future__ import annotations

import json

import pytest

from conda_advise.cli import build_parser, execute
from conda_advise.models import AdvisoryReport, ProviderName, Severity


def test_build_parser_uses_osv_configuration_by_default() -> None:
    args = build_parser().parse_args([])

    assert args.provider is None
    assert args.minimum_severity is None
    assert not args.refresh


def test_build_parser_accepts_basilisk_and_standard_conda_options() -> None:
    args = build_parser().parse_args(
        [
            "--provider",
            "basilisk",
            "--minimum-severity",
            "medium",
            "--offline",
            "--json",
            "-p",
            "/tmp/example",
        ]
    )

    assert args.provider == "basilisk"
    assert args.minimum_severity == "medium"
    assert args.offline
    assert args.json
    assert args.prefix == "/tmp/example"


@pytest.mark.parametrize(
    ("provider_args", "expected_provider"),
    [
        ([], "osv"),
        (["--provider=basilisk"], "basilisk"),
    ],
    ids=["configured-default", "cli-override"],
)
def test_execute_scans_selected_prefix_and_emits_json(
    monkeypatch,
    tmp_path,
    capsys,
    provider_args: list[str],
    expected_provider: str,
) -> None:
    prefix = tmp_path / "environment"
    (prefix / "conda-meta").mkdir(parents=True)
    (prefix / "conda-meta" / "history").touch()
    calls = []

    def fake_scan_records(records, **options):
        calls.append((tuple(records), options))
        return AdvisoryReport(
            schema_version=1,
            generated_at="2026-09-04T12:00:00Z",
            target=options["target"],
            provider=ProviderName(options["provider"]),
            minimum_severity=Severity.parse(options["minimum_severity"]),
            subjects=(),
            coverage=(),
            findings=(),
        )

    monkeypatch.setattr("conda_advise.scanner.scan_records", fake_scan_records)
    args = build_parser().parse_args(
        ["-p", str(prefix), "--offline", "--json", *provider_args]
    )

    result = execute(args)

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert result == 0
    assert not captured.err
    assert payload["target"] == str(prefix)
    assert payload["provider"] == expected_provider
    assert len(calls) == 1
    assert calls[0][0] == ()
    assert calls[0][1]["provider"] == expected_provider
    assert calls[0][1]["offline"] is True


def test_execute_rejects_offline_refresh_as_json(capsys) -> None:
    args = build_parser().parse_args(["--offline", "--refresh", "--json"])

    result = execute(args)

    captured = capsys.readouterr()
    assert result == 2
    assert not captured.err
    assert json.loads(captured.out)["error"]["message"] == (
        "--offline and --refresh cannot be used together"
    )


def test_global_conda_json_produces_one_json_document(
    monkeypatch, tmp_path, capsys
) -> None:
    from conda.base.context import reset_context
    from conda.cli.main import main_subshell

    prefix = tmp_path / "environment"
    (prefix / "conda-meta").mkdir(parents=True)
    (prefix / "conda-meta" / "history").touch()

    def fake_scan_records(records, **options):
        return AdvisoryReport(
            schema_version=1,
            generated_at="2026-09-04T12:00:00Z",
            target=options["target"],
            provider=ProviderName(options["provider"]),
            minimum_severity=Severity.parse(options["minimum_severity"]),
            subjects=(),
            coverage=(),
            findings=(),
        )

    monkeypatch.setattr("conda_advise.scanner.scan_records", fake_scan_records)
    try:
        result = main_subshell(
            "--json",
            "advise",
            "--offline",
            "-p",
            str(prefix),
        )
        captured = capsys.readouterr()
    finally:
        reset_context()

    assert result == 0
    assert not captured.err
    assert json.loads(captured.out)["target"] == str(prefix)
