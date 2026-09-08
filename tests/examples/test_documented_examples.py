from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from jsonschema import Draft202012Validator

from demos.fixtures.wait import wait_for_server

if TYPE_CHECKING:
    from collections.abc import Iterator

PROJECT_ROOT = Path(__file__).parents[2]
SCHEMA_PATH = PROJECT_ROOT / "schema" / "conda-advise-report-v1.schema.json"
FIXTURES = Path(__file__).parent / "fixtures"
DEMO_FIXTURES = PROJECT_ROOT / "demos" / "fixtures"


@pytest.fixture
def report_schema() -> dict[str, object]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def advisory_services(
    tmp_path: Path,
) -> Iterator[tuple[dict[str, str], Path, subprocess.Popen[bytes]]]:
    environment = os.environ.copy()
    environment["CONDA_ADVISE_CACHE_PATH"] = str(tmp_path / "cache" / "cache.sqlite3")
    environment["CONDARC"] = str(tmp_path / "condarc")
    environment["CONDA_PKGS_DIRS"] = str(tmp_path / "pkgs")
    # These examples test provider results and cache reuse, not startup speed.
    environment["CONDA_PLUGINS_CONDA_ADVISE_TIMEOUT_SECONDS"] = "30"
    server = subprocess.Popen(
        [sys.executable, str(DEMO_FIXTURES / "server.py"), str(tmp_path)],
        cwd=PROJECT_ROOT,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_for_server(tmp_path, server.pid)
        assert server.poll() is None
        yield environment, tmp_path / "prefix", server
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)


def test_report_schema_is_valid(report_schema: dict[str, object]) -> None:
    Draft202012Validator.check_schema(report_schema)


@pytest.mark.parametrize(
    "fixture_name",
    ["report-v1.json"],
    ids=["complete-osv-report"],
)
def test_documented_reports_match_schema(
    report_schema: dict[str, object],
    fixture_name: str,
) -> None:
    payload = json.loads((FIXTURES / fixture_name).read_text(encoding="utf-8"))
    Draft202012Validator(report_schema).validate(payload)


def test_json_error_matches_schema(report_schema: dict[str, object]) -> None:
    payload = {
        "schema_version": 1,
        "target": "/missing/prefix",
        "error": {"message": "target prefix does not exist"},
    }
    Draft202012Validator(report_schema).validate(payload)


def test_documented_help_command() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "conda", "advise", "--help"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert "--provider {osv,basilisk}" in completed.stdout


@pytest.mark.parametrize("provider", ["osv", "basilisk"], ids=["osv", "basilisk"])
def test_documented_provider_scans(
    advisory_services: tuple[dict[str, str], Path, subprocess.Popen[bytes]],
    report_schema: dict[str, object],
    provider: str,
) -> None:
    environment, prefix, _server = advisory_services
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "conda",
            "advise",
            "--prefix",
            str(prefix),
            "--provider",
            provider,
            "--json",
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 1, completed.stderr
    payload = json.loads(completed.stdout)
    Draft202012Validator(report_schema).validate(payload)
    assert payload["provider"] == provider
    assert payload["summary"]["qualifying_matches"] == 1


def test_documented_offline_scan_uses_cached_results(
    advisory_services: tuple[dict[str, str], Path, subprocess.Popen[bytes]],
    report_schema: dict[str, object],
) -> None:
    environment, prefix, server = advisory_services
    command = [
        sys.executable,
        "-m",
        "conda",
        "advise",
        "--prefix",
        str(prefix),
        "--provider",
        "osv",
        "--json",
    ]
    online = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert online.returncode == 1, online.stderr

    server.terminate()
    server.wait(timeout=5)
    offline = subprocess.run(
        [*command, "--offline"],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert offline.returncode == 1, offline.stderr
    payload = json.loads(offline.stdout)
    Draft202012Validator(report_schema).validate(payload)
    assert payload["summary"]["qualifying_matches"] == 1
    assert payload["summary"]["incomplete"] == 0


def test_demo_install_emits_post_solve_warning(
    advisory_services: tuple[dict[str, str], Path, subprocess.Popen[bytes]],
) -> None:
    environment, prefix, server = advisory_services
    service_url = wait_for_server(prefix.parent, server.pid)
    transaction_prefix = prefix.parent / "transaction-prefix"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "conda",
            "create",
            "--quiet",
            "--yes",
            "--prefix",
            str(transaction_prefix),
            "--override-channels",
            "--channel",
            f"{service_url}/channel",
            "--solver",
            "libmamba",
            "demo-package",
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "conda-advise:" in completed.stderr
    assert "1 package has advisory matches" in completed.stderr
    assert "incomplete" not in completed.stderr
    assert (transaction_prefix / "share" / "conda-advise-demo.txt").read_text(
        encoding="utf-8"
    ) == "deterministic conda-advise demonstration\n"
