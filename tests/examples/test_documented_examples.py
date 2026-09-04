from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.request import urlopen

import pytest
from jsonschema import Draft202012Validator

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
    environment["XDG_CACHE_HOME"] = str(tmp_path / "cache")
    environment["CONDARC"] = str(tmp_path / "condarc")
    subprocess.run(
        [sys.executable, str(DEMO_FIXTURES / "setup.py"), str(tmp_path)],
        cwd=PROJECT_ROOT,
        env=environment,
        check=True,
        capture_output=True,
    )
    server = subprocess.Popen(
        [sys.executable, str(DEMO_FIXTURES / "server.py"), str(tmp_path)],
        cwd=PROJECT_ROOT,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _attempt in range(100):
            try:
                with urlopen("http://127.0.0.1:8765/health", timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("fixture advisory server did not start")
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
