"""Tests for conda plugin registration."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import ssl
import subprocess
import sys
import tarfile
import threading
import time
from dataclasses import dataclass
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from statistics import median
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest
from conda.base.context import context
from conda.models.records import PackageRecord

from conda_advise.cache import AdvisoryCache
from conda_advise.models import (
    AdvisoryReport,
    Coverage,
    CoverageStatus,
    Evidence,
    EvidenceType,
    Finding,
    ProviderName,
    Severity,
)
from conda_advise.plugin import (
    BASILISK_URL_SETTING,
    MINIMUM_SEVERITY_SETTING,
    ORIGINS_SETTING,
    OSV_URL_SETTING,
    PARSELMOUTH_URL_SETTING,
    POST_SOLVE_SETTING,
    PROVIDER_SETTING,
    TIMEOUT_SETTING,
    _post_solve,
    conda_post_solves,
    conda_settings,
    conda_subcommands,
)
from conda_advise.provenance import subject_from_record

if TYPE_CHECKING:
    from collections.abc import Iterator

INTEGRATION_PACKAGE = "conda-advise-hook-fixture"
INTEGRATION_VERSIONS = ("1.0", "2.0")


@dataclass(frozen=True, slots=True)
class LocalTransactionChannel:
    url: str
    environment: dict[str, str]
    disabled_config: Path
    enabled_config: Path
    matched_config: Path
    sha256_by_version: dict[str, str]


class LocalChannelHandler(SimpleHTTPRequestHandler):
    requests: list[str] = []
    versions_by_sha256: dict[str, str] = {}

    def _send_json(self, payload: object) -> None:
        response = json.dumps(payload, sort_keys=True).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def do_GET(self) -> None:
        self.requests.append(self.path)
        if self.path.startswith("/matching-provider/hash-v0/"):
            sha256 = self.path.rsplit("/", 1)[-1]
            version = self.versions_by_sha256[sha256]
            self._send_json(
                {
                    "pypi_normalized_names": [INTEGRATION_PACKAGE],
                    "versions": {INTEGRATION_PACKAGE: version},
                }
            )
            return
        if self.path == "/matching-provider/v1/vulns/GHSA-aaaa-bbbb-cccc":
            self._send_json(
                {
                    "id": "GHSA-aaaa-bbbb-cccc",
                    "modified": "2026-09-04T12:00:00Z",
                    "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                    "affected": [
                        {
                            "package": {
                                "ecosystem": "PyPI",
                                "name": INTEGRATION_PACKAGE,
                            },
                            "ranges": [
                                {"type": "ECOSYSTEM", "events": [{"fixed": "3.0"}]}
                            ],
                        }
                    ],
                }
            )
            return
        if self.path.startswith("/provider/hash-v0/"):
            self._send_json([])
            return
        super().do_GET()

    def do_POST(self) -> None:
        self.requests.append(self.path)
        if self.path == "/matching-provider/v1/querybatch":
            length = int(self.headers.get("content-length", "0"))
            request = json.loads(self.rfile.read(length))
            self._send_json(
                {
                    "results": [
                        {
                            "vulns": [
                                {
                                    "id": "GHSA-aaaa-bbbb-cccc",
                                    "modified": "2026-09-04T12:00:00Z",
                                }
                            ]
                        }
                        for _ in request["queries"]
                    ]
                }
            )
            return
        self.send_error(404)

    def log_message(self, *_: object) -> None:
        return


def make_record(
    *,
    name: str = "demo",
    version: str = "1.0",
    digest: str = "a",
    sha256: str | None = None,
) -> PackageRecord:
    return PackageRecord(
        name=name,
        version=version,
        build="py_0",
        build_number=0,
        channel="conda-forge",
        subdir="noarch",
        fn=f"{name}-{version}-py_0.conda",
        url=(
            f"https://conda.anaconda.org/conda-forge/noarch/{name}-{version}-py_0.conda"
        ),
        sha256=sha256 or digest * 64,
    )


def make_hook_report(record: PackageRecord) -> AdvisoryReport:
    subject = subject_from_record(record)
    return AdvisoryReport(
        schema_version=1,
        generated_at="2026-09-04T12:00:00Z",
        target="/target",
        provider=ProviderName.OSV,
        minimum_severity=Severity.HIGH,
        subjects=(subject,),
        coverage=(
            Coverage(
                subject=subject.identifier,
                provider=ProviderName.OSV,
                status=CoverageStatus.COMPLETE,
                reason=None,
                checked_at="2026-09-04T12:00:00Z",
            ),
        ),
        findings=(
            Finding(
                subject=subject.identifier,
                id="CVE-2026-0001",
                aliases=("CVE-2026-0001",),
                summary="Example advisory",
                severity=Severity.HIGH,
                score=7.5,
                fixes=("1.1",),
                evidence=(
                    Evidence(
                        type=EvidenceType.ARTIFACT_COMPONENT,
                        provider=ProviderName.OSV,
                        artifact_sha256=subject.sha256,
                        component_purl="pkg:pypi/demo@1.0",
                    ),
                ),
                source_records=(),
            ),
        ),
    )


def make_settings() -> SimpleNamespace:
    return SimpleNamespace(
        conda_advise_provider="osv",
        conda_advise_post_solve="warn",
        conda_advise_minimum_severity="high",
        conda_advise_timeout_seconds=5,
        conda_advise_conda_forge_origins=("https://conda.anaconda.org/conda-forge",),
        conda_advise_osv_url="https://api.osv.dev",
        conda_advise_parselmouth_url="https://conda-mapping.prefix.dev",
        conda_advise_basilisk_url="https://api.basilisk.prefix.dev",
    )


@pytest.fixture
def local_transaction_channel(
    tmp_path: Path,
) -> Iterator[LocalTransactionChannel]:
    channel = tmp_path / "channel"
    noarch = channel / "noarch"
    noarch.mkdir(parents=True)
    packages = {}
    sha256_by_version = {}
    for version in INTEGRATION_VERSIONS:
        filename = f"{INTEGRATION_PACKAGE}-{version}-0.tar.bz2"
        package_path = noarch / filename
        index = {
            "name": INTEGRATION_PACKAGE,
            "version": version,
            "build": "0",
            "build_number": 0,
            "subdir": "noarch",
            "noarch": "generic",
            "depends": [],
        }
        members = {
            "info/index.json": json.dumps(index, sort_keys=True).encode(),
            "info/files": b"",
        }
        with tarfile.open(package_path, mode="w:bz2") as archive:
            for name, contents in members.items():
                member = tarfile.TarInfo(name)
                member.size = len(contents)
                member.mode = 0o644
                archive.addfile(member, io.BytesIO(contents))
        artifact = package_path.read_bytes()
        sha256 = hashlib.sha256(artifact).hexdigest()
        sha256_by_version[version] = sha256
        packages[filename] = {
            **index,
            "sha256": sha256,
            "md5": hashlib.md5(artifact, usedforsecurity=False).hexdigest(),
            "size": len(artifact),
        }
    for subdir in (context.subdir, "noarch"):
        directory = channel / subdir
        directory.mkdir(parents=True, exist_ok=True)
        repodata = {
            "info": {"subdir": subdir},
            "packages": {},
            "packages.conda": {},
            "removed": [],
        }
        if subdir == "noarch":
            repodata["packages"] = packages
        encoded = json.dumps(repodata, sort_keys=True)
        (directory / "repodata.json").write_text(encoded, encoding="utf-8")
        (directory / "current_repodata.json").write_text(encoded, encoding="utf-8")

    openssl = shutil.which("openssl")
    assert openssl is not None, "the conda runtime does not provide openssl"
    certificate = tmp_path / "certificate.pem"
    private_key = tmp_path / "private-key.pem"
    generated = subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert generated.returncode == 0, generated.stderr
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        partial(LocalChannelHandler, directory=str(tmp_path)),
    )
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(certificate, private_key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    LocalChannelHandler.requests = []
    LocalChannelHandler.versions_by_sha256 = {
        sha256: version for version, sha256 in sha256_by_version.items()
    }
    thread.start()
    channel_url = f"https://127.0.0.1:{server.server_port}/channel"
    provider_url = f"https://127.0.0.1:{server.server_port}/provider"

    configurations = {}
    for configuration, post_solve, advisory_url in (
        ("off", "off", provider_url),
        ("warn", "warn", provider_url),
        (
            "matched",
            "warn",
            f"https://127.0.0.1:{server.server_port}/matching-provider",
        ),
    ):
        directory = tmp_path / f"config-{configuration}"
        directory.mkdir()
        condarc = directory / "condarc"
        condarc.write_text(
            "\n".join(
                (
                    "plugins:",
                    f'  conda_advise_post_solve: "{post_solve}"',
                    "  conda_advise_provider: osv",
                    "  conda_advise_timeout_seconds: 5",
                    f"  conda_advise_osv_url: {advisory_url}",
                    f"  conda_advise_parselmouth_url: {advisory_url}",
                    f"  conda_advise_basilisk_url: {provider_url}",
                    "  conda_advise_conda_forge_origins:",
                    f"    - {channel_url}",
                    "channels: []",
                    "default_channels: []",
                    "repodata_use_zst: false",
                    "repodata_use_shards: false",
                    "ssl_verify: false",
                    "",
                )
            ),
            encoding="utf-8",
        )
        configurations[configuration] = condarc

    environment = os.environ.copy()
    for name in (
        "CONDARC",
        "CONDA_DRY_RUN",
        "CONDA_JSON",
        "CONDA_NO_PLUGINS",
        "CONDA_OFFLINE",
        "CONDA_SOLVER",
        "CONDA_SUBDIR",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "CONDA_ENVS_PATH": str(tmp_path / "envs"),
            "CONDA_NOTICES_INTERCEPT_CHANNEL_NOTICES": "false",
            "CONDA_PKGS_DIRS": str(tmp_path / "packages"),
            "CONDA_REGISTER_ENVS": "false",
            "HTTP_PROXY": "http://127.0.0.1:1",
            "HTTPS_PROXY": "http://127.0.0.1:1",
            "NO_PROXY": "127.0.0.1,localhost",
            "PYTHONNOUSERSITE": "1",
            "XDG_CACHE_HOME": str(tmp_path / "cache"),
            "http_proxy": "http://127.0.0.1:1",
            "https_proxy": "http://127.0.0.1:1",
            "no_proxy": "127.0.0.1,localhost",
        }
    )
    try:
        yield LocalTransactionChannel(
            url=channel_url,
            environment=environment,
            disabled_config=configurations["off"],
            enabled_config=configurations["warn"],
            matched_config=configurations["matched"],
            sha256_by_version=sha256_by_version,
        )
    finally:
        if thread.is_alive():
            server.shutdown()
            thread.join(timeout=5)
        server.server_close()


def run_conda_transaction(
    operation: str,
    channel: str,
    target: Path,
    solver: str,
    environment: dict[str, str],
    condarc: Path,
    *,
    package: str | None = None,
    dry_run: bool = False,
    json_output: bool = False,
    offline: bool = False,
) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, "-m", "conda"]
    if json_output:
        command.append("--json")
    command.extend(
        (
            operation,
            "--override-channels",
            "--channel",
            channel,
            "--prefix",
            str(target),
            "--solver",
            solver,
            "-y",
        )
    )
    if operation == "create":
        command.append("--no-default-packages")
    if dry_run:
        command.append("--dry-run")
    if offline:
        command.append("--offline")
    if package is not None:
        command.append(package)
    return subprocess.run(
        command,
        cwd=Path(__file__).parents[1],
        env={**environment, "CONDARC": str(condarc)},
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def installed_version(target: Path) -> str:
    records = tuple((target / "conda-meta").glob(f"{INTEGRATION_PACKAGE}-*.json"))
    assert len(records) == 1
    return json.loads(records[0].read_text(encoding="utf-8"))["version"]


def test_conda_subcommands_registers_advise_and_common_typo() -> None:
    subcommands = list(conda_subcommands())

    assert [subcommand.name for subcommand in subcommands] == ["advise", "advice"]
    assert (
        subcommands[0].summary
        == "Report advisory matches and coverage for a conda environment."
    )
    assert all(callable(subcommand.action) for subcommand in subcommands)
    assert all(callable(subcommand.configure_parser) for subcommand in subcommands)
    assert subcommands[0].action is subcommands[1].action


def test_conda_settings_registers_flat_settings() -> None:
    settings = {setting.name: setting for setting in conda_settings()}

    assert set(settings) == {
        BASILISK_URL_SETTING,
        MINIMUM_SEVERITY_SETTING,
        ORIGINS_SETTING,
        OSV_URL_SETTING,
        PARSELMOUTH_URL_SETTING,
        POST_SOLVE_SETTING,
        PROVIDER_SETTING,
        TIMEOUT_SETTING,
    }
    assert settings[PROVIDER_SETTING].parameter.default.value == "osv"
    assert settings[POST_SOLVE_SETTING].parameter.default.value == "warn"
    assert settings[MINIMUM_SEVERITY_SETTING].parameter.default.value == "high"
    assert settings[TIMEOUT_SETTING].parameter.default.value == 5


def test_conda_post_solves_registers_warning_hook() -> None:
    hooks = list(conda_post_solves())

    assert len(hooks) == 1
    assert hooks[0].name == "conda-advise"
    assert callable(hooks[0].action)


def test_plugin_import_does_not_eagerly_import_runtime_modules() -> None:
    code = """
import sys
import conda_advise.plugin

eager_modules = {
    "conda_advise.cli.main",
    "conda_advise.reporting",
    "conda_advise.scanner",
    "conda_advise.providers.osv",
    "conda_advise.providers.basilisk",
}
loaded = sorted(eager_modules.intersection(sys.modules))
if loaded:
    raise SystemExit(f"eager runtime imports: {loaded}")
"""

    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("solver", ["classic", "libmamba"])
def test_conda_runs_discovered_post_solve_hook_during_real_dry_run(
    solver: str,
    local_transaction_channel: LocalTransactionChannel,
) -> None:
    setup = local_transaction_channel
    root = setup.disabled_config.parents[1]

    json_prefix = root / "json-prefix"
    baseline = run_conda_transaction(
        "create",
        setup.url,
        json_prefix,
        solver,
        setup.environment,
        setup.disabled_config,
        package=INTEGRATION_PACKAGE,
        dry_run=True,
        json_output=True,
    )
    assert baseline.returncode == 0, baseline.stderr
    assert "conda-advise:" not in baseline.stderr

    human = run_conda_transaction(
        "create",
        setup.url,
        root / "human-prefix",
        solver,
        setup.environment,
        setup.enabled_config,
        package=INTEGRATION_PACKAGE,
        dry_run=True,
        json_output=False,
    )
    assert human.returncode == 0, human.stderr
    assert INTEGRATION_PACKAGE in human.stdout
    assert (
        "conda-advise: advisory coverage is incomplete for 1 package." in human.stderr
    )

    machine = run_conda_transaction(
        "create",
        setup.url,
        json_prefix,
        solver,
        setup.environment,
        setup.enabled_config,
        package=INTEGRATION_PACKAGE,
        dry_run=True,
        json_output=True,
    )
    assert machine.returncode == 0, machine.stderr
    assert (
        "conda-advise: advisory coverage is incomplete for 1 package." in machine.stderr
    )
    baseline_payload = json.loads(baseline.stdout)
    machine_payload = json.loads(machine.stdout)
    assert machine_payload == baseline_payload
    assert "conda-advise:" not in machine.stdout
    assert machine_payload["success"] is True
    assert any(
        record["name"] == INTEGRATION_PACKAGE
        for record in machine_payload["actions"]["LINK"]
    )
    assert any(
        path.startswith("/provider/hash-v0/") for path in LocalChannelHandler.requests
    )


@pytest.mark.parametrize("solver", ["classic", "libmamba"])
def test_real_transaction_summary_includes_the_advisory_tag(
    solver: str,
    local_transaction_channel: LocalTransactionChannel,
) -> None:
    setup = local_transaction_channel
    LocalChannelHandler.requests = []

    result = run_conda_transaction(
        "create",
        setup.url,
        setup.disabled_config.parents[1] / f"matched-{solver}",
        solver,
        setup.environment,
        setup.matched_config,
        package=f"{INTEGRATION_PACKAGE}=1.0",
        dry_run=True,
    )

    assert result.returncode == 0, result.stderr
    assert "[advisory:high]" in result.stdout
    assert "1 package has advisory matches at or above high" in result.stderr
    assert "/matching-provider/v1/querybatch" in LocalChannelHandler.requests
    assert (
        "/matching-provider/v1/vulns/GHSA-aaaa-bbbb-cccc"
        in LocalChannelHandler.requests
    )


@pytest.mark.parametrize(
    ("operation", "initial_version", "package", "expected_version"),
    [
        ("create", None, f"{INTEGRATION_PACKAGE}=1.0", "1.0"),
        ("install", None, f"{INTEGRATION_PACKAGE}=1.0", "1.0"),
        ("update", "1.0", INTEGRATION_PACKAGE, "2.0"),
    ],
    ids=["create", "install", "update"],
)
@pytest.mark.parametrize("solver", ["classic", "libmamba"])
def test_conda_runs_discovered_post_solve_hook_for_real_transactions_with_y(
    operation: str,
    initial_version: str | None,
    package: str,
    expected_version: str,
    solver: str,
    local_transaction_channel: LocalTransactionChannel,
) -> None:
    setup = local_transaction_channel
    target = setup.disabled_config.parents[1] / f"{operation}-{solver}"
    if operation == "install":
        conda_meta = target / "conda-meta"
        conda_meta.mkdir(parents=True)
        (conda_meta / "history").write_text("", encoding="utf-8")
    if initial_version is not None:
        initial = run_conda_transaction(
            "create",
            setup.url,
            target,
            solver,
            setup.environment,
            setup.disabled_config,
            package=f"{INTEGRATION_PACKAGE}={initial_version}",
        )
        assert initial.returncode == 0, initial.stderr
        assert installed_version(target) == initial_version

    LocalChannelHandler.requests = []
    result = run_conda_transaction(
        operation,
        setup.url,
        target,
        solver,
        setup.environment,
        setup.enabled_config,
        package=package,
    )

    assert result.returncode == 0, result.stderr
    assert installed_version(target) == expected_version
    assert (
        "conda-advise: advisory coverage is incomplete for 1 package." in result.stderr
    )
    expected_path = f"/provider/hash-v0/{setup.sha256_by_version[expected_version]}"
    assert expected_path in LocalChannelHandler.requests


@pytest.mark.parametrize("solver", ["classic", "libmamba"])
def test_conda_offline_transaction_uses_cached_artifact_without_provider_request(
    solver: str,
    local_transaction_channel: LocalTransactionChannel,
) -> None:
    setup = local_transaction_channel
    root = setup.disabled_config.parents[1]
    warm = run_conda_transaction(
        "create",
        setup.url,
        root / f"warm-{solver}",
        solver,
        setup.environment,
        setup.disabled_config,
        package=f"{INTEGRATION_PACKAGE}=1.0",
    )
    assert warm.returncode == 0, warm.stderr

    LocalChannelHandler.requests = []
    target = root / f"offline-{solver}"
    result = run_conda_transaction(
        "create",
        setup.url,
        target,
        solver,
        setup.environment,
        setup.enabled_config,
        package=f"{INTEGRATION_PACKAGE}=1.0",
        offline=True,
    )

    assert result.returncode == 0, result.stderr
    assert installed_version(target) == "1.0"
    assert (
        "conda-advise: advisory coverage is incomplete for 1 package." in result.stderr
    )
    assert not LocalChannelHandler.requests


def test_post_solve_provider_failure_does_not_abort_transaction(
    monkeypatch, caplog
) -> None:
    def fail_scan(*args, **kwargs):
        raise RuntimeError("provider failed")

    monkeypatch.setattr(context, "plugins", make_settings())
    monkeypatch.setattr(context, "offline", False)
    monkeypatch.setattr("conda_advise.scanner.scan_records", fail_scan)

    _post_solve("repodata.json", (), (object(),))

    assert "could not complete the advisory check: provider failed" in caplog.text


def test_post_solve_checks_only_link_records(
    monkeypatch,
    capsys,
) -> None:
    link_record = make_record()
    unlink_records = (make_record(version="0.9", digest="b"),)
    calls = []

    def fake_scan_records(records, **options):
        calls.append((tuple(records), options))
        return make_hook_report(link_record)

    monkeypatch.setattr(context, "plugins", make_settings())
    monkeypatch.setattr(context, "offline", False)
    monkeypatch.setattr("conda_advise.scanner.scan_records", fake_scan_records)

    _post_solve(
        "repodata.json",
        unlink_records,
        (link_record,),
    )

    captured = capsys.readouterr()
    assert not captured.out
    assert "1 package has advisory matches" in captured.err
    assert link_record.metadata == {"[advisory:high]"}
    assert all(not record.metadata for record in unlink_records)
    assert len(calls) == 1
    assert calls[0][0] == (link_record,)
    assert calls[0][1]["provider"] == "osv"
    assert calls[0][1]["target"] == str(context.target_prefix)


@pytest.mark.parametrize(
    ("json_output", "console"),
    [(True, "classic"), (False, "json")],
    ids=["json-flag", "json-console"],
)
def test_post_solve_uses_plain_warning_in_global_json_mode(
    monkeypatch, json_output: bool, console: str
) -> None:
    link_record = make_record()
    rich_output = []

    monkeypatch.setattr(context, "plugins", make_settings())
    monkeypatch.setattr(context, "offline", False)
    monkeypatch.setattr(context, "json", json_output)
    monkeypatch.setattr(
        type(context),
        "console",
        property(lambda self: console),
        raising=False,
    )
    monkeypatch.setattr(
        "conda_advise.scanner.scan_records",
        lambda records, **options: make_hook_report(link_record),
    )
    monkeypatch.setattr(
        "conda_advise.reporting.render_hook_warning",
        lambda report, **options: rich_output.append(options["rich_output"]),
    )

    _post_solve("repodata.json", (), (link_record,))

    assert rich_output == [False]


def test_cached_post_solve_of_100_records(
    monkeypatch, tmp_path, capsys, caplog
) -> None:
    from conda_advise.scanner import scan_records

    records = tuple(
        make_record(name=f"demo-{index}", sha256=f"{index + 1:064x}")
        for index in range(100)
    )
    cache_path = tmp_path / "cache.sqlite3"
    with AdvisoryCache(cache_path) as cache:
        for record in records:
            assert record.sha256 is not None
            cache.put(
                "parselmouth:https://conda-mapping.prefix.dev",
                record.sha256,
                {
                    "pypi_normalized_names": [record.name],
                    "versions": {record.name: record.version},
                },
                positive=True,
            )
            cache.put(
                "osv.query:https://api.osv.dev",
                f"pkg:pypi/{record.name}@{record.version}",
                {"vulns": []},
                positive=False,
            )

    monkeypatch.setattr(context, "plugins", make_settings())
    monkeypatch.setattr(context, "offline", True)
    monkeypatch.setattr("conda_advise.cache.default_cache_path", lambda: cache_path)
    monkeypatch.setattr(
        "conda_advise.network.get_session",
        lambda url: pytest.fail(f"cached hook attempted {url}"),
    )

    cached_report = scan_records(records, offline=True, cache_path=cache_path)
    assert cached_report.summary.mapped == 100
    assert not cached_report.has_incomplete

    samples = []
    for _ in range(5):
        started = time.perf_counter()
        _post_solve("repodata.json", (), records)
        samples.append(time.perf_counter() - started)

    elapsed = median(samples)
    captured = capsys.readouterr()
    assert not captured.out
    assert not captured.err
    assert "could not complete the advisory check" not in caplog.text
    if os.environ.get("_CONDA_ADVISE_ENFORCE_PERFORMANCE_TARGETS") == "1":
        assert elapsed < 0.1, f"cached post-solve median was {elapsed:.3f} seconds"
