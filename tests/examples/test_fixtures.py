from __future__ import annotations

import errno
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from conda_advise.cache import AdvisoryCache
from conda_advise.kev import DEFAULT_KEV_URL
from demos.fixtures.setup import create_fixture
from demos.fixtures.wait import wait_for_server
from recipe.offline_smoke import check_offline


@pytest.mark.parametrize("operation", ["demo", "offline-smoke"])
def test_fixture_cache_does_not_modify_user_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    user_cache = tmp_path / "user-cache.sqlite3"
    source = f"kev:{DEFAULT_KEV_URL}"
    expected = {"count": 0, "vulnerabilities": []}
    with AdvisoryCache(user_cache) as cache:
        cache.put(source, "catalog", expected, positive=True)
    monkeypatch.setenv("CONDA_ADVISE_CACHE_PATH", str(user_cache))
    root = tmp_path / "fixture"
    root.mkdir(mode=0o700)

    if operation == "demo":
        create_fixture(root, "http://127.0.0.1:49152")
    else:
        check_offline(root)

    assert os.environ["CONDA_ADVISE_CACHE_PATH"] == str(user_cache)
    with AdvisoryCache(user_cache) as cache:
        entry = cache.get(source, "catalog")
        assert entry is not None
        assert entry.payload == expected
    with AdvisoryCache(root / "cache" / "cache.sqlite3") as cache:
        entry = cache.get(source, "catalog")
        assert entry is not None
        assert entry.payload["vulnerabilities"] == [{"cveID": "CVE-2026-0001"}]


@pytest.mark.parametrize("target", ["root", "condarc", "cache"])
def test_demo_setup_rejects_existing_symlinks(tmp_path: Path, target: str) -> None:
    victim = tmp_path / "victim"
    victim.mkdir()
    marker = victim / "marker"
    marker.write_text("unchanged", encoding="utf-8")
    root = tmp_path / "fixture"
    if target == "root":
        link = root
    else:
        root.mkdir(mode=0o700)
        link = root / target
    try:
        link.symlink_to(victim, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(ValueError, match="private and empty"):
        create_fixture(root, "http://127.0.0.1:49152")

    assert marker.read_text(encoding="utf-8") == "unchanged"
    assert list(victim.iterdir()) == [marker]


def test_demo_readiness_rejects_another_process(tmp_path: Path) -> None:
    (tmp_path / "ready.json").write_text(
        json.dumps({"pid": 123, "url": "http://127.0.0.1:8765"}), encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="wrong process ID"):
        wait_for_server(tmp_path, 456)


def test_demo_listener_starts_with_legacy_port_occupied(tmp_path: Path) -> None:
    with socket.socket() as listener:
        try:
            listener.bind(("127.0.0.1", 8765))
        except OSError:
            pytest.skip("legacy demo port is already occupied")
        listener.listen()
        server = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).parents[2] / "demos" / "fixtures" / "server.py"),
                str(tmp_path),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            service_url = wait_for_server(tmp_path, server.pid)
            assert server.poll() is None
            assert service_url != "http://127.0.0.1:8765"
            assert service_url in (tmp_path / "condarc").read_text(encoding="utf-8")
            with socket.socket() as competing_listener:
                competing_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                port = int(service_url.rsplit(":", 1)[-1])
                with pytest.raises(OSError) as caught:  # noqa: PT011
                    competing_listener.bind(("127.0.0.1", port))
                assert caught.value.errno in {
                    errno.EADDRINUSE,
                    errno.EACCES,
                    10048,
                    10013,
                }
            listener.settimeout(0.1)
            with pytest.raises(TimeoutError):
                listener.accept()
        finally:
            server.terminate()
            server.wait(timeout=5)
