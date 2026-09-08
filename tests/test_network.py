from __future__ import annotations

import gzip
import importlib
import json
import subprocess
import sys
import textwrap
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest
from conda.base.context import context
from conda.gateways.connection.session import CondaSession, get_channel_name_from_url

import conda_advise.network as network
from conda_advise.models import FailureReason
from conda_advise.network import JsonRequest, _fetch_one, fetch_json


@pytest.fixture
def http_server():
    requests = []
    release = threading.Event()

    class JsonHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self._respond(None)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            self._respond(json.loads(self.rfile.read(length)))

        def log_message(self, *_: object) -> None:
            return

        def _respond(self, payload: dict[str, object] | None) -> None:
            path = urlsplit(self.path).path
            requests.append((self.command, path, payload, dict(self.headers)))
            body = json.dumps({"method": self.command, "payload": payload}).encode()
            status = 200
            headers = {"Content-Type": "application/json"}
            if path in ("/307", "/407", "/404", "/503"):
                status = int(path[1:])
                headers["Location"] = "/redirect-target"
            elif path == "/invalid":
                body = b"not json"
            elif path == "/array":
                body = b"[]"
            elif path == "/non-finite":
                body = b'{"score": NaN}'
            elif path == "/deep":
                body = b'{"nested":' * 2000 + b"null" + b"}" * 2000
            elif path in ("/oversized", "/unadvertised"):
                body = json.dumps({"large": "a" * 256}).encode()
            elif path == "/gzip":
                body = gzip.compress(json.dumps({"large": "a" * 100000}).encode())
                headers["Content-Encoding"] = "gzip"
            elif path == "/stall":
                release.wait(10)
            elif path == "/drip":
                body = b" " * 10000
            if path != "/unadvertised":
                headers["Content-Length"] = str(len(body))
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            try:
                if path == "/drip":
                    for byte in body:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        if release.wait(0.02):
                            break
                else:
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), JsonHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join()


def test_fetch_json_uses_conda_session_against_a_local_http_server(http_server) -> None:
    url, requests = http_server
    responses = fetch_json(
        [JsonRequest("post", "POST", f"{url}/data", {"value": 1})],
        deadline=time.monotonic() + 10,
        max_workers=1,
    )

    assert responses["post"].payload == {"method": "POST", "payload": {"value": 1}}
    assert [(method, payload) for method, _, payload, _ in requests] == [
        ("POST", {"value": 1})
    ]
    assert requests[0][3]["Accept-Encoding"] == "identity"


def test_fetch_json_deduplicates_identical_requests(http_server) -> None:
    url, requests = http_server
    response = fetch_json(
        [
            JsonRequest("first", "GET", f"{url}/data"),
            JsonRequest("second", "GET", f"{url}/data"),
            JsonRequest("second", "GET", f"{url}/different"),
        ],
        deadline=time.monotonic() + 10,
        max_workers=2,
    )

    assert len(requests) == 1
    assert response["first"].payload == response["second"].payload
    assert response["second"].key == "second"


def test_fetch_json_caps_conda_network_timeouts_by_deadline(
    monkeypatch, http_server
) -> None:
    url, _ = http_server
    calls = []
    session = CondaSession()
    send = session.send

    def record_send(request, **options):
        calls.append(options["timeout"])
        return send(request, **options)

    monkeypatch.setattr(context, "remote_connect_timeout_secs", 0.25)
    monkeypatch.setattr(context, "remote_read_timeout_secs", 0.5)
    monkeypatch.setattr(session, "send", record_send)
    monkeypatch.setattr(network, "get_session", lambda url: session)

    response = _fetch_one(JsonRequest("key", "GET", url), time.monotonic() + 1)

    assert response.succeeded
    assert calls == [(0.25, 0.5)]


@pytest.mark.parametrize("status", [307, 407], ids=["redirect", "proxy-challenge"])
def test_fetch_json_rejects_redirect_and_proxy_challenge_before_auth_hooks(
    monkeypatch, http_server, status
) -> None:
    url, requests = http_server
    prompts = []

    def get_credentials(scheme):
        prompts.append(scheme)
        return "user", "secret"

    monkeypatch.setattr(
        "conda.gateways.connection.session.get_proxy_username_and_pass", get_credentials
    )
    session = CondaSession()
    monkeypatch.setattr(session, "proxies", {"http": url})
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setattr(network, "get_session", lambda url: session)
    response = _fetch_one(
        JsonRequest("key", "POST", f"http://origin.invalid/{status}", {"private": 1}),
        time.monotonic() + 2,
    )

    assert response.status_code == status
    assert response.reason is FailureReason.REQUEST_FAILED
    assert len(requests) == 1
    assert "Proxy-Authorization" not in requests[0][3]
    assert not prompts


@pytest.mark.parametrize(
    ("path", "status", "reason"),
    [
        ("/404", 404, None),
        ("/503", 503, FailureReason.REQUEST_FAILED),
        ("/invalid", 200, FailureReason.INVALID_RESPONSE),
        ("/array", 200, FailureReason.INVALID_RESPONSE),
        ("/non-finite", 200, FailureReason.INVALID_RESPONSE),
        ("/deep", 200, FailureReason.INVALID_RESPONSE),
    ],
    ids=["not-found", "http", "decode", "array", "non-finite", "deep"],
)
def test_fetch_json_types_failures(
    monkeypatch, http_server, path, status, reason
) -> None:
    url, _ = http_server
    session = CondaSession()
    for adapter in session.adapters.values():
        if hasattr(adapter, "max_retries"):
            monkeypatch.setattr(adapter.max_retries, "total", 0)
    response = _fetch_one(
        JsonRequest("key", "GET", f"{url}{path}"), time.monotonic() + 2
    )

    assert response.status_code == status
    assert response.reason is reason
    assert response.not_found is (path == "/404")


@pytest.mark.parametrize("path", ["/oversized", "/unadvertised", "/gzip"])
def test_fetch_json_bounds_advertised_streamed_and_compressed_bodies(
    monkeypatch, http_server, path
) -> None:
    url, _ = http_server
    monkeypatch.setattr(network, "MAX_RESPONSE_BYTES", 128)
    response = _fetch_one(
        JsonRequest("large", "GET", f"{url}{path}"), time.monotonic() + 2
    )

    assert response.reason is FailureReason.INVALID_RESPONSE
    assert response.payload is None


@pytest.mark.parametrize("path", ["/307", "/407", "/oversized", "/gzip"])
def test_response_guard_rejects_headers_before_reading_the_body(
    monkeypatch, path
) -> None:
    from requests import Response

    class UnreadableBody:
        def read(self, *args, **kwargs):
            pytest.fail("rejected response body must not be read")

        def close(self):
            return

        def release_conn(self):
            return

    response = Response()
    response.raw = UnreadableBody()
    response.status_code = int(path[1:]) if path in ("/307", "/407") else 200
    if path == "/oversized":
        response.headers["Content-Length"] = str(network.MAX_RESPONSE_BYTES + 1)
    if path == "/gzip":
        response.headers["Content-Encoding"] = "gzip"

    with pytest.raises(network._RejectedResponse):
        network._guard_response(response)


def test_fetch_json_preserves_offline_configuration(monkeypatch, http_server) -> None:
    url, requests = http_server
    monkeypatch.setattr(context, "offline", True)
    response = fetch_json(
        [JsonRequest("key", "GET", url)],
        deadline=time.monotonic() + 10,
        max_workers=1,
    )["key"]

    assert response.reason is FailureReason.REQUEST_FAILED
    assert not requests


def test_fetch_json_preserves_selected_auth_plugin_and_context(
    monkeypatch, tmp_path, http_server
) -> None:
    url, requests = http_server
    plugin_file = tmp_path / "advise_test_auth_plugin.py"
    plugin_file.write_text(
        textwrap.dedent("""\
            from __future__ import annotations
            from conda.base.context import context
            from conda.plugins import hookimpl
            from conda.plugins.types import ChannelAuthBase, CondaAuthHandler

            class TestAuth(ChannelAuthBase):
                def __call__(self, request):
                    request.headers["Authorization"] = (
                        f"Bearer test-{context.remote_read_timeout_secs}"
                    )
                    return request

            @hookimpl
            def conda_auth_handlers():
                yield CondaAuthHandler(name="advise-test-auth", handler=TestAuth)
            """),
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    plugin = importlib.import_module("advise_test_auth_plugin")
    manager = context.plugin_manager
    manager.register(plugin)
    monkeypatch.setattr(
        context,
        "channel_settings",
        (
            {
                "channel": get_channel_name_from_url(f"{url}/data"),
                "auth": "advise-test-auth",
            },
        ),
    )
    monkeypatch.setattr(context, "remote_read_timeout_secs", 3.25)
    try:
        response = fetch_json(
            [JsonRequest("key", "GET", f"{url}/data")],
            deadline=time.monotonic() + 10,
            max_workers=1,
        )["key"]
    finally:
        manager.unregister(plugin)
        sys.modules.pop("advise_test_auth_plugin", None)

    assert response.succeeded
    assert requests[0][3]["Authorization"] == "Bearer test-3.25"


def test_fetch_json_reports_nontransferable_plugins_as_incomplete(http_server) -> None:
    url, requests = http_server

    class LocalPlugin:
        pass

    plugin = LocalPlugin()
    manager = context.plugin_manager
    manager.register(plugin)
    try:
        response = fetch_json(
            [JsonRequest("key", "GET", url)],
            deadline=time.monotonic() + 10,
            max_workers=1,
        )["key"]
    finally:
        manager.unregister(plugin)

    assert response.reason is FailureReason.REQUEST_FAILED
    assert "could not be transferred" in response.message
    assert not requests


@pytest.mark.parametrize("offline", [False, True], ids=["online", "offline"])
def test_worker_discards_sessions_cached_during_plugin_import(
    monkeypatch, tmp_path, http_server, offline
) -> None:
    url, requests = http_server
    plugin_file = tmp_path / "advise_import_session.py"
    plugin_file.write_text(
        "from conda.base.context import context\n"
        "from conda.gateways.connection.session import get_session\n"
        "from conda.plugins import hookimpl\n"
        "from conda.plugins.types import ChannelAuthBase, CondaAuthHandler\n"
        f"SESSION = get_session({url!r})\n"
        "SETTINGS = context.plugins\n"
        "class TestAuth(ChannelAuthBase):\n"
        "    def __call__(self, request):\n"
        "        request.headers['Authorization'] = "
        "context.plugins.conda_advise_minimum_severity\n"
        "        return request\n"
        "class TestPlugin:\n"
        "    @hookimpl\n"
        "    def conda_auth_handlers(self):\n"
        "        yield CondaAuthHandler(name='cached-auth', handler=TestAuth)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    plugin_module = importlib.import_module("advise_import_session")
    plugin = plugin_module.TestPlugin()
    manager = context.plugin_manager
    manager.register(plugin)
    monkeypatch.setattr(context, "offline", offline)
    monkeypatch.setattr(
        context,
        "channel_settings",
        ({"channel": get_channel_name_from_url(url), "auth": "cached-auth"},),
    )
    try:
        response = fetch_json(
            [JsonRequest("key", "GET", url)],
            deadline=time.monotonic() + 10,
            max_workers=1,
        )["key"]
    finally:
        manager.unregister(plugin)
        sys.modules.pop("advise_import_session", None)
    if offline:
        assert response.reason is FailureReason.REQUEST_FAILED
        assert not requests
    else:
        assert response.succeeded
        assert requests[0][3]["Authorization"] == "high"


@pytest.mark.parametrize("path", ["/stall", "/drip"])
def test_deadline_kills_workers_and_allows_interpreter_exit(http_server, path) -> None:
    url, requests = http_server
    code = textwrap.dedent("""\
        import multiprocessing
        import sys
        import time
        from conda_advise.network import JsonRequest, fetch_json
        from conda_advise.models import FailureReason

        responses = fetch_json(
            [JsonRequest(str(i), 'GET', sys.argv[1]) for i in range(100)],
            deadline=time.monotonic() + 2,
            max_workers=20,
        )
        assert all(
            r.reason is FailureReason.DEADLINE_EXCEEDED
            for r in responses.values()
        )
        assert not multiprocessing.active_children()
        print('finished')
        """)
    started = time.monotonic()
    result = subprocess.run(
        [sys.executable, "-c", code, f"{url}{path}"],
        capture_output=True,
        text=True,
        timeout=6,
        check=True,
    )

    assert result.stdout.strip() == "finished"
    assert time.monotonic() - started < 5
    assert len(requests) == 1


def test_fetch_json_submits_only_the_worker_limit(http_server) -> None:
    url, requests = http_server
    # Different methods keep the requests distinct while all block on headers.
    response = fetch_json(
        [
            JsonRequest(str(index), "POST", f"{url}/stall", {"index": index})
            for index in range(30)
        ],
        deadline=time.monotonic() + 2,
        max_workers=30,
    )

    assert len(requests) <= network.MAX_WORKERS
    assert all(
        item.reason is FailureReason.DEADLINE_EXCEEDED for item in response.values()
    )


def test_fetch_json_empty_and_expired_requests(http_server) -> None:
    url, requests = http_server
    assert fetch_json([], deadline=0, max_workers=1) == {}
    response = fetch_json([JsonRequest("key", "GET", url)], deadline=0, max_workers=1)
    assert response["key"].reason is FailureReason.DEADLINE_EXCEEDED
    assert not requests


def test_fetch_json_reuses_workers_and_caps_total_response_bytes(
    monkeypatch, http_server
) -> None:
    url, requests = http_server
    monkeypatch.setattr(network, "MAX_TOTAL_RESPONSE_BYTES", 1024)
    response = fetch_json(
        [
            JsonRequest(str(index), "POST", url, {"index": index, "value": "a" * 100})
            for index in range(30)
        ],
        deadline=time.monotonic() + 10,
        max_workers=1,
    )

    assert 1 < len(requests) < 30
    assert any(item.succeeded for item in response.values())
    assert any(
        item.reason is FailureReason.INVALID_RESPONSE
        and item.message == "provider responses exceed the scan size limit"
        for item in response.values()
    )
