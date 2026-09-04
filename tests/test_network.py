from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import conda_advise.network as network
from conda_advise.models import FailureReason
from conda_advise.network import JsonRequest, fetch_json


class JsonHandler(BaseHTTPRequestHandler):
    requests: list[tuple[str, dict[str, object] | None]] = []

    def do_GET(self) -> None:
        self._respond(None)

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        payload = json.loads(self.rfile.read(length))
        self._respond(payload)

    def log_message(self, *_: object) -> None:
        return

    def _respond(self, payload: dict[str, object] | None) -> None:
        self.requests.append((self.command, payload))
        response = json.dumps({"method": self.command, "payload": payload}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


def test_fetch_json_uses_conda_session_against_a_local_http_server() -> None:
    JsonHandler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), JsonHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/data"
        responses = fetch_json(
            [JsonRequest("post", "POST", url, {"value": 1})],
            deadline=time.monotonic() + 2,
            max_workers=1,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

    assert responses["post"].payload == {
        "method": "POST",
        "payload": {"value": 1},
    }
    assert JsonHandler.requests == [("POST", {"value": 1})]


def test_fetch_json_deduplicates_identical_requests(monkeypatch) -> None:
    calls = []

    class Response:
        status_code = 200

        def raise_for_status(self) -> None:
            return

        def json(self) -> dict[str, object]:
            return {"ok": True}

    class Session:
        def request(self, method, url, **options):
            calls.append((method, url, options.get("json")))
            return Response()

    monkeypatch.setattr(network, "get_session", lambda url: Session())
    request = JsonRequest("first", "GET", "https://example.test/data")
    duplicate = JsonRequest("second", "GET", "https://example.test/data")

    responses = fetch_json(
        [request, duplicate], deadline=time.monotonic() + 1, max_workers=2
    )

    assert calls == [("GET", "https://example.test/data", None)]
    assert responses["first"].payload == responses["second"].payload
    assert responses["second"].key == "second"


def test_fetch_json_caps_conda_network_timeouts_by_deadline(monkeypatch) -> None:
    calls = []

    class CondaContext:
        remote_connect_timeout_secs = 0.25
        remote_read_timeout_secs = 0.5

    class Response:
        status_code = 200

        def raise_for_status(self) -> None:
            return

        def json(self) -> dict[str, object]:
            return {"ok": True}

    class Session:
        def request(self, method, url, **options):
            calls.append(options["timeout"])
            return Response()

    monkeypatch.setattr(network, "context", CondaContext())
    monkeypatch.setattr(network, "get_session", lambda url: Session())

    fetch_json(
        [JsonRequest("key", "GET", "https://example.test/data")],
        deadline=time.monotonic() + 1,
        max_workers=1,
    )

    assert calls == [(0.25, 0.5)]


def test_fetch_json_rejects_redirects_without_forwarding_data(monkeypatch) -> None:
    calls = []

    class Response:
        status_code = 307

        def raise_for_status(self) -> None:
            return

        def json(self) -> dict[str, object]:
            pytest.fail("redirect response should not be decoded")

    class Session:
        def request(self, method, url, **options):
            calls.append(options)
            return Response()

    monkeypatch.setattr(network, "get_session", lambda url: Session())

    response = fetch_json(
        [JsonRequest("key", "POST", "https://example.test/data", {"secret": 1})],
        deadline=time.monotonic() + 1,
        max_workers=1,
    )["key"]

    assert response.status_code == 307
    assert response.reason is FailureReason.REQUEST_FAILED
    assert calls[0]["allow_redirects"] is False


@pytest.mark.parametrize(
    ("behavior", "status", "reason"),
    [
        ("not-found", 404, None),
        ("http-error", 503, FailureReason.REQUEST_FAILED),
        ("decode-error", 200, FailureReason.INVALID_RESPONSE),
        ("non-finite", 200, FailureReason.INVALID_RESPONSE),
        ("offline-error", None, FailureReason.REQUEST_FAILED),
    ],
    ids=["not-found", "http", "decode", "non-finite", "offline"],
)
def test_fetch_json_types_failures(monkeypatch, behavior, status, reason) -> None:
    class Response:
        status_code = status

        def raise_for_status(self) -> None:
            if behavior == "http-error":
                raise RuntimeError("unavailable")

        def json(self) -> dict[str, object]:
            if behavior == "decode-error":
                raise ValueError("invalid JSON")
            if behavior == "non-finite":
                return {"score": float("nan")}
            return {"ok": True}

    class Session:
        def request(self, method, url, **options):
            if behavior == "offline-error":
                raise RuntimeError("offline")
            return Response()

    monkeypatch.setattr(network, "get_session", lambda url: Session())

    response = fetch_json(
        [JsonRequest("key", "GET", "https://example.test/data")],
        deadline=time.monotonic() + 1,
        max_workers=1,
    )["key"]

    assert response.status_code == status
    assert response.reason is reason
    assert response.not_found is (behavior == "not-found")


def test_fetch_json_stops_waiting_for_late_workers(monkeypatch) -> None:
    release = threading.Event()

    class Session:
        def request(self, method, url, **options):
            release.wait(1)
            raise RuntimeError("released")

    monkeypatch.setattr(network, "get_session", lambda url: Session())
    started = time.monotonic()
    response = fetch_json(
        [JsonRequest("late", "GET", "https://example.test/data")],
        deadline=started + 0.02,
        max_workers=1,
    )["late"]
    elapsed = time.monotonic() - started
    release.set()

    assert response.reason is FailureReason.DEADLINE_EXCEEDED
    assert elapsed < 0.2
