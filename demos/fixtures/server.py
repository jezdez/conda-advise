"""Serve deterministic Parselmouth, OSV, and Basilisk demo responses."""

from __future__ import annotations

import json
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlsplit

if TYPE_CHECKING:
    from collections.abc import Mapping

ARTIFACT_SHA256 = "1" * 64
MODIFIED = "2026-08-01T12:00:00Z"
ADVISORY_ID = "GHSA-demo-0001-0001"
ADVISORY = {
    "schema_version": "1.7.0",
    "id": ADVISORY_ID,
    "modified": MODIFIED,
    "published": "2026-07-31T12:00:00Z",
    "aliases": ["CVE-2026-0001"],
    "summary": "Demo package accepts an unsafe example input",
    "severity": [
        {
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
    ],
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "demo-package"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "1.0.1"}],
                }
            ],
        }
    ],
    "references": [
        {"type": "ADVISORY", "url": "https://example.invalid/GHSA-demo-0001-0001"}
    ],
}


class FixtureHandler(BaseHTTPRequestHandler):
    """Return fixed provider responses without logging requests."""

    channel_root: Path
    channel_sha256: str

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/health":
            self._send({"status": "ok"})
            return
        if path in {
            f"/hash-v0/{ARTIFACT_SHA256}",
            f"/hash-v0/{self.channel_sha256}",
        }:
            self._send(
                {
                    "filename": "demo-package-1.0.0-py_0.conda",
                    "pypi_normalized_names": ["demo-package"],
                    "versions": {"demo-package": "1.0.0"},
                }
            )
            return
        if path == f"/v1/vulns/{ADVISORY_ID}":
            self._send(ADVISORY)
            return
        if path.startswith("/channel/"):
            relative = Path(unquote(path.removeprefix("/channel/")))
            candidate = (self.channel_root / relative).resolve()
            if self.channel_root not in candidate.parents:
                self._send({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
                return
            if candidate.is_file():
                self._send_file(candidate)
                return
        self._send({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if self.path != "/v1/querybatch":
            self._send({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length))
        queries = payload.get("queries", [])
        self._send(
            {
                "results": [
                    {"vulns": [{"id": ADVISORY_ID, "modified": MODIFIED}]}
                    for _query in queries
                ]
            }
        )

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(
        self,
        payload: Mapping[str, object],
        *,
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        encoded = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_file(self, path: Path) -> None:
        content = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


class FixtureServer(ThreadingHTTPServer):
    """Allow consecutive recordings and tests to reuse the loopback port."""

    allow_reuse_address = True


if __name__ == "__main__":
    fixture_root = Path(sys.argv[1]).resolve()
    fixture = json.loads((fixture_root / "fixture.json").read_text(encoding="utf-8"))
    FixtureHandler.channel_root = (fixture_root / "channel").resolve()
    FixtureHandler.channel_sha256 = fixture["channel_sha256"]
    FixtureServer(("127.0.0.1", 8765), FixtureHandler).serve_forever()
