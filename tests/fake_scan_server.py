"""
A minimal stand-in for the scan.nextcloud.com API used by the end-to-end tests.

The real plugin talks to three endpoints (``/api/queue``, ``/api/result/<uuid>``
and ``/api/requeue``). This module serves exactly those endpoints from recorded
fixtures, so the whole CLI can be exercised over real HTTP without needing a
Nextcloud instance or network access.

The fixtures in ``tests/fixtures/`` mirror the structure of real Scan API
responses but use anonymized ``example.com`` hostnames: an up-to-date instance
(rating A+), an end-of-life one (rating F) and two with known vulnerabilities.
"""
from __future__ import annotations

import json
import pathlib
import threading
import uuid as uuid_module
from collections import Counter
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures"

# Hostnames covered by the shipped fixtures. All are reserved example.com
# names, so a stray real request can never hit somebody's instance.
HOST_OK = "uptodate.example.com"
HOST_EOL = "endoflife.example.com"
HOST_VULNERABLE = "vulnerable.example.com"
HOST_WARNING = "outdated.example.com"

DEFAULT_FIXTURES: dict[str, str] = {
    HOST_OK: "result_ok.json",
    HOST_EOL: "result_eol.json",
    HOST_VULNERABLE: "result_vulnerable.json",
    HOST_WARNING: "result_warning.json",
}

# Response body the real API returns (as a bare JSON string) when the scan
# queue for a source IP is saturated.
TOO_MANY_INSTANCES = "Too many instances queued, please try again later."


@dataclass(frozen=True)
class RawBody:
    """A response body that is sent verbatim instead of being JSON-encoded."""

    payload: str


def load_fixture(name: str) -> dict[str, Any]:
    """Load a recorded Scan API result document from tests/fixtures/."""
    data: dict[str, Any] = json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))
    return data


class FakeScanAPI:
    """
    In-process HTTP server that mimics the Nextcloud Scan API.

    Behaviour is driven by attributes that a test can tweak before (or while)
    the CLI under test runs:

    ``results``
        Maps a hostname to the JSON document ``/api/result/<uuid>`` returns.
    ``rescan_results``
        Maps a hostname to the document served *after* ``/api/requeue`` was
        called for it, so rescans can be observed end to end.
    ``too_many_instances``
        Hostnames for which ``/api/queue`` answers with the API's
        "Too many instances" string instead of a UUID.
    ``queue_failures`` / ``result_failures``
        Number of times the respective endpoint should fail before serving a
        normal response (used to exercise retry/backoff). ``/api/queue`` fails
        with HTTP 503, ``/api/result`` with an unparsable body -- the plugin
        does not check the status code there, but does parse the JSON.
    ``unknown_hosts``
        Hostnames for which ``/api/queue`` answers HTTP 404, mimicking a
        domain where no Nextcloud/ownCloud was found.

    The server additionally exposes ``/webhook`` as a receiver for the
    plugin's optional webhook notifications. Deliveries are recorded in
    ``webhook_calls``; set ``webhook_status`` to make it fail.
    """

    def __init__(self) -> None:
        self.results: dict[str, dict[str, Any]] = {
            host: load_fixture(fixture) for host, fixture in DEFAULT_FIXTURES.items()
        }
        self.rescan_results: dict[str, dict[str, Any]] = {}
        self.too_many_instances: set[str] = set()
        self.unknown_hosts: set[str] = set()
        self.queue_failures = 0
        self.result_failures = 0

        self.webhook_calls: list[dict[str, Any]] = []
        self.webhook_headers: list[dict[str, str]] = []
        self.webhook_status = 200

        self.requests: Counter[str] = Counter()
        self.queued_hosts: list[str] = []
        self.requeued_hosts: list[str] = []

        self._uuid_to_host: dict[str, str] = {}
        self._rescanned: set[str] = set()
        self._lock = threading.Lock()
        self.base_url = ""
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # --- lifecycle ---
    def start(self) -> str:
        """Start serving on a free localhost port and return the base URL."""
        api = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                """Silence the default stderr access log."""

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                payload = self.rfile.read(length).decode("utf-8")
                path = urlparse(self.path).path

                if path == "/webhook":
                    status, body = api._handle_webhook(payload, dict(self.headers))
                    self._respond(status, body)
                    return

                host = parse_qs(payload).get("url", [""])[0]
                if path == "/api/queue":
                    status, body = api._handle_queue(host)
                elif path == "/api/requeue":
                    status, body = api._handle_requeue(host)
                else:
                    status, body = 404, {"error": "not found"}
                self._respond(status, body)

            def do_GET(self) -> None:
                path = urlparse(self.path).path
                if path.startswith("/api/result/"):
                    status, body = api._handle_result(path.rsplit("/", 1)[-1])
                else:
                    status, body = 404, {"error": "not found"}
                self._respond(status, body)

            def _respond(self, status: int, body: Any) -> None:
                if isinstance(body, RawBody):
                    encoded = body.payload.encode("utf-8")
                else:
                    encoded = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        host, port = self._server.server_address[0], self._server.server_address[1]
        self.base_url = f"http://{host!s}:{port}"
        return self.base_url

    def stop(self) -> None:
        """Shut the server down and join its thread."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    # --- endpoint handlers ---
    def _handle_queue(self, host: str) -> tuple[int, Any]:
        with self._lock:
            self.requests["queue"] += 1
            self.queued_hosts.append(host)

            if self.queue_failures > 0:
                self.queue_failures -= 1
                return 503, {"error": "service unavailable"}
            if host in self.too_many_instances:
                return 200, TOO_MANY_INSTANCES
            if host in self.unknown_hosts or host not in self.results:
                return 404, {"error": "no Nextcloud or ownCloud found"}

            uuid = str(uuid_module.uuid5(uuid_module.NAMESPACE_DNS, host))
            self._uuid_to_host[uuid] = host
            return 200, {"uuid": uuid}

    def _handle_webhook(self, payload: str, headers: dict[str, str]) -> tuple[int, Any]:
        with self._lock:
            self.requests["webhook"] += 1
            self.webhook_headers.append(headers)
            try:
                self.webhook_calls.append(json.loads(payload))
            except json.JSONDecodeError:
                return 400, {"error": "payload was not valid JSON"}
            if self.webhook_status >= 400:
                return self.webhook_status, {"error": "webhook rejected"}
            return self.webhook_status, {"received": True}

    def _handle_requeue(self, host: str) -> tuple[int, Any]:
        with self._lock:
            self.requests["requeue"] += 1
            self.requeued_hosts.append(host)
            self._rescanned.add(host)
            return 200, {"uuid": str(uuid_module.uuid5(uuid_module.NAMESPACE_DNS, host))}

    def _handle_result(self, uuid: str) -> tuple[int, Any]:
        with self._lock:
            self.requests["result"] += 1

            if self.result_failures > 0:
                self.result_failures -= 1
                return 503, RawBody("<html>502 Bad Gateway</html>")

            host = self._uuid_to_host.get(uuid)
            if host is None:
                return 404, {"error": "unknown uuid"}
            if host in self._rescanned and host in self.rescan_results:
                return 200, self.rescan_results[host]
            return 200, self.results[host]
