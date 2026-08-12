"""
Scan API compatible HTTP service.

This is what runs inside the local Docker container: a drop-in replacement
for scan.nextcloud.com that speaks the same three endpoints, so the plugin
only needs a different base URL.

======================================  ==========================================
Endpoint                                Behaviour
======================================  ==========================================
``POST /api/queue`` (``url=<host>``)    Scan the host and return ``{"uuid": ...}``
``GET  /api/result/<uuid>``             Return the stored scan result
``POST /api/requeue`` (``url=<host>``)  Discard the cached result and scan again
``GET  /api/scan?url=<host>``           Convenience: scan and return the result
``GET  /healthz``                       Liveness probe
======================================  ==========================================

Results are cached per host for ``cache_ttl`` seconds so that a monitoring
system polling several times a minute does not hammer the instance.
"""

from __future__ import annotations

import hmac
import json
import logging
import threading
import time
import urllib.parse
import uuid as uuid_module
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .scanner import ScanError, ScannerSettings, scan
from .serverinfo import ServerInfoSettings

LOGGER = logging.getLogger("check_nextcloud.service")

DEFAULT_LISTEN = "0.0.0.0"  # nosec B104 - a container service must bind all interfaces
DEFAULT_PORT = 8080
DEFAULT_CACHE_TTL_SECONDS = 900
MAX_BODY_BYTES = 8192


@dataclass
class _Entry:
    """One cached scan result."""

    uuid: str
    host: str
    result: dict[str, Any]
    created_at: float


@dataclass
class ScanStore:
    """Thread-safe result cache keyed by uuid and by host."""

    scanner_settings: ScannerSettings = field(default_factory=ScannerSettings)
    serverinfo_settings: ServerInfoSettings | None = None
    cache_ttl: int = DEFAULT_CACHE_TTL_SECONDS
    _by_uuid: dict[str, _Entry] = field(default_factory=dict)
    _by_host: dict[str, str] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _fresh(self, entry: _Entry) -> bool:
        return (time.time() - entry.created_at) < self.cache_ttl

    def get_by_uuid(self, uuid: str) -> dict[str, Any] | None:
        """Return a stored result, ignoring its age (the client asked for it)."""
        with self._lock:
            entry = self._by_uuid.get(uuid)
        return entry.result if entry else None

    def scan(self, host: str, *, force: bool = False) -> _Entry:
        """Scan a host, reusing a cached result unless force is set."""
        with self._lock:
            cached_uuid = self._by_host.get(host)
            entry = self._by_uuid.get(cached_uuid) if cached_uuid else None
            if entry and not force and self._fresh(entry):
                LOGGER.debug("Serving cached result for %s", host)
                return entry

        result = scan(
            host,
            settings=self.scanner_settings,
            serverinfo_settings=self.serverinfo_settings,
        )
        entry = _Entry(
            uuid=str(uuid_module.uuid4()), host=host, result=result, created_at=time.time()
        )
        with self._lock:
            self._by_uuid[entry.uuid] = entry
            self._by_host[host] = entry.uuid
        return entry

    def purge(self) -> None:
        """Drop cache entries that outlived the TTL."""
        with self._lock:
            stale = [key for key, entry in self._by_uuid.items() if not self._fresh(entry)]
            for key in stale:
                host = self._by_uuid.pop(key).host
                if self._by_host.get(host) == key:
                    self._by_host.pop(host, None)


class _Handler(BaseHTTPRequestHandler):
    """Request handler implementing the Scan API surface."""

    server_version = "check-nextcloud-scanner"
    protocol_version = "HTTP/1.1"

    store: ScanStore
    auth_token: str | None = None

    def log_message(self, format: str, *args: Any) -> None:
        """Route the built-in access log through the module logger."""
        LOGGER.debug("%s - %s", self.address_string(), format % args)

    # --- helpers ---
    def _send_json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: HTTPStatus, message: str) -> None:
        self._send_json({"error": message, "status": int(status)}, status)

    def _authorized(self) -> bool:
        if not self.auth_token:
            return True
        provided = self.headers.get("X-Auth-Token") or ""
        authorization = self.headers.get("Authorization") or ""
        if authorization.lower().startswith("bearer "):
            provided = provided or authorization[7:].strip()
        return hmac.compare_digest(provided, self.auth_token)

    def _read_host(self) -> str | None:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            return None
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        fields = urllib.parse.parse_qs(body)
        values = fields.get("url") or fields.get("host") or []
        return values[0].strip() if values else None

    def _scan_and_reply(self, host: str, *, force: bool, full: bool) -> None:
        try:
            entry = self.store.scan(host, force=force)
        except ScanError as exc:
            LOGGER.info("Scan of %s failed: %s", host, exc)
            self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        self._send_json(entry.result if full else {"uuid": entry.uuid})

    # --- routes ---
    def do_GET(self) -> None:
        """Handle result lookups, one-shot scans and the health probe."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/healthz":
            self._send_json({"status": "ok"})
            return

        if not self._authorized():
            self._send_error(HTTPStatus.UNAUTHORIZED, "Invalid or missing token.")
            return

        if path.startswith("/api/result/"):
            uuid = path[len("/api/result/"):]
            result = self.store.get_by_uuid(uuid)
            if result is None:
                self._send_error(HTTPStatus.NOT_FOUND, f"Unknown scan {uuid}.")
                return
            self._send_json(result)
            return

        if path == "/api/scan":
            query = urllib.parse.parse_qs(parsed.query)
            hosts = query.get("url") or query.get("host") or []
            if not hosts:
                self._send_error(HTTPStatus.BAD_REQUEST, "Missing 'url' parameter.")
                return
            force = (query.get("force") or ["0"])[0].lower() in {"1", "true", "yes"}
            self._scan_and_reply(hosts[0].strip(), force=force, full=True)
            return

        self._send_error(HTTPStatus.NOT_FOUND, f"Unknown endpoint {path}.")

    def do_POST(self) -> None:
        """Handle queue and requeue requests."""
        path = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"

        if not self._authorized():
            self._send_error(HTTPStatus.UNAUTHORIZED, "Invalid or missing token.")
            return

        if path not in {"/api/queue", "/api/requeue"}:
            self._send_error(HTTPStatus.NOT_FOUND, f"Unknown endpoint {path}.")
            return

        host = self._read_host()
        if not host:
            self._send_error(HTTPStatus.BAD_REQUEST, "Missing 'url' parameter.")
            return

        self.store.purge()
        self._scan_and_reply(host, force=path == "/api/requeue", full=False)


def build_server(
    store: ScanStore,
    listen: str = DEFAULT_LISTEN,
    port: int = DEFAULT_PORT,
    auth_token: str | None = None,
) -> ThreadingHTTPServer:
    """Create the HTTP server without starting it (handy for tests)."""
    handler = type("BoundHandler", (_Handler,), {"store": store, "auth_token": auth_token})
    return ThreadingHTTPServer((listen, port), handler)


def serve(
    store: ScanStore,
    listen: str = DEFAULT_LISTEN,
    port: int = DEFAULT_PORT,
    auth_token: str | None = None,
) -> None:
    """Run the scan service until interrupted."""
    server = build_server(store, listen, port, auth_token)
    LOGGER.info("Local Nextcloud scan service listening on %s:%d", listen, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - interactive shutdown
        LOGGER.info("Shutting down")
    finally:
        server.server_close()
