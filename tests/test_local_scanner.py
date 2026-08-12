"""
Integration tests for the local scanner.

A small HTTP server impersonates a Nextcloud instance so that the whole
scan path (status.php, headers, exposed paths, WebDAV, extra checks) runs
without touching the network.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from nextcloud_local_scan.scanner import (
    ScanError,
    ScannerSettings,
    failed_extra_checks,
    scan,
)
from nextcloud_local_scan.serverinfo import ServerInfoSettings

STATUS = {
    "installed": True,
    "maintenance": False,
    "needsDbUpgrade": False,
    "version": "30.0.2.2",
    "versionstring": "Nextcloud 30.0.2",
    "edition": "",
    "productname": "Nextcloud",
    "extendedSupport": False,
}

SECURE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "X-XSS-Protection": "1; mode=block",
    "X-Download-Options": "noopen",
    "X-Permitted-Cross-Domain-Policies": "none",
    "X-Robots-Tag": "noindex, nofollow",
    "Strict-Transport-Security": "max-age=15768000",
    "Content-Security-Policy": "default-src 'self'",
    "Referrer-Policy": "no-referrer",
}


def _make_handler(*, status_payload, headers, expose_config, catch_all):
    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _respond(self, code, body=b"", extra=None):
            self.send_response(code)
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/status.php":
                self._respond(
                    200,
                    json.dumps(status_payload).encode(),
                    {"Content-Type": "application/json"},
                )
            elif self.path == "/":
                self._respond(200, b"<html>Nextcloud</html>", headers)
            elif self.path == "/config/config.php" and expose_config:
                self._respond(200, b"<?php $CONFIG = array();", {})
            elif self.path == "/remote.php/dav/":
                self._respond(401, b"", {"WWW-Authenticate": "Basic"})
            elif catch_all:
                # A single page application answers every unknown path with the
                # very same HTML shell instead of a 404.
                self._respond(200, b"<html>app shell</html>", {"Content-Type": "text/html"})
            else:
                self._respond(404, b"not found", {})

        do_HEAD = do_GET

    return _Handler


@pytest.fixture
def instance():
    """Start a fake Nextcloud instance; the test controls its behaviour."""
    servers = []

    def _start(*, status_payload=None, headers=None, expose_config=False, catch_all=False):
        handler = _make_handler(
            status_payload=status_payload or STATUS,
            headers=headers if headers is not None else SECURE_HEADERS,
            expose_config=expose_config,
            catch_all=catch_all,
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        return f"127.0.0.1:{server.server_address[1]}"

    yield _start

    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _settings(**overrides):
    defaults = {
        "scheme": "http",
        "timeout": 5,
        "use_updater_server": False,
        # The fake instance reports version 30, which the real release schedule
        # no longer supports; pin the schedule so the tests stay stable.
        "supported_majors": (30, 29),
    }
    defaults.update(overrides)
    return ScannerSettings(**defaults)


def test_scan_returns_a_scan_api_compatible_document(instance):
    """The local result carries exactly the fields consumers expect."""
    host = instance()

    result = scan(host, _settings(), ServerInfoSettings(mode="off"))

    assert result["product"] == "Nextcloud"
    assert result["version"] == "30.0.2.2"
    assert result["domain"] == "127.0.0.1"
    assert set(result["setup"]) == {"https", "headers"}
    assert result["scannedAt"]["timezone"] == "UTC"
    assert isinstance(result["vulnerabilities"], list)
    assert result["hardenings"]["CSPv3"] is True
    assert result["hardenings"]["appPasswordsScannedForHaveIBeenPwned"] is True


def test_security_headers_are_evaluated(instance):
    """Present headers are reported as True, missing ones as False."""
    host = instance(headers={"X-Content-Type-Options": "nosniff"})

    result = scan(host, _settings(), ServerInfoSettings(mode="off"))

    headers = result["setup"]["headers"]
    assert headers["X-Content-Type-Options"] is True
    assert headers["X-Frame-Options"] is False
    assert headers["X-Permitted-Cross-Domain-Policies"] is False


def test_hardenings_are_derived_from_the_release(instance):
    """An old release cannot provide measures introduced later."""
    old_status = dict(STATUS, version="13.0.1.1")
    host = instance(status_payload=old_status)

    result = scan(host, _settings(), ServerInfoSettings(mode="off"))

    assert result["hardenings"]["passwordConfirmation"] is True
    assert result["hardenings"]["CSPv3"] is False
    assert result["hardenings"]["__HostPrefix"] is False


def test_publicly_readable_config_lowers_the_rating(instance):
    """An exposed config.php is a critical finding and caps the rating."""
    host = instance(expose_config=True)

    result = scan(host, _settings(), ServerInfoSettings(mode="off"))

    failures = failed_extra_checks(result)
    assert "exposed:/config/config.php" in failures
    assert result["rating"] <= 2


def test_extra_checks_can_be_disabled(instance):
    """Without extra checks the result mirrors the public scanner only."""
    host = instance(expose_config=True)

    result = scan(host, _settings(extra_checks=False), ServerInfoSettings(mode="off"))

    assert result["extraChecks"] == []
    assert result["rating"] == 5


def test_maintenance_mode_is_reported(instance):
    """Maintenance mode and pending database upgrades become findings."""
    host = instance(status_payload=dict(STATUS, maintenance=True, needsDbUpgrade=True))

    result = scan(host, _settings(), ServerInfoSettings(mode="off"))

    failures = failed_extra_checks(result)
    assert "maintenanceMode" in failures
    assert "databaseUpgrade" in failures


def test_update_information_comes_from_serverinfo(instance, mocker):
    """A pending update reported by serverinfo yields rating 4."""
    host = instance()
    mocker.patch(
        "nextcloud_local_scan.scanner.fetch_update_info",
        return_value=mocker.MagicMock(
            known=True,
            available=True,
            available_version="30.0.4.0",
            as_dict=lambda: {"available": True, "availableVersion": "30.0.4.0"},
        ),
    )

    result = scan(host, _settings(extra_checks=False), ServerInfoSettings(mode="api"))

    assert result["rating"] == 4
    assert result["updates"]["available"] is True


def test_missing_instance_raises_scan_error():
    """A host without status.php cannot be scanned."""
    with pytest.raises(ScanError):
        scan("127.0.0.1:1", _settings(timeout=1), ServerInfoSettings(mode="off"))


def test_a_retired_major_release_is_rated_end_of_life(instance):
    """A major release below the oldest supported one gets an F."""
    host = instance()

    result = scan(host, _settings(supported_majors=(34, 33, 32)), ServerInfoSettings(mode="off"))

    assert result["EOL"] is True
    assert result["rating"] == 0
    assert result["supportedMajorVersions"] == [34, 33, 32]


def test_the_release_schedule_can_be_ignored(instance):
    """Operators running a vendor-maintained build can turn the check off."""
    host = instance()

    result = scan(
        host,
        _settings(supported_majors=(34, 33, 32), use_release_schedule=False),
        ServerInfoSettings(mode="off"),
    )

    assert result["EOL"] is False
    assert result["rating"] > 0


def test_a_catch_all_frontend_does_not_report_exposed_paths(instance):
    """oCIS answers every path with its app shell; that is not an exposure."""
    host = instance(catch_all=True)

    result = scan(host, _settings(), ServerInfoSettings(mode="off"))

    assert [check for check in failed_extra_checks(result) if check.startswith("exposed:")] == []
