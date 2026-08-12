"""Tests for the Scan API compatible service that runs in the container."""

import threading

import pytest
import requests

from nextcloud_local_scan.scanner import ScanError
from nextcloud_local_scan.service import ScanStore, build_server

RESULT = {
    "domain": "cloud.example.com",
    "product": "Nextcloud",
    "version": "30.0.2.2",
    "rating": 5,
    "vulnerabilities": [],
}


@pytest.fixture
def service(mocker):
    """Run the service with a stubbed scanner on an ephemeral port."""
    scans = []

    def _start(*, token=None, scan_side_effect=None):
        def _fake_scan(host, settings=None, serverinfo_settings=None):
            scans.append(host)
            if scan_side_effect is not None:
                raise scan_side_effect
            return dict(RESULT, domain=host)

        mocker.patch("nextcloud_local_scan.service.scan", side_effect=_fake_scan)
        server = build_server(ScanStore(cache_ttl=60), "127.0.0.1", 0, token)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        return f"http://127.0.0.1:{server.server_address[1]}", scans

    servers = []
    yield _start
    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_queue_and_result_follow_the_scan_api(service):
    """POST /api/queue returns a uuid that GET /api/result/<uuid> resolves."""
    base, _ = service()

    queued = requests.post(f"{base}/api/queue", data={"url": "cloud.example.com"}, timeout=5)
    assert queued.status_code == 200
    uuid = queued.json()["uuid"]

    result = requests.get(f"{base}/api/result/{uuid}", timeout=5)
    assert result.status_code == 200
    assert result.json()["domain"] == "cloud.example.com"
    assert result.json()["rating"] == 5


def test_results_are_cached_per_host_and_requeue_forces_a_rescan(service):
    """A second queue reuses the cache; requeue always scans again."""
    base, scans = service()

    requests.post(f"{base}/api/queue", data={"url": "cloud.example.com"}, timeout=5)
    requests.post(f"{base}/api/queue", data={"url": "cloud.example.com"}, timeout=5)
    assert scans == ["cloud.example.com"]

    requests.post(f"{base}/api/requeue", data={"url": "cloud.example.com"}, timeout=5)
    assert scans == ["cloud.example.com", "cloud.example.com"]


def test_unknown_uuid_yields_404(service):
    """Asking for a result that was never produced is an error."""
    base, _ = service()

    response = requests.get(f"{base}/api/result/does-not-exist", timeout=5)

    assert response.status_code == 404
    assert "error" in response.json()


def test_unscannable_host_yields_400(service):
    """A host without Nextcloud is reported as a client error."""
    base, _ = service(scan_side_effect=ScanError("no Nextcloud found"))

    response = requests.post(f"{base}/api/queue", data={"url": "example.com"}, timeout=5)

    assert response.status_code == 400
    assert "no Nextcloud found" in response.json()["error"]


def test_token_is_enforced_when_configured(service):
    """With a token, unauthenticated API calls are rejected."""
    base, _ = service(token="s3cr3t")

    denied = requests.post(f"{base}/api/queue", data={"url": "cloud.example.com"}, timeout=5)
    assert denied.status_code == 401

    allowed = requests.post(
        f"{base}/api/queue",
        data={"url": "cloud.example.com"},
        headers={"X-Auth-Token": "s3cr3t"},
        timeout=5,
    )
    assert allowed.status_code == 200


def test_health_endpoint_needs_no_token(service):
    """Container health probes must work without credentials."""
    base, _ = service(token="s3cr3t")

    response = requests.get(f"{base}/healthz", timeout=5)

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_one_shot_scan_endpoint_returns_the_document(service):
    """GET /api/scan is a convenience wrapper around queue plus result."""
    base, _ = service()

    response = requests.get(f"{base}/api/scan", params={"url": "cloud.example.com"}, timeout=5)

    assert response.status_code == 200
    assert response.json()["version"] == "30.0.2.2"
