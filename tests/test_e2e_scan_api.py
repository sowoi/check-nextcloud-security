"""
End-to-end tests for the plugin.

These tests run ``check_nextcloud_security`` as a real subprocess against a
local stand-in for scan.nextcloud.com (``tests/fake_scan_server.py``), which
replays canned responses modelled on the real Scan API. No Nextcloud instance and
no internet access are required, yet the full path -- CLI parsing, HTTP
requests, retries, rating evaluation, perfdata and Nagios exit code -- is
exercised.
"""
from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest

from check_nextcloud_security import NagiosExitCode
from tests.fake_scan_server import (
    HOST_EOL,
    HOST_OK,
    HOST_VULNERABLE,
    HOST_WARNING,
    FakeScanAPI,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNNER = Path(__file__).parent / "e2e_cli.py"


@dataclass(frozen=True)
class CliRun:
    """Captured outcome of one plugin invocation."""

    exit_code: int
    stdout: str
    stderr: str

    @property
    def first_line(self) -> str:
        """The Nagios status line (first line of the plugin output)."""
        return self.stdout.splitlines()[0] if self.stdout.splitlines() else ""

    @property
    def perfdata(self) -> str:
        """Everything after the first ``|`` in the output."""
        _, _, perfdata = self.stdout.partition("|")
        return perfdata.strip()


@pytest.fixture
def scan_api() -> Iterator[FakeScanAPI]:
    """Start the fake Scan API for the duration of a test."""
    api = FakeScanAPI()
    api.start()
    yield api
    api.stop()


@pytest.fixture
def run_plugin(scan_api: FakeScanAPI):
    """Return a callable that runs the plugin against the fake Scan API."""
    def _run(args: Sequence[str], env: dict[str, str] | None = None) -> CliRun:
        process_env = {
            key: value for key, value in os.environ.items() if not key.startswith("CNS_")
        }
        process_env["CNS_TEST_SCAN_BASE_URL"] = scan_api.base_url
        process_env["PYTHONPATH"] = str(REPO_ROOT)
        process_env.update(env or {})

        completed = subprocess.run(
            [sys.executable, str(RUNNER), *args],
            capture_output=True,
            check=False,
            text=True,
            cwd=REPO_ROOT,
            env=process_env,
            timeout=60,
        )
        return CliRun(completed.returncode, completed.stdout, completed.stderr)

    return _run


# --- Happy path -------------------------------------------------------------
def test_e2e_healthy_host_returns_ok(run_plugin, scan_api):
    """A host rated A+ with no vulnerabilities exits OK with matching output."""
    result = run_plugin(["-H", HOST_OK])

    assert result.exit_code == NagiosExitCode.OK
    assert result.first_line.startswith("OK: Server is up to date.")
    assert "Nextcloud" in result.stdout
    assert f"on {HOST_OK}" in result.stdout
    assert "rating: A+" in result.stdout
    assert scan_api.queued_hosts == [HOST_OK]
    assert scan_api.requests["result"] == 1
    assert scan_api.requests["requeue"] == 0


def test_e2e_healthy_host_emits_perfdata(run_plugin):
    """The OK result carries Nagios performance data for rating, vulns and time."""
    result = run_plugin(["-H", HOST_OK])

    assert "rating=5;@0:3;@0:1;0;5" in result.perfdata
    assert "vulnerabilities=0;;;0;" in result.perfdata
    assert "time=" in result.perfdata


# --- Poor ratings -----------------------------------------------------------
def test_e2e_end_of_life_host_returns_critical(run_plugin):
    """An end-of-life instance (rating F) exits CRITICAL."""
    result = run_plugin(["-H", HOST_EOL])

    assert result.exit_code == NagiosExitCode.CRITICAL
    assert "end-of-life" in result.first_line
    assert "rating: F" in result.stdout
    assert "rating=0;@0:3;@0:1;0;5" in result.perfdata


def test_e2e_vulnerable_host_returns_critical(run_plugin):
    """A host with high-severity vulnerabilities exits CRITICAL and counts them."""
    result = run_plugin(["-H", HOST_VULNERABLE])

    assert result.exit_code == NagiosExitCode.CRITICAL
    assert result.first_line == "CRITICAL: Found 2 vulnerabilities (rating E)."
    assert "rating: E" in result.stdout
    assert "vulnerabilities=2;;;0;" in result.perfdata


def test_e2e_outdated_host_returns_warning(run_plugin):
    """A host rated C with one vulnerability exits WARNING."""
    result = run_plugin(["-H", HOST_WARNING])

    assert result.exit_code == NagiosExitCode.WARNING
    assert result.first_line == "WARNING: Found 1 vulnerabilities (rating C)."
    assert "rating: C" in result.stdout


# --- Error handling ---------------------------------------------------------
def test_e2e_unknown_host_returns_unknown(run_plugin):
    """A domain the Scan API cannot queue produces UNKNOWN, not a traceback."""
    result = run_plugin(["-H", "no-nextcloud.example.com", "--backoff-factor", "0"])

    assert result.exit_code == NagiosExitCode.UNKNOWN
    assert result.first_line.startswith("UNKNOWN: no-nextcloud.example.com Scan failed!")
    assert "Traceback" not in result.stderr


def test_e2e_too_many_instances_returns_unknown(run_plugin, scan_api):
    """The API's 'Too many instances' throttling reply is reported as UNKNOWN."""
    scan_api.too_many_instances.add(HOST_OK)

    result = run_plugin(["-H", HOST_OK, "--backoff-factor", "0"])

    assert result.exit_code == NagiosExitCode.UNKNOWN
    assert "Too many instances" in result.stdout


def test_e2e_ip_address_is_rejected_without_contacting_api(run_plugin, scan_api):
    """IP addresses are refused locally; the Scan API is never contacted."""
    result = run_plugin(["-H", "192.168.0.10"])

    assert result.exit_code == NagiosExitCode.UNKNOWN
    assert result.first_line == "IP addresses are not supported by the Scan API."
    assert scan_api.requests["queue"] == 0


# --- Retry / backoff --------------------------------------------------------
def test_e2e_retries_transient_queue_failure(run_plugin, scan_api):
    """A transient 503 on /api/queue is retried and the run still succeeds."""
    scan_api.queue_failures = 2

    result = run_plugin(["-H", HOST_OK, "--retries", "2", "--backoff-factor", "0"])

    assert result.exit_code == NagiosExitCode.OK
    assert scan_api.requests["queue"] == 3


def test_e2e_gives_up_after_exhausting_retries(run_plugin, scan_api):
    """Once retries are exhausted the plugin reports UNKNOWN instead of hanging."""
    scan_api.queue_failures = 10

    result = run_plugin(["-H", HOST_OK, "--retries", "1", "--backoff-factor", "0"])

    assert result.exit_code == NagiosExitCode.UNKNOWN
    assert scan_api.requests["queue"] == 2


def test_e2e_retries_unparsable_result_body(run_plugin, scan_api):
    """A non-JSON body from /api/result is retried before succeeding."""
    scan_api.result_failures = 1

    result = run_plugin(["-H", HOST_OK, "--retries", "2", "--backoff-factor", "0"])

    assert result.exit_code == NagiosExitCode.OK
    assert scan_api.requests["result"] == 2


# --- Rescan -----------------------------------------------------------------
def test_e2e_rescan_requeues_and_uses_fresh_result(run_plugin, scan_api):
    """--rescan requeues the host and evaluates the refreshed scan result."""
    fixed = dict(scan_api.results[HOST_EOL])
    fixed.update({"rating": 5, "version": "34.0.2.1", "EOL": False})
    scan_api.rescan_results[HOST_EOL] = fixed

    result = run_plugin(["-H", HOST_EOL, "--rescan"])

    assert result.exit_code == NagiosExitCode.OK
    assert scan_api.requeued_hosts == [HOST_EOL]
    assert "rating: A+" in result.stdout


# --- Multi-host -------------------------------------------------------------
def test_e2e_multiple_hosts_aggregate_to_worst_status(run_plugin, scan_api):
    """A comma-separated host list is scanned in order and aggregated."""
    result = run_plugin(["-H", f"{HOST_OK},{HOST_WARNING},{HOST_EOL}"])

    assert result.exit_code == NagiosExitCode.CRITICAL
    assert result.first_line == "Checked 3 host(s): overall CRITICAL (1 CRITICAL, 1 WARNING, 1 OK)"
    assert f"[{HOST_OK}]" in result.stdout
    assert f"[{HOST_WARNING}]" in result.stdout
    assert f"[{HOST_EOL}]" in result.stdout
    assert scan_api.queued_hosts == [HOST_OK, HOST_WARNING, HOST_EOL]


def test_e2e_one_failing_host_does_not_abort_the_others(run_plugin):
    """An unreachable host is reported as UNKNOWN while the others still run."""
    result = run_plugin(
        ["-H", f"broken.example.com,{HOST_OK}", "--retries", "0", "--backoff-factor", "0"]
    )

    assert result.exit_code == NagiosExitCode.UNKNOWN
    assert "1 UNKNOWN, 1 OK" in result.first_line
    assert "OK: Server is up to date." in result.stdout


# --- Environment variable configuration -------------------------------------
def test_e2e_host_can_be_supplied_via_environment(run_plugin):
    """CNS_HOST is honoured when no --host flag is given."""
    result = run_plugin([], env={"CNS_HOST": HOST_OK})

    assert result.exit_code == NagiosExitCode.OK
    assert f"on {HOST_OK}" in result.stdout


def test_e2e_rescan_and_debug_can_be_enabled_via_environment(run_plugin, scan_api):
    """CNS_RESCAN and CNS_DEBUG configure the run without command-line flags."""
    result = run_plugin([], env={"CNS_HOST": HOST_OK, "CNS_RESCAN": "true", "CNS_DEBUG": "1"})

    assert result.exit_code == NagiosExitCode.OK
    assert scan_api.requeued_hosts == [HOST_OK]
    assert "[DEBUG]" in result.stderr


# --- Rating thresholds ------------------------------------------------------
def test_e2e_custom_thresholds_escalate_an_ok_host(run_plugin):
    """Tightened -w/-c thresholds turn an A+ instance into a CRITICAL result."""
    result = run_plugin(["-H", HOST_OK, "-w", "5", "-c", "5"])

    assert result.exit_code == NagiosExitCode.CRITICAL
    assert "critical threshold" in result.first_line
    assert "rating=5;@0:5;@0:5;0;5" in result.perfdata


def test_e2e_custom_thresholds_can_accept_a_warning_host(run_plugin):
    """Relaxed thresholds accept a rating that would warn by default."""
    scan = run_plugin(["-H", HOST_WARNING, "-w", "0", "-c", "0"])

    # The host still has a known vulnerability, so it warns regardless.
    assert scan.exit_code == NagiosExitCode.WARNING
    assert "Found 1 vulnerabilities" in scan.first_line


def test_e2e_rejects_critical_threshold_above_warning(run_plugin):
    """An inconsistent threshold pair is rejected before any scan is started."""
    result = run_plugin(["-H", HOST_OK, "-w", "1", "-c", "3"])

    assert result.exit_code != 0
    assert "must not be higher than" in result.stderr


def test_e2e_rejects_out_of_range_threshold(run_plugin):
    """Ratings outside 0-5 are refused with a helpful message."""
    result = run_plugin(["-H", HOST_OK, "-w", "9"])

    assert result.exit_code != 0
    assert "between 0 and 5" in result.stderr


def test_e2e_thresholds_can_be_set_via_environment(run_plugin):
    """CNS_WARNING / CNS_CRITICAL configure the thresholds without flags."""
    warned = run_plugin([], env={"CNS_HOST": HOST_OK, "CNS_WARNING": "5", "CNS_CRITICAL": "4"})
    assert warned.exit_code == NagiosExitCode.WARNING

    crit = run_plugin([], env={"CNS_HOST": HOST_OK, "CNS_WARNING": "5", "CNS_CRITICAL": "5"})
    assert crit.exit_code == NagiosExitCode.CRITICAL


# --- Hardening --------------------------------------------------------------
def test_e2e_check_hardening_reports_missing_headers(run_plugin):
    """--check-hardening surfaces the missing security headers of a weak host."""
    result = run_plugin(["-H", HOST_EOL, "--check-hardening"])

    assert result.exit_code == NagiosExitCode.CRITICAL
    assert "Missing hardening:" in result.stdout
    assert "X-Frame-Options" in result.stdout
    assert "hardenings_missing=4;;;0;" in result.perfdata


def test_e2e_check_hardening_passes_for_a_hardened_host(run_plugin):
    """A fully hardened instance stays OK and reports zero findings."""
    result = run_plugin(["-H", HOST_OK, "--check-hardening"])

    assert result.exit_code == NagiosExitCode.OK
    assert "Hardening: all checked measures in place" in result.stdout
    assert "hardenings_missing=0;;;0;" in result.perfdata


def test_e2e_check_hardening_can_be_enabled_via_environment(run_plugin):
    """CNS_CHECK_HARDENING enables the hardening report without a flag."""
    result = run_plugin([], env={"CNS_HOST": HOST_OK, "CNS_CHECK_HARDENING": "yes"})

    assert result.exit_code == NagiosExitCode.OK
    assert "hardenings_missing=0;;;0;" in result.perfdata


# --- Timeout ----------------------------------------------------------------
def test_e2e_rejects_non_positive_timeout(run_plugin):
    """--timeout must be positive; zero would disable the safety net."""
    result = run_plugin(["-H", HOST_OK, "--timeout", "0"])

    assert result.exit_code != 0
    assert "positive number of seconds" in result.stderr


def test_e2e_custom_timeout_is_accepted(run_plugin):
    """A valid --timeout does not interfere with a normal run."""
    result = run_plugin(["-H", HOST_OK, "--timeout", "5"])

    assert result.exit_code == NagiosExitCode.OK


# --- Webhook ----------------------------------------------------------------
def test_e2e_webhook_fires_on_critical(run_plugin, scan_api):
    """A CRITICAL result posts a JSON notification to the configured webhook."""
    result = run_plugin(
        ["-H", HOST_EOL, "--webhook-url", f"{scan_api.base_url}/webhook"]
    )

    assert result.exit_code == NagiosExitCode.CRITICAL
    assert len(scan_api.webhook_calls) == 1

    payload = scan_api.webhook_calls[0]
    assert payload["host"] == HOST_EOL
    assert payload["status"] == "CRITICAL"
    assert payload["exit_code"] == 2
    assert payload["rating_label"] == "F"
    assert payload["eol"] is True
    assert payload["product"] == "Nextcloud"
    assert "end-of-life" in payload["message"]
    assert "Webhook delivery failed" not in result.stdout


def test_e2e_webhook_stays_silent_for_ok(run_plugin, scan_api):
    """An OK result does not notify when the trigger is left at 'critical'."""
    result = run_plugin(["-H", HOST_OK, "--webhook-url", f"{scan_api.base_url}/webhook"])

    assert result.exit_code == NagiosExitCode.OK
    assert scan_api.webhook_calls == []


def test_e2e_webhook_on_warning_includes_warning_results(run_plugin, scan_api):
    """--webhook-on warning also notifies for WARNING results."""
    result = run_plugin(
        [
            "-H",
            HOST_WARNING,
            "--webhook-url",
            f"{scan_api.base_url}/webhook",
            "--webhook-on",
            "warning",
        ]
    )

    assert result.exit_code == NagiosExitCode.WARNING
    assert len(scan_api.webhook_calls) == 1
    assert scan_api.webhook_calls[0]["status"] == "WARNING"
    assert scan_api.webhook_calls[0]["vulnerabilities"] == ["CVE-2023-28998"]


def test_e2e_webhook_fires_for_unreachable_host(run_plugin, scan_api):
    """With --webhook-on unknown, a failed scan also raises a notification."""
    result = run_plugin(
        [
            "-H",
            "no-nextcloud.example.com",
            "--webhook-url",
            f"{scan_api.base_url}/webhook",
            "--webhook-on",
            "unknown",
            "--retries",
            "0",
            "--backoff-factor",
            "0",
        ]
    )

    assert result.exit_code == NagiosExitCode.UNKNOWN
    assert len(scan_api.webhook_calls) == 1
    assert scan_api.webhook_calls[0]["status"] == "UNKNOWN"
    assert "Scan failed" in scan_api.webhook_calls[0]["message"]


def test_e2e_webhook_sends_custom_headers(run_plugin, scan_api):
    """--webhook-header values reach the receiver, allowing authentication."""
    run_plugin(
        [
            "-H",
            HOST_EOL,
            "--webhook-url",
            f"{scan_api.base_url}/webhook",
            "--webhook-header",
            "X-Auth-Token: s3cret",
            "--webhook-header",
            "X-Env: prod",
        ]
    )

    headers = scan_api.webhook_headers[0]
    assert headers["Content-Type"] == "application/json"
    assert headers["X-Auth-Token"] == "s3cret"
    assert headers["X-Env"] == "prod"


def test_e2e_failing_webhook_does_not_change_the_exit_code(run_plugin, scan_api):
    """A rejecting receiver is reported, but the scan verdict is unchanged."""
    scan_api.webhook_status = 500

    result = run_plugin(
        [
            "-H",
            HOST_EOL,
            "--webhook-url",
            f"{scan_api.base_url}/webhook",
            "--retries",
            "1",
            "--backoff-factor",
            "0",
        ]
    )

    assert result.exit_code == NagiosExitCode.CRITICAL
    assert "Webhook delivery failed" in result.stdout
    assert scan_api.requests["webhook"] == 2


def test_e2e_webhook_fires_per_host_in_multi_host_mode(run_plugin, scan_api):
    """Each critical host in a multi-host run produces its own notification."""
    result = run_plugin(
        ["-H", f"{HOST_OK},{HOST_EOL},{HOST_VULNERABLE}", "--webhook-url",
         f"{scan_api.base_url}/webhook"]
    )

    assert result.exit_code == NagiosExitCode.CRITICAL
    notified = {call["host"] for call in scan_api.webhook_calls}
    assert notified == {HOST_EOL, HOST_VULNERABLE}


def test_e2e_webhook_can_be_configured_via_environment(run_plugin, scan_api):
    """CNS_WEBHOOK_* variables configure the notification without any flags."""
    result = run_plugin(
        [],
        env={
            "CNS_HOST": HOST_EOL,
            "CNS_WEBHOOK_URL": f"{scan_api.base_url}/webhook",
            "CNS_WEBHOOK_HEADERS": "X-Auth-Token: abc; X-Env: prod",
        },
    )

    assert result.exit_code == NagiosExitCode.CRITICAL
    assert len(scan_api.webhook_calls) == 1
    assert scan_api.webhook_headers[0]["X-Auth-Token"] == "abc"


def test_e2e_rejects_non_http_webhook_url(run_plugin):
    """A non-HTTP webhook URL is refused before any scan is started."""
    result = run_plugin(["-H", HOST_OK, "--webhook-url", "ftp://example.com/hook"])

    assert result.exit_code != 0
    assert "must be an http(s) URL" in result.stderr


def test_e2e_rejects_invalid_webhook_trigger(run_plugin):
    """--webhook-on only accepts the documented levels."""
    result = run_plugin(["-H", HOST_OK, "--webhook-on", "sometimes"])

    assert result.exit_code != 0
    assert "invalid choice" in result.stderr
