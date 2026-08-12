"""Tests for the scan backend selection of the plugin."""

import sys

import pytest

import check_nextcloud_security as cns
from check_nextcloud_security import NagiosExitCode, ScanContext, ScanResult

LOCAL_RESULT = {
    "domain": "cloud.example.com",
    "product": "Nextcloud",
    "version": "30.0.2.2",
    "scannedAt": {"date": "2026-08-12 08:00:00.000000"},
    "rating": 5,
    "EOL": False,
    "vulnerabilities": [],
    "hardenings": {"CSPv3": True},
    "setup": {"https": {"used": True, "enforced": True}, "headers": {"X-Frame-Options": True}},
    "updates": {
        "available": True,
        "version": "30.0.2.2",
        "availableVersion": "30.0.4.0",
        "appUpdates": {},
        "lastCheckedAt": None,
        "source": "api",
        "error": None,
    },
    "extraChecks": [
        {"id": "header:Referrer-Policy", "severity": "medium", "passed": False, "detail": "missing"},
        {"id": "tlsProtocol", "severity": "high", "passed": True, "detail": "TLSv1.3"},
    ],
}


def _run_main(mocker, argv):
    mocker.patch.object(sys, "argv", ["prog"] + argv)
    mocker.patch("check_nextcloud_security.logging.basicConfig")
    with pytest.raises(SystemExit) as excinfo:
        cns.main()
    return excinfo.value.code


def test_default_backend_is_the_public_scan_api(mocker):
    """Without configuration the check still uses scan.nextcloud.com."""
    context = ScanContext(host="cloud.example.com")

    assert context.scan_backend == "remote"
    assert context.queue_url == "https://scan.nextcloud.com/api/queue"
    assert context.result_url_for("uuid") == "https://scan.nextcloud.com/api/result/uuid"


def test_scan_url_points_the_remote_backend_at_the_local_container(mocker):
    """--scan-url redirects every Scan API call to the container."""
    captured = {}

    def _capture(context):
        captured["context"] = context
        return ScanResult(response=LOCAL_RESULT, uuid="uuid")

    mocker.patch("check_nextcloud_security.send_scan_request", side_effect=_capture)
    mocker.patch("check_nextcloud_security.check_vulnerabilities")
    mocker.patch("check_nextcloud_security.logging.basicConfig")
    mocker.patch.object(
        sys,
        "argv",
        ["prog", "-H", "cloud.example.com", "--scan-url", "http://scanner:8080",
         "--scan-token", "t"],
    )

    cns.main()

    context = captured["context"]
    assert context.queue_url == "http://scanner:8080/api/queue"
    assert context.requeue_url == "http://scanner:8080/api/requeue"
    assert cns._build_request_info(context).headers["X-Auth-Token"] == "t"


def test_local_backend_runs_the_in_process_scanner(mocker):
    """--scan-backend local bypasses every scan service."""
    local_scan = mocker.patch(
        "check_nextcloud_security.local_scan", return_value=LOCAL_RESULT
    )
    post = mocker.patch("check_nextcloud_security.requests.post")

    code = _run_main(mocker, ["-H", "cloud.example.com", "--scan-backend", "local"])

    assert code == int(NagiosExitCode.OK)
    post.assert_not_called()
    local_scan.assert_called_once()
    assert local_scan.call_args.args[0] == "cloud.example.com"


def test_local_backend_reports_update_state_and_extra_checks(mocker, capsys):
    """serverinfo update data and the additional checks reach the output."""
    mocker.patch("check_nextcloud_security.local_scan", return_value=LOCAL_RESULT)

    _run_main(mocker, ["-H", "cloud.example.com", "--scan-backend", "local"])

    output = capsys.readouterr().out
    assert "Additional checks failed (1): header:Referrer-Policy" in output
    assert "server update available: 30.0.4.0" in output
    assert "extra_checks_failed=1" in output
    assert "update_available=1" in output


def test_update_warning_raises_an_otherwise_ok_result(mocker, capsys):
    """--update-warning turns a pending update into a WARNING."""
    mocker.patch("check_nextcloud_security.local_scan", return_value=LOCAL_RESULT)

    code = _run_main(
        mocker, ["-H", "cloud.example.com", "--scan-backend", "local", "--update-warning"]
    )

    assert code == int(NagiosExitCode.WARNING)
    assert "WARNING: Update available (30.0.4.0)" in capsys.readouterr().out


def test_local_backend_accepts_ip_addresses(mocker):
    """The public API rejects IPs, the local scanner does not."""
    context = ScanContext(host="192.0.2.10", scan_backend="local")

    cns.check_if_ip_or_host("192.0.2.10", context)

    with pytest.raises(SystemExit):
        cns.check_if_ip_or_host("192.0.2.10", ScanContext(host="192.0.2.10"))


def test_local_scan_failure_becomes_unknown(mocker, capsys):
    """An unscannable instance is reported as UNKNOWN, not as a traceback."""
    mocker.patch(
        "check_nextcloud_security.local_scan",
        side_effect=cns.ScanError("status.php is unreachable"),
    )

    code = _run_main(mocker, ["-H", "cloud.example.com", "--scan-backend", "local"])

    assert code == int(NagiosExitCode.UNKNOWN)
    assert "Local scan failed" in capsys.readouterr().out


def test_rescan_is_ignored_for_local_scans(mocker):
    """A local scan is always fresh, so no requeue request is made."""
    mocker.patch("check_nextcloud_security.local_scan", return_value=LOCAL_RESULT)
    post = mocker.patch("check_nextcloud_security.requests.post")

    _run_main(mocker, ["-H", "cloud.example.com", "--scan-backend", "local", "-r"])

    post.assert_not_called()


def test_yaml_configuration_selects_the_backend(mocker, tmp_path, capsys):
    """Everything can be configured through the YAML file alone."""
    config_file = tmp_path / "config.yml"
    config_file.write_text(
        "host: cloud.example.com\n"
        "scan:\n  backend: local\n"
        "update_warning: true\n",
        encoding="utf-8",
    )
    local_scan = mocker.patch(
        "check_nextcloud_security.local_scan", return_value=LOCAL_RESULT
    )

    code = _run_main(mocker, ["--config", str(config_file)])

    assert code == int(NagiosExitCode.WARNING)
    local_scan.assert_called_once()


def test_serverinfo_settings_come_from_the_configuration(mocker, tmp_path):
    """Serverinfo credentials may be supplied by a secret file."""
    secret = tmp_path / "token"
    secret.write_text("monitoring-token\n", encoding="utf-8")
    config_file = tmp_path / "config.yml"
    config_file.write_text(
        "host: cloud.example.com\n"
        "serverinfo:\n"
        "  mode: api\n"
        "  url: https://cloud.example.com\n"
        f"  token: file://{secret}\n",
        encoding="utf-8",
    )
    captured = {}

    def _capture(context):
        captured["context"] = context
        return ScanResult(response=LOCAL_RESULT, uuid="uuid")

    mocker.patch("check_nextcloud_security.send_scan_request", side_effect=_capture)
    mocker.patch("check_nextcloud_security.check_vulnerabilities")
    mocker.patch("check_nextcloud_security.logging.basicConfig")
    mocker.patch.object(sys, "argv", ["prog", "--config", str(config_file)])

    cns.main()

    settings = captured["context"].serverinfo_settings
    assert settings.mode == "api"
    assert settings.token == "monitoring-token"
    assert settings.effective_mode() == "api"


def test_remote_backend_asks_the_local_instance_for_updates(mocker, capsys):
    """Even with the public Scan API, updates come from serverinfo."""
    remote_result = {key: value for key, value in LOCAL_RESULT.items()
                     if key not in {"updates", "extraChecks"}}
    mocker.patch(
        "check_nextcloud_security.send_scan_request",
        return_value=ScanResult(response=remote_result, uuid="uuid"),
    )
    fetch = mocker.patch(
        "check_nextcloud_security.fetch_update_info",
        return_value=cns.UpdateInfo(available=False, version="30.0.2.2", source="occ"),
    )

    _run_main(
        mocker,
        ["-H", "cloud.example.com", "--serverinfo-mode", "occ", "--serverinfo-occ", "occ"],
    )

    fetch.assert_called_once()
    assert "server up to date" in capsys.readouterr().out


def test_no_update_check_disables_the_serverinfo_lookup(mocker, tmp_path):
    """--no-update-check wins over any configured serverinfo transport."""
    config_file = tmp_path / "config.yml"
    config_file.write_text(
        "host: cloud.example.com\n"
        "serverinfo:\n"
        "  mode: api\n"
        "  url: https://cloud.example.com\n"
        "  token: monitoring-token\n",
        encoding="utf-8",
    )
    captured = {}

    def _capture(context):
        captured["context"] = context
        return ScanResult(response=LOCAL_RESULT, uuid="uuid")

    mocker.patch("check_nextcloud_security.send_scan_request", side_effect=_capture)
    mocker.patch("check_nextcloud_security.check_vulnerabilities")
    mocker.patch("check_nextcloud_security.logging.basicConfig")
    mocker.patch.object(
        sys,
        "argv",
        [
            "prog",
            "--config",
            str(config_file),
            "--no-update-check",
            "--serverinfo-occ",
            "php /var/www/html/occ",
        ],
    )

    cns.main()

    settings = captured["context"].serverinfo_settings
    assert settings.mode == "off"
    assert settings.effective_mode() == "off"


def test_no_update_check_suppresses_the_update_line(mocker, capsys):
    """No update information is reported when the check is disabled."""
    mocker.patch("check_nextcloud_security.local_scan", return_value=LOCAL_RESULT)
    fetch = mocker.patch("check_nextcloud_security.fetch_update_info")

    exit_code = _run_main(
        mocker,
        ["--host", "cloud.example.com", "--scan-backend", "local", "--no-update-check"],
    )

    assert exit_code == NagiosExitCode.OK.value
    fetch.assert_not_called()
    assert "Update" not in capsys.readouterr().out


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://cloud.example.com", ["cloud.example.com"]),
        ("http://cloud.example.com/", ["cloud.example.com"]),
        ("cloud.example.com", ["cloud.example.com"]),
        ("https://cloud.example.com:8443/index.php", ["cloud.example.com:8443"]),
        ("a.example.com, https://b.example.com", ["a.example.com", "b.example.com"]),
        ("https://[2001:db8::1]/", ["[2001:db8::1]"]),
    ],
)
def test_host_values_may_be_urls(raw, expected):
    """A pasted URL is reduced to the bare host."""
    assert cns._parse_hosts(raw) == expected


def test_unreachable_scan_service_is_reported_as_such(mocker, capsys):
    """A connection error names the scan service instead of blaming the instance."""
    import requests

    mocker.patch(
        "check_nextcloud_security.requests.post",
        side_effect=requests.exceptions.ConnectionError("Name or service not known"),
    )

    exit_code = _run_main(
        mocker,
        [
            "--host",
            "https://cloud.example.com",
            "--scan-url",
            "http://host.docker.internal:8080",
            "--retries",
            "0",
        ],
    )

    output = capsys.readouterr().out
    assert exit_code == NagiosExitCode.UNKNOWN.value
    assert "Scan service http://host.docker.internal:8080 is unreachable" in output
    assert "no Nextcloud/ownCloud found" not in output
