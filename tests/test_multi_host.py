import sys

import pytest

import check_nextcloud_security as cns
from check_nextcloud_security import NagiosExitCode, ScanResult


# --- _parse_hosts ---
@pytest.mark.parametrize(
    "raw_host, expected",
    [
        ("nextcloud.example.com", ["nextcloud.example.com"]),
        (
            "a.example.com,b.example.com,c.example.com",
            ["a.example.com", "b.example.com", "c.example.com"],
        ),
        (
            " a.example.com , b.example.com ",
            ["a.example.com", "b.example.com"],
        ),
        ("a.example.com,,b.example.com,", ["a.example.com", "b.example.com"]),
        ("   ", []),
        ("", []),
    ],
)
def test_parse_hosts(raw_host, expected):
    """
    Test that _parse_hosts splits a comma-separated --host value into a
    clean list, stripping whitespace and dropping empty entries.
    """
    assert cns._parse_hosts(raw_host) == expected


# --- _aggregate_exit_code ---
@pytest.mark.parametrize(
    "codes, expected",
    [
        ([NagiosExitCode.OK, NagiosExitCode.OK], NagiosExitCode.OK),
        ([NagiosExitCode.OK, NagiosExitCode.WARNING], NagiosExitCode.WARNING),
        ([NagiosExitCode.WARNING, NagiosExitCode.CRITICAL], NagiosExitCode.CRITICAL),
        # UNKNOWN must not mask a confirmed CRITICAL/WARNING found elsewhere.
        ([NagiosExitCode.UNKNOWN, NagiosExitCode.CRITICAL], NagiosExitCode.CRITICAL),
        ([NagiosExitCode.UNKNOWN, NagiosExitCode.WARNING], NagiosExitCode.WARNING),
        ([NagiosExitCode.UNKNOWN, NagiosExitCode.OK], NagiosExitCode.UNKNOWN),
        ([NagiosExitCode.OK], NagiosExitCode.OK),
    ],
)
def test_aggregate_exit_code(codes, expected):
    """
    Test that _aggregate_exit_code picks the worst status using the
    CRITICAL > WARNING > UNKNOWN > OK priority order.
    """
    assert cns._aggregate_exit_code(codes) == expected


# --- _run_single_host_check ---
def test_run_single_host_check_captures_message_and_exit_code(mocker):
    """
    Test that _run_single_host_check captures the printed output and exit
    code of a single host's scan-and-check flow instead of exiting.
    """
    context = cns.ScanContext(host="nextcloud.example.com")
    mocker.patch("check_nextcloud_security.check_if_ip_or_host")
    mocker.patch(
        "check_nextcloud_security.send_scan_request",
        return_value=ScanResult(response={}, uuid="uuid"),
    )

    def _fake_check_vulnerabilities(ctx, scan_result, duration_seconds=None):
        print("CRITICAL: something bad | rating=1;;;0;5")
        sys.exit(int(NagiosExitCode.CRITICAL))

    mocker.patch(
        "check_nextcloud_security.check_vulnerabilities",
        side_effect=_fake_check_vulnerabilities,
    )

    message, exit_code = cns._run_single_host_check(context)

    assert "CRITICAL: something bad" in message
    assert exit_code == NagiosExitCode.CRITICAL


def test_run_single_host_check_handles_ip_rejection(mocker):
    """
    Test that a host failing check_if_ip_or_host (e.g. a bare IP) is
    reported as UNKNOWN instead of raising, so other hosts still get
    processed.
    """
    context = cns.ScanContext(host="192.168.1.1")

    message, exit_code = cns._run_single_host_check(context)

    assert "IP addresses are not supported" in message
    assert exit_code == NagiosExitCode.UNKNOWN


# --- main() with multiple hosts ---
def test_main_processes_multiple_hosts_and_exits_with_worst_status(mocker, capsys):
    """
    Test that main() processes each host in a comma-separated --host list,
    calling the scan-and-check flow once per host, and exits with the worst
    aggregated status across all hosts.
    """
    test_args = ["prog", "-H", "ok.example.com,critical.example.com"]
    mocker.patch.object(sys, "argv", test_args)
    mocker.patch("check_nextcloud_security.logging.basicConfig")
    mocker.patch("check_nextcloud_security.check_if_ip_or_host")
    mocker.patch(
        "check_nextcloud_security.send_scan_request",
        return_value=ScanResult(response={}, uuid="uuid"),
    )

    def _fake_check_vulnerabilities(ctx, scan_result, duration_seconds=None):
        if ctx.host == "ok.example.com":
            print("OK: Server is up to date.")
            sys.exit(int(NagiosExitCode.OK))
        print("CRITICAL: Found vulnerabilities.")
        sys.exit(int(NagiosExitCode.CRITICAL))

    mock_check_vuln = mocker.patch(
        "check_nextcloud_security.check_vulnerabilities",
        side_effect=_fake_check_vulnerabilities,
    )

    with pytest.raises(SystemExit) as e:
        cns.main()

    assert e.value.code == int(NagiosExitCode.CRITICAL)
    assert mock_check_vuln.call_count == 2

    out = capsys.readouterr().out
    assert "Checked 2 host(s): overall CRITICAL" in out
    assert "[ok.example.com]" in out
    assert "OK: Server is up to date." in out
    assert "[critical.example.com]" in out
    assert "CRITICAL: Found vulnerabilities." in out


def test_main_single_host_from_list_behaves_like_single_host(mocker):
    """
    Test that a --host value with only one entry (no comma) still follows
    the original single-host code path, letting the underlying
    check_vulnerabilities call terminate the process directly.
    """
    test_args = ["prog", "-H", "nextcloud.example.com"]
    mocker.patch.object(sys, "argv", test_args)
    mocker.patch("check_nextcloud_security.logging.basicConfig")
    mocker.patch("check_nextcloud_security.check_if_ip_or_host")
    mocker.patch(
        "check_nextcloud_security.send_scan_request",
        return_value=ScanResult(response={}, uuid="uuid"),
    )
    mock_check_vuln = mocker.patch("check_nextcloud_security.check_vulnerabilities")

    # No SystemExit is raised because check_vulnerabilities is mocked
    # without a side effect, matching pre-existing single-host behavior.
    cns.main()

    mock_check_vuln.assert_called_once()


def test_main_host_list_via_environment_variable(mocker, monkeypatch, capsys):
    """
    Test that CNS_HOST also accepts a comma-separated list of hosts.
    """
    monkeypatch.setenv("CNS_HOST", "a.example.com,b.example.com")
    mocker.patch.object(sys, "argv", ["prog"])
    mocker.patch("check_nextcloud_security.logging.basicConfig")
    mocker.patch("check_nextcloud_security.check_if_ip_or_host")
    mocker.patch(
        "check_nextcloud_security.send_scan_request",
        return_value=ScanResult(response={}, uuid="uuid"),
    )

    def _fake_check_vulnerabilities(ctx, scan_result, duration_seconds=None):
        print(f"OK: {ctx.host} is fine.")
        sys.exit(int(NagiosExitCode.OK))

    mocker.patch(
        "check_nextcloud_security.check_vulnerabilities",
        side_effect=_fake_check_vulnerabilities,
    )

    with pytest.raises(SystemExit) as e:
        cns.main()

    assert e.value.code == int(NagiosExitCode.OK)
    out = capsys.readouterr().out
    assert "a.example.com is fine" in out
    assert "b.example.com is fine" in out
