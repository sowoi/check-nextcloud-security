import sys

import pytest

import check_nextcloud_security as cns


def _run_main_and_capture_context(mocker, args):
    """Run cns.main() with the given argv, returning the ScanContext it built."""
    mocker.patch.object(sys, "argv", ["prog"] + args)
    mocker.patch("check_nextcloud_security.check_if_ip_or_host")
    mocker.patch(
        "check_nextcloud_security.send_scan_request",
        return_value=cns.ScanResult(response={}, uuid="uuid"),
    )
    captured = {}

    def _fake_check_vulnerabilities(context, scan_result, duration_seconds=None):
        captured["context"] = context

    mocker.patch(
        "check_nextcloud_security.check_vulnerabilities",
        side_effect=_fake_check_vulnerabilities,
    )
    mocker.patch("check_nextcloud_security.logging.basicConfig")

    cns.main()
    return captured["context"]


def test_host_can_be_supplied_via_environment_variable(mocker, monkeypatch):
    """
    Test that CNS_HOST is used as the --host value when the flag is omitted.
    """
    monkeypatch.setenv("CNS_HOST", "nextcloud.env-example.com")

    context = _run_main_and_capture_context(mocker, [])

    assert context.host == "nextcloud.env-example.com"


def test_cli_host_flag_overrides_environment_variable(mocker, monkeypatch):
    """
    Test that an explicit --host flag takes precedence over CNS_HOST.
    """
    monkeypatch.setenv("CNS_HOST", "nextcloud.env-example.com")

    context = _run_main_and_capture_context(mocker, ["-H", "nextcloud.cli-example.com"])

    assert context.host == "nextcloud.cli-example.com"


def test_proxy_can_be_supplied_via_environment_variable(mocker, monkeypatch):
    """
    Test that CNS_PROXY populates the proxy setting when --proxy is omitted.
    """
    monkeypatch.setenv("CNS_HOST", "nextcloud.example.com")
    monkeypatch.setenv("CNS_PROXY", "http://proxy.example.com:3128")

    context = _run_main_and_capture_context(mocker, [])

    assert context.proxy == "http://proxy.example.com:3128"


def test_debug_and_rescan_can_be_enabled_via_environment_variables(mocker, monkeypatch):
    """
    Test that CNS_DEBUG and CNS_RESCAN act as boolean switches, accepting
    common truthy string representations.
    """
    monkeypatch.setenv("CNS_HOST", "nextcloud.example.com")
    monkeypatch.setenv("CNS_DEBUG", "true")
    monkeypatch.setenv("CNS_RESCAN", "1")

    context = _run_main_and_capture_context(mocker, [])

    assert context.debug is True
    assert context.rescan is True


@pytest.mark.parametrize("falsy_value", ["", "0", "false", "no", "off"])
def test_debug_env_var_falsy_values_do_not_enable_debug(mocker, monkeypatch, falsy_value):
    """
    Test that common falsy string values for CNS_DEBUG are not interpreted
    as enabling debug mode.
    """
    monkeypatch.setenv("CNS_HOST", "nextcloud.example.com")
    if falsy_value:
        monkeypatch.setenv("CNS_DEBUG", falsy_value)

    context = _run_main_and_capture_context(mocker, [])

    assert context.debug is False


def test_retries_and_backoff_factor_can_be_supplied_via_environment_variables(mocker, monkeypatch):
    """
    Test that CNS_RETRIES and CNS_BACKOFF_FACTOR configure the retry
    mechanism when the corresponding flags are omitted.
    """
    monkeypatch.setenv("CNS_HOST", "nextcloud.example.com")
    monkeypatch.setenv("CNS_RETRIES", "5")
    monkeypatch.setenv("CNS_BACKOFF_FACTOR", "2.5")

    context = _run_main_and_capture_context(mocker, [])

    assert context.retries == 5
    assert context.backoff_factor == 2.5


def test_cli_retries_flag_overrides_environment_variable(mocker, monkeypatch):
    """
    Test that an explicit --retries flag takes precedence over CNS_RETRIES.
    """
    monkeypatch.setenv("CNS_HOST", "nextcloud.example.com")
    monkeypatch.setenv("CNS_RETRIES", "5")

    context = _run_main_and_capture_context(mocker, ["--retries", "1"])

    assert context.retries == 1


def test_invalid_retries_env_var_falls_back_to_default(mocker, monkeypatch):
    """
    Test that a non-numeric CNS_RETRIES value is ignored in favor of the
    documented default, rather than crashing argument parsing.
    """
    monkeypatch.setenv("CNS_HOST", "nextcloud.example.com")
    monkeypatch.setenv("CNS_RETRIES", "not-a-number")

    context = _run_main_and_capture_context(mocker, [])

    assert context.retries == cns.DEFAULT_RETRIES


def test_main_exits_when_no_host_and_no_env_var(mocker, monkeypatch):
    """
    Test that main() still requires a host (via flag or CNS_HOST) and exits
    with an error when neither is supplied.
    """
    mocker.patch.object(sys, "argv", ["prog"])

    with pytest.raises(SystemExit):
        cns.main()
