import pytest
import sys
import check_nextcloud_security as cns
from check_nextcloud_security import ScanContext, ScanResult


def test_main_calls_all_functions(mocker):
    """
    Test that the main function calls all critical sub-functions
    with the correct arguments when a host is provided.

    Mocks necessary functions to control execution flow and verify calls.
    Specifically checks if 'check_if_ip_or_host', 'send_scan_request',
    and 'check_vulnerabilities' are called once with expected arguments.
    """
    test_args = ["prog", "-H", "nextcloud.example.com"]
    mocker.patch.object(sys, "argv", test_args)
    mock_check_ip = mocker.patch("check_nextcloud_security.check_if_ip_or_host")
    mock_scan_result = ScanResult(
        response={"status": "ok"},
        uuid="uuid123"
    )
    mock_send_scan = mocker.patch(
        "check_nextcloud_security.send_scan_request",
        return_value=mock_scan_result,
    )
    mock_check_vuln = mocker.patch("check_nextcloud_security.check_vulnerabilities")

    mocker.patch("check_nextcloud_security.logging.basicConfig")

    cns.main()

    expected_context = ScanContext(
        host="nextcloud.example.com",
        proxy=None,
        debug=False,
        rescan=False
    )

    mock_check_ip.assert_called_once_with("nextcloud.example.com")
    mock_send_scan.assert_called_once_with(expected_context)
    mock_check_vuln.assert_called_once_with(expected_context, mock_scan_result)


def test_main_debug_mode_enables_debug_logging(mocker):
    """
    Test that the main function configures logging to DEBUG level
    when the '-d' or '--debug' argument is provided in the command line.

    Mocks logging.basicConfig and asserts that it is called with the
    correct 'level' keyword argument.
    """
    test_args = ["prog", "-H", "nextcloud.example.com", "-d"]
    mocker.patch.object(sys, "argv", test_args)

    mock_basic_config = mocker.patch("check_nextcloud_security.logging.basicConfig")
    mocker.patch("check_nextcloud_security.check_if_ip_or_host")

    mocker.patch(
        "check_nextcloud_security.send_scan_request",
        return_value=ScanResult(response={}, uuid="uuid"),
    )
    mocker.patch("check_nextcloud_security.check_vulnerabilities")

    cns.main()

    mock_basic_config.assert_called_once()
    kwargs = mock_basic_config.call_args.kwargs
    assert kwargs["level"] == cns.logging.DEBUG


def test_main_exits_when_no_host(mocker):
    """
    Test that the main function terminates execution with a SystemExit
    if the required '--host' or '-H' argument is missing.

    Patches sys.argv to simulate a call without a host and checks for
    the SystemExit exception.
    """
    test_args = ["prog"]
    mocker.patch.object(sys, "argv", test_args)

    with pytest.raises(SystemExit):
        cns.main()
