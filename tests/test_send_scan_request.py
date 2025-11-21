from check_nextcloud_security import send_scan_request, ScanContext, ScanResult

import pytest
from unittest.mock import MagicMock

def test_send_scan_request_success(mocker) -> None:
    """
    Tests the successful execution of send_scan_request.
    """
    context = ScanContext(host="nextcloud.nextcloud.com")

    # mock for post
    mock_scan_post = mocker.patch("check_nextcloud_security.requests.post")
    mock_response_post = MagicMock()
    mock_response_post.raise_for_status.return_value = None
    mock_response_post.json.return_value = {'uuid': '123-uid'}
    mock_scan_post.return_value = mock_response_post

    # mock for get
    mock_scan_get = mocker.patch("check_nextcloud_security.requests.get")
    mock_response_get = MagicMock()
    mock_response_get.raise_for_status.return_value = None
    mock_response_get.json.return_value = {'domain': 'nextcloud.nextlcoud.com', 'url': 'https://nextcloud.nextcloud.com/status.php',
                                           'version': '29.0.2.2', 'product': 'Nextcloud', 'edition': '',
                                           'scannedAt': {'date': '2025-11-11 02:36:50.000000', 'timezone_type': 3, 'timezone': 'UTC'},
                                           'rating': 5, 'vulnerabilities': [],
                                           'hardenings': {'bruteforceProtection': True, 'CSPv3': True, 'sameSiteCookies': True, 'passwordConfirmation': True, '__HostPrefix': True,
                                                          'appPasswordsCanBeRestricted': True,
                                                          'appPasswordsScannedForHaveIBeenPwned': True},
                                           'setup': {'https': {'enforced': True, 'used': True}, 'headers': {'X-Frame-Options': False, 'X-Content-Type-Options': False,
                                                                                                            'X-XSS-Protection': False, 'X-Download-Options': True, 'X-Permitted-Cross-Domain-Policies': False}},
                                           'EOL': False, 'latestVersionInBranch': True}
    mock_scan_get.return_value = mock_response_get

    result: ScanResult = send_scan_request(context)

    assert isinstance(result, ScanResult)
    assert result.uuid == "123-uid"
    assert result.response['rating'] == 5
    mock_scan_post.assert_called_once()
    assert mock_scan_post.call_args.kwargs['data'] == {'url': 'nextcloud.nextcloud.com'}
    mock_scan_get.assert_called_once()


def test_send_scan_request_critical(mocker) -> None:
    """
    Tests the successful execution of send_scan_request when critical issues
    are present in the scan result.
    """
    context = ScanContext(host="nextcloud.nextcloud.com")

    # mock for post
    mock_scan_post = mocker.patch("check_nextcloud_security.requests.post")
    mock_response_post = MagicMock()
    mock_response_post.raise_for_status.return_value = None
    mock_response_post.json.return_value = {'uuid': '123-uid'}
    mock_scan_post.return_value = mock_response_post

    # mock for get
    mock_scan_get = mocker.patch("check_nextcloud_security.requests.get")
    mock_response_get = MagicMock()
    mock_response_get.raise_for_status.return_value = None
    mock_response_get.json.return_value = {'domain': 'nextcloud.nextlcoud.com', 'url': 'https://nextcloud.nextcloud.com/status.php',
                                           'version': '29.0.2.2', 'product': 'Nextcloud', 'edition': '',
                                           'scannedAt': {'date': '2025-11-11 02:36:50.000000', 'timezone_type': 3, 'timezone': 'UTC'},
                                           'rating': 0, 'vulnerabilities': [],
                                           'hardenings': {'bruteforceProtection': True, 'CSPv3': True, 'sameSiteCookies': True, 'passwordConfirmation': True, '__HostPrefix': True,
                                                          'appPasswordsCanBeRestricted': True,
                                                          'appPasswordsScannedForHaveIBeenPwned': True},
                                           'setup': {'https': {'enforced': True, 'used': True}, 'headers': {'X-Frame-Options': False, 'X-Content-Type-Options': False,
                                                                                                            'X-XSS-Protection': False, 'X-Download-Options': True, 'X-Permitted-Cross-Domain-Policies': False}},
                                           'EOL': True, 'latestVersionInBranch': False}
    mock_scan_get.return_value = mock_response_get

    result: ScanResult = send_scan_request(context)

    assert isinstance(result, ScanResult)
    assert result.uuid == "123-uid"
    assert result.response['rating'] == 0
    assert result.response['EOL']
    assert not result.response['latestVersionInBranch']

    mock_scan_post.assert_called_once()
    mock_scan_get.assert_called_once()


def test_send_scan_request_post_failure(mocker):
    """
    Tests that send_scan_request exits with code 3 if the initial POST request fails
    (e.g., due to network error, connection refusal, etc.).
    """
    context = ScanContext(host="nextcloud.nextlcoud.com")

    mocker.patch("check_nextcloud_security.requests.post", side_effect=Exception("Network error"))

    with pytest.raises(SystemExit) as e:
        send_scan_request(context) # Aufruf mit Context

    assert e.value.code == 3


def test_send_scan_request_too_many_instances(mocker):
    """
    Tests that send_scan_request exits with code 3 if the scan API reports
    that too many instances have been submitted recently.
    """
    # Erstellung des ScanContext-Objekts
    context = ScanContext(host="nextcloud.nextlcoud.com")

    mock_post = mocker.patch("check_nextcloud_security.requests.post")
    mock_post.return_value.json.return_value = "Too many instances"
    mock_post.return_value.raise_for_status.return_value = None

    with pytest.raises(SystemExit) as e:
        send_scan_request(context)

    assert e.value.code == 3


def test_send_scan_request_missing_uuid(mocker):
    """
    Tests that send_scan_request exits with code 3 if the initial POST request
    succeeds but does not return the required 'uuid' in the JSON response.
    """
    context = ScanContext(host="nextcloud.nextlcoud.com")

    mock_post = mocker.patch("check_nextcloud_security.requests.post")
    mock_post.return_value.json.return_value = {}
    mock_post.return_value.raise_for_status.return_value = None

    with pytest.raises(SystemExit) as e:
        send_scan_request(context)

    assert e.value.code == 3