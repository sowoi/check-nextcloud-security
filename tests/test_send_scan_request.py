from check_nextcloud_security import send_scan_request

import pytest
from unittest.mock import MagicMock

def test_send_scan_request_success(mocker) -> None:
    """
    Tests the successful execution of send_scan_request.

    Mocks both the initial POST request (to start the scan) and the subsequent
    GET request (to retrieve the result), simulating a successful scan with
    a 'rating' of 5 (best) and asserts the returned data structure and content.
    """
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

    headers, data, response_scan, uuid = send_scan_request("nextcloud.nextcloud.com", None)

    assert headers["Content-type"] == "application/x-www-form-urlencoded"
    assert data == {"url": "nextcloud.nextcloud.com"}
    assert response_scan['rating'] == 5
    assert uuid == "123-uid"

    mock_scan_post.assert_called_once()
    mock_scan_get.assert_called_once()


def test_send_scan_request_critical(mocker) -> None:
    """
    Tests the successful execution of send_scan_request when critical issues
    are present in the scan result.

    Mocks both the POST and GET requests, simulating a scan that returns a
    low 'rating' (0), indicates 'EOL' (End-of-Life), and is not the
    'latestVersionInBranch'. Asserts the critical values are correctly captured.
    """
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

    headers, data, response_scan, uuid = send_scan_request("nextcloud.nextcloud.com", None)

    assert headers["Content-type"] == "application/x-www-form-urlencoded"
    assert data == {"url": "nextcloud.nextcloud.com"}
    assert response_scan['rating'] == 0
    assert response_scan['EOL']
    assert not response_scan['latestVersionInBranch']
    assert uuid == "123-uid"

    mock_scan_post.assert_called_once()
    mock_scan_get.assert_called_once()


def test_send_scan_request_post_failure(mocker):
    """
    Tests that send_scan_request exits with code 3 if the initial POST request fails
    (e.g., due to network error, connection refusal, etc.).

    Mocks requests.post to raise an Exception and asserts SystemExit with code 3.
    """
    mocker.patch("check_nextcloud_security.requests.post", side_effect=Exception("Network error"))

    with pytest.raises(SystemExit) as e:
        send_scan_request("nextcloud.nextlcoud.com", None)

    assert e.value.code == 3


def test_send_scan_request_too_many_instances(mocker):
    """
    Tests that send_scan_request exits with code 3 if the scan API reports
    that too many instances have been submitted recently.

    Mocks the POST response to return the specific 'Too many instances' string.
    """
    mock_post = mocker.patch("check_nextcloud_security.requests.post")
    mock_post.return_value.json.return_value = "Too many instances"
    mock_post.return_value.raise_for_status.return_value = None

    with pytest.raises(SystemExit) as e:
        send_scan_request("nextcloud.nextlcoud.com", None)

    assert e.value.code == 3


def test_send_scan_request_missing_uuid(mocker):
    """
    Tests that send_scan_request exits with code 3 if the initial POST request
    succeeds but does not return the required 'uuid' in the JSON response.

    Mocks the POST response to return an empty dictionary.
    """
    mock_post = mocker.patch("check_nextcloud_security.requests.post")
    mock_post.return_value.json.return_value = {}
    mock_post.return_value.raise_for_status.return_value = None

    with pytest.raises(SystemExit) as e:
        send_scan_request("nextcloud.nextlcoud.com", None)

    assert e.value.code == 3
