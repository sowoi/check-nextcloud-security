import pytest
from check_nextcloud_security import check_vulnerabilities, ScanContext, ScanResult


@pytest.mark.parametrize(
    "response_scan, expected_exit, expected_substring",
    [
        (
                {"rating": 5, "vulnerabilities": [], "product": "Nextcloud", "version": "29.0", "domain": "test.com"},
                0,
                "OK: Server is up to date",
        ),
        (
                {"rating": 4, "vulnerabilities": [], "product": "Nextcloud", "version": "29.0", "domain": "test.com"},
                0,
                "OK: Update available",
        ),
        (
                {"rating": 3, "vulnerabilities": [{"id": 1}], "product": "Nextcloud", "version": "29.0",
                 "domain": "test.com"},
                1,
                "WARNING: Found 1 vulnerabilities",
        ),
        (
                {"rating": 1, "vulnerabilities": [{"id": 42}], "product": "Nextcloud", "version": "29.0",
                 "domain": "test.com"},
                2,
                "CRITICAL: Found 1 vulnerabilities",
        ),
        (
                {"rating": 0, "product": "Nextcloud", "version": "29.0", "domain": "test.com"},
                2,
                "end-of-life",
        ),
        (
                {"rating": 99, "product": "Nextcloud", "version": "29.0", "domain": "test.com"},
                3,
                "UNKNOWN: Scan result unclear",
        ),
    ],
)
def test_check_vulnerabilities_various_ratings(response_scan, expected_exit, expected_substring, capsys):
    """
    Tests various scan rating scenarios for the check_vulnerabilities function.
    """
    context = ScanContext(host="test.com", rescan=False)
    response_scan.setdefault("scannedAt", {"date": "Unknown"})
    result = ScanResult(response=response_scan, uuid="uuid-test")

    with pytest.raises(SystemExit) as e:
        check_vulnerabilities(context, result)

    out = capsys.readouterr().out
    assert expected_substring in out
    assert e.value.code == expected_exit


def test_check_vulnerabilities_rescan_success(mocker, capsys):
    """
    Tests the rescan functionality when the initial result is poor but the
    subsequent rescan is successful.
    """
    context = ScanContext(host="test.com", rescan=True)

    initial_response = {"rating": 2, "product": "Nextcloud", "version": "28.0", "domain": "test.com"}
    initial_response.setdefault("scannedAt", {"date": "Unknown"})
    initial_result = ScanResult(response=initial_response, uuid="uuid-rescan")

    mock_post = mocker.patch("check_nextcloud_security.requests.post")
    mock_get = mocker.patch("check_nextcloud_security.requests.get")

    mock_get.return_value.json.return_value = {
        "rating": 5,
        "vulnerabilities": [],
        "product": "Nextcloud",
        "version": "29.0",
        "domain": "test.com",
        "scannedAt": {"date": "2025-01-01"}
    }

    with pytest.raises(SystemExit) as e:
        check_vulnerabilities(context, initial_result)

    out = capsys.readouterr().out
    assert "OK: Server is up to date" in out
    assert e.value.code == 0
    mock_post.assert_called_once()
    mock_get.assert_called_once()


def test_check_vulnerabilities_rescan_failure(mocker, capsys):
    """
    Tests that the program handles rescan failure gracefully.
    """
    context = ScanContext(host="test.com", rescan=True)

    initial_response = {"rating": 2, "product": "Nextcloud", "version": "28.0", "domain": "test.com"}
    initial_response.setdefault("scannedAt", {"date": "Unknown"})
    initial_result = ScanResult(response=initial_response, uuid="uuid-fail")

    mocker.patch("check_nextcloud_security.requests.post", side_effect=Exception("network error"))

    with pytest.raises(SystemExit) as e:
        check_vulnerabilities(context, initial_result)

    out = capsys.readouterr().out
    assert "UNKNOWN: Failed to rescan" in out
    assert e.value.code == 3