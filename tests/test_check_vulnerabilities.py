import pytest
from check_nextcloud_security import check_vulnerabilities


@pytest.mark.parametrize(
    "response_scan, expected_exit, expected_substring",
    [
        (
            {"rating": 5, "vulnerabilities": [], "product": "Nextcloud", "version": "29.0"},
            0,
            "OK: Server is up to date",
        ),
        (
            {"rating": 4, "vulnerabilities": [], "product": "Nextcloud", "version": "29.0"},
            0,
            "OK: Update available",
        ),
        (
            {"rating": 3, "vulnerabilities": [{"id": 1}]},
            1,
            "WARNING: Found 1 vulnerabilities",
        ),
        (
            {"rating": 1, "vulnerabilities": [{"id": 42}]},
            2,
            "CRITICAL: Found 1 vulnerabilities",
        ),
        (
            {"rating": 0},
            2,
            "end-of-life",
        ),
        (
            {"rating": 99},
            3,
            "UNKNOWN: Scan result unclear",
        ),
    ],
)
def test_check_vulnerabilities_various_ratings(response_scan, expected_exit, expected_substring, capsys):
    """
    Tests various scan rating scenarios for the check_vulnerabilities function.

    Uses `pytest.mark.parametrize` to check how different 'rating' and
    'vulnerabilities' combinations in the scan response affect the program's
    exit code and the output message.
    """
    with pytest.raises(SystemExit) as e:
        check_vulnerabilities(None, False, {}, {}, response_scan, "uuid-test")

    out = capsys.readouterr().out
    assert expected_substring in out
    assert e.value.code == expected_exit

def test_check_vulnerabilities_rescan_success(mocker, capsys):
    """
    Tests the rescan functionality when the initial result is poor but the
    subsequent rescan is successful.

    Mocks requests.post and requests.get to simulate a successful rescan
    that returns a "rating": 5. Asserts the exit code is 0 (OK) and the
    success message is printed.
    """
    mock_post = mocker.patch("check_nextcloud_security.requests.post")
    mock_get = mocker.patch("check_nextcloud_security.requests.get")
    mock_get.return_value.json.return_value = {"rating": 5, "vulnerabilities": []}

    with pytest.raises(SystemExit) as e:
        check_vulnerabilities(None, True, {}, {}, {"rating": 2}, "uuid-rescan")

    out = capsys.readouterr().out
    assert "OK: Server is up to date" in out
    assert e.value.code == 0
    mock_post.assert_called_once()
    mock_get.assert_called_once()


def test_check_vulnerabilities_rescan_failure(mocker, capsys):
    """
    Tests that the program handles rescan failure gracefully.

    Mocks requests.post to raise an Exception during the rescan attempt.
    Asserts the exit code is 3 (UNKNOWN) and an appropriate failure message
    is printed to stdout.
    """
    mocker.patch("check_nextcloud_security.requests.post", side_effect=Exception("network error"))

    with pytest.raises(SystemExit) as e:
        check_vulnerabilities(None, True, {}, {}, {"rating": 2}, "uuid-fail")

    out = capsys.readouterr().out
    assert "UNKNOWN: Failed to rescan" in out
    assert e.value.code == 3