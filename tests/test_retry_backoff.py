import pytest
import requests

from check_nextcloud_security import (
    ScanContext,
    _call_with_retry,
    send_scan_request,
)


def test_call_with_retry_succeeds_on_first_attempt():
    """
    Test that _call_with_retry returns the function's result immediately
    when it succeeds without raising.
    """
    result = _call_with_retry(
        lambda: "ok", retries=3, backoff_factor=0.1, description="test"
    )
    assert result == "ok"


def test_call_with_retry_succeeds_after_transient_failures(mocker):
    """
    Test that _call_with_retry retries a failing function and returns its
    result once it eventually succeeds, sleeping with exponential backoff
    between attempts.
    """
    mock_sleep = mocker.patch("check_nextcloud_security.time.sleep")

    attempts = {"count": 0}

    def flaky():
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise requests.exceptions.ConnectionError("temporary failure")
        return "recovered"

    result = _call_with_retry(flaky, retries=3, backoff_factor=1.0, description="test")

    assert result == "recovered"
    assert attempts["count"] == 3
    # Two failures before success -> two sleeps, with exponential backoff.
    assert mock_sleep.call_count == 2
    mock_sleep.assert_any_call(1.0)  # backoff_factor * 2**0
    mock_sleep.assert_any_call(2.0)  # backoff_factor * 2**1


def test_call_with_retry_raises_last_error_once_exhausted(mocker):
    """
    Test that _call_with_retry re-raises the most recent exception after
    exhausting all retry attempts, without sleeping after the final attempt.
    """
    mock_sleep = mocker.patch("check_nextcloud_security.time.sleep")

    def always_fails():
        raise requests.exceptions.Timeout("still failing")

    with pytest.raises(requests.exceptions.Timeout):
        _call_with_retry(always_fails, retries=2, backoff_factor=0.5, description="test")

    # 2 retries -> 3 total attempts -> 2 sleeps between them, none after the last.
    assert mock_sleep.call_count == 2


def test_send_scan_request_recovers_from_transient_post_failure(mocker):
    """
    Test that send_scan_request succeeds if the POST to queue a scan fails
    transiently but succeeds within the configured retry budget.
    """
    context = ScanContext(host="nextcloud.example.com", retries=2, backoff_factor=0.1)

    mock_post = mocker.patch("check_nextcloud_security.requests.post")
    mock_post.side_effect = [
        requests.exceptions.ConnectionError("temporary failure"),
        mocker.MagicMock(
            **{"raise_for_status.return_value": None, "json.return_value": {"uuid": "abc-123"}}
        ),
    ]

    mock_get = mocker.patch("check_nextcloud_security.requests.get")
    mock_get.return_value.json.return_value = {"rating": 5, "vulnerabilities": []}

    result = send_scan_request(context)

    assert result.uuid == "abc-123"
    assert mock_post.call_count == 2


def test_send_scan_request_fails_after_exhausting_retries(mocker):
    """
    Test that send_scan_request exits with UNKNOWN (3) once the configured
    number of retries for the initial POST request is exhausted.
    """
    context = ScanContext(host="nextcloud.example.com", retries=1, backoff_factor=0.1)

    mocker.patch(
        "check_nextcloud_security.requests.post",
        side_effect=requests.exceptions.ConnectionError("persistent failure"),
    )

    with pytest.raises(SystemExit) as e:
        send_scan_request(context)

    assert e.value.code == 3
