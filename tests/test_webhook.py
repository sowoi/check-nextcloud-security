"""Unit tests for the optional webhook notification."""
import pytest
import requests

from check_nextcloud_security import (
    NagiosExitCode,
    ScanContext,
    ScanResult,
    _parse_webhook_headers,
    _webhook_should_fire,
    check_vulnerabilities,
)

WEBHOOK_URL = "https://hooks.example.com/nextcloud"

CRITICAL_RESPONSE = {
    "rating": 0,
    "vulnerabilities": [],
    "product": "Nextcloud",
    "version": "29.0.2.2",
    "domain": "test.com",
    "scannedAt": {"date": "2026-01-01"},
    "EOL": True,
}

OK_RESPONSE = {
    "rating": 5,
    "vulnerabilities": [],
    "product": "Nextcloud",
    "version": "34.0.2.1",
    "domain": "test.com",
    "scannedAt": {"date": "2026-01-01"},
}


def _run(context: ScanContext, response: dict, **kwargs) -> int:
    """Run check_vulnerabilities and return its exit code."""
    with pytest.raises(SystemExit) as excinfo:
        check_vulnerabilities(context, ScanResult(response=response, uuid="uuid-test"), **kwargs)
    assert isinstance(excinfo.value.code, int)
    return excinfo.value.code


@pytest.mark.parametrize(
    "webhook_on, exit_code, expected",
    [
        ("critical", NagiosExitCode.CRITICAL, True),
        ("critical", NagiosExitCode.WARNING, False),
        ("critical", NagiosExitCode.UNKNOWN, False),
        ("critical", NagiosExitCode.OK, False),
        ("warning", NagiosExitCode.WARNING, True),
        ("warning", NagiosExitCode.UNKNOWN, False),
        ("unknown", NagiosExitCode.UNKNOWN, True),
        ("unknown", NagiosExitCode.OK, False),
        ("always", NagiosExitCode.OK, True),
    ],
)
def test_webhook_trigger_matrix(webhook_on, exit_code, expected):
    """Each --webhook-on level fires for its own state and every worse one."""
    context = ScanContext(host="test.com", webhook_url=WEBHOOK_URL, webhook_on=webhook_on)

    assert _webhook_should_fire(context, exit_code) is expected


def test_webhook_is_disabled_without_a_url():
    """No webhook URL means no notification, whatever the state."""
    context = ScanContext(host="test.com")

    assert _webhook_should_fire(context, NagiosExitCode.CRITICAL) is False


def test_no_webhook_is_sent_when_not_configured(mocker):
    """A critical result stays silent when no webhook is configured."""
    post = mocker.patch("check_nextcloud_security.requests.post")

    exit_code = _run(ScanContext(host="test.com"), dict(CRITICAL_RESPONSE))

    assert exit_code == NagiosExitCode.CRITICAL
    post.assert_not_called()


def test_no_webhook_is_sent_for_an_ok_result(mocker):
    """By default only critical results notify, so an OK run posts nothing."""
    post = mocker.patch("check_nextcloud_security.requests.post")
    context = ScanContext(host="test.com", webhook_url=WEBHOOK_URL)

    exit_code = _run(context, dict(OK_RESPONSE))

    assert exit_code == NagiosExitCode.OK
    post.assert_not_called()


def test_critical_result_posts_the_expected_payload(mocker):
    """A critical result posts a JSON document describing the finding."""
    post = mocker.patch("check_nextcloud_security.requests.post")
    context = ScanContext(host="test.com", webhook_url=WEBHOOK_URL)

    _run(context, dict(CRITICAL_RESPONSE), duration_seconds=1.2345)

    post.assert_called_once()
    assert post.call_args.args[0] == WEBHOOK_URL
    payload = post.call_args.kwargs["json"]
    assert payload["plugin"] == "check-nextcloud-security"
    assert payload["host"] == "test.com"
    assert payload["status"] == "CRITICAL"
    assert payload["exit_code"] == 2
    assert payload["rating"] == 0
    assert payload["rating_label"] == "F"
    assert payload["eol"] is True
    assert payload["product"] == "Nextcloud"
    assert payload["vulnerability_count"] == 0
    assert payload["scan_uuid"] == "uuid-test"
    assert payload["duration_seconds"] == 1.234
    assert "end-of-life" in payload["message"]
    assert payload["timestamp"].endswith("+00:00")


def test_payload_lists_vulnerability_identifiers(mocker):
    """Reported CVEs are included so the receiver can act on them."""
    post = mocker.patch("check_nextcloud_security.requests.post")
    context = ScanContext(host="test.com", webhook_url=WEBHOOK_URL)
    response = {
        **CRITICAL_RESPONSE,
        "rating": 1,
        "EOL": False,
        "vulnerabilities": [{"id": "CVE-2023-1"}, {"id": "CVE-2023-2"}],
    }

    _run(context, response)

    payload = post.call_args.kwargs["json"]
    assert payload["vulnerability_count"] == 2
    assert payload["vulnerabilities"] == ["CVE-2023-1", "CVE-2023-2"]


def test_payload_includes_missing_hardenings_when_enabled(mocker):
    """Hardening findings travel with the payload only when they were checked."""
    post = mocker.patch("check_nextcloud_security.requests.post")
    response = {
        **CRITICAL_RESPONSE,
        "hardenings": {"bruteforceProtection": False},
    }

    _run(ScanContext(host="test.com", webhook_url=WEBHOOK_URL), dict(response))
    assert post.call_args.kwargs["json"]["missing_hardenings"] == []

    _run(
        ScanContext(host="test.com", webhook_url=WEBHOOK_URL, check_hardening=True),
        dict(response),
    )
    assert post.call_args.kwargs["json"]["missing_hardenings"] == ["bruteforceProtection"]


def test_custom_headers_are_sent(mocker):
    """Extra headers (e.g. an auth token) are merged into the request."""
    post = mocker.patch("check_nextcloud_security.requests.post")
    context = ScanContext(
        host="test.com",
        webhook_url=WEBHOOK_URL,
        webhook_headers=(("X-Auth-Token", "s3cret"),),
    )

    _run(context, dict(CRITICAL_RESPONSE))

    headers = post.call_args.kwargs["headers"]
    assert headers["Content-Type"] == "application/json"
    assert headers["X-Auth-Token"] == "s3cret"


def test_webhook_uses_its_own_timeout(mocker):
    """The webhook timeout is independent of the Scan API timeout."""
    post = mocker.patch("check_nextcloud_security.requests.post")
    context = ScanContext(
        host="test.com", webhook_url=WEBHOOK_URL, timeout=10, webhook_timeout=3
    )

    _run(context, dict(CRITICAL_RESPONSE))

    assert post.call_args.kwargs["timeout"] == 3


def test_webhook_failure_does_not_change_the_exit_code(mocker, capsys):
    """A broken webhook is reported in the output but must not mask the result."""
    mocker.patch(
        "check_nextcloud_security.requests.post",
        side_effect=requests.exceptions.ConnectionError("no route to host"),
    )
    context = ScanContext(host="test.com", webhook_url=WEBHOOK_URL, retries=0)

    exit_code = _run(context, dict(CRITICAL_RESPONSE))

    out = capsys.readouterr().out
    assert exit_code == NagiosExitCode.CRITICAL
    assert "Webhook delivery failed" in out


def test_webhook_delivery_is_retried(mocker):
    """Transient webhook errors are retried with the configured retry budget."""
    post = mocker.patch("check_nextcloud_security.requests.post")
    post.return_value.raise_for_status.side_effect = [
        requests.exceptions.HTTPError("503"),
        None,
    ]
    context = ScanContext(
        host="test.com", webhook_url=WEBHOOK_URL, retries=2, backoff_factor=0
    )

    exit_code = _run(context, dict(CRITICAL_RESPONSE))

    assert exit_code == NagiosExitCode.CRITICAL
    assert post.call_count == 2


@pytest.mark.parametrize(
    "raw, expected",
    [
        (["X-Auth-Token: abc"], (("X-Auth-Token", "abc"),)),
        (["A:1", "B: 2"], (("A", "1"), ("B", "2"))),
        (["no-colon"], ()),
        ([": value"], ()),
        ([], ()),
    ],
)
def test_parse_webhook_headers(raw, expected):
    """Header strings are parsed leniently; malformed entries are dropped."""
    assert _parse_webhook_headers(raw) == expected


def test_parse_webhook_headers_falls_back_to_environment(monkeypatch):
    """CNS_WEBHOOK_HEADERS is used when no --webhook-header flag was given."""
    monkeypatch.setenv("CNS_WEBHOOK_HEADERS", "X-Auth-Token: abc; X-Env: prod")

    assert _parse_webhook_headers(None) == (("X-Auth-Token", "abc"), ("X-Env", "prod"))
