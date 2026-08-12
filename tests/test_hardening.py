"""Tests for the optional hardening / security-header evaluation."""
import pytest

from check_nextcloud_security import (
    NagiosExitCode,
    ScanContext,
    ScanResult,
    _collect_missing_hardenings,
    check_vulnerabilities,
)

WEAK_RESPONSE = {
    "rating": 5,
    "vulnerabilities": [],
    "domain": "test.com",
    "product": "Nextcloud",
    "version": "34.0.2.1",
    "scannedAt": {"date": "2026-01-01"},
    "hardenings": {"bruteforceProtection": False, "CSPv3": True},
    "setup": {
        "https": {"enforced": False, "used": True},
        "headers": {"X-Frame-Options": False, "X-Content-Type-Options": True},
    },
}

STRONG_RESPONSE = {
    **WEAK_RESPONSE,
    "hardenings": {"bruteforceProtection": True, "CSPv3": True},
    "setup": {
        "https": {"enforced": True, "used": True},
        "headers": {"X-Frame-Options": True, "X-Content-Type-Options": True},
    },
}


def _run(context: ScanContext, response: dict) -> int:
    """Run check_vulnerabilities and return its exit code."""
    with pytest.raises(SystemExit) as excinfo:
        check_vulnerabilities(context, ScanResult(response=response, uuid="uuid-test"))
    assert isinstance(excinfo.value.code, int)
    return excinfo.value.code


def test_collect_missing_hardenings_covers_all_sections():
    """Missing hardenings, unenforced HTTPS and absent headers are all reported."""
    missing = _collect_missing_hardenings(WEAK_RESPONSE)

    assert missing == ["bruteforceProtection", "httpsEnforced", "X-Frame-Options"]


def test_collect_missing_hardenings_tolerates_absent_sections():
    """A response without hardening information yields no findings."""
    assert _collect_missing_hardenings({"rating": 5}) == []


def test_hardening_findings_are_ignored_by_default(capsys):
    """Without --check-hardening a weakly configured but patched server is OK."""
    exit_code = _run(ScanContext(host="test.com"), dict(WEAK_RESPONSE))

    out = capsys.readouterr().out
    assert exit_code == NagiosExitCode.OK
    assert "Missing hardening" not in out
    assert "hardenings_missing" not in out


def test_hardening_findings_raise_ok_to_warning(capsys):
    """With --check-hardening, missing measures turn an OK result into WARNING."""
    context = ScanContext(host="test.com", check_hardening=True)

    exit_code = _run(context, dict(WEAK_RESPONSE))

    out = capsys.readouterr().out
    assert exit_code == NagiosExitCode.WARNING
    assert "3 hardening measure(s) missing" in out
    assert "bruteforceProtection" in out
    assert "httpsEnforced" in out
    assert "X-Frame-Options" in out
    assert "hardenings_missing=3;;;0;" in out


def test_hardening_findings_do_not_downgrade_a_critical_result(capsys):
    """A vulnerability-driven CRITICAL stays CRITICAL when hardening is checked."""
    context = ScanContext(host="test.com", check_hardening=True)
    response = {**WEAK_RESPONSE, "rating": 1, "vulnerabilities": [{"id": "CVE-2023-1"}]}

    exit_code = _run(context, response)

    out = capsys.readouterr().out
    assert exit_code == NagiosExitCode.CRITICAL
    assert out.startswith("CRITICAL: Found 1 vulnerabilities")
    assert "Missing hardening" in out


def test_fully_hardened_server_reports_success(capsys):
    """A server with every checked measure in place stays OK and says so."""
    context = ScanContext(host="test.com", check_hardening=True)

    exit_code = _run(context, dict(STRONG_RESPONSE))

    out = capsys.readouterr().out
    assert exit_code == NagiosExitCode.OK
    assert "Hardening: all checked measures in place" in out
    assert "hardenings_missing=0;;;0;" in out
