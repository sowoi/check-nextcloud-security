"""Tests for the rating threshold logic and the states it produces."""
import pytest

from check_nextcloud_security import (
    NagiosExitCode,
    ScanContext,
    ScanResult,
    check_vulnerabilities,
)


def _run(context: ScanContext, response: dict) -> tuple[int, str]:
    """Run check_vulnerabilities and return its exit code and output."""
    response.setdefault("scannedAt", {"date": "Unknown"})
    with pytest.raises(SystemExit) as excinfo:
        check_vulnerabilities(context, ScanResult(response=response, uuid="uuid-test"))
    assert isinstance(excinfo.value.code, int)
    return excinfo.value.code, ""


@pytest.mark.parametrize(
    "rating, expected_exit",
    [
        (5, NagiosExitCode.OK),
        (4, NagiosExitCode.OK),
        (3, NagiosExitCode.WARNING),
        (2, NagiosExitCode.WARNING),
        (1, NagiosExitCode.CRITICAL),
        (0, NagiosExitCode.CRITICAL),
    ],
)
def test_poor_rating_without_vulnerabilities_is_not_unknown(rating, expected_exit, capsys):
    """
    A poor rating must map to WARNING/CRITICAL even when the API lists no
    individual vulnerabilities. Previously these ratings fell through to
    'UNKNOWN: Scan result unclear'.
    """
    context = ScanContext(host="test.com")
    response = {"rating": rating, "vulnerabilities": [], "domain": "test.com"}

    exit_code, _ = _run(context, response)

    assert exit_code == expected_exit
    assert "Scan result unclear" not in capsys.readouterr().out


@pytest.mark.parametrize("rating", [5, 4])
def test_good_rating_with_vulnerabilities_warns(rating, capsys):
    """
    Vulnerabilities always raise the state to at least WARNING, even when the
    overall rating still looks acceptable.
    """
    context = ScanContext(host="test.com")
    response = {"rating": rating, "vulnerabilities": [{"id": "CVE-2024-1"}], "domain": "test.com"}

    exit_code, _ = _run(context, response)

    assert exit_code == NagiosExitCode.WARNING
    assert "Found 1 vulnerabilities" in capsys.readouterr().out


def test_custom_thresholds_tighten_the_check(capsys):
    """Raising the thresholds turns an otherwise OK rating into CRITICAL."""
    context = ScanContext(host="test.com", warning_rating=5, critical_rating=4)
    response = {"rating": 4, "vulnerabilities": [], "domain": "test.com"}

    exit_code, _ = _run(context, response)

    assert exit_code == NagiosExitCode.CRITICAL
    assert "critical threshold" in capsys.readouterr().out


def test_custom_thresholds_relax_the_check(capsys):
    """Lowering the thresholds accepts a rating that would otherwise warn."""
    context = ScanContext(host="test.com", warning_rating=1, critical_rating=0)
    response = {"rating": 2, "vulnerabilities": [], "domain": "test.com"}

    exit_code, _ = _run(context, response)

    assert exit_code == NagiosExitCode.OK


def test_eol_flag_is_critical_even_with_acceptable_rating(capsys):
    """An explicit EOL flag outweighs an otherwise acceptable rating."""
    context = ScanContext(host="test.com")
    response = {"rating": 4, "vulnerabilities": [], "domain": "test.com", "EOL": True}

    exit_code, _ = _run(context, response)

    assert exit_code == NagiosExitCode.CRITICAL
    assert "end-of-life" in capsys.readouterr().out


def test_unknown_rating_stays_unknown(capsys):
    """A rating outside the documented 0-5 range is reported as UNKNOWN."""
    context = ScanContext(host="test.com")

    exit_code, _ = _run(context, {"rating": 99, "domain": "test.com"})

    assert exit_code == NagiosExitCode.UNKNOWN
    assert "Scan result unclear" in capsys.readouterr().out


def test_vulnerability_identifiers_are_listed(capsys):
    """The output names the reported vulnerabilities so operators can triage."""
    context = ScanContext(host="test.com")
    response = {
        "rating": 1,
        "domain": "test.com",
        "vulnerabilities": [{"id": "CVE-2023-1"}, {"id": "CVE-2023-2"}],
    }

    _run(context, response)

    out = capsys.readouterr().out
    assert "CVE-2023-1" in out
    assert "CVE-2023-2" in out


def test_long_vulnerability_list_is_truncated(capsys):
    """Only the first few identifiers are printed to keep the output readable."""
    context = ScanContext(host="test.com")
    response = {
        "rating": 1,
        "domain": "test.com",
        "vulnerabilities": [{"id": f"CVE-2023-{index}"} for index in range(8)],
    }

    _run(context, response)

    assert "(+3 more)" in capsys.readouterr().out
