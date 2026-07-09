import pytest

from check_nextcloud_security import _build_perfdata, check_vulnerabilities, ScanContext, ScanResult

RATE_MAP = {5: "A+", 4: "A", 3: "C", 2: "D", 1: "E", 0: "F"}


@pytest.mark.parametrize(
    "rating, num_vulns, duration_seconds, expected_fragments",
    [
        (5, 0, 1.234, ["rating=5;;;0;5", "vulnerabilities=0;;;0;", "time=1.234s;;;0;"]),
        (0, 3, None, ["rating=0;;;0;5", "vulnerabilities=3;;;0;"]),
        (99, 0, None, ["rating=U;;;0;5", "vulnerabilities=0;;;0;"]),
    ],
)
def test_build_perfdata_formats_expected_fields(
    rating, num_vulns, duration_seconds, expected_fragments
):
    """
    Test that _build_perfdata renders rating, vulnerability count, and
    (when available) scan duration in standard Nagios perfdata syntax.
    """
    perfdata = _build_perfdata(rating, RATE_MAP, num_vulns, duration_seconds)

    for fragment in expected_fragments:
        assert fragment in perfdata

    if duration_seconds is None:
        assert "time=" not in perfdata


def test_check_vulnerabilities_output_includes_perfdata_after_pipe(capsys):
    """
    Test that check_vulnerabilities appends a '|'-delimited performance
    data section to its output, as required by the Nagios plugin API.
    """
    context = ScanContext(host="test.com")
    response_scan = {
        "rating": 5,
        "vulnerabilities": [],
        "product": "Nextcloud",
        "version": "29.0",
        "domain": "test.com",
        "scannedAt": {"date": "2025-01-01"},
    }
    result = ScanResult(response=response_scan, uuid="uuid-test")

    with pytest.raises(SystemExit):
        check_vulnerabilities(context, result, duration_seconds=0.5)

    out = capsys.readouterr().out
    assert "|" in out
    perfdata = out.split("|", 1)[1]
    assert "rating=5;;;0;5" in perfdata
    assert "vulnerabilities=0;;;0;" in perfdata
    assert "time=0.500s;;;0;" in perfdata


def test_check_vulnerabilities_output_omits_time_when_duration_not_provided(capsys):
    """
    Test that the 'time' perfdata metric is omitted when no duration was
    measured (e.g. when check_vulnerabilities is called without timing info).
    """
    context = ScanContext(host="test.com")
    response_scan = {
        "rating": 5,
        "vulnerabilities": [],
        "product": "Nextcloud",
        "version": "29.0",
        "domain": "test.com",
        "scannedAt": {"date": "2025-01-01"},
    }
    result = ScanResult(response=response_scan, uuid="uuid-test")

    with pytest.raises(SystemExit):
        check_vulnerabilities(context, result)

    out = capsys.readouterr().out
    assert "time=" not in out
