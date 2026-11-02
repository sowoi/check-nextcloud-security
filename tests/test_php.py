"""Tests for the PHP version assessment (e.g. PHP2Shell, CVE-2026-109618/109619)."""

from datetime import date

import pytest

from check_nextcloud_security import ScanContext, ScanResult, check_vulnerabilities
from nextcloud_local_scan.php import (
    STATUS_EOL,
    STATUS_OK,
    STATUS_UNKNOWN,
    STATUS_VENDOR_BUILD,
    STATUS_VULNERABLE,
    assess_php_version,
    load_php_advisories,
    parse_php_version,
)

TODAY = date(2026, 11, 2)


def _assess(version, source="api", **kwargs):
    return assess_php_version(version, source, today=TODAY, **kwargs)


@pytest.mark.parametrize(
    "version, status",
    [
        ("8.2.34", STATUS_VULNERABLE),
        ("8.2.35", STATUS_OK),
        ("8.3.35", STATUS_VULNERABLE),
        ("8.3.36", STATUS_OK),
        ("8.3.40", STATUS_OK),
        ("8.4.26", STATUS_VULNERABLE),
        ("8.4.27", STATUS_OK),
        ("8.5.11", STATUS_VULNERABLE),
        ("8.5.12", STATUS_OK),
        ("8.6.0", STATUS_OK),
    ],
)
def test_php2shell_boundaries(version, status):
    """Every version below the first fixed release of its branch is affected."""
    assessment = _assess(version)

    assert assessment.status == status
    if status == STATUS_VULNERABLE:
        assert assessment.advisories[0].id == "PHP2Shell"
        assert "CVE-2026-109618" in assessment.advisories[0].cves


def test_bundled_data_lists_the_php2shell_fixes():
    """Guard against accidental edits of the curated fix table."""
    advisory = next(a for a in load_php_advisories()["advisories"] if a["id"] == "PHP2Shell")

    assert advisory["fixed"] == {
        "8.2": "8.2.35",
        "8.3": "8.3.36",
        "8.4": "8.4.27",
        "8.5": "8.5.12",
    }


def test_old_branch_without_upstream_fix_is_vulnerable_and_eol():
    """PHP 8.1 got no release: affected, no fixed version, end of life."""
    assessment = _assess("8.1.31")

    assert assessment.status == STATUS_VULNERABLE
    assert assessment.advisories[0].fixed_version is None
    assert assessment.eol is True
    assert "no upstream fix" in assessment.summary()


def test_branch_older_than_the_eol_table_is_eol():
    assessment = _assess("7.3.33")

    assert assessment.eol is True


def test_patched_but_eol_branch_reports_eol():
    """A fixed 8.2 is EOL once its end-of-life date has passed."""
    assessment = assess_php_version("8.2.35", "api", today=date(2027, 1, 15))

    assert assessment.status == STATUS_EOL
    assert assessment.advisories == []


def test_distribution_build_is_reported_as_vendor_build():
    """Debian/Ubuntu builds may carry a backport the version does not show."""
    assessment = _assess("8.1.2-1ubuntu2.14", source="cli")

    assert assessment.status == STATUS_VENDOR_BUILD
    assert "--php-ignore" in (assessment.hint or "")


def test_pre_release_is_not_a_vendor_build():
    assert parse_php_version("8.4.0RC1").is_vendor_build is False
    assert parse_php_version("8.2.7-1~deb12u1").is_vendor_build is True


@pytest.mark.parametrize("ignore", [["PHP2Shell"], ["php2shell"], ["CVE-2026-109619"]])
def test_acknowledged_advisory_is_ignored(ignore):
    assessment = _assess("8.3.12", ignore=ignore)

    assert assessment.status == STATUS_OK
    assert assessment.ignored == ["PHP2Shell"]
    assert "acknowledged" in assessment.summary()


@pytest.mark.parametrize("raw", [None, "", "unknown", "eight"])
def test_unknown_version(raw):
    assessment = _assess(raw)

    assert assessment.status == STATUS_UNKNOWN
    assert "not available" in assessment.summary()


def test_cli_source_adds_fpm_hint():
    """The CLI may differ from PHP-FPM, which is what the attack targets."""
    assessment = _assess("8.3.36", source="cli")

    assert assessment.status == STATUS_OK
    assert "PHP-FPM" in (assessment.hint or "")


# --- integration with the plugin state --------------------------------------


def _run(response_scan, capsys, **context_kwargs):
    response_scan = {
        "product": "Nextcloud",
        "version": "31.0.9",
        "domain": "test.com",
        "vulnerabilities": [],
        "scannedAt": {"date": "now"},
        **response_scan,
    }
    context = ScanContext(host="test.com", **context_kwargs)
    with pytest.raises(SystemExit) as exc:
        check_vulnerabilities(context, ScanResult(response=response_scan, uuid="u"))
    return exc.value.code, capsys.readouterr().out


def _updates(php_version, php_source="api"):
    return {
        "available": False,
        "source": "api",
        "phpVersion": php_version,
        "phpSource": php_source,
    }


def test_vulnerable_php_turns_ok_into_critical(capsys):
    code, out = _run({"rating": 5, "updates": _updates("8.3.12")}, capsys)

    assert code == 2
    assert out.startswith("CRITICAL: PHP 8.3.12 is affected by PHP2Shell")
    assert "fixed in 8.3.36" in out
    assert "php_advisories=1;;;0;" in out


def test_vulnerable_php_escalates_warning_to_critical(capsys):
    code, out = _run(
        {"rating": 3, "vulnerabilities": [{"id": 1}], "updates": _updates("8.4.20")}, capsys
    )

    assert code == 2
    assert "PHP2Shell" in out.splitlines()[0]


def test_vulnerable_php_keeps_an_existing_critical_message(capsys):
    code, out = _run({"rating": 0, "updates": _updates("8.4.20")}, capsys)

    assert code == 2
    assert out.startswith("CRITICAL: This server version is end-of-life")
    assert "affected by PHP2Shell" in out


def test_vendor_build_raises_ok_to_warning_only(capsys):
    code, out = _run({"rating": 5, "updates": _updates("8.1.2-1ubuntu2.14", "cli")}, capsys)

    assert code == 1
    assert out.startswith("WARNING: PHP 8.1.2-1ubuntu2.14 may be affected")


def test_patched_php_leaves_ok_alone(capsys):
    code, out = _run({"rating": 5, "updates": _updates("8.5.12")}, capsys)

    assert code == 0
    assert "PHP 8.5.12 via api, no known critical PHP advisory" in out
    assert "php_advisories=0" in out


def test_missing_php_version_is_stated_but_harmless(capsys):
    """Older scanner containers do not send phpVersion: unknown, not OK."""
    code, out = _run({"rating": 5, "updates": {"available": False, "source": "api"}}, capsys)

    assert code == 0
    assert "PHP check: version not available" in out
    assert "php_advisories" not in out


def test_php_ignore_and_no_php_check(capsys):
    code, out = _run(
        {"rating": 5, "updates": _updates("8.5.3")}, capsys, php_ignore=("PHP2Shell",)
    )
    assert code == 0
    assert "acknowledged: PHP2Shell" in out

    code, out = _run({"rating": 5, "updates": _updates("8.5.3")}, capsys, php_check=False)
    assert code == 0
    assert "PHP" not in out
