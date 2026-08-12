"""Tests for the advisory database and the updater server fallback."""

import json
from unittest.mock import MagicMock

from nextcloud_local_scan.scanner import ScannerSettings, _query_updater_server
from nextcloud_local_scan.vulndb import load_database

NATIVE_DB = {
    "advisories": [
        {
            "id": "NC-SA-EXAMPLE-1",
            "title": "Example flaw",
            "severity": "high",
            "introduced": "30.0.0",
            "fixed": "30.0.3",
        },
        {
            "id": "NC-SA-EXAMPLE-2",
            "title": "Disabled entry",
            "severity": "critical",
            "fixed": "99.0.0",
            "enabled": False,
        },
    ]
}

GITHUB_DB = [
    {
        "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
        "cve_id": "CVE-2026-0001",
        "summary": "Example GitHub advisory",
        "severity": "critical",
        "html_url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
        "cwes": [{"cwe_id": "CWE-79"}],
        "vulnerabilities": [
            {
                "package": {"ecosystem": "composer", "name": "nextcloud/server"},
                "vulnerable_version_range": ">= 30.0.0, < 30.0.4",
            }
        ],
    }
]


def _write(tmp_path, name, document):
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return str(path)


def test_native_advisories_match_the_version_range(tmp_path):
    """Advisories apply to [introduced, fixed) only."""
    database = load_database(extra_files=[_write(tmp_path, "db.json", NATIVE_DB)],
                             include_bundled=False)

    assert [advisory.id for advisory in database.matches("30.0.2.2")] == ["NC-SA-EXAMPLE-1"]
    assert database.matches("30.0.3.0") == []
    assert database.matches("29.0.9.0") == []


def test_disabled_advisories_are_skipped(tmp_path):
    """'enabled: false' entries document the schema without matching."""
    database = load_database(extra_files=[_write(tmp_path, "db.json", NATIVE_DB)],
                             include_bundled=False)

    assert all(advisory.id != "NC-SA-EXAMPLE-2" for advisory in database.advisories)


def test_github_advisory_format_is_understood(tmp_path):
    """A mirrored GitHub Advisory feed needs no conversion."""
    database = load_database(extra_files=[_write(tmp_path, "gh.json", GITHUB_DB)],
                             include_bundled=False)

    hits = database.matches("30.0.2.2")
    assert [advisory.id for advisory in hits] == ["CVE-2026-0001"]
    assert hits[0].severity == "critical"
    assert hits[0].fixed == "30.0.4"
    assert database.matches("30.0.4.0") == []


def test_bundled_database_is_loaded_by_default():
    """The shipped database is valid and never matches by accident."""
    database = load_database()

    assert database.sources
    assert database.matches("30.0.2.2") == []


def test_unreachable_feed_does_not_break_the_scan(mocker):
    """A feed error is logged, the local entries still provide a verdict."""
    mocker.patch(
        "nextcloud_local_scan.vulndb.requests.get", side_effect=OSError("no network")
    )

    database = load_database(feed_url="https://example.com/feed.json", include_bundled=True)

    assert database.matches("30.0.2.2") == []


def test_updater_server_response_is_parsed(mocker):
    """The updater server answer yields the newest version and the EOL flag."""
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.text = (
        '<?xml version="1.0"?><owncloud><version>30.0.4.0</version>'
        "<versionstring>Nextcloud 30.0.4</versionstring><eol>1</eol></owncloud>"
    )
    mocker.patch("nextcloud_local_scan.scanner.requests.get", return_value=response)

    result = _query_updater_server("30.0.2.2", ScannerSettings())

    assert result == {"available": True, "eol": True, "available_version": "30.0.4.0"}


def test_updater_server_error_means_up_to_date(mocker):
    """'No more content available' is the answer for a current release."""
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.text = "<?xml version='1.0'?><owncloud><error>No more content available.</error></owncloud>"
    mocker.patch("nextcloud_local_scan.scanner.requests.get", return_value=response)

    assert _query_updater_server("30.0.4.0", ScannerSettings()) == {"available": False}
