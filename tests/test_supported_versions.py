"""Tests for the release schedule that drives the end-of-life rating."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from nextcloud_local_scan.versions import (
    SUPPORTED_VERSIONS_FILE,
    is_end_of_life,
    load_supported_majors,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_script():
    """Import the release script, which lives outside the installed package."""
    path = REPO_ROOT / "scripts" / "update_supported_versions.py"
    spec = importlib.util.spec_from_file_location("update_supported_versions", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SCHEDULE_HTML = """
<h2>Currently supported versions</h2>
<table>
  <tr><th>Version code</th><th>Version name</th><th>Release date</th><th>End of life</th></tr>
  <tr><td>34</td><td>Hub 26 Spring</td><td>2026-06-09</td><td>2027-06</td></tr>
  <tr><td>33</td><td>Hub 25</td><td>2026-02-17</td><td>2027-02</td></tr>
  <tr><td>32</td><td>Hub 24</td><td>2025-09-16</td><td>2026-09</td></tr>
</table>
<h2>Previous versions</h2>
<table>
  <tr><th>Version code</th></tr>
  <tr><td>31</td></tr>
</table>
"""


def test_the_supported_versions_are_read_from_the_first_table():
    """Only the table below the 'Currently supported versions' heading counts."""
    script = _load_script()

    assert script.extract_versions(SCHEDULE_HTML) == [34, 33, 32]


def test_a_changed_page_layout_is_rejected():
    """Rather than write nonsense, the script fails loudly."""
    script = _load_script()

    with pytest.raises(script.ExtractionError):
        script.extract_versions("<h2>Release schedule</h2><table></table>")


def test_the_bundled_file_lists_supported_majors():
    """The file shipped with the package is present and plausible."""
    document = json.loads(SUPPORTED_VERSIONS_FILE.read_text(encoding="utf-8"))

    assert document["supported"] == load_supported_majors()
    assert document["oldest_supported"] == min(document["supported"])
    assert load_supported_majors() == sorted(load_supported_majors(), reverse=True)


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("29.0.2.2", True),
        ("31.0.9", True),
        ("32.0.0", False),
        ("34.0.1", False),
        # A build newer than anything on the schedule is not end of life.
        ("35.0.0", False),
    ],
)
def test_end_of_life_is_decided_by_the_major_release(version, expected):
    """Everything below the oldest supported major release is out of support."""
    assert is_end_of_life(version, supported=[34, 33, 32]) is expected


def test_an_unknown_version_or_missing_schedule_is_not_a_verdict():
    """Without data the scanner must not claim an instance is end of life."""
    assert is_end_of_life(None, supported=[34, 33, 32]) is None
    assert is_end_of_life("32.0.0", supported=[]) is None


def test_a_missing_schedule_file_yields_no_versions(tmp_path):
    """A stripped-down installation degrades instead of crashing."""
    assert load_supported_majors(tmp_path / "absent.json") == []


def test_owncloud_is_not_measured_against_the_nextcloud_schedule():
    """ownCloud versions its releases independently of Nextcloud."""
    from nextcloud_local_scan.versions import derive_hardenings

    assert derive_hardenings("10.11.0.0", "Infinite Scale") == {}
    assert derive_hardenings("30.0.2.2", "Nextcloud") != {}
