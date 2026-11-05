from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def load_module() -> ModuleType:
    path = REPO_ROOT / "scripts" / "release_notes.py"
    spec = importlib.util.spec_from_file_location("release_notes", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHANGELOG_TEXT = """# Changelog

## [2.0.0] - 2026-01-01

### Fixed

- Something.

## [1.0.0] - 2025-06-01

### Added

- First release.
"""


@pytest.fixture
def notes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    module = load_module()
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(CHANGELOG_TEXT, encoding="utf-8")
    monkeypatch.setattr(module, "CHANGELOG", changelog)
    monkeypatch.setattr(module, "RELEASE", tmp_path / "RELEASE.md")
    return module


def test_refresh_date_updates_only_the_given_version(notes: ModuleType) -> None:
    assert notes.main(["--version", "2.0.0", "--date", "2026-02-03", "--refresh-date"]) == 0
    text = notes.CHANGELOG.read_text(encoding="utf-8")
    assert "## [2.0.0] - 2026-02-03" in text
    assert "## [1.0.0] - 2025-06-01" in text
    assert notes.RELEASE.read_text(encoding="utf-8").startswith(
        "## check-nextcloud-security 2.0.0\n\n### Fixed\n\n- Something.\n"
    )


def test_date_is_kept_without_refresh_date(notes: ModuleType) -> None:
    assert notes.main(["--version", "2.0.0", "--date", "2026-02-03"]) == 0
    assert "## [2.0.0] - 2026-01-01" in notes.CHANGELOG.read_text(encoding="utf-8")


def test_refresh_date_is_a_no_op_for_the_same_day(notes: ModuleType) -> None:
    assert notes.refresh_date("2.0.0", "2026-01-01") is False
    assert notes.CHANGELOG.read_text(encoding="utf-8") == CHANGELOG_TEXT
