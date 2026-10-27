#!/usr/bin/env python3
"""Maintain CHANGELOG.md and RELEASE.md for a release.

The version is read from ``pyproject.toml``. Whenever it changes, the release
workflow calls this script to

* write ``RELEASE.md`` (overwritten on every release) with the notes of the
  version being released, and
* prepend that same entry to ``CHANGELOG.md`` (older releases are kept).

If ``CHANGELOG.md`` already contains a section for the version, that section is
reused verbatim - hand-written notes always win over generated ones. Otherwise
the notes are generated from the commit subjects since the previous tag,
grouped by their Conventional Commit type.
"""

from __future__ import annotations

import argparse
import re
import subprocess  # nosec B404 - fixed argv, no shell
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
RELEASE = REPO_ROOT / "RELEASE.md"

CHANGELOG_HEADER = """# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
"""

# Conventional Commit type -> Keep a Changelog section.
SECTIONS: dict[str, str] = {
    "feat": "Added",
    "change": "Changed",
    "refactor": "Changed",
    "perf": "Changed",
    "deprecate": "Deprecated",
    "remove": "Removed",
    "revert": "Removed",
    "fix": "Fixed",
    "security": "Security",
    "docs": "Documentation",
}
SECTION_ORDER = [
    "Added",
    "Changed",
    "Deprecated",
    "Removed",
    "Fixed",
    "Security",
    "Documentation",
]
# Commit types that are noise in a changelog.
IGNORED_TYPES = {"chore", "ci", "build", "test", "style"}

COMMIT_RE = re.compile(
    r"^(?P<type>[a-z]+)(?:\((?P<scope>[^)]*)\))?(?P<breaking>!)?:\s*(?P<text>.+)$"
)


def run_git(*args: str) -> str:
    """Run a git command inside the repository and return its stdout."""
    result = subprocess.run(  # nosec B603 B607 - fixed argv, no shell, git from PATH
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def project_version() -> str:
    """Read the current version from pyproject.toml."""
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def previous_tag(version: str) -> str | None:
    """Return the most recent tag that is not the tag of this release."""
    tags = run_git("tag", "--sort=-creatordate").splitlines()
    for tag in tags:
        if tag.strip() and tag.strip() != f"v{version}":
            return tag.strip()
    return None


def section_of(commit_type: str, breaking: bool) -> str | None:
    """Map a Conventional Commit type onto a changelog section."""
    if breaking:
        return "Changed"
    if commit_type in IGNORED_TYPES:
        return None
    return SECTIONS.get(commit_type, "Changed")


def collect_commits(since: str | None) -> dict[str, list[str]]:
    """Group commit subjects since ``since`` into changelog sections."""
    revision = f"{since}..HEAD" if since else "HEAD"
    log = run_git("log", revision, "--no-merges", "--pretty=format:%s")
    grouped: dict[str, list[str]] = {}
    for line in log.splitlines():
        subject = line.strip()
        if not subject:
            continue
        match = COMMIT_RE.match(subject)
        if match:
            section = section_of(match.group("type"), bool(match.group("breaking")))
            if section is None:
                continue
            scope = match.group("scope")
            text = match.group("text").strip()
            entry = f"**{scope}:** {text}" if scope else text
            if match.group("breaking"):
                entry = f"**Breaking:** {entry}"
        else:
            section = "Changed"
            entry = subject
        entry = entry[0].upper() + entry[1:]
        grouped.setdefault(section, []).append(entry)
    return grouped


def generate_body(since: str | None) -> str:
    """Render the changelog body for the commits since ``since``."""
    grouped = collect_commits(since)
    if not grouped:
        return "### Changed\n\n- Maintenance release without documented changes.\n"
    parts: list[str] = []
    for section in SECTION_ORDER:
        entries = grouped.get(section)
        if not entries:
            continue
        unique = list(dict.fromkeys(entries))
        body = "\n".join(f"- {entry}" for entry in unique)
        parts.append(f"### {section}\n\n{body}\n")
    return "\n".join(parts)


def existing_entry(version: str) -> str | None:
    """Return the body of an already documented changelog section, if any."""
    if not CHANGELOG.exists():
        return None
    text = CHANGELOG.read_text(encoding="utf-8")
    pattern = re.compile(
        rf"^## \[{re.escape(version)}\][^\n]*\n(?P<body>.*?)(?=^## \[|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(text)
    if match is None:
        return None
    return match.group("body").strip("\n")


def prepend_changelog(version: str, released: str, body: str) -> None:
    """Insert a new version section directly below the changelog header."""
    entry = f"## [{version}] - {released}\n\n{body.rstrip()}\n"
    if not CHANGELOG.exists():
        CHANGELOG.write_text(f"{CHANGELOG_HEADER}\n{entry}", encoding="utf-8")
        return
    text = CHANGELOG.read_text(encoding="utf-8")
    marker = re.search(r"^## \[", text, re.MULTILINE)
    if marker is None:
        CHANGELOG.write_text(f"{text.rstrip()}\n\n{entry}", encoding="utf-8")
        return
    head = text[: marker.start()].rstrip("\n")
    tail = text[marker.start() :]
    CHANGELOG.write_text(f"{head}\n\n{entry}\n{tail}", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    """Entry point for the release workflow."""
    parser = argparse.ArgumentParser(description="Update CHANGELOG.md and RELEASE.md.")
    parser.add_argument("--version", default=None, help="Version to document. Default: pyproject.toml.")
    parser.add_argument("--previous-tag", default=None, help="Tag to compare against. Default: latest tag.")
    parser.add_argument("--date", default=None, help="Release date. Default: today (UTC).")
    args = parser.parse_args(argv)

    version = args.version or project_version()
    released = args.date or datetime.now(tz=UTC).date().isoformat()

    body = existing_entry(version)
    reused = body is not None
    if body is None:
        since = args.previous_tag or previous_tag(version)
        body = generate_body(since)
        prepend_changelog(version, released, body)

    RELEASE.write_text(
        f"## check-nextcloud-security {version}\n\n{body.rstrip()}\n", encoding="utf-8"
    )
    print(f"{'Reused' if reused else 'Generated'} release notes for {version}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
