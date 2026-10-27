#!/usr/bin/env python3
"""Refresh the list of supported Nextcloud major releases.

Reads the "Currently supported versions" table from Nextcloud's public
maintenance and release schedule and writes the major version codes to
``nextcloud_local_scan/data/supported_versions.json``.

The local scanner uses that file to decide whether an instance is end of life:
anything below the oldest supported major release no longer receives security
fixes and is rated F, exactly as scan.nextcloud.com reports it.

The script is run by the release workflow, but works standalone:

    python scripts/update_supported_versions.py            # fetch and write
    python scripts/update_supported_versions.py --check    # fail if outdated
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET = REPO_ROOT / "nextcloud_local_scan" / "data" / "supported_versions.json"

SCHEDULE_URL = "https://github.com/nextcloud/server/wiki/Maintenance-and-Release-Schedule"
HEADING = "currently supported versions"
USER_AGENT = "check-nextcloud-security/supported-versions"

# A plausibility window; the wiki has listed three supported branches for years.
MIN_BRANCHES = 2
MAX_BRANCHES = 6
# Guards against a mangled page yielding nonsense like "1" or "2026".
MIN_MAJOR = 10
MAX_MAJOR = 200


class ExtractionError(RuntimeError):
    """The schedule page could not be parsed."""


def fetch(url: str, timeout: int = 30) -> str:
    """Download the schedule page."""
    if not url.startswith(("http://", "https://")):
        raise ExtractionError(f"Refusing to fetch a non-HTTP URL: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310 - scheme validated above
        charset = response.headers.get_content_charset() or "utf-8"
        return str(response.read().decode(charset, errors="replace"))


def _strip_tags(markup: str) -> str:
    """Reduce a table cell to its text."""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", markup)).strip()


def extract_versions(html: str) -> list[int]:
    """
    Return the supported major versions, newest first.

    Only the first table after the "Currently supported versions" heading is
    considered; its first column holds the major version code.
    """
    position = html.lower().find(HEADING)
    if position < 0:
        raise ExtractionError(f"Heading {HEADING!r} not found on the schedule page")

    table = re.search(r"<table.*?</table>", html[position:], re.DOTALL | re.IGNORECASE)
    if table is None:
        raise ExtractionError("No table found below the 'Currently supported versions' heading")

    versions: list[int] = []
    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", table.group(0), re.DOTALL | re.IGNORECASE):
        cells = re.findall(r"<t[hd][^>]*>(.*?)</t[hd]>", row, re.DOTALL | re.IGNORECASE)
        if not cells:
            continue
        first = _strip_tags(cells[0])
        if not re.fullmatch(r"\d+", first):
            continue  # header row, or a footnote
        major = int(first)
        if MIN_MAJOR <= major <= MAX_MAJOR and major not in versions:
            versions.append(major)

    if not MIN_BRANCHES <= len(versions) <= MAX_BRANCHES:
        raise ExtractionError(
            f"Found {len(versions)} supported versions ({versions}), "
            f"expected between {MIN_BRANCHES} and {MAX_BRANCHES} - "
            "the page layout has probably changed"
        )
    return sorted(versions, reverse=True)


def build_document(versions: list[int], source: str) -> dict[str, Any]:
    """Assemble the JSON document written to disk."""
    return {
        "_comment": (
            "Supported Nextcloud major releases, extracted from the official "
            "maintenance and release schedule. Every major version below "
            "'oldest_supported' is treated as end of life (rating F) by the "
            "local scanner. Regenerate with scripts/update_supported_versions.py."
        ),
        "source": source,
        "updated": datetime.now(tz=UTC).date().isoformat(),
        "supported": versions,
        "oldest_supported": min(versions),
    }


def load_current() -> dict[str, Any] | None:
    """Read the file that is currently checked in, if any."""
    if not TARGET.exists():
        return None
    try:
        loaded = json.loads(TARGET.read_text(encoding="utf-8"))
    except ValueError:
        return None
    return loaded if isinstance(loaded, dict) else None


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(description="Update the supported Nextcloud versions.")
    parser.add_argument("--url", default=SCHEDULE_URL, help="Schedule page to read.")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Only report whether the file is up to date; write nothing.",
    )
    parser.add_argument(
        "--allow-failure",
        action="store_true",
        help="Exit successfully when the page cannot be read or parsed.",
    )
    args = parser.parse_args(argv)

    try:
        versions = extract_versions(fetch(args.url, timeout=args.timeout))
    except (ExtractionError, urllib.error.URLError, OSError) as exc:
        print(f"Could not determine the supported versions: {exc}", file=sys.stderr)
        # A release must not fail because a wiki page moved; the file that is
        # checked in stays in place and the scanner keeps using it.
        return 0 if args.allow_failure else 1

    current = load_current()
    unchanged = current is not None and current.get("supported") == versions
    if unchanged:
        print(f"Supported versions unchanged: {versions}")
        return 0

    previous = current.get("supported") if current else None
    if args.check:
        print(f"Outdated: file has {previous}, schedule says {versions}", file=sys.stderr)
        return 1

    TARGET.write_text(
        json.dumps(build_document(versions, args.url), indent=2) + "\n", encoding="utf-8"
    )
    print(f"Updated supported versions: {previous} -> {versions}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
