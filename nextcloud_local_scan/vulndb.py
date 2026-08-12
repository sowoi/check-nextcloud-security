"""
Advisory database used by the local scanner.

Three sources are merged, all of them optional:

* the advisory file bundled with this package,
* a user supplied JSON file (``--vulnerability-db`` / ``scanner.vulnerability_db``),
* a remote JSON feed (``--vulnerability-feed`` / ``scanner.vulnerability_feed``).

Both the native format (``{"advisories": [...]}``) and the GitHub Advisory
API format (a list of objects carrying ``ghsa_id`` and ``vulnerabilities``)
are understood, so an air-gapped installation can mirror the GitHub feed to a
file without any conversion.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

from .versions import is_in_range

LOGGER = logging.getLogger("check_nextcloud.vulndb")

BUNDLED_DB = Path(__file__).with_name("data") / "vulnerabilities.json"

# Range expressions used by the GitHub Advisory API, e.g. ">= 28.0.0, < 28.0.4".
_RANGE_PART = re.compile(r"(>=|<=|>|<|=)\s*([0-9][0-9.]*)")

SEVERITY_ORDER = {"low": 1, "moderate": 2, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Advisory:
    """A single known vulnerability affecting a range of Nextcloud releases."""

    id: str
    title: str = ""
    description: str = ""
    severity: str = "unknown"
    url: str = ""
    cwe: str = ""
    introduced: str | None = None
    fixed: str | None = None

    def affects(self, version: str | None) -> bool:
        """Return True when the advisory applies to the given version."""
        return is_in_range(version, self.introduced, self.fixed)

    def as_dict(self) -> dict[str, Any]:
        """Render the advisory the way the Scan API lists vulnerabilities."""
        return {
            "id": self.id,
            "cwe": self.cwe,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "url": self.url,
            "fixedIn": self.fixed,
        }


def _parse_range(expression: str | None) -> tuple[str | None, str | None]:
    """Translate a GitHub version range expression into (introduced, fixed)."""
    if not expression:
        return None, None
    introduced: str | None = None
    fixed: str | None = None
    for operator, version in _RANGE_PART.findall(expression):
        if operator in {">=", ">"}:
            introduced = version
        elif operator == "<":
            fixed = version
        elif operator == "<=":
            # Inclusive upper bound: treat the next patch level as fixed.
            parts = version.split(".")
            parts[-1] = str(int(parts[-1]) + 1) if parts[-1].isdigit() else parts[-1]
            fixed = ".".join(parts)
        elif operator == "=":
            introduced = version
            fixed = version + ".1"
    return introduced, fixed


def _from_github(entry: dict[str, Any]) -> Advisory | None:
    """Convert a GitHub Advisory API record into an Advisory."""
    identifier = entry.get("cve_id") or entry.get("ghsa_id")
    if not identifier:
        return None

    introduced: str | None = None
    fixed: str | None = None
    for affected in entry.get("vulnerabilities") or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package") or {}
        name = str(package.get("name", "")).lower()
        if name and "nextcloud" not in name:
            continue
        introduced, fixed = _parse_range(affected.get("vulnerable_version_range"))
        if not fixed:
            fixed = affected.get("first_patched_version") or fixed
        break
    else:
        return None

    return Advisory(
        id=str(identifier),
        title=str(entry.get("summary") or ""),
        description=str(entry.get("description") or "")[:500],
        severity=str(entry.get("severity") or "unknown").lower(),
        url=str(entry.get("html_url") or ""),
        cwe=",".join(
            str(item.get("cwe_id"))
            for item in (entry.get("cwes") or [])
            if isinstance(item, dict) and item.get("cwe_id")
        ),
        introduced=introduced,
        fixed=fixed,
    )


def _from_native(entry: dict[str, Any]) -> Advisory | None:
    """Convert a native advisory record into an Advisory."""
    identifier = entry.get("id")
    if not identifier or entry.get("enabled") is False:
        return None
    return Advisory(
        id=str(identifier),
        title=str(entry.get("title") or ""),
        description=str(entry.get("description") or ""),
        severity=str(entry.get("severity") or "unknown").lower(),
        url=str(entry.get("url") or ""),
        cwe=str(entry.get("cwe") or ""),
        introduced=entry.get("introduced"),
        fixed=entry.get("fixed"),
    )


def _parse_document(document: Any) -> list[Advisory]:
    """Parse either advisory format into a list of advisories."""
    if isinstance(document, dict):
        records = document.get("advisories")
        if records is None:
            records = document.get("data") or []
    else:
        records = document

    advisories: list[Advisory] = []
    for record in records or []:
        if not isinstance(record, dict):
            continue
        advisory = _from_github(record) if "ghsa_id" in record else _from_native(record)
        if advisory is not None:
            advisories.append(advisory)
    return advisories


@dataclass
class VulnerabilityDatabase:
    """Merged advisory database with version matching."""

    advisories: list[Advisory]
    sources: list[str]

    def matches(self, version: str | None) -> list[Advisory]:
        """Return every advisory affecting the given version, worst first."""
        hits = [advisory for advisory in self.advisories if advisory.affects(version)]
        return sorted(
            hits,
            key=lambda advisory: (-SEVERITY_ORDER.get(advisory.severity, 0), advisory.id),
        )

    def worst_severity(self, version: str | None) -> str | None:
        """Return the highest severity affecting the given version."""
        hits = self.matches(version)
        return hits[0].severity if hits else None


def _load_file(path: Path) -> list[Advisory]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        LOGGER.warning("Ignoring advisory file %s: %s", path, exc)
        return []
    return _parse_document(document)


def _load_feed(url: str, timeout: int, verify: bool, proxies: dict[str, str] | None) -> list[Advisory]:
    try:
        response = requests.get(
            url,
            timeout=timeout,
            verify=verify,
            proxies=proxies,
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        document = response.json()
    except (requests.exceptions.RequestException, OSError, ValueError) as exc:
        # A stale or unreachable feed must never turn a healthy instance into
        # an UNKNOWN result: the local database still provides a verdict.
        LOGGER.warning("Ignoring advisory feed %s: %s", url, exc)
        return []
    return _parse_document(document)


def load_database(
    *,
    extra_files: Iterable[str] = (),
    feed_url: str | None = None,
    include_bundled: bool = True,
    timeout: int = 10,
    verify: bool = True,
    proxies: dict[str, str] | None = None,
) -> VulnerabilityDatabase:
    """Load and merge every configured advisory source, de-duplicated by id."""
    advisories: dict[str, Advisory] = {}
    sources: list[str] = []

    if include_bundled and BUNDLED_DB.is_file():
        for advisory in _load_file(BUNDLED_DB):
            advisories[advisory.id] = advisory
        sources.append(str(BUNDLED_DB))

    for candidate in extra_files:
        path = Path(candidate).expanduser()
        if not path.is_file():
            LOGGER.warning("Advisory file %s does not exist.", path)
            continue
        for advisory in _load_file(path):
            advisories[advisory.id] = advisory
        sources.append(str(path))

    if feed_url:
        loaded = _load_feed(feed_url, timeout=timeout, verify=verify, proxies=proxies)
        for advisory in loaded:
            advisories[advisory.id] = advisory
        if loaded:
            sources.append(feed_url)

    return VulnerabilityDatabase(advisories=list(advisories.values()), sources=sources)
