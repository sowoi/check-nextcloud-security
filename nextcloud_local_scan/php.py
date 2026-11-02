"""
Assessment of the PHP version a Nextcloud instance runs on.

The version is taken from the *serverinfo* app (see
:mod:`nextcloud_local_scan.serverinfo`) and compared against a curated list of
critical PHP advisories bundled in ``data/php_advisories.json``. Nothing is
fetched from php.net at runtime.

Two sources are distinguished:

``api``
    The serverinfo OCS endpoint runs inside the web SAPI (PHP-FPM, mod_php),
    so it reports exactly the interpreter that serves requests - the attack
    surface. It also notices a PHP package that was upgraded while the FPM
    workers still run the old binary.

``cli``
    Anything obtained through ``occ`` is the command line interpreter. It may
    differ from the one serving web requests, so a "fixed" verdict derived
    from it comes with a hint to verify PHP-FPM.

Distribution packages often backport security fixes without changing the
upstream version number. Debian/Ubuntu builds can be recognised by a suffix
such as ``8.1.2-1ubuntu2.14`` (CLI only, the serverinfo API strips it) and are
reported as WARNING instead of CRITICAL. Other vendors (RHEL, AlmaLinux, ...)
cannot be told apart; such advisories can be acknowledged explicitly.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

PHP_ADVISORIES_FILE = Path(__file__).with_name("data") / "php_advisories.json"

# '8.3.12', '8.1.2-1ubuntu2.14', '8.2.7-1~deb12u1', '8.4.0RC1'
_VERSION = re.compile(r"^\s*(\d+)\.(\d+)\.(\d+)(.*)$")

STATUS_OK = "ok"
STATUS_VULNERABLE = "vulnerable"
STATUS_VENDOR_BUILD = "vendor-build"
STATUS_EOL = "eol"
STATUS_UNKNOWN = "unknown"


@dataclass(frozen=True)
class PhpVersion:
    """A parsed PHP version string."""

    major: int
    minor: int
    patch: int
    suffix: str = ""

    @property
    def branch(self) -> str:
        """Release branch, e.g. '8.3'."""
        return f"{self.major}.{self.minor}"

    @property
    def number(self) -> tuple[int, int, int]:
        """Comparable numeric part."""
        return (self.major, self.minor, self.patch)

    @property
    def is_vendor_build(self) -> bool:
        """
        True for distribution builds such as '8.1.2-1ubuntu2.14'.

        Pre-releases ('8.4.0RC1') carry a suffix too but are upstream builds.
        """
        return self.suffix.startswith(("-", "+", "~"))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}{self.suffix}"


def parse_php_version(raw: str | None) -> PhpVersion | None:
    """Parse a PHP version string, returning None for anything unusable."""
    if not raw:
        return None
    match = _VERSION.match(str(raw))
    if not match:
        return None
    major, minor, patch, suffix = match.groups()
    return PhpVersion(int(major), int(minor), int(patch), suffix.strip())


def _branch_key(branch: str) -> tuple[int, ...]:
    return tuple(int(part) for part in branch.split("."))


def load_php_advisories(path: Path | None = None) -> dict[str, Any]:
    """Load the bundled advisory list."""
    with (path or PHP_ADVISORIES_FILE).open(encoding="utf-8") as handle:
        data: dict[str, Any] = json.load(handle)
    return data


@dataclass
class PhpAdvisoryMatch:
    """One advisory that applies to the installed PHP version."""

    id: str
    cves: list[str]
    severity: str
    fixed_version: str | None
    url: str | None = None

    def label(self) -> str:
        cves = f" ({', '.join(self.cves)})" if self.cves else ""
        return f"{self.id}{cves}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "cves": list(self.cves),
            "severity": self.severity,
            "fixedVersion": self.fixed_version,
            "url": self.url,
        }


@dataclass
class PhpAssessment:
    """Verdict on the PHP version of one instance."""

    version: str | None
    source: str | None
    status: str = STATUS_UNKNOWN
    advisories: list[PhpAdvisoryMatch] = field(default_factory=list)
    ignored: list[str] = field(default_factory=list)
    eol: bool = False
    eol_date: str | None = None
    hint: str | None = None

    @property
    def known(self) -> bool:
        return self.status != STATUS_UNKNOWN

    @property
    def is_cli(self) -> bool:
        return bool(self.source) and "cli" in str(self.source)

    def summary(self) -> str:
        """One-line, human readable rendering for the plugin output."""
        if not self.known:
            return (
                "PHP check: version not available "
                "(needs the serverinfo API or occ, see README)"
            )
        origin = f" via {self.source}" if self.source else ""
        parts = [f"PHP {self.version}{origin}"]
        if self.advisories:
            listed = "; ".join(
                f"{match.label()}"
                + (f", fixed in {match.fixed_version}" if match.fixed_version
                   else ", no upstream fix for this branch")
                for match in self.advisories
            )
            parts.append(f"affected by {listed}")
        if self.eol:
            parts.append(f"branch end of life since {self.eol_date}")
        if not self.advisories and not self.eol:
            parts.append("no known critical PHP advisory")
        if self.ignored:
            parts.append(f"acknowledged: {', '.join(self.ignored)}")
        line = ", ".join(parts)
        if self.hint:
            line += f" ({self.hint})"
        return line

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "source": self.source,
            "status": self.status,
            "advisories": [match.as_dict() for match in self.advisories],
            "ignored": list(self.ignored),
            "eol": self.eol,
            "eolDate": self.eol_date,
            "hint": self.hint,
        }


def assess_php_version(
    raw_version: str | None,
    source: str | None = None,
    *,
    ignore: tuple[str, ...] | list[str] = (),
    today: date | None = None,
    data: dict[str, Any] | None = None,
) -> PhpAssessment:
    """
    Compare a PHP version with the bundled advisory list.

    ``ignore`` holds advisory ids or CVE numbers (case-insensitive) the
    operator has acknowledged, typically because the distribution backported
    the fix without changing the version number.
    """
    parsed = parse_php_version(raw_version)
    if parsed is None:
        return PhpAssessment(version=raw_version or None, source=source)

    data = data if data is not None else load_php_advisories()
    today = today or date.today()
    ignored_keys = {item.strip().upper() for item in ignore if item and item.strip()}

    assessment = PhpAssessment(version=str(parsed), source=source, status=STATUS_OK)

    for advisory in data.get("advisories", []):
        fixed: dict[str, str] = advisory.get("fixed") or {}
        if not fixed:
            continue
        oldest_fixed_branch = min(fixed, key=_branch_key)
        fixed_version: str | None = None
        if parsed.branch in fixed:
            fixed_parsed = parse_php_version(fixed[parsed.branch])
            if fixed_parsed is None or parsed.number >= fixed_parsed.number:
                continue
            fixed_version = fixed[parsed.branch]
        elif _branch_key(parsed.branch) < _branch_key(oldest_fixed_branch):
            fixed_version = None  # older branch, no upstream release
        else:
            continue  # newer branch than the advisory knows about

        advisory_id = str(advisory.get("id"))
        cves = [str(cve) for cve in advisory.get("cves", [])]
        if {advisory_id.upper(), *(cve.upper() for cve in cves)} & ignored_keys:
            assessment.ignored.append(advisory_id)
            continue
        assessment.advisories.append(
            PhpAdvisoryMatch(
                id=advisory_id,
                cves=cves,
                severity=str(advisory.get("severity") or "critical"),
                fixed_version=fixed_version,
                url=advisory.get("url"),
            )
        )

    eol_date = (data.get("eol") or {}).get(parsed.branch)
    if eol_date:
        try:
            assessment.eol = date.fromisoformat(eol_date) < today
        except ValueError:
            assessment.eol = False
        if assessment.eol:
            assessment.eol_date = eol_date
    elif data.get("eol") and _branch_key(parsed.branch) < min(
        (_branch_key(branch) for branch in data["eol"]), default=(0,)
    ):
        assessment.eol = True
        assessment.eol_date = "before " + min(data["eol"].values())

    if assessment.advisories:
        if parsed.is_vendor_build:
            assessment.status = STATUS_VENDOR_BUILD
            assessment.hint = (
                "distribution build: verify that the vendor backported the fix, "
                "then acknowledge it with --php-ignore"
            )
        else:
            assessment.status = STATUS_VULNERABLE
    elif assessment.eol:
        assessment.status = STATUS_EOL

    if assessment.is_cli and assessment.status in (STATUS_OK, STATUS_EOL):
        assessment.hint = (
            "command line PHP; make sure PHP-FPM / the web server run the same "
            "version and were restarted"
        )
    return assessment
