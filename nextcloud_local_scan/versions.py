"""
Version helpers and the version-derived feature matrix.

scan.nextcloud.com reports hardening measures it cannot observe from the
outside (brute-force protection, ``__Host-`` cookie prefixes, ...) by looking
at the release that introduced them. The local scanner does the same, using
:data:`HARDENING_MATRIX`.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from pathlib import Path

LOGGER = logging.getLogger(__name__)

# Maintained by scripts/update_supported_versions.py from Nextcloud's official
# maintenance and release schedule.
SUPPORTED_VERSIONS_FILE = Path(__file__).with_name("data") / "supported_versions.json"

# Nextcloud major release that first shipped each hardening measure. The keys
# match the 'hardenings' block returned by scan.nextcloud.com.
HARDENING_MATRIX: dict[str, int] = {
    "sameSiteCookies": 9,
    "bruteforceProtection": 12,
    "passwordConfirmation": 13,
    "CSPv3": 14,
    "__HostPrefix": 15,
    "appPasswordsCanBeRestricted": 17,
    "appPasswordsScannedForHaveIBeenPwned": 18,
}

_VERSION_PART = re.compile(r"\d+")


def parse_version(version: str | None) -> tuple[int, ...]:
    """
    Turn a version string into a comparable tuple of integers.

    Accepts the forms seen in the wild: '30.0.2.2', 'Nextcloud 30.0.2',
    '30.0.2 RC1'. Unparsable input yields an empty tuple, which compares
    lower than every real version.
    """
    if not version:
        return ()
    return tuple(int(part) for part in _VERSION_PART.findall(str(version)))


def compare_versions(left: str | None, right: str | None) -> int:
    """Return -1, 0 or 1 for left <, == or > right (missing parts count as 0)."""
    left_parts = parse_version(left)
    right_parts = parse_version(right)
    length = max(len(left_parts), len(right_parts))
    padded_left = left_parts + (0,) * (length - len(left_parts))
    padded_right = right_parts + (0,) * (length - len(right_parts))
    if padded_left < padded_right:
        return -1
    if padded_left > padded_right:
        return 1
    return 0


def major_version(version: str | None) -> int | None:
    """Return the major release number (the branch) of a version string."""
    parts = parse_version(version)
    return parts[0] if parts else None


def is_in_range(version: str | None, introduced: str | None, fixed: str | None) -> bool:
    """
    Test whether version falls into the half-open range [introduced, fixed).

    Both bounds are optional: an advisory without 'introduced' affects every
    older release, one without 'fixed' has no patched version yet.
    """
    if not parse_version(version):
        return False
    if introduced and compare_versions(version, introduced) < 0:
        return False
    return not (fixed and compare_versions(version, fixed) >= 0)


def derive_hardenings(version: str | None, product: str | None = None) -> dict[str, bool]:
    """
    Report which hardening measures the running release supports.

    Mirrors the 'hardenings' block of the Scan API: the value is True when
    the installed version is new enough to provide the measure.

    The matrix maps Nextcloud major releases. ownCloud and Infinite Scale
    number their releases independently, so comparing them against it would
    produce meaningless answers - those products get an empty block instead.
    """
    if product is not None and "nextcloud" not in product.strip().lower():
        return {}
    major = major_version(version)
    if major is None:
        return {name: False for name in sorted(HARDENING_MATRIX)}
    return {
        name: major >= since for name, since in sorted(HARDENING_MATRIX.items())
    }


def newest(versions: Iterable[str]) -> str | None:
    """Return the highest version from an iterable, or None when it is empty."""
    candidates = [version for version in versions if parse_version(version)]
    if not candidates:
        return None
    return max(candidates, key=parse_version)


def load_supported_majors(path: Path | None = None) -> list[int]:
    """
    Read the major releases that still receive security fixes.

    Returns an empty list when the file is missing or unusable, which the
    callers treat as "no local knowledge" rather than "everything is EOL".
    """
    source = path or SUPPORTED_VERSIONS_FILE
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        LOGGER.debug("Supported versions unavailable (%s): %s", source, exc)
        return []
    if not isinstance(document, dict):
        return []
    majors = [int(entry) for entry in document.get("supported", []) if str(entry).isdigit()]
    return sorted(majors, reverse=True)


def is_end_of_life(version: str | None, supported: Iterable[int] | None = None) -> bool | None:
    """
    Decide whether a version's major release is out of support.

    True when the major release is older than the oldest supported one, False
    when it is supported or newer (an unreleased build is not EOL), and None
    when either the version or the support list is unknown.
    """
    majors = list(supported) if supported is not None else load_supported_majors()
    major = major_version(version)
    if not majors or major is None:
        return None
    return major < min(majors)
