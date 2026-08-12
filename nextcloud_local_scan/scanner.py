"""
Local re-implementation of the scan.nextcloud.com checks.

The scanner talks to the Nextcloud instance directly and produces a result
document with the same shape as ``GET https://scan.nextcloud.com/api/result/<uuid>``,
so every consumer of the Scan API keeps working unchanged:

* ``product`` / ``version`` / ``edition`` / ``domain`` from ``status.php``
* ``hardenings`` derived from the release that introduced each measure
* ``setup.https`` and ``setup.headers`` from live HTTP responses
* ``vulnerabilities`` from the local advisory database
* ``rating`` (0-5) and ``EOL``

On top of that it adds checks the public scanner does not perform, reported
in the ``extraChecks`` block: TLS certificate and protocol state, publicly
readable installation paths, directory listings, unauthenticated WebDAV,
software version disclosure and missing modern security headers.

Update information is taken from the local instance via the *serverinfo* app
(see :mod:`nextcloud_local_scan.serverinfo`) and only falls back to the
public updater server when serverinfo is unavailable.
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import requests

from .serverinfo import ServerInfoSettings, UpdateInfo, fetch_update_info
from .versions import (
    compare_versions,
    derive_hardenings,
    is_end_of_life,
    load_supported_majors,
    major_version,
    parse_version,
)
from .vulndb import VulnerabilityDatabase, load_database

LOGGER = logging.getLogger("check_nextcloud.scanner")

UPDATER_SERVER_URL = "https://updates.nextcloud.com/updater_server/"

# Headers reported by scan.nextcloud.com in setup.headers.
SCAN_HEADERS: tuple[str, ...] = (
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "X-Download-Options",
    "X-Permitted-Cross-Domain-Policies",
    "X-Robots-Tag",
)

# Expected values; None means "any non-empty value is accepted".
HEADER_EXPECTATIONS: dict[str, str | None] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "X-XSS-Protection": None,
    "X-Download-Options": "noopen",
    "X-Permitted-Cross-Domain-Policies": "none",
    "X-Robots-Tag": None,
}

# Additional headers checked by this scanner only (extraChecks).
MODERN_HEADERS: tuple[str, ...] = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "Referrer-Policy",
)

# Paths that must never be readable from the internet.
EXPOSED_PATHS: tuple[tuple[str, str], ...] = (
    ("/config/config.php", "critical"),
    ("/data/.ocdata", "critical"),
    ("/data/.ncdata", "critical"),
    ("/data/nextcloud.log", "critical"),
    ("/data/owncloud.log", "critical"),
    ("/db_structure.xml", "high"),
    ("/.user.ini", "high"),
    ("/.htaccess", "high"),
    ("/README.md", "low"),
    ("/3rdparty/", "high"),
)

# Requested to find out how the server answers for something that cannot exist.
CATCH_ALL_PATH = "/check-nextcloud-security-probe-404"

SEVERITY_RATING_CAP: dict[str, int] = {"critical": 2, "high": 3, "medium": 4, "low": 5}

MIN_RATING = 0
MAX_RATING = 5

DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_TLS_MIN_DAYS = 14

USER_AGENT = "check-nextcloud-security local scanner"

REQUEST_ERRORS = (requests.exceptions.RequestException, ValueError)


class ScanError(RuntimeError):
    """Raised when the instance cannot be scanned at all."""


@dataclass(frozen=True)
class ScannerSettings:
    """Tunables for a local scan run."""

    timeout: int = DEFAULT_TIMEOUT_SECONDS
    verify_tls: bool = True
    proxy: str | None = None
    scheme: str = "https"
    port: int | None = None
    extra_checks: bool = True
    extra_checks_affect_rating: bool = True
    tls_min_days: int = DEFAULT_TLS_MIN_DAYS
    use_updater_server: bool = True
    use_release_schedule: bool = True
    supported_majors: tuple[int, ...] | None = None
    updater_server_url: str = UPDATER_SERVER_URL
    vulnerability_files: tuple[str, ...] = ()
    vulnerability_feed: str | None = None
    include_bundled_db: bool = True
    user_agent: str = USER_AGENT

    @property
    def proxies(self) -> dict[str, str] | None:
        """requests-style proxy mapping."""
        return {"http": self.proxy, "https": self.proxy} if self.proxy else None


@dataclass
class Finding:
    """A single extra security finding."""

    id: str
    severity: str
    passed: bool
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        """Render the finding for JSON output."""
        return {
            "id": self.id,
            "severity": self.severity,
            "passed": self.passed,
            "detail": self.detail,
        }


@dataclass
class _Probe:
    """Shared HTTP helper bound to one host."""

    base_url: str
    settings: ScannerSettings
    session: requests.Session = field(default_factory=requests.Session)

    def get(self, path: str, *, allow_redirects: bool = True, method: str = "GET",
            base_url: str | None = None) -> requests.Response | None:
        """Perform one request, returning None when it fails."""
        url = f"{base_url or self.base_url}{path}"
        try:
            return self.session.request(
                method,
                url,
                timeout=self.settings.timeout,
                verify=self.settings.verify_tls,
                proxies=self.settings.proxies,
                allow_redirects=allow_redirects,
                headers={"User-Agent": self.settings.user_agent},
            )
        except REQUEST_ERRORS as exc:
            LOGGER.debug("Request to %s failed: %s", url, exc)
            return None


def _host_and_port(host: str, settings: ScannerSettings) -> tuple[str, int]:
    """Split an optional ':port' suffix off the host and apply the default."""
    hostname = host.strip().rstrip("/")
    for prefix in ("https://", "http://"):
        hostname = hostname.removeprefix(prefix)
    hostname = hostname.split("/", 1)[0]

    port = settings.port
    if hostname.startswith("["):  # bracketed IPv6 literal
        closing = hostname.find("]")
        if closing != -1 and hostname[closing + 1:].startswith(":"):
            port = port or int(hostname[closing + 2:])
            hostname = hostname[: closing + 1]
    elif hostname.count(":") == 1:
        hostname, _, raw_port = hostname.partition(":")
        port = port or int(raw_port)

    if port is None:
        port = 443 if settings.scheme == "https" else 80
    return hostname, port


def _base_url(hostname: str, port: int, scheme: str) -> str:
    """Build the base URL, omitting the port when it is the scheme default."""
    default_port = 443 if scheme == "https" else 80
    if port == default_port:
        return f"{scheme}://{hostname}"
    return f"{scheme}://{hostname}:{port}"


def _fetch_status(probe: _Probe) -> dict[str, Any]:
    """Read and validate status.php, the entry point of every Nextcloud scan."""
    response = probe.get("/status.php")
    if response is None:
        raise ScanError(f"{probe.base_url}/status.php is unreachable")
    if response.status_code >= 400:
        raise ScanError(
            f"{probe.base_url}/status.php returned HTTP {response.status_code}"
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise ScanError(f"{probe.base_url}/status.php did not return JSON: {exc}") from exc
    if not isinstance(payload, dict) or "version" not in payload:
        raise ScanError(f"No Nextcloud/ownCloud instance found at {probe.base_url}")
    return payload


def _check_headers(response: requests.Response | None) -> dict[str, bool]:
    """Evaluate the security headers reported by the Scan API."""
    if response is None:
        return {name: False for name in SCAN_HEADERS}

    result: dict[str, bool] = {}
    for name in SCAN_HEADERS:
        value = response.headers.get(name)
        expected = HEADER_EXPECTATIONS.get(name)
        if not value:
            result[name] = False
        elif expected is None:
            result[name] = True
        else:
            result[name] = expected.lower() in value.lower()
    return result


def _check_https(probe: _Probe, hostname: str, settings: ScannerSettings) -> dict[str, Any]:
    """Determine whether HTTPS is used and enforced for plain HTTP requests."""
    used = probe.base_url.startswith("https://")
    enforced = False

    plain = _Probe(base_url=f"http://{hostname}", settings=settings, session=probe.session)
    response = plain.get("/", allow_redirects=False)
    if response is not None:
        location = response.headers.get("Location", "")
        enforced = response.is_redirect and location.lower().startswith("https://")
    elif used:
        # Port 80 closed or filtered: plain HTTP simply cannot be spoken.
        enforced = True

    return {"used": used, "enforced": enforced}


def _tls_findings(hostname: str, port: int, settings: ScannerSettings) -> list[Finding]:
    """Inspect the TLS certificate lifetime and the negotiated protocol."""
    findings: list[Finding] = []
    context = ssl.create_default_context()
    if not settings.verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    try:
        with (
            socket.create_connection((hostname, port), timeout=settings.timeout) as raw,
            context.wrap_socket(raw, server_hostname=hostname) as tls,
        ):
            certificate = tls.getpeercert()
            protocol = tls.version() or "unknown"
    except (OSError, ssl.SSLError) as exc:
        return [
            Finding("tlsHandshake", "high", False, f"TLS handshake with {hostname}:{port} failed: {exc}")
        ]

    findings.append(Finding("tlsHandshake", "high", True, f"TLS handshake succeeded ({protocol})"))

    modern = protocol in {"TLSv1.3", "TLSv1.2"}
    findings.append(
        Finding(
            "tlsProtocol",
            "high",
            modern,
            f"Negotiated {protocol}" + ("" if modern else " (TLS 1.2 or newer expected)"),
        )
    )

    not_after = (certificate or {}).get("notAfter")
    if isinstance(not_after, str):
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            findings.append(
                Finding("tlsCertificate", "medium", False, f"Unparsable certificate date {not_after!r}")
            )
        else:
            days_left = (expires - datetime.now(timezone.utc)).days
            findings.append(
                Finding(
                    "tlsCertificate",
                    "high" if days_left <= 0 else "medium",
                    days_left >= settings.tls_min_days,
                    f"Certificate expires in {days_left} day(s) ({not_after})",
                )
            )
    return findings


def _is_nextcloud(product: str | None) -> bool:
    """Whether the release schedule applies to the scanned product."""
    return "nextcloud" in (product or "").strip().lower()


def _catch_all_probe(probe: _Probe) -> requests.Response | None:
    """
    Fetch a path that cannot exist, to learn how the server answers 404.

    Single-page frontends (ownCloud Infinite Scale, Nextcloud behind some
    proxies) serve the application shell with HTTP 200 for *every* path. Taking
    that at face value would report the whole installation as world-readable.
    """
    response = probe.get(CATCH_ALL_PATH, allow_redirects=False)
    if response is None or response.status_code != 200:
        return None
    return response


def _looks_like_catch_all(response: requests.Response, control: requests.Response) -> bool:
    """Decide whether a 200 response is just the server's catch-all page."""
    if len(response.content) == len(control.content):
        return True
    content_type = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
    # None of the probed files is HTML; an HTML answer is the frontend, not
    # the file itself.
    return content_type in {"text/html", "application/xhtml+xml"}


def _exposed_path_findings(probe: _Probe) -> list[Finding]:
    """Check that installation internals are not readable over HTTP."""
    control = _catch_all_probe(probe)
    findings: list[Finding] = []
    for path, severity in EXPOSED_PATHS:
        response = probe.get(path, allow_redirects=False)
        if response is None:
            findings.append(Finding(f"exposed:{path}", severity, True, "Not reachable"))
            continue

        exposed = response.status_code == 200 and bool(response.content.strip())
        detail = f"HTTP {response.status_code}"
        if exposed and control is not None and _looks_like_catch_all(response, control):
            exposed = False
            detail = f"HTTP {response.status_code} - catch-all response, file not served"
        elif exposed:
            detail = f"HTTP {response.status_code} - publicly readable"

        findings.append(Finding(f"exposed:{path}", severity, not exposed, detail))
    return findings


def _webdav_finding(probe: _Probe) -> Finding:
    """WebDAV must demand authentication."""
    response = probe.get("/remote.php/dav/", allow_redirects=False)
    if response is None:
        return Finding("webdavAuthentication", "medium", True, "WebDAV endpoint not reachable")
    protected = response.status_code in {401, 403, 405, 501}
    return Finding(
        "webdavAuthentication",
        "critical",
        protected,
        f"/remote.php/dav/ answered HTTP {response.status_code}",
    )


def _directory_listing_finding(probe: _Probe) -> Finding:
    """A readable /data directory listing leaks user files."""
    response = probe.get("/data/", allow_redirects=False)
    if response is None:
        return Finding("directoryListing", "critical", True, "/data/ not reachable")
    body = response.text[:2000].lower() if response.status_code == 200 else ""
    listing = "index of /" in body or "<title>index of" in body
    return Finding(
        "directoryListing",
        "critical",
        not listing,
        "Directory listing enabled for /data/" if listing else f"HTTP {response.status_code}",
    )


def _disclosure_findings(response: requests.Response | None) -> list[Finding]:
    """Report software versions leaked through response headers."""
    if response is None:
        return []
    findings: list[Finding] = []
    for header in ("Server", "X-Powered-By"):
        value = response.headers.get(header, "")
        leaks = bool(re.search(r"\d+\.\d+", value))
        findings.append(
            Finding(
                f"versionDisclosure:{header}",
                "low",
                not leaks,
                f"{header}: {value}" if value else f"{header} not sent",
            )
        )
    return findings


def _modern_header_findings(response: requests.Response | None) -> list[Finding]:
    """Check headers the public scanner does not evaluate."""
    findings: list[Finding] = []
    for name in MODERN_HEADERS:
        value = response.headers.get(name) if response is not None else None
        detail = f"{name}: {value}" if value else f"{name} missing"
        severity = "medium" if name != "Strict-Transport-Security" else "high"
        findings.append(Finding(f"header:{name}", severity, bool(value), detail))
    return findings


def _maintenance_finding(status: dict[str, Any]) -> list[Finding]:
    """Report maintenance mode and pending database upgrades."""
    findings = []
    if status.get("maintenance"):
        findings.append(
            Finding("maintenanceMode", "medium", False, "Instance is in maintenance mode")
        )
    if status.get("needsDbUpgrade"):
        findings.append(
            Finding("databaseUpgrade", "high", False, "Instance needs a database upgrade")
        )
    return findings


def _updater_element(body: str, name: str) -> str | None:
    """
    Read one element from the updater server response.

    The answer is a flat, three-element XML document. It is matched with a
    regular expression on purpose: no XML parser is exposed to a remote
    document, which rules out entity expansion attacks.
    """
    match = re.search(rf"<{name}>(.*?)</{name}>", body, re.DOTALL)
    return match.group(1).strip() if match else None


def _query_updater_server(version: str, settings: ScannerSettings) -> dict[str, Any]:
    """
    Ask the official updater server about newer releases and EOL state.

    Only used as a fallback when the local instance could not be asked; the
    request contains nothing but the version numbers.
    """
    parts = parse_version(version)
    if not parts:
        return {}
    padded = (list(parts) + [0, 0, 0, 0])[:4]
    version_string = "x".join(str(part) for part in padded) + "xinstalledatx0xstablexxx0x0x0x0x0"

    try:
        response = requests.get(
            settings.updater_server_url,
            params={"version": version_string},
            timeout=settings.timeout,
            proxies=settings.proxies,
            headers={"User-Agent": settings.user_agent},
        )
        response.raise_for_status()
        body = response.text.strip()
    except requests.exceptions.RequestException as exc:
        LOGGER.debug("Updater server query failed: %s", exc)
        return {}

    if not body or _updater_element(body, "error") is not None:
        return {"available": False}

    latest = _updater_element(body, "version")
    result: dict[str, Any] = {
        "available": bool(latest),
        "eol": _updater_element(body, "eol") == "1",
    }
    if latest:
        result["available_version"] = latest
    return result


def _apply_rating_caps(rating: int, findings: Iterable[Finding]) -> int:
    """Lower the rating according to the worst failed extra check."""
    for finding in findings:
        if finding.passed:
            continue
        rating = min(rating, SEVERITY_RATING_CAP.get(finding.severity, MAX_RATING))
    return max(rating, MIN_RATING)


def _compute_rating(
    *,
    eol: bool,
    vulnerabilities: list[dict[str, Any]],
    update_available: bool | None,
    latest_in_branch: bool | None,
    behind_branch: bool,
    findings: list[Finding],
    settings: ScannerSettings,
) -> int:
    """
    Map the collected evidence onto the 0-5 scale of the Scan API.

    5 (A+) fully up to date, 4 (A) update available inside the branch,
    3 (C) a whole major release behind, 2 (D) known vulnerabilities,
    1 (E) critical or high vulnerabilities, 0 (F) end of life.
    """
    if eol:
        return MIN_RATING

    if vulnerabilities:
        severities = {str(entry.get("severity", "")).lower() for entry in vulnerabilities}
        rating = 1 if severities & {"critical", "high"} else 2
    elif behind_branch:
        rating = 3
    elif update_available or latest_in_branch is False:
        rating = 4
    else:
        rating = MAX_RATING

    if settings.extra_checks and settings.extra_checks_affect_rating:
        rating = _apply_rating_caps(rating, findings)
    return rating


def _collect_extra_findings(
    probe: _Probe,
    hostname: str,
    port: int,
    settings: ScannerSettings,
    status: dict[str, Any],
    root_response: requests.Response | None,
) -> list[Finding]:
    """Run every check that goes beyond the public scanner."""
    findings: list[Finding] = []
    if probe.base_url.startswith("https://"):
        findings.extend(_tls_findings(hostname, port, settings))
    findings.extend(_modern_header_findings(root_response))
    findings.extend(_exposed_path_findings(probe))
    findings.append(_webdav_finding(probe))
    findings.append(_directory_listing_finding(probe))
    findings.extend(_disclosure_findings(root_response))
    findings.extend(_maintenance_finding(status))
    return findings


def scan(
    host: str,
    settings: ScannerSettings | None = None,
    serverinfo_settings: ServerInfoSettings | None = None,
    database: VulnerabilityDatabase | None = None,
) -> dict[str, Any]:
    """
    Scan one instance and return a Scan-API compatible result document.

    Raises :class:`ScanError` when the instance does not expose a usable
    ``status.php``; every other problem is reported inside the result.
    """
    settings = settings or ScannerSettings()
    hostname, port = _host_and_port(host, settings)
    base_url = _base_url(hostname, port, settings.scheme)

    probe = _Probe(base_url=base_url, settings=settings)
    https_unavailable: str | None = None
    try:
        status = _fetch_status(probe)
    except ScanError as exc:
        if settings.scheme != "https":
            raise
        # An instance that is only reachable over plain HTTP is still worth
        # reporting - as a critical finding rather than as a failed scan.
        LOGGER.debug("HTTPS scan failed (%s), retrying over HTTP", exc)
        fallback_port = port if port != 443 else 80
        base_url = _base_url(hostname, fallback_port, "http")
        probe = _Probe(base_url=base_url, settings=settings)
        try:
            status = _fetch_status(probe)
        except ScanError:
            raise exc from None
        https_unavailable = str(exc)
        port = fallback_port

    version = str(status.get("version") or "")
    product = str(status.get("productname") or "Nextcloud")
    edition = str(status.get("edition") or "")

    root_response = probe.get("/", allow_redirects=True)
    headers = _check_headers(root_response)
    https = _check_https(probe, hostname, settings)
    hardenings = derive_hardenings(version, product)

    update_info: UpdateInfo = (
        fetch_update_info(serverinfo_settings, hostname)
        if serverinfo_settings is not None
        else UpdateInfo(source="disabled")
    )

    # The release schedule bundled with the package is the primary source for
    # end-of-life state: the updater server answers with an empty document both
    # for a current release and for one whose branch is no longer served, so it
    # cannot tell the two apart on its own.
    eol = False
    if _is_nextcloud(product) and settings.use_release_schedule:
        schedule_eol = is_end_of_life(version, settings.supported_majors)
        eol = bool(schedule_eol)

    update_available = update_info.available
    available_version = update_info.available_version

    if not update_info.known and settings.use_updater_server:
        updater = _query_updater_server(version, settings)
        if updater:
            update_available = bool(updater.get("available"))
            available_version = updater.get("available_version") or available_version
            eol = eol or bool(updater.get("eol"))
            update_info = UpdateInfo(
                available=update_available,
                version=version,
                available_version=available_version,
                source="updater server",
                error=update_info.error,
            )

    latest_in_branch: bool | None = None
    behind_branch = False
    if available_version:
        installed_branch = major_version(version)
        available_branch = major_version(available_version)
        behind_branch = (
            installed_branch is not None
            and available_branch is not None
            and available_branch > installed_branch
        )
        latest_in_branch = behind_branch or compare_versions(version, available_version) >= 0
    elif update_available is False:
        latest_in_branch = True

    database = database or load_database(
        extra_files=settings.vulnerability_files,
        feed_url=settings.vulnerability_feed,
        include_bundled=settings.include_bundled_db,
        timeout=settings.timeout,
        verify=settings.verify_tls,
        proxies=settings.proxies,
    )
    vulnerabilities = [advisory.as_dict() for advisory in database.matches(version)]

    findings = (
        _collect_extra_findings(probe, hostname, port, settings, status, root_response)
        if settings.extra_checks
        else []
    )
    if https_unavailable and settings.extra_checks:
        findings.insert(
            0,
            Finding("httpsAvailable", "critical", False, f"HTTPS unusable: {https_unavailable}"),
        )

    rating = _compute_rating(
        eol=eol,
        vulnerabilities=vulnerabilities,
        update_available=update_available,
        latest_in_branch=latest_in_branch,
        behind_branch=behind_branch,
        findings=findings,
        settings=settings,
    )

    scanned_at = datetime.now(timezone.utc)
    result: dict[str, Any] = {
        "domain": hostname,
        "url": f"{base_url}/status.php",
        "product": product,
        "version": version,
        "edition": edition,
        "scannedAt": {
            "date": scanned_at.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "timezone_type": 3,
            "timezone": "UTC",
        },
        "rating": rating,
        "EOL": eol,
        "supportedMajorVersions": list(settings.supported_majors or load_supported_majors()),
        "latestVersionInBranch": latest_in_branch,
        "vulnerabilities": vulnerabilities,
        "hardenings": hardenings,
        "setup": {"https": https, "headers": headers},
        # Fields below are specific to the local scanner.
        "scanner": "check-nextcloud-security local scanner",
        "updates": update_info.as_dict(),
        "extraChecks": [finding.as_dict() for finding in findings],
        "advisorySources": database.sources,
    }
    return result


def failed_extra_checks(result: dict[str, Any]) -> list[str]:
    """List the ids of extra checks that did not pass, worst severity first."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    failures = [
        entry
        for entry in result.get("extraChecks", [])
        if isinstance(entry, dict) and not entry.get("passed", True)
    ]
    failures.sort(key=lambda entry: order.get(str(entry.get("severity")), 9))
    return [str(entry.get("id")) for entry in failures]
