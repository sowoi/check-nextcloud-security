#!/usr/bin/env python3
"""
Check a Nextcloud instance for known vulnerabilities using scan.nextcloud.com API.
Authors: Massoud Ahmed, Georg Schlagholz (IT-Native GmbH)
"""
import argparse
import contextlib
import io
import ipaddress
import logging
import os
import sys
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, NoReturn, TypeVar

import requests

__version__ = "1.4.0"

LOGGER = logging.getLogger("check_nextcloud")

SCAN_QUEUE_URL = "https://scan.nextcloud.com/api/queue"
SCAN_RESULT_URL = "https://scan.nextcloud.com/api/result"
SCAN_REQUEUE_URL = "https://scan.nextcloud.com/api/requeue"

DEFAULT_TIMEOUT_SECONDS = 10

# Rating values returned by the Scan API, from best (5) to worst (0).
RATE_MAP: dict[int, str] = {5: "A+", 4: "A", 3: "C", 2: "D", 1: "E", 0: "F"}
MIN_RATING = 0
MAX_RATING = 5

# Default rating thresholds: a rating at or below these values triggers the
# corresponding state. 3 == "C", 1 == "E".
DEFAULT_WARNING_RATING = 3
DEFAULT_CRITICAL_RATING = 1

# Prefix for all environment variables recognized by this plugin, e.g. CNS_HOST.
ENV_PREFIX = "CNS_"

# Nagios states that may trigger the optional webhook, keyed by the value
# accepted for --webhook-on.
WEBHOOK_TRIGGERS: dict[str, frozenset["NagiosExitCode"]] = {}
DEFAULT_WEBHOOK_ON = "critical"
DEFAULT_WEBHOOK_TIMEOUT_SECONDS = 10

DEFAULT_RETRIES = 2
DEFAULT_BACKOFF_FACTOR = 0.5

# Errors expected from a failing HTTP call or an unparsable JSON body.
REQUEST_ERRORS = (requests.exceptions.RequestException, ValueError)

T = TypeVar("T")


class NagiosExitCode(IntEnum):
    """Standard Nagios/Icinga plugin exit codes."""

    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3


# Which states trigger the webhook, for each --webhook-on value. Higher
# settings include every state that is at least as severe.
WEBHOOK_TRIGGERS.update({
    "critical": frozenset({NagiosExitCode.CRITICAL}),
    "warning": frozenset({NagiosExitCode.CRITICAL, NagiosExitCode.WARNING}),
    "unknown": frozenset(
        {NagiosExitCode.CRITICAL, NagiosExitCode.WARNING, NagiosExitCode.UNKNOWN}
    ),
    "always": frozenset(NagiosExitCode),
})


@dataclass(frozen=True)
class ScanContext:
    """Immutable configuration for a single scan run."""

    host: str
    proxy: str | None = None
    debug: bool = False
    rescan: bool = False
    retries: int = DEFAULT_RETRIES
    backoff_factor: float = DEFAULT_BACKOFF_FACTOR
    timeout: int = DEFAULT_TIMEOUT_SECONDS
    warning_rating: int = DEFAULT_WARNING_RATING
    critical_rating: int = DEFAULT_CRITICAL_RATING
    check_hardening: bool = False
    webhook_url: str | None = None
    webhook_on: str = DEFAULT_WEBHOOK_ON
    webhook_timeout: int = DEFAULT_WEBHOOK_TIMEOUT_SECONDS
    # Stored as a tuple of pairs so ScanContext stays hashable/frozen.
    webhook_headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ScanRequestInfo:
    """HTTP request parameters shared by all calls to the Scan API."""

    headers: dict[str, str] = field(default_factory=lambda: {
        "Content-type": "application/x-www-form-urlencoded",
        "X-CSRF": "true",
    })
    data: dict[str, str] = field(default_factory=dict)
    proxies: dict[str, str] | None = None
    timeout: int = DEFAULT_TIMEOUT_SECONDS


@dataclass
class ScanResult:
    """Result of a completed (or in-progress) scan lookup."""

    response: dict[str, Any]
    uuid: str


# --- Environment variable helpers ---
def _env(name: str) -> str | None:
    """Read a CNS_-prefixed environment variable (e.g. CNS_HOST)."""
    return os.environ.get(f"{ENV_PREFIX}{name}")


def _env_bool(name: str) -> bool:
    """Interpret a CNS_-prefixed environment variable as a boolean flag."""
    value = _env(name)
    return value is not None and value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    """Read a CNS_-prefixed environment variable as an int, falling back to default."""
    value = _env(name)
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        LOGGER.warning("Ignoring invalid %s%s=%r (expected an integer).", ENV_PREFIX, name, value)
        return default


def _env_float(name: str, default: float) -> float:
    """Read a CNS_-prefixed environment variable as a float, falling back to default."""
    value = _env(name)
    if not value:
        return default
    try:
        return float(value)
    except ValueError:
        LOGGER.warning("Ignoring invalid %s%s=%r (expected a number).", ENV_PREFIX, name, value)
        return default


def _fail(message: str, exit_code: NagiosExitCode = NagiosExitCode.UNKNOWN) -> NoReturn:
    """Print a Nagios-formatted failure message and terminate the program."""
    print(message)
    sys.exit(int(exit_code))


def _build_request_info(context: ScanContext) -> ScanRequestInfo:
    """Build the shared request parameters (headers, payload, proxies) for a context."""
    return ScanRequestInfo(
        data={"url": context.host},
        proxies={"http": context.proxy, "https": context.proxy} if context.proxy else None,
        timeout=context.timeout,
    )


def _call_with_retry(
    func: Callable[[], T], *, retries: int, backoff_factor: float, description: str
) -> T:
    """
    Call func(), retrying on transient request errors with exponential backoff.

    Sleeps backoff_factor * 2**attempt seconds between attempts (0, 1, 2, ...).
    Re-raises the last encountered error once retries are exhausted.
    """
    last_exc: BaseException = RuntimeError(f"{description}: no attempt was made")
    for attempt in range(retries + 1):
        try:
            return func()
        except REQUEST_ERRORS as exc:
            last_exc = exc
            if attempt == retries:
                break
            sleep_seconds = backoff_factor * (2**attempt)
            LOGGER.debug(
                "%s failed (attempt %d/%d): %s - retrying in %.1fs",
                description,
                attempt + 1,
                retries + 1,
                exc,
                sleep_seconds,
            )
            time.sleep(sleep_seconds)
    raise last_exc


# --- Utility Functions ---
def check_if_ip_or_host(host: str) -> None:
    """
    Exit if host is an IP address (not supported by the API).

    Accepts both plain IPv4/IPv6 literals and the bracketed IPv6 form
    ('[2001:db8::1]') that may be copied from a URL.
    """
    candidate = host.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    # An IPv6 literal may carry a zone index (fe80::1%eth0), which
    # ipaddress rejects but which is still unmistakably an address.
    candidate = candidate.split("%", 1)[0]

    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return
    _fail("IP addresses are not supported by the Scan API.")


def send_scan_request(context: ScanContext) -> ScanResult:
    """Send initial security check request to the Nextcloud Scan Server."""

    request_info = _build_request_info(context)

    LOGGER.debug("Initiating scan for host: %s", context.host)
    if context.proxy:
        LOGGER.debug("Using proxy: %s", context.proxy)

    def _queue_scan() -> Any:
        response = requests.post(
            SCAN_QUEUE_URL,
            headers=request_info.headers,
            data=request_info.data,
            proxies=request_info.proxies,
            timeout=request_info.timeout,
        )
        response.raise_for_status()
        return response.json()

    try:
        answer = _call_with_retry(
            _queue_scan,
            retries=context.retries,
            backoff_factor=context.backoff_factor,
            description=f"Queueing scan for {context.host}",
        )
    except REQUEST_ERRORS as exc:
        LOGGER.debug("Scan request failed for %s: %s", context.host, exc, exc_info=True)
        _notify_and_fail(
            context,
            f"UNKNOWN: {context.host} Scan failed! Either no Nextcloud/ownCloud found "
            f"or too many scans queued: {exc}",
        )

    LOGGER.debug("Response from scan.nextcloud.com: %s", answer)

    if isinstance(answer, str) and "Too many instances" in answer:
        _notify_and_fail(context, f"UNKNOWN: {context.host} Scan failed! Reason: {answer}")

    uuid: str | None = answer.get("uuid")
    if not uuid:
        _notify_and_fail(context, f"UNKNOWN: Failed to retrieve scan UUID for {context.host}.")

    def _fetch_result() -> Any:
        return requests.get(
            f"{SCAN_RESULT_URL}/{uuid}",
            proxies=request_info.proxies,
            timeout=request_info.timeout,
        ).json()

    try:
        response_scan = _call_with_retry(
            _fetch_result,
            retries=context.retries,
            backoff_factor=context.backoff_factor,
            description=f"Fetching scan result for {context.host}",
        )
    except REQUEST_ERRORS as exc:
        LOGGER.debug("Fetching scan result failed for %s: %s", context.host, exc, exc_info=True)
        _notify_and_fail(
            context, f"UNKNOWN: Could not retrieve scan results for {context.host}: {exc}"
        )

    return ScanResult(response=response_scan, uuid=uuid)


def check_vulnerabilities(
    context: ScanContext,
    scan_result: ScanResult,
    duration_seconds: float | None = None,
) -> None:
    """Check the Nextcloud instance for known vulnerabilities and print the result."""

    request_info = _build_request_info(context)

    uuid_url = f"{SCAN_RESULT_URL}/{scan_result.uuid}"
    response_scan = scan_result.response

    if context.rescan:
        LOGGER.debug("Triggering rescan for %s", scan_result.uuid)

        def _requeue_scan() -> Any:
            requests.post(
                SCAN_REQUEUE_URL,
                headers=request_info.headers,
                data=request_info.data,
                proxies=request_info.proxies,
                timeout=request_info.timeout,
            )
            return requests.get(
                uuid_url, proxies=request_info.proxies, timeout=request_info.timeout
            ).json()

        try:
            response_scan = _call_with_retry(
                _requeue_scan,
                retries=context.retries,
                backoff_factor=context.backoff_factor,
                description=f"Rescanning {scan_result.uuid}",
            )
        except REQUEST_ERRORS as exc:
            LOGGER.debug("Rescan failed for %s: %s", scan_result.uuid, exc, exc_info=True)
            _notify_and_fail(context, f"UNKNOWN: Failed to rescan {scan_result.uuid}: {exc}")

    rating: int = response_scan.get("rating", -1)
    product: str = response_scan.get("product", "Unknown")
    version: str = response_scan.get("version", "Unknown")
    domain: str = response_scan.get("domain", "Unknown")
    scan_date: str = response_scan.get("scannedAt", {}).get("date", "Unknown")
    rate: str = RATE_MAP.get(rating, "Unknown")

    vulnerabilities: list[dict[str, Any]] = response_scan.get("vulnerabilities", [])
    num_vulns: int = len(vulnerabilities)

    msg, exit_code = _evaluate_rating(context, response_scan, rating, num_vulns)

    missing_hardenings = _collect_missing_hardenings(response_scan)
    detail_lines = [f"{product} {version} on {domain}, rating: {rate}, last scanned: {scan_date}"]

    if num_vulns:
        detail_lines.append(f"Known vulnerabilities: {_format_vulnerabilities(vulnerabilities)}")

    if context.check_hardening:
        if missing_hardenings:
            detail_lines.append(f"Missing hardening: {', '.join(missing_hardenings)}")
            if exit_code is NagiosExitCode.OK:
                msg = (
                    f"WARNING: {len(missing_hardenings)} hardening measure(s) missing, "
                    "but no known vulnerabilities."
                )
                exit_code = NagiosExitCode.WARNING
        else:
            detail_lines.append("Hardening: all checked measures in place")

    perfdata = _build_perfdata(
        rating,
        RATE_MAP,
        num_vulns,
        duration_seconds,
        context=context,
        missing_hardenings=len(missing_hardenings) if context.check_hardening else None,
    )

    if _webhook_should_fire(context, exit_code):
        payload = _build_webhook_payload(
            context,
            scan_result=scan_result,
            response_scan=response_scan,
            message=msg,
            exit_code=exit_code,
            rating=rating,
            rate=rate,
            vulnerabilities=vulnerabilities,
            missing_hardenings=missing_hardenings,
            duration_seconds=duration_seconds,
        )
        if not _send_webhook(context, payload):
            detail_lines.append("Webhook delivery failed (see debug log)")

    _fail(f"{msg}\n" + "\n".join(detail_lines) + f" | {perfdata}", exit_code)


def _webhook_should_fire(context: ScanContext, exit_code: NagiosExitCode) -> bool:
    """Decide whether the configured webhook applies to this result."""
    if not context.webhook_url:
        return False
    return exit_code in WEBHOOK_TRIGGERS.get(context.webhook_on, frozenset())


def _build_base_payload(
    context: ScanContext, message: str, exit_code: NagiosExitCode
) -> dict[str, Any]:
    """Build the fields every webhook payload carries, regardless of outcome."""
    return {
        "plugin": "check-nextcloud-security",
        "plugin_version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": context.host,
        "status": exit_code.name,
        "exit_code": int(exit_code),
        "message": message,
    }


def _build_webhook_payload(
    context: ScanContext,
    *,
    scan_result: ScanResult,
    response_scan: dict[str, Any],
    message: str,
    exit_code: NagiosExitCode,
    rating: int,
    rate: str,
    vulnerabilities: list[dict[str, Any]],
    missing_hardenings: list[str],
    duration_seconds: float | None,
) -> dict[str, Any]:
    """
    Build the JSON document posted to the webhook.

    The payload is intentionally flat and self-describing so it can be
    consumed by generic receivers (alertmanager bridges, chat bots, ticket
    systems) without needing to parse the plugin's human-readable output.
    """
    return {
        **_build_base_payload(context, message, exit_code),
        "rating": rating,
        "rating_label": rate,
        "product": response_scan.get("product"),
        "product_version": response_scan.get("version"),
        "domain": response_scan.get("domain"),
        "scanned_at": response_scan.get("scannedAt", {}).get("date"),
        "eol": bool(response_scan.get("EOL")) or rating == MIN_RATING,
        "vulnerability_count": len(vulnerabilities),
        "vulnerabilities": [
            entry.get("id") for entry in vulnerabilities if isinstance(entry, dict)
        ],
        "missing_hardenings": missing_hardenings if context.check_hardening else [],
        "scan_url": f"{SCAN_RESULT_URL}/{scan_result.uuid}",
        "scan_uuid": scan_result.uuid,
        "duration_seconds": round(duration_seconds, 3) if duration_seconds is not None else None,
    }


def _send_webhook(context: ScanContext, payload: dict[str, Any]) -> bool:
    """
    POST the payload to the configured webhook URL.

    Delivery is best-effort: a failing webhook is logged but never changes the
    check's own state, because the monitoring result must stay truthful about
    the Nextcloud instance rather than about the notification channel.
    """
    url = context.webhook_url
    if not url:
        return True

    headers = {"Content-Type": "application/json"}
    headers.update(dict(context.webhook_headers))
    proxies = _build_request_info(context).proxies

    LOGGER.debug("Posting %s webhook for %s to %s", payload["status"], context.host, url)

    def _post() -> None:
        response = requests.post(
            url,
            json=payload,
            headers=headers,
            proxies=proxies,
            timeout=context.webhook_timeout,
        )
        response.raise_for_status()

    try:
        _call_with_retry(
            _post,
            retries=context.retries,
            backoff_factor=context.backoff_factor,
            description=f"Webhook notification for {context.host}",
        )
    except REQUEST_ERRORS as exc:
        LOGGER.warning("Webhook notification for %s failed: %s", context.host, exc)
        LOGGER.debug("Webhook failure detail", exc_info=True)
        return False

    LOGGER.debug("Webhook notification for %s delivered", context.host)
    return True


def _notify_and_fail(
    context: ScanContext,
    message: str,
    exit_code: NagiosExitCode = NagiosExitCode.UNKNOWN,
) -> NoReturn:
    """
    Fire the webhook (if configured for this state) and then terminate.

    Used for aborts that happen before a scan result exists, so that an
    unreachable instance can raise an alert just like a vulnerable one.
    """
    if _webhook_should_fire(context, exit_code):
        payload = _build_base_payload(context, message, exit_code)
        if not _send_webhook(context, payload):
            message = f"{message}\nWebhook delivery failed (see debug log)"
    _fail(message, exit_code)


def _evaluate_rating(
    context: ScanContext,
    response_scan: dict[str, Any],
    rating: int,
    num_vulns: int,
) -> tuple[str, NagiosExitCode]:
    """
    Map a scan rating and vulnerability count onto a Nagios state.

    The rating thresholds (context.warning_rating / context.critical_rating)
    are inclusive: a rating at or below the threshold triggers that state.
    Known vulnerabilities always raise the state to at least WARNING, even
    when the rating itself still looks acceptable.
    """
    if rating not in RATE_MAP:
        return "UNKNOWN: Scan result unclear. Please verify manually.", NagiosExitCode.UNKNOWN

    rate = RATE_MAP[rating]
    is_eol = bool(response_scan.get("EOL")) or rating == MIN_RATING

    if is_eol:
        return (
            "CRITICAL: This server version is end-of-life and has no security fixes.",
            NagiosExitCode.CRITICAL,
        )

    if rating <= context.critical_rating:
        if num_vulns:
            return (
                f"CRITICAL: Found {num_vulns} vulnerabilities (rating {rate}).",
                NagiosExitCode.CRITICAL,
            )
        return (
            (
                f"CRITICAL: Rating {rate} is at or below the critical threshold "
                f"{RATE_MAP[context.critical_rating]}."
            ),
            NagiosExitCode.CRITICAL,
        )

    if num_vulns:
        return (
            f"WARNING: Found {num_vulns} vulnerabilities (rating {rate}).",
            NagiosExitCode.WARNING,
        )

    if rating <= context.warning_rating:
        return (
            (
                f"WARNING: Rating {rate} is at or below the warning threshold "
                f"{RATE_MAP[context.warning_rating]}, but no known vulnerabilities."
            ),
            NagiosExitCode.WARNING,
        )

    if rating == MAX_RATING:
        return "OK: Server is up to date. No known vulnerabilities.", NagiosExitCode.OK
    return "OK: Update available, but no known vulnerabilities.", NagiosExitCode.OK


def _format_vulnerabilities(vulnerabilities: list[dict[str, Any]], limit: int = 5) -> str:
    """Summarize vulnerability identifiers, truncating long lists."""
    names = [
        str(entry.get("id") or entry.get("cwe") or "unnamed")
        for entry in vulnerabilities
        if isinstance(entry, dict)
    ]
    shown = names[:limit]
    remaining = len(names) - len(shown)
    summary = ", ".join(shown) if shown else "details unavailable"
    return f"{summary} (+{remaining} more)" if remaining > 0 else summary


def _collect_missing_hardenings(response_scan: dict[str, Any]) -> list[str]:
    """
    List the hardening measures the Scan API reported as absent.

    Covers the 'hardenings' block (brute-force protection, CSPv3, ...), the
    security-related response headers under 'setup.headers', and whether
    HTTPS is enforced.
    """
    missing: list[str] = []

    hardenings = response_scan.get("hardenings")
    if isinstance(hardenings, dict):
        missing.extend(name for name, enabled in sorted(hardenings.items()) if not enabled)

    setup = response_scan.get("setup")
    if isinstance(setup, dict):
        https = setup.get("https")
        if isinstance(https, dict) and not https.get("enforced", True):
            missing.append("httpsEnforced")

        headers = setup.get("headers")
        if isinstance(headers, dict):
            missing.extend(name for name, enabled in sorted(headers.items()) if not enabled)

    return missing


def _build_perfdata(
    rating: int,
    rate_map: dict[int, str],
    num_vulns: int,
    duration_seconds: float | None,
    context: ScanContext | None = None,
    missing_hardenings: int | None = None,
) -> str:
    """
    Build a Nagios/Icinga performance data string.

    Format reference: 'label'=value[UOM];[warn];[crit];[min];[max]
    See https://nagios-plugins.org/doc/guidelines.html#AEN200

    The rating metric carries the configured warning/critical thresholds so
    that graphing frontends can render them alongside the measured value.
    """
    rating_value = str(rating) if rating in rate_map else "U"
    # Nagios range syntax: '@start:end' means "alert when inside the range",
    # which matches our inclusive at-or-below-threshold semantics.
    warn = f"@{MIN_RATING}:{context.warning_rating}" if context else ""
    crit = f"@{MIN_RATING}:{context.critical_rating}" if context else ""
    parts = [
        f"rating={rating_value};{warn};{crit};0;5",
        f"vulnerabilities={num_vulns};;;0;",
    ]
    if duration_seconds is not None:
        parts.append(f"time={duration_seconds:.3f}s;;;0;")
    if missing_hardenings is not None:
        parts.append(f"hardenings_missing={missing_hardenings};;;0;")
    return " ".join(parts)


# --- Main ---
def build_arg_parser() -> argparse.ArgumentParser:
    """
    Build and return the command-line argument parser.

    Every option can also be supplied via a CNS_-prefixed environment
    variable (e.g. CNS_HOST, CNS_PROXY). An explicit command-line flag
    always takes precedence over its environment variable counterpart.
    """
    parser = argparse.ArgumentParser(
        prog="check_nextcloud_security",
        description=__doc__,
    )

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}\nhttps://github.com/sowoi/check-nextcloud-security",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=_env_bool("DEBUG"),
        help=f"Enable debug mode. Default: False (env: {ENV_PREFIX}DEBUG).",
    )
    parser.add_argument(
        "-H",
        "--host",
        required=_env("HOST") is None,
        default=_env("HOST"),
        help=(
            "Nextcloud server address (hostname, not IP). Accepts a comma-separated "
            "list (e.g. 'a.example.com,b.example.com') to check multiple hosts in "
            f"one run. Required, env: {ENV_PREFIX}HOST."
        ),
    )
    parser.add_argument(
        "-P",
        "--proxy",
        default=_env("PROXY"),
        help=f"Proxy server address. Default: None (env: {ENV_PREFIX}PROXY).",
    )
    parser.add_argument(
        "-r",
        "--rescan",
        action="store_true",
        default=_env_bool("RESCAN"),
        help=f"Trigger rescan on every check. Default: False (env: {ENV_PREFIX}RESCAN).",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=_env_int("RETRIES", DEFAULT_RETRIES),
        help=(
            f"Number of retry attempts for transient network errors. "
            f"Default: {DEFAULT_RETRIES} (env: {ENV_PREFIX}RETRIES)."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=_env_int("TIMEOUT", DEFAULT_TIMEOUT_SECONDS),
        help=(
            f"HTTP timeout in seconds for each Scan API call. "
            f"Default: {DEFAULT_TIMEOUT_SECONDS} (env: {ENV_PREFIX}TIMEOUT)."
        ),
    )
    parser.add_argument(
        "-w",
        "--warning",
        type=int,
        default=_env_int("WARNING", DEFAULT_WARNING_RATING),
        help=(
            "Rating (0-5) at or below which the check reports WARNING. "
            f"Default: {DEFAULT_WARNING_RATING} ({RATE_MAP[DEFAULT_WARNING_RATING]}), "
            f"env: {ENV_PREFIX}WARNING."
        ),
    )
    parser.add_argument(
        "-c",
        "--critical",
        type=int,
        default=_env_int("CRITICAL", DEFAULT_CRITICAL_RATING),
        help=(
            "Rating (0-5) at or below which the check reports CRITICAL. "
            f"Default: {DEFAULT_CRITICAL_RATING} ({RATE_MAP[DEFAULT_CRITICAL_RATING]}), "
            f"env: {ENV_PREFIX}CRITICAL."
        ),
    )
    parser.add_argument(
        "--check-hardening",
        action="store_true",
        default=_env_bool("CHECK_HARDENING"),
        help=(
            "Also report hardening measures and security headers the Scan API "
            "found missing, raising an otherwise OK result to WARNING. "
            f"Default: False (env: {ENV_PREFIX}CHECK_HARDENING)."
        ),
    )
    parser.add_argument(
        "--webhook-url",
        default=_env("WEBHOOK_URL"),
        help=(
            "Optional HTTP(S) endpoint that receives a JSON notification when the "
            "check reaches the state selected by --webhook-on. Disabled when unset "
            f"(env: {ENV_PREFIX}WEBHOOK_URL)."
        ),
    )
    parser.add_argument(
        "--webhook-on",
        choices=sorted(WEBHOOK_TRIGGERS),
        default=_env("WEBHOOK_ON") or DEFAULT_WEBHOOK_ON,
        help=(
            "Lowest state that triggers the webhook: 'critical' only, 'warning' and "
            "worse, 'unknown' and worse, or 'always'. "
            f"Default: {DEFAULT_WEBHOOK_ON} (env: {ENV_PREFIX}WEBHOOK_ON)."
        ),
    )
    parser.add_argument(
        "--webhook-header",
        action="append",
        default=None,
        metavar="NAME:VALUE",
        help=(
            "Extra HTTP header for the webhook request, e.g. "
            "'X-Auth-Token: <token>'. May be given multiple times "
            f"(env: {ENV_PREFIX}WEBHOOK_HEADERS, entries separated by ';')."
        ),
    )
    parser.add_argument(
        "--webhook-timeout",
        type=int,
        default=_env_int("WEBHOOK_TIMEOUT", DEFAULT_WEBHOOK_TIMEOUT_SECONDS),
        help=(
            f"HTTP timeout in seconds for the webhook call. "
            f"Default: {DEFAULT_WEBHOOK_TIMEOUT_SECONDS} (env: {ENV_PREFIX}WEBHOOK_TIMEOUT)."
        ),
    )
    parser.add_argument(
        "--backoff-factor",
        type=float,
        default=_env_float("BACKOFF_FACTOR", DEFAULT_BACKOFF_FACTOR),
        help=(
            f"Exponential backoff factor (in seconds) between retries. "
            f"Default: {DEFAULT_BACKOFF_FACTOR} (env: {ENV_PREFIX}BACKOFF_FACTOR)."
        ),
    )

    return parser


def _parse_webhook_headers(raw_headers: list[str] | None) -> tuple[tuple[str, str], ...]:
    """
    Parse 'Name: value' header strings into a tuple of pairs.

    Falls back to the CNS_WEBHOOK_HEADERS environment variable (entries
    separated by ';') when no --webhook-header flag was given. Entries without
    a colon are skipped with a warning rather than aborting the check.
    """
    entries = raw_headers
    if entries is None:
        env_value = _env("WEBHOOK_HEADERS")
        entries = env_value.split(";") if env_value else []

    headers: list[tuple[str, str]] = []
    for entry in entries:
        name, separator, value = entry.partition(":")
        if not separator or not name.strip():
            LOGGER.warning("Ignoring malformed webhook header %r (expected 'Name: value').", entry)
            continue
        headers.append((name.strip(), value.strip()))
    return tuple(headers)


def _validate_thresholds(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Reject rating thresholds outside 0-5 or with critical above warning."""
    for name in ("warning", "critical"):
        value = getattr(args, name)
        if not MIN_RATING <= value <= MAX_RATING:
            parser.error(
                f"--{name} must be a rating between {MIN_RATING} and {MAX_RATING}, got {value}."
            )
    if args.critical > args.warning:
        parser.error(
            f"--critical ({args.critical}) must not be higher than --warning ({args.warning})."
        )
    if args.timeout <= 0:
        parser.error(f"--timeout must be a positive number of seconds, got {args.timeout}.")
    if args.webhook_timeout <= 0:
        parser.error(
            "--webhook-timeout must be a positive number of seconds, "
            f"got {args.webhook_timeout}."
        )
    if args.webhook_url and not args.webhook_url.lower().startswith(("http://", "https://")):
        parser.error(f"--webhook-url must be an http(s) URL, got {args.webhook_url!r}.")


def _parse_hosts(raw_host: str) -> list[str]:
    """
    Split a --host value into a list of hosts.

    Accepts a single hostname or a comma-separated list (e.g.
    'a.example.com, b.example.com'). Blank entries (from stray commas or
    surrounding whitespace) are dropped.
    """
    return [part.strip() for part in raw_host.split(",") if part.strip()]


def _build_context(host: str, args: argparse.Namespace) -> ScanContext:
    """Build a ScanContext for a single host from the parsed CLI arguments."""
    return ScanContext(
        host=host,
        proxy=args.proxy,
        debug=args.debug,
        rescan=args.rescan,
        retries=args.retries,
        backoff_factor=args.backoff_factor,
        timeout=args.timeout,
        warning_rating=args.warning,
        critical_rating=args.critical,
        check_hardening=args.check_hardening,
        webhook_url=args.webhook_url,
        webhook_on=args.webhook_on,
        webhook_timeout=args.webhook_timeout,
        webhook_headers=_parse_webhook_headers(args.webhook_header),
    )


# Priority used to determine the overall (worst) status across multiple
# hosts. UNKNOWN ranks below WARNING/CRITICAL so that a host we couldn't
# reach never masks a confirmed vulnerability found on another host.
_STATUS_PRIORITY: dict[NagiosExitCode, int] = {
    NagiosExitCode.CRITICAL: 3,
    NagiosExitCode.WARNING: 2,
    NagiosExitCode.UNKNOWN: 1,
    NagiosExitCode.OK: 0,
}


def _aggregate_exit_code(exit_codes: list[NagiosExitCode]) -> NagiosExitCode:
    """Return the worst status among exit_codes (CRITICAL > WARNING > UNKNOWN > OK)."""
    return max(exit_codes, key=lambda code: _STATUS_PRIORITY.get(code, 0))


def _run_single_host_check(context: ScanContext) -> tuple[str, NagiosExitCode]:
    """
    Run the full scan-and-check flow for a single host.

    Unlike calling check_if_ip_or_host/send_scan_request/check_vulnerabilities
    directly, this captures the printed result and exit code instead of
    terminating the process, so that a list of hosts can be processed one
    by one without one host's failure aborting the rest.
    """
    buffer = io.StringIO()
    exit_code = NagiosExitCode.UNKNOWN
    try:
        with contextlib.redirect_stdout(buffer):
            check_if_ip_or_host(context.host)
            start = time.perf_counter()
            scan_result = send_scan_request(context)
            duration_seconds = time.perf_counter() - start
            check_vulnerabilities(context, scan_result, duration_seconds=duration_seconds)
    except SystemExit as exc:
        if isinstance(exc.code, int):
            exit_code = NagiosExitCode(exc.code)
    return buffer.getvalue().rstrip("\n"), exit_code


def _summarize_multi_host_result(exit_codes: list[NagiosExitCode]) -> str:
    """Build a one-line summary of how many hosts ended up in each status."""
    counts = Counter(code.name for code in exit_codes)
    breakdown = ", ".join(
        f"{counts[name]} {name}"
        for name in ("CRITICAL", "WARNING", "UNKNOWN", "OK")
        if counts.get(name)
    )
    overall = _aggregate_exit_code(exit_codes)
    return f"Checked {len(exit_codes)} host(s): overall {overall.name} ({breakdown})"


def _run_multi_host_checks(hosts: list[str], args: argparse.Namespace) -> NagiosExitCode:
    """
    Run the scan-and-check flow for each host in turn.

    Prints a summary line followed by one result block per host, and
    returns the aggregated (worst) exit code across all hosts.
    """
    blocks = []
    exit_codes = []
    for host in hosts:
        context = _build_context(host, args)
        LOGGER.debug("Starting scan for host: %s", context.host)
        message, exit_code = _run_single_host_check(context)
        blocks.append(f"[{host}]\n{message}")
        exit_codes.append(exit_code)

    print(_summarize_multi_host_result(exit_codes))
    print()
    print("\n\n".join(blocks))

    return _aggregate_exit_code(exit_codes)


def main() -> None:
    """Main entry point."""
    parser = build_arg_parser()
    args = parser.parse_args()

    hosts = _parse_hosts(args.host or "")
    if not hosts:
        parser.error(f"--host must not be empty (or set the {ENV_PREFIX}HOST environment variable).")

    _validate_thresholds(parser, args)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if len(hosts) == 1:
        context = _build_context(hosts[0], args)
        LOGGER.debug("Starting scan for host: %s", context.host)

        check_if_ip_or_host(context.host)

        start = time.perf_counter()
        scan_result = send_scan_request(context)
        duration_seconds = time.perf_counter() - start

        check_vulnerabilities(context, scan_result, duration_seconds=duration_seconds)
        return

    LOGGER.debug("Starting scan for %d hosts: %s", len(hosts), ", ".join(hosts))
    exit_code = _run_multi_host_checks(hosts, args)
    sys.exit(int(exit_code))


if __name__ == "__main__":
    main()
