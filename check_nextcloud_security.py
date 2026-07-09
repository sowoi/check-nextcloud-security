#!/usr/bin/env python3
"""
Check a Nextcloud instance for known vulnerabilities using scan.nextcloud.com API.
Authors: Massoud Ahmed, Georg Schlagholz (IT-Native GmbH)
"""
import argparse
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, List, NoReturn, Optional, TypeVar

import requests

__version__ = "1.1.0"

LOGGER = logging.getLogger("check_nextcloud")

SCAN_QUEUE_URL = "https://scan.nextcloud.com/api/queue"
SCAN_RESULT_URL = "https://scan.nextcloud.com/api/result"
SCAN_REQUEUE_URL = "https://scan.nextcloud.com/api/requeue"

REQUEST_TIMEOUT_SECONDS = 10

# Prefix for all environment variables recognized by this plugin, e.g. CNS_HOST.
ENV_PREFIX = "CNS_"

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


@dataclass(frozen=True)
class ScanContext:
    """Immutable configuration for a single scan run."""

    host: str
    proxy: Optional[str] = None
    debug: bool = False
    rescan: bool = False
    retries: int = DEFAULT_RETRIES
    backoff_factor: float = DEFAULT_BACKOFF_FACTOR


@dataclass(frozen=True)
class ScanRequestInfo:
    """HTTP request parameters shared by all calls to the Scan API."""

    headers: Dict[str, str] = field(default_factory=lambda: {
        "Content-type": "application/x-www-form-urlencoded",
        "X-CSRF": "true",
    })
    data: Dict[str, str] = field(default_factory=dict)
    proxies: Optional[Dict[str, str]] = None


@dataclass
class ScanResult:
    """Result of a completed (or in-progress) scan lookup."""

    response: Dict[str, Any]
    uuid: str


# --- Environment variable helpers ---
def _env(name: str) -> Optional[str]:
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
    """Exit if host is an IP address (not supported by the API)."""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
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
            timeout=REQUEST_TIMEOUT_SECONDS,
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
        _fail(
            f"UNKNOWN: {context.host} Scan failed! Either no Nextcloud/ownCloud found "
            f"or too many scans queued: {exc}"
        )

    LOGGER.debug("Response from scan.nextcloud.com: %s", answer)

    if isinstance(answer, str) and "Too many instances" in answer:
        _fail(f"UNKNOWN: {context.host} Scan failed! Reason: {answer}")

    uuid: Optional[str] = answer.get("uuid")
    if not uuid:
        _fail(f"UNKNOWN: Failed to retrieve scan UUID for {context.host}.")

    def _fetch_result() -> Any:
        return requests.get(
            f"{SCAN_RESULT_URL}/{uuid}",
            proxies=request_info.proxies,
            timeout=REQUEST_TIMEOUT_SECONDS,
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
        _fail(f"UNKNOWN: Could not retrieve scan results for {context.host}: {exc}")

    return ScanResult(response=response_scan, uuid=uuid)


def check_vulnerabilities(
    context: ScanContext,
    scan_result: ScanResult,
    duration_seconds: Optional[float] = None,
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
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            return requests.get(
                uuid_url, proxies=request_info.proxies, timeout=REQUEST_TIMEOUT_SECONDS
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
            _fail(f"UNKNOWN: Failed to rescan {scan_result.uuid}: {exc}")

    rating: int = response_scan.get("rating", -1)
    product: str = response_scan.get("product", "Unknown")
    version: str = response_scan.get("version", "Unknown")
    domain: str = response_scan.get("domain", "Unknown")
    scan_date: str = response_scan.get("scannedAt", {}).get("date", "Unknown")

    rate_map: Dict[int, str] = {5: "A+", 4: "A", 3: "C", 2: "D", 1: "E", 0: "F"}
    rate: str = rate_map.get(rating, "Unknown")

    vulnerabilities: List[Dict[str, Any]] = response_scan.get("vulnerabilities", [])
    num_vulns: int = len(vulnerabilities)

    msg: str = "UNKNOWN: Scan result unclear. Please verify manually."
    exit_code: NagiosExitCode = NagiosExitCode.UNKNOWN

    if rating in {5, 4} and num_vulns == 0:
        msg = (
            "OK: Server is up to date. No known vulnerabilities."
            if rating == 5
            else "OK: Update available, but no known vulnerabilities."
        )
        exit_code = NagiosExitCode.OK

    elif num_vulns > 0:
        severity_map = {1: "high", 2: "medium", 3: "low"}
        severity = severity_map.get(rating, "unknown")

        if rating <= 1:
            msg = f"CRITICAL: Found {num_vulns} vulnerabilities (at least one {severity})."
            exit_code = NagiosExitCode.CRITICAL
        elif rating <= 3:
            msg = f"WARNING: Found {num_vulns} vulnerabilities (at least one {severity})."
            exit_code = NagiosExitCode.WARNING
    elif rating == 0:
        msg = "CRITICAL: This server version is end-of-life and has no security fixes."
        exit_code = NagiosExitCode.CRITICAL

    _fail(
        f"{msg}\n{product} {version} on {domain}, rating: {rate}, last scanned: {scan_date} "
        f"| {_build_perfdata(rating, rate_map, num_vulns, duration_seconds)}",
        exit_code,
    )


def _build_perfdata(
    rating: int,
    rate_map: Dict[int, str],
    num_vulns: int,
    duration_seconds: Optional[float],
) -> str:
    """
    Build a Nagios/Icinga performance data string.

    Format reference: 'label'=value[UOM];[warn];[crit];[min];[max]
    See https://nagios-plugins.org/doc/guidelines.html#AEN200
    """
    rating_value = str(rating) if rating in rate_map else "U"
    parts = [
        f"rating={rating_value};;;0;5",
        f"vulnerabilities={num_vulns};;;0;",
    ]
    if duration_seconds is not None:
        parts.append(f"time={duration_seconds:.3f}s;;;0;")
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
        version=f"%(prog)s {__version__}",
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
        help=f"Nextcloud server address (hostname, not IP). Required, env: {ENV_PREFIX}HOST.",
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
        "--backoff-factor",
        type=float,
        default=_env_float("BACKOFF_FACTOR", DEFAULT_BACKOFF_FACTOR),
        help=(
            f"Exponential backoff factor (in seconds) between retries. "
            f"Default: {DEFAULT_BACKOFF_FACTOR} (env: {ENV_PREFIX}BACKOFF_FACTOR)."
        ),
    )

    return parser


def main() -> None:
    """Main entry point."""
    parser = build_arg_parser()
    args = parser.parse_args()

    host = args.host.strip() if args.host else ""
    if not host:
        parser.error(f"--host must not be empty (or set the {ENV_PREFIX}HOST environment variable).")

    context = ScanContext(
        host=host,
        proxy=args.proxy,
        debug=args.debug,
        rescan=args.rescan,
        retries=args.retries,
        backoff_factor=args.backoff_factor,
    )

    logging.basicConfig(
        level=logging.DEBUG if context.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    LOGGER.debug("Starting scan for host: %s", context.host)

    check_if_ip_or_host(context.host)

    start = time.perf_counter()
    scan_result = send_scan_request(context)
    duration_seconds = time.perf_counter() - start

    check_vulnerabilities(context, scan_result, duration_seconds=duration_seconds)


if __name__ == "__main__":
    main()
