#!/usr/bin/env python3
"""
Check a Nextcloud instance for known vulnerabilities using scan.nextcloud.com API.
Authors: Massoud Ahmed, Georg Schlagholz (IT-Native GmbH)
"""
import argparse
import logging
import re
import sys
from typing import Any, Dict, Optional
from dataclasses import dataclass, field
import requests

LOGGER = logging.getLogger("check_nextcloud")
SCAN_QUEUE_URL = "https://scan.nextcloud.com/api/queue"
SCAN_RESULT_URL = "https://scan.nextcloud.com/api/result"
SCAN_REQUEUE_URL = "https://scan.nextcloud.com/api/requeue"


@dataclass(frozen=True)
class ScanContext:
    host: str
    proxy: Optional[str] = None
    debug: bool = False
    rescan: bool = False


@dataclass(frozen=True)
class ScanRequestInfo:
    headers: Dict[str, str] = field(default_factory=lambda: {
        "Content-type": "application/x-www-form-urlencoded",
        "X-CSRF": "true",
    })
    data: Dict[str, str] = field(default_factory=dict)
    proxies: Optional[Dict[str, str]] = None
    uuid: Optional[str] = None


@dataclass
class ScanResult:
    response: Dict[str, Any]
    uuid: str


# --- Utility Functions ---
def check_if_ip_or_host(host: str) -> None:
    """Exit if host is an IP address (not supported by the API)."""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        print("IP addresses are not supported by the Scan API.")
        sys.exit(3)


def send_scan_request(context: ScanContext) -> ScanResult:
    """Send initial security check request to the Nextcloud Scan Server."""

    request_info = ScanRequestInfo(
        data={"url": context.host},
        proxies={"http": context.proxy, "https": context.proxy} if context.proxy else None
    )

    LOGGER.debug("Initiating scan for host: %s", context.host)
    if context.proxy:
        LOGGER.debug("Using proxy: %s", context.proxy)

    try:
        response = requests.post(
            SCAN_QUEUE_URL,
            headers=request_info.headers,
            data=request_info.data,
            proxies=request_info.proxies,
            timeout=10,
        )
        response.raise_for_status()
        answer = response.json()
    except Exception as e:
        print(
            f"UNKNOWN: {context.host} Scan failed! Either no Nextcloud/ownCloud found "
            f"or too many scans queued: {e}"
        )
        sys.exit(3)

    LOGGER.debug("Response from scan.nextcloud.com: %s", answer)

    if isinstance(answer, str) and "Too many instances" in answer:
        print(f"UNKNOWN: {context.host} Scan failed! Reason: {answer}")
        sys.exit(3)

    uuid: Optional[str] = answer.get("uuid")
    if not uuid:
        print(f"UNKNOWN: Failed to retrieve scan UUID for {context.host}.")
        sys.exit(3)

    try:
        response_scan = requests.get(
            f"{SCAN_RESULT_URL}/{uuid}", proxies=request_info.proxies, timeout=10
        ).json()
    except Exception as e:
        print(f"UNKNOWN: Could not retrieve scan results for {context.host}: {e}")
        sys.exit(3)

    return ScanResult(response=response_scan, uuid=uuid)


def check_vulnerabilities(context: ScanContext, scan_result: ScanResult) -> None:
    """Check the Nextcloud instance for known vulnerabilities and print the result."""

    request_info = ScanRequestInfo(
        data={"url": context.host},
        proxies={"http": context.proxy, "https": context.proxy} if context.proxy else None
    )

    uuid_url = f"{SCAN_RESULT_URL}/{scan_result.uuid}"
    response_scan = scan_result.response

    if context.rescan:
        LOGGER.debug("Triggering rescan for %s", scan_result.uuid)
        try:
            requests.post(
                SCAN_REQUEUE_URL,
                headers=request_info.headers,
                data=request_info.data,
                proxies=request_info.proxies,
                timeout=10
            )
            response_scan = requests.get(uuid_url, proxies=request_info.proxies, timeout=10).json()
        except Exception as e:
            print(f"UNKNOWN: Failed to rescan {scan_result.uuid}: {e}")
            sys.exit(3)

    rating: int = response_scan.get("rating", -1)
    product: str = response_scan.get("product", "Unknown")
    version: str = response_scan.get("version", "Unknown")
    domain: str = response_scan.get("domain", "Unknown")
    scan_date: str = response_scan.get("scannedAt", {}).get("date", "Unknown")

    rate_map: Dict[int, str] = {5: "A+", 4: "A", 3: "C", 2: "D", 1: "E", 0: "F"}
    rate: str = rate_map.get(rating, "Unknown")

    vulnerabilities: list[Dict[str, Any]] = response_scan.get("vulnerabilities", [])
    num_vulns: int = len(vulnerabilities)

    msg: str = "UNKNOWN: Scan result unclear. Please verify manually."
    exit_code: int = 3

    if rating in {5, 4} and num_vulns == 0:
        msg = (
            "OK: Server is up to date. No known vulnerabilities."
            if rating == 5
            else "OK: Update available, but no known vulnerabilities."
        )
        exit_code = 0

    elif num_vulns > 0:
        severity_map = {1: "high", 2: "medium", 3: "low"}
        severity = severity_map.get(rating, "unknown")

        if rating <= 1:
            msg = f"CRITICAL: Found {num_vulns} vulnerabilities (at least one {severity})."
            exit_code = 2
        elif rating <= 3:
            msg = f"WARNING: Found {num_vulns} vulnerabilities (at least one {severity})."
            exit_code = 1
    elif rating == 0:
        msg = "CRITICAL: This server version is end-of-life and has no security fixes."
        exit_code = 2

    print(f"{msg}\n{product} {version} on {domain}, rating: {rate}, last scanned: {scan_date}")
    sys.exit(exit_code)


# --- Main ---
def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode.")
    parser.add_argument("-H", "--host", required=True, help="Nextcloud server address.")
    parser.add_argument("-P", "--proxy", default=None, help="Proxy server address.")
    parser.add_argument(
        "-r",
        "--rescan",
        action="store_true",
        default=False,
        help="Trigger rescan on every check. Default: False.",
    )

    args = parser.parse_args()

    context = ScanContext(
        host=args.host,
        proxy=args.proxy,
        debug=args.debug,
        rescan=args.rescan
    )

    logging.basicConfig(
        level=logging.DEBUG if context.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    LOGGER.debug("Starting scan for host: %s", context.host)

    check_if_ip_or_host(context.host)
    scan_result = send_scan_request(context)
    check_vulnerabilities(context, scan_result)


if __name__ == "__main__":
    main()