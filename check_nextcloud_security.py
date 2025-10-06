#! /usr/bin/python3
"""Check nextcloud instance for known vulnerabilities on scan.nextcloud.com"""
# Developer: Massoud Ahmed, Georg Schlagholz (IT-Native GmbH)

# pylint: disable=invalid-name,line-too-long

import argparse
import logging
import re
import sys

import requests

LOGGER = logging.getLogger("check_nextcloud")


def checkIfIPorHost(host, debug):
    """Check if the host is an IP address or a hostname"""
    regex = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    result = regex.match(host)
    if debug:
        print(result)
    if result:
        print("IP addresses are not supported by the Scan API.")
        sys.exit(3)


def checkVulnerabilities(
    host, proxy
):  # pylint: disable=too-many-branches,too-many-locals,too-many-statements
    """Check the Nextcloud instance for known vulnerabilities"""
    c = 0
    w = 0

    headers = {
        "Content-type": "application/x-www-form-urlencoded",
        "X-CSRF": "true",
    }
    data = {
        "url": host,
    }

    LOGGER.debug("Scanning server adress %s", host)

    if proxy is not None:
        LOGGER.debug("Using proxy %s", proxy)
        proxies = {
            "http": proxy,
            "https": proxy,
        }

        response = requests.post(
            "https://scan.nextcloud.com/api/queue",
            headers=headers,
            data=data,
            proxies=proxies,
            timeout=10,
        )
    else:
        response = requests.post(
            "https://scan.nextcloud.com/api/queue", headers=headers, data=data, timeout=10
        )
    try:
        answer = response.json()
    except Exception as e:  # pylint: disable=broad-except
        print(
            "UNKNOWN: ",
            host,
            "Scan failed! The scan for",
            host,
            "failed. Either no Nextcloud or ownCloud can be found there or you tried to scan too many servers: ",
            e,
        )
        sys.exit(3)
    LOGGER.debug("Got response from scan.nextcloud.com: \n%s", answer)
    if isinstance(answer, str) and answer == "Too many instances queued.":
        LOGGER.warning("Nextcloud scan is rate limited: Too many instances queued.")
        print(
            "UNKNOWN: ",
            host,
            "Scan failed! The scan for",
            host,
            "failed, because: ",
            answer,
        )
        sys.exit(3)
    uuidSite = "https://scan.nextcloud.com/api/result/" + str(answer["uuid"])
    LOGGER.debug("UUID is: %s", str(answer["uuid"]))
    if proxy is not None:
        checkUUID = requests.get(uuidSite, proxies=proxies, timeout=10)
    else:
        checkUUID = requests.get(uuidSite, timeout=10)
    responseScan = checkUUID.json()

    rating = responseScan["rating"]

    if rating == 5:
        rate = "A+"
    elif rating == 4:
        rate = "A"
    elif rating == 3:
        rate = "C"
        w = 1
    elif rating == 2:
        rate = "D"
        w = 1
    elif rating == 1:
        rate = "E"
        c = 1
    elif rating == 0:
        rate = "F"
        c = 1
        msg = "CRITICAL: This server version is end of life and has no security fixes anymore."
    else:
        rate = "Unknown"
        c = 1

    if len(responseScan["vulnerabilities"]) == 0:
        if rating == 5:
            msg = "OK: Server is up to date. No known vulnerabilities"
        elif rating == 4:
            msg = "OK: Update available, but no known vulnerabilities"

    else:
        if rating == 1:
            c = 1
            msg = (
                "CRITICAL: found ",
                str(len(responseScan["vulnerabilities"])),
                ' vulnerabilities. This server is vulnerable to at least one vulnerability rated "high"',
            )
        elif rating == 2:
            w = 1
            msg = (
                "Warning: found ",
                str(len(responseScan["vulnerabilities"])),
                ' vulnerabilities. This server is vulnerable to at least one vulnerability rated "medium".',
            )
        elif rating == 3:
            w = 1
            msg = (
                "Warning: found ",
                str(len(responseScan["vulnerabilities"])),
                ' vulnerabilities. This server is vulnerable to at least one vulnerability rated "low".',
            )

    scanDate = responseScan["scannedAt"]["date"]

    # Set the message if none was set before
    if not msg:
        msg = "UNKNOWN: The scan result is unknown. Please check the scan result manually."

    if c == 1:
        print(
            msg,
            "\n",
            responseScan["product"],
            responseScan["version"],
            " on",
            responseScan["domain"],
            ", rating is",
            rate,
            ", last scanned:",
            scanDate,
        )
        sys.exit(2)
    elif w == 1:
        print(
            msg,
            "\n",
            responseScan["product"],
            responseScan["version"],
            " on ",
            responseScan["domain"],
            ", rating is ",
            rate,
            ", last scanned: ",
            scanDate,
        )
        sys.exit(1)
    else:
        print(
            msg,
            "\n",
            responseScan["product"],
            responseScan["version"],
            " on ",
            responseScan["domain"],
            ", rating is ",
            rate,
            ", last scanned: ",
            scanDate,
        )
        sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)

    # Sub-groups using ArgumentParser groups
    gen_opts = parser.add_argument_group("Generic options")
    host_opts = parser.add_argument_group("Host options")
    proxy_opts = parser.add_argument_group("Proxy options")

    # -d / --debug
    gen_opts.add_argument(
        "-d",
        "--debug",
        dest="debug",
        default=False,
        action="store_true",
        help="Enable debugging outputs (default: no)",
    )

    # -H / --host
    host_opts.add_argument(
        "-H",
        "--host",
        dest="host",
        default=None,
        metavar="HOST",
        help="Nextcloud server address",
    )

    # -P / --proxy
    proxy_opts.add_argument(
        "-P",
        "--proxy",
        dest="proxy",
        default=None,
        metavar="HOST",
        help="Proxy server address",
    )

    # parse arguments
    options = parser.parse_args()


    if (options.host) is None:
        print("Please define host IP or hostname. Use -h to show help")
        sys.exit(3)

    # set loggin
    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
        LOGGER.setLevel(logging.DEBUG)
    else:
        logging.basicConfig()
        LOGGER.setLevel(logging.INFO)
    checkIfIPorHost(options.host, options.debug)
    checkVulnerabilities(options.host, options.proxy)
