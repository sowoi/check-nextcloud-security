#! /usr/bin/python3
# Check nextcloud instance for known vulnerabilities on scan.nextcloud.com
# Developer: Massoud Ahmed, Georg Schlagholz (IT-Native GmbH)


import logging
import re
import sys
from optparse import OptionGroup, OptionParser

import requests

LOGGER = logging.getLogger("check_nextcloud")


def checkIfIPorHost(host, logging):
    regex = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    result = regex.match(host)
    if logging:
        print(result)
    if result:
        print("IP addresses are not supported by the Scan API.")
        sys.exit(3)


def checkVulnerabilities(host, proxy):
    c = 0
    w = 0

    headers = {
        "Content-type": "application/x-www-form-urlencoded",
        "X-CSRF": "true",
    }
    data = {
        "url": host,
    }

    LOGGER.debug("Scanning server adress" + host)

    if proxy is not None:
        LOGGER.debug("Using proxy " + proxy)
        proxies = {
            "http": proxy,
            "https": proxy,
        }

        response = requests.post(
            "https://scan.nextcloud.com/api/queue",
            headers=headers,
            data=data,
            proxies=proxies,
        )
    else:
        response = requests.post(
            "https://scan.nextcloud.com/api/queue", headers=headers, data=data
        )
    try:
        answer = response.json()
    except Exception:
        print(
            "UNKNOWN: ",
            host,
            "Scan failed! The scan for",
            host,
            "failed. Either no Nextcloud or ownCloud can be found there or you tried to scan too many servers.",
        )
        sys.exit(3)
    LOGGER.debug("Got response from scan.nextcloud.com: \n", answer)
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
    LOGGER.debug("UUID is: " + str(answer["uuid"]))
    requeue = "https://scan.nextcloud.com/api/requeue"
    if proxy is not None:
        checkUUID = requests.get(uuidSite, proxies=proxies)
    else:
        checkUUID = requests.get(uuidSite)
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

    if rating == 0:
        c = 1
        critical = "CRITICAL: This server version is end of life and has no security fixes anymore."

    if len(responseScan["vulnerabilities"]) == 0:
        if rating == 5:
            ok = "OK: Server is up to date. No known vulnerabilities"
        elif rating == 4:
            ok = "OK: Update available, but no known vulnerabilities"

    else:
        if rating == 1:
            c = 1
            critical = (
                "CRITICAL: found ",
                str(len(responseScan["vulnerabilities"])),
                ' vulnerabilities.  This server is vulnerable to at least one vulnerability rated "high"',
            )
        elif rating == 2:
            w = 1
            warning = (
                "Warning: found ",
                str(len(responseScan["vulnerabilities"])),
                ' vulnerabilities. This server is vulnerable to at least one vulnerability rated "medium".',
            )
        elif rating == 3:
            w = 1
            warning = (
                "Warning: found ",
                str(len(responseScan["vulnerabilities"])),
                ' vulnerabilities. This server is vulnerable to at least one vulnerability rated "low".',
            )

    scanDate = responseScan["scannedAt"]["date"]

    if c == 1:
        print(
            critical,
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
            warning,
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
            ok,
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

    desc = """%prog checks your nextcloud server for vulnerabilities """
    parser = OptionParser(description=desc)
    gen_opts = OptionGroup(parser, "Generic options")
    host_opts = OptionGroup(parser, "Host options")
    proxy_opts = OptionGroup(parser, "Proxy options")

    parser.add_option_group(gen_opts)
    parser.add_option_group(host_opts)
    parser.add_option_group(proxy_opts)

    # -d / --debug
    gen_opts.add_option(
        "-d",
        "--debug",
        dest="debug",
        default=False,
        action="store_true",
        help="enable debugging outputs (default: no)",
    )

    # -H / --host
    host_opts.add_option(
        "-H",
        "--host",
        dest="host",
        default=None,
        action="store",
        metavar="HOST",
        help="Nextcloud server adress",
    )

    # -P / --proxy
    proxy_opts.add_option(
        "-P",
        "--proxy",
        dest="proxy",
        default=None,
        action="store",
        metavar="HOST",
        help="Nextcloud server adress",
    )

    # parse arguments
    (options, args) = parser.parse_args()

    host = options.host
    proxy = options.proxy

    if (options.host) is None:
        print("Please define host IP or hostname. Use -h to show help")
        exit(3)

    # set loggin
    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
        LOGGER.setLevel(logging.DEBUG)
    else:
        logging.basicConfig()
        LOGGER.setLevel(logging.INFO)
    checkIfIPorHost(host, options.debug)
    checkVulnerabilities(host, proxy)
