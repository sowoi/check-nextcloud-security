"""
Command line interface of the local scan service.

``check-nextcloud-scanner serve``
    Start the Scan API compatible HTTP service (this is what the container
    image runs by default).
``check-nextcloud-scanner scan <host>``
    Scan a single instance and print the result document as JSON.

Every option can equally be set in the YAML configuration file, through a
``CNS_``-prefixed environment variable or through a secret reference.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from .config import ConfigurationError, load_configuration
from .factory import scanner_settings_from_config, serverinfo_settings_from_config
from .scanner import ScanError, scan
from .serverinfo import MODES
from .service import (
    DEFAULT_CACHE_TTL_SECONDS,
    DEFAULT_LISTEN,
    DEFAULT_PORT,
    ScanStore,
    serve,
)

LOGGER = logging.getLogger("check_nextcloud.cli")

__all__ = ["build_arg_parser", "main"]


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the scanner CLI."""
    parser = argparse.ArgumentParser(
        prog="check-nextcloud-scanner",
        description="Local, self-hosted replacement for the scan.nextcloud.com checks.",
    )
    parser.add_argument("-c", "--config", help="Path to the YAML configuration file.")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument(
        "--serverinfo-mode",
        choices=MODES,
        help="How to reach the local instance for update information (default: auto).",
    )
    parser.add_argument("--no-extra-checks", action="store_true",
                        help="Only run the checks scan.nextcloud.com performs.")
    parser.add_argument("--insecure", action="store_true",
                        help="Do not verify TLS certificates of the scanned instance.")

    subparsers = parser.add_subparsers(dest="command")

    serve_parser = subparsers.add_parser("serve", help="Run the Scan API compatible service.")
    serve_parser.add_argument("--listen", help=f"Bind address. Default: {DEFAULT_LISTEN}.")
    serve_parser.add_argument("--port", type=int, help=f"Bind port. Default: {DEFAULT_PORT}.")
    serve_parser.add_argument(
        "--cache-ttl",
        type=int,
        help=f"Seconds a scan result is reused. Default: {DEFAULT_CACHE_TTL_SECONDS}.",
    )
    serve_parser.add_argument("--token", help="Require this token on every API request.")

    scan_parser = subparsers.add_parser("scan", help="Scan one instance and print JSON.")
    scan_parser.add_argument("host", nargs="?", help="Hostname of the Nextcloud instance.")

    return parser


def _configure_logging(debug: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main(argv: list[str] | None = None) -> int:
    """Entry point of the ``check-nextcloud-scanner`` command."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        config = load_configuration(args.config)
    except ConfigurationError as exc:
        parser.error(str(exc))

    _configure_logging(args.debug or config.get_bool("DEBUG"))
    if config.source:
        LOGGER.debug("Using configuration file %s", config.source)

    try:
        scanner_settings = scanner_settings_from_config(
            config,
            extra_checks=False if args.no_extra_checks else None,
            verify_tls=False if args.insecure else None,
        )
        serverinfo_settings = serverinfo_settings_from_config(
            config, mode=args.serverinfo_mode
        )
    except ConfigurationError as exc:
        parser.error(str(exc))

    command = args.command or "serve"

    if command == "scan":
        host = args.host or config.get("HOST")
        if not host:
            parser.error("No host given (argument, config key 'host' or CNS_HOST).")
        try:
            result = scan(host, scanner_settings, serverinfo_settings)
        except ScanError as exc:
            print(json.dumps({"error": str(exc), "domain": host}, indent=2))
            return 2
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    store = ScanStore(
        scanner_settings=scanner_settings,
        serverinfo_settings=serverinfo_settings,
        cache_ttl=args.cache_ttl or config.get_int("SERVICE_CACHE_TTL", DEFAULT_CACHE_TTL_SECONDS),
    )
    serve(
        store,
        listen=args.listen or config.get("SERVICE_LISTEN") or DEFAULT_LISTEN,
        port=args.port or config.get_int("SERVICE_PORT", DEFAULT_PORT),
        auth_token=args.token or config.get("SERVICE_TOKEN"),
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
