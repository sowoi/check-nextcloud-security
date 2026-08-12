"""
Entry point used by the end-to-end tests to run the plugin as a real process.

The plugin defaults to the scan.nextcloud.com endpoints, so this launcher
repoints its base URL at the fake Scan API (see ``tests/fake_scan_server.py``)
via the ``CNS_TEST_SCAN_BASE_URL`` environment variable before delegating to the
plugin's own ``main()``. Everything else -- argument parsing, HTTP handling,
retries, output formatting and the exit code -- runs unmodified.

The default is patched rather than ``--scan-url`` being passed so that tests
which set ``--scan-url`` themselves keep testing the real precedence rules.
"""
import os
import sys

import check_nextcloud_security as cns


def run() -> None:
    """Redirect the Scan API endpoints to the fake server and run the plugin."""
    cns.DEFAULT_SCAN_BASE_URL = os.environ["CNS_TEST_SCAN_BASE_URL"].rstrip("/")
    cns.main()


if __name__ == "__main__":
    try:
        run()
    except SystemExit:
        raise
    except Exception as exc:  # pragma: no cover - defensive, surfaces crashes in tests
        print(f"E2E runner crashed: {exc!r}", file=sys.stderr)
        raise
