"""
Entry point used by the end-to-end tests to run the plugin as a real process.

The plugin hardcodes the scan.nextcloud.com endpoints, so this launcher points
them at the fake Scan API (see ``tests/fake_scan_server.py``) via the
``CNS_TEST_SCAN_BASE_URL`` environment variable before delegating to the
plugin's own ``main()``. Everything else -- argument parsing, HTTP handling,
retries, output formatting and the exit code -- runs unmodified.
"""
import os
import sys

import check_nextcloud_security as cns


def run() -> None:
    """Redirect the Scan API endpoints to the fake server and run the plugin."""
    base_url = os.environ["CNS_TEST_SCAN_BASE_URL"].rstrip("/")
    cns.SCAN_QUEUE_URL = f"{base_url}/api/queue"
    cns.SCAN_RESULT_URL = f"{base_url}/api/result"
    cns.SCAN_REQUEUE_URL = f"{base_url}/api/requeue"
    cns.main()


if __name__ == "__main__":
    try:
        run()
    except SystemExit:
        raise
    except Exception as exc:  # pragma: no cover - defensive, surfaces crashes in tests
        print(f"E2E runner crashed: {exc!r}", file=sys.stderr)
        raise
