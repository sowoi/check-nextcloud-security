import os

import pytest


@pytest.fixture(autouse=True)
def no_retry_sleep(monkeypatch):
    """
    Prevent the retry/backoff mechanism from actually sleeping during tests.

    Without this, tests that trigger retries (e.g. simulated network errors)
    would be slowed down by real time.sleep() calls.
    """
    monkeypatch.setattr("check_nextcloud_security.time.sleep", lambda seconds: None)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """
    Ensure CNS_-prefixed environment variables never leak into tests.

    Without this, a developer's local environment (or a previous test) could
    silently change argparse defaults and cause flaky test results.
    """
    for name in list(os.environ):
        if name.startswith("CNS_"):
            monkeypatch.delenv(name, raising=False)
