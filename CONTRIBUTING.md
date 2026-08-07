<!-- TOC -->
* [CONTRIBUTING](#contributing)
  * [Guidelines](#guidelines)
  * [Local setup](#local-setup)
    * [1. Install `uv`](#1-install-uv)
  * [Install Dependencies](#install-dependencies)
  * [Running Tests](#running-tests)
    * [End-to-end tests](#end-to-end-tests)
  * [Linting](#linting)
<!-- TOC -->

# CONTRIBUTING
We welcome and appreciate all contributions to this project! Before submitting a Pull Request (PR), please take a moment to review this guide.

---

## Guidelines

* Ensure your code adheres to the existing coding style.
* Write clear and concise commit messages.
* **Always** run the tests and linting before submitting a PR.
* Keep PRs focused on a single feature or fix.

---

## Local setup

We recommend using **`uv`** for managing dependencies and running development tasks.

### 1. Install `uv`

If you haven't already, install the `uv` package manager (or your preferred installation method):

```
pipx install uv
```

## Install Dependencies

Install the project's runtime dependencies along with the necessary development dependencies specified in the test group:

```
uv sync
```

## Running Tests
Tests are managed using pytest, and the required packages are defined in the test dependency group.

To run the complete test suite:
```
uv run --group test pytest
```

### End-to-end tests

`tests/test_e2e_scan_api.py` runs the plugin as a real subprocess against a
local stand-in for `scan.nextcloud.com` (`tests/fake_scan_server.py`). The
server replays canned responses modelled on the real Scan API (see
`tests/fixtures/`), so no Nextcloud instance, Docker container or internet
access is required.

To run only the end-to-end tests:
```
uv run --group test pytest tests/test_e2e_scan_api.py
```

To cover a new API behaviour, add a fixture to `tests/fixtures/` and register
it in `DEFAULT_FIXTURES` in `tests/fake_scan_server.py`.

## Linting
We use Ruff for linting and code formatting checks.

To run the linting check:
```
uvx ruff check
```
