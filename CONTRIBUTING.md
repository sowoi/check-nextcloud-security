<!-- TOC -->
* [CONTRIBUTING](#contributing)
  * [Guidelines](#guidelines)
  * [Local setup](#local-setup)
    * [1. Install `uv`](#1-install-uv)
  * [Install Dependencies](#install-dependencies)
    * [Exporting a requirements.txt](#exporting-a-requirementstxt)
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

`uv` is the only dependency manager this project uses. Every dependency is
declared in `pyproject.toml` and pinned in `uv.lock` - there is no
`requirements.txt`, and none should be added.

Install the runtime dependencies together with the development dependencies
from the `test` group:

```
uv sync --group test
```

Add or change a dependency by editing `pyproject.toml` (or with
`uv add <package>` / `uv add --group test <package>`) and committing the
updated `uv.lock`.

### Exporting a requirements.txt

Some deployment tools still expect a `requirements.txt`. Generate it from the
lock file rather than maintaining it by hand, and treat it as a build artefact
that is never committed:

```
uv export --no-dev --no-emit-project --format requirements.txt -o requirements.txt

# without hashes, if the consuming tool cannot handle them:
uv export --no-dev --no-emit-project --no-hashes --format requirements.txt -o requirements.txt
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

## Releasing
Releases are driven entirely by the `version` field in `pyproject.toml`.

1. Open a pull request that bumps the version. As long as no tag `v<version>`
   exists, the [release-notes workflow](.github/workflows/release-notes.yml)
   runs `scripts/release_notes.py` and `scripts/update_supported_versions.py`
   on every push and commits the result to the pull request branch: the new
   section at the top of [`CHANGELOG.md`](CHANGELOG.md), `RELEASE.md`
   (overwritten on every release) and `supported_versions.json`. Edit the
   `CHANGELOG.md` section in the pull request if needed; `RELEASE.md` follows
   on the next push.
2. Once the pull request is merged, the
   [publish workflow](.github/workflows/publish-pypi.yml) builds the package,
   publishes it to PyPI, creates the tag `v<version>` and opens a GitHub
   release with `RELEASE.md` as its body, followed by GitHub's generated
   "What's Changed" section.
3. `main` is protected, so the publish workflow never pushes to it. If the
   release notes on `main` were not up to date, it opens a follow-up pull
   request with the files the release was built with.

If `CHANGELOG.md` already contains a `## [<version>]` section, those
hand-written notes are used as-is. Otherwise they are generated from the commit
subjects since the previous tag, grouped by their
[Conventional Commit](https://www.conventionalcommits.org/) type (`feat` ->
Added, `fix` -> Fixed, `security` -> Security, ...; `chore`, `ci`, `build`,
`test` and `style` are skipped). Preview the result locally with:

```shell
python scripts/release_notes.py
```
