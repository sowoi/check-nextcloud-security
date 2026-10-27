# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

New entries are added on top by the release workflow whenever the version in
`pyproject.toml` changes; the same entry is written to `RELEASE.md` and used as
the body of the GitHub release.

## [1.4.1] - 2026-10-27

### Added

- **Python 3.15 support.** The test matrix, mypy configuration and the Docker
  image now cover Python 3.15.
- **CI.** The Python version check runs as a parallel matrix (3.10 to 3.15),
  `uv lock --check` guards `uv.lock`, and a new `docker build` workflow builds
  the image and smoke-tests the plugin and the scanner health probe.
  Dependabot now also updates Docker images and GitHub Actions.

### Changed

- **Docker image runs on Python 3.15 by default** (`python:3.15-slim`) and uses
  uv 0.13.6.
- **Dependencies updated** to the latest releases: `certifi`, `types-requests`,
  `mypy`, `nox` and `pytest-mock`.
- **`uv.lock` is now tracked** in version control.
- **Hardened `docker-compose.yml`:** read-only root filesystem, all
  capabilities dropped and `no-new-privileges` for scanner and check.

### Fixed

- **nox tested every session with the same Python.** `test` is a dependency
  group, not an extra, so pytest was never installed into the session
  environment and the outer one was used. Each session now installs its own
  test tools and runs `python -m pytest` with its own interpreter.

## [1.4.0] - 2026-08-12

### Added

- **Local scan backend.** `--scan-backend local` runs the scan.nextcloud.com
  checks in-process, so no data leaves your network. IP addresses and custom
  ports are accepted as `--host`.
- **Self-hosted scanner container.** The new `check-nextcloud-scanner serve`
  entry point implements the Scan API (`/api/queue`, `/api/result/<uuid>`,
  `/api/requeue`, `/api/scan`, `/healthz`) with optional token authentication
  and a per-host result cache. Point the plugin at it with `--scan-url`.
  A `docker-compose.yml` starts scanner and check together.
- **Additional security checks** beyond the public scanner (`extraChecks`):
  TLS handshake, protocol and certificate expiry; `Strict-Transport-Security`,
  `Content-Security-Policy` and `Referrer-Policy`; exposed installation files
  (`config.php`, `.ocdata`, logs, `.htaccess`, `3rdparty/`); directory listing;
  unauthenticated WebDAV; web server and PHP version disclosure; maintenance
  mode and pending database upgrades. Disable with `--no-extra-checks`.
- **Update check against the local instance** via the serverinfo app - either
  the OCS API (`--serverinfo-mode api`) or the command line
  (`--serverinfo-mode occ`, optionally inside a container via
  `--serverinfo-container`). `--update-warning` turns a pending update into a
  WARNING; `--no-update-check` (or `--serverinfo-mode off`) disables it
  entirely.
- **Configuration file and secret provider.** All options can be set in YAML
  (`--config`, `CNS_CONFIG_FILE`, `./check-nextcloud-security.yml`,
  `/etc/check-nextcloud-security/config.yml`) and every value may be a
  `secret://`, `file://`, `env://` or `exec://` reference, or use the `_FILE`
  convention. Precedence is command line > environment > file > default.
- **End-of-life detection for the local backend.** The supported Nextcloud
  major releases are bundled in
  `nextcloud_local_scan/data/supported_versions.json` and scraped from the
  official maintenance and release schedule by
  `scripts/update_supported_versions.py`. Any major release below the oldest
  supported one is now rated `F`, matching scan.nextcloud.com; the public
  updater server cannot make that distinction on its own. A release workflow
  step and a monthly scheduled workflow keep the file current. Configurable via
  `scanner.use_release_schedule` and `scanner.supported_majors`.
- **ownCloud and Infinite Scale** are supported by the local backend: single
  page frontends that answer every path with HTTP 200 no longer produce phantom
  "exposed path" findings, and the Nextcloud-specific hardening matrix and
  release schedule are skipped for other products.
- **Local advisory database** with support for additional files and a JSON
  feed, in the native and the GitHub Advisory format.
- New performance data `extra_checks_failed` and `update_available`; the
  webhook payload gained `failed_extra_checks`, `scan_backend` and `update`.
- Secret templates in `secrets/` (`scanner_token.example`,
  `serverinfo_token.example`) plus setup instructions for `docker-compose.yml`.
- `nextcloud_local_scan/README.md` documenting how local results can differ
  from scan.nextcloud.com (end-of-life detection, advisory data, rating caps)
  and what applies when scanning ownCloud.
- `CHANGELOG.md`, `RELEASE.md` and a release workflow that maintains both.

### Changed

- The default remains scan.nextcloud.com - local scanning is strictly opt-in
  and the output format, thresholds and exit codes are unchanged.
- `--rescan` is a no-op for the local backend, which always scans fresh.
- PyYAML is now a runtime dependency.
- `uv` is the single dependency manager: `requirements.txt` was removed (its
  contents are declared in `pyproject.toml` and pinned in `uv.lock`), and the
  Docker image is built with `uv build` / `uv pip install`. Generate a
  `requirements.txt` on demand with `uv export` if a deployment tool needs one.
- README: pipx/uv/pip is now the primary installation route (Docker follows as
  an alternative), local scanning is introduced up front, and updating with
  pipx/uv/pip is documented. The release process moved to `CONTRIBUTING.md`.
- `.dockerignore` keeps secrets, virtualenvs, caches, tests and deployment
  helpers out of the build context.

### Fixed

- `--host` now accepts a full URL (`https://cloud.example.com/`) and reduces it
  to the bare host instead of passing the URL on to the scan service.
- A scan service that cannot be reached is reported as such, rather than as
  "no Nextcloud/ownCloud found or too many scans queued".
- Wheel build failed with "A second file is being added to the wheel archive"
  because `nextcloud_local_scan/data` was both packaged and force-included.
  The package data is now included exactly once, and
  `check_nextcloud_security.py` is no longer missing from the wheel.

## [1.3.0] - 2026-08-07

### Added

- Additional webhook configuration parameters and end-to-end tests.

### Fixed

- Missing error statements in the check output.
