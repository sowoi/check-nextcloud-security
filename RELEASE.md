## check-nextcloud-security 1.5.0

### Added

- **Python 3.15 support.** The test matrix, mypy configuration and the Docker
  image now cover Python 3.15.
- **CI.** The Python version check runs as a parallel matrix (3.11 to 3.15),
  `uv lock --check` guards `uv.lock`, and a new `docker build` workflow builds
  the image and smoke-tests the plugin and the scanner health probe.
  Dependabot now also updates Docker images and GitHub Actions.

### Changed

- **Python 3.10 is no longer supported** (end of life); the minimum is now
  Python 3.11.
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
