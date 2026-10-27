# syntax=docker/dockerfile:1
#
# Builds a self-contained image for check-nextcloud-security.
# End users do not need Python, pip, or uv installed on the host -
# only Docker. See README.md for usage examples.

FROM python:3.15-slim AS builder

# uv is this project's dependency manager and build front end; the same
# command is used in CI (see .github/workflows/publish-pypi.yml).
COPY --from=ghcr.io/astral-sh/uv:0.13.6 /uv /uvx /bin/

WORKDIR /src

# Only copy what is needed to build the wheel, keeping the build cache-friendly.
COPY pyproject.toml README.md LICENSE ./
COPY check_nextcloud_security.py ./
COPY nextcloud_local_scan ./nextcloud_local_scan

RUN uv build --wheel --out-dir /dist


FROM python:3.15-slim

LABEL org.opencontainers.image.title="check-nextcloud-security" \
      org.opencontainers.image.description="Nagios/Icinga plugin and self-hosted scanner for Nextcloud instances (scan.nextcloud.com compatible)" \
      org.opencontainers.image.source="https://github.com/sowoi/check-nextcloud-security" \
      org.opencontainers.image.licenses="GPL-3.0-only"

COPY --from=ghcr.io/astral-sh/uv:0.13.6 /uv /bin/
COPY --from=builder /dist/*.whl /tmp/

# Dependencies are resolved from the wheel metadata (pyproject.toml);
# this project has no requirements.txt - generate one with `uv export`
# if some tool of yours needs it.
RUN uv pip install --system --no-cache /tmp/*.whl \
    && rm -rf /tmp/*.whl /bin/uv \
    && useradd --no-create-home --shell /usr/sbin/nologin nagios

USER nagios

# Port of the built-in scan service (`check-nextcloud-scanner serve`).
EXPOSE 8080

ENTRYPOINT ["check-nextcloud-security"]
# No default CMD: with no arguments, the entrypoint relies entirely on
# CNS_-prefixed environment variables (see README.md "Environment variables").
# Run `docker run --rm check-nextcloud-security --help` explicitly for usage.
#
# The same image also ships the local scanner service. Start it with:
#   docker run --rm -p 8080:8080 \
#     --entrypoint check-nextcloud-scanner check-nextcloud-security serve
# and point the plugin at it with --scan-url http://<host>:8080.
