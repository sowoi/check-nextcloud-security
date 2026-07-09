# syntax=docker/dockerfile:1
#
# Builds a self-contained image for check-nextcloud-security.
# End users do not need Python, pip, or uv installed on the host -
# only Docker. See README.md for usage examples.

FROM python:3.13-slim AS builder

WORKDIR /src

# Only copy what is needed to build the wheel, keeping the build cache-friendly.
COPY pyproject.toml README.md LICENSE ./
COPY check_nextcloud_security.py ./

RUN pip install --no-cache-dir build \
    && python -m build --wheel --outdir /dist


FROM python:3.13-slim

LABEL org.opencontainers.image.title="check-nextcloud-security" \
      org.opencontainers.image.description="Nagios/Icinga plugin to check a Nextcloud instance for known vulnerabilities via scan.nextcloud.com" \
      org.opencontainers.image.source="https://github.com/sowoi/check-nextcloud-security" \
      org.opencontainers.image.licenses="GPL-3.0-only"

COPY --from=builder /dist/*.whl /tmp/

RUN pip install --no-cache-dir /tmp/*.whl \
    && rm -rf /tmp/*.whl \
    && useradd --no-create-home --shell /usr/sbin/nologin nagios

USER nagios

ENTRYPOINT ["check-nextcloud-security"]
# No default CMD: with no arguments, the entrypoint relies entirely on
# CNS_-prefixed environment variables (see README.md "Environment variables").
# Run `docker run --rm check-nextcloud-security --help` explicitly for usage.
