"""
Build scanner and serverinfo settings from the layered configuration.

Keeping this in one place means the plugin, the one-shot CLI and the
container service all understand exactly the same YAML keys, environment
variables and secret references.
"""

from __future__ import annotations

from typing import Any

from .config import Configuration
from .scanner import (
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_TLS_MIN_DAYS,
    UPDATER_SERVER_URL,
    USER_AGENT,
    ScannerSettings,
)
from .serverinfo import (
    DEFAULT_OCC_COMMAND,
    DEFAULT_OCC_TIMEOUT_SECONDS,
    MODES,
    ServerInfoSettings,
)


def _supported_majors(config: Configuration) -> tuple[int, ...] | None:
    """Read a manual override of the bundled release schedule, if configured."""
    entries = [
        part.strip()
        for item in config.get_list("SCANNER_SUPPORTED_MAJORS")
        for part in item.split(",")
        if part.strip().isdigit()
    ]
    if not entries:
        return None
    return tuple(sorted({int(item) for item in entries}, reverse=True))


def _override(value: Any, fallback: Any) -> Any:
    """Return value unless it is None (an unset command line flag)."""
    return fallback if value is None else value


def scanner_settings_from_config(
    config: Configuration, **overrides: Any
) -> ScannerSettings:
    """
    Build :class:`ScannerSettings` from configuration file and environment.

    Keyword overrides (typically parsed command line flags) win over both;
    passing ``None`` means "not specified on the command line".
    """
    port = config.get("SCANNER_TARGET_PORT")
    settings = ScannerSettings(
        timeout=config.get_int("SCANNER_TIMEOUT", config.get_int("TIMEOUT", DEFAULT_TIMEOUT_SECONDS)),
        verify_tls=config.get_bool("SCANNER_VERIFY_TLS", True),
        proxy=config.get("SCANNER_PROXY") or config.get("PROXY"),
        scheme=config.get("SCANNER_SCHEME") or "https",
        port=int(port) if port else None,
        extra_checks=config.get_bool("SCANNER_EXTRA_CHECKS", True),
        extra_checks_affect_rating=config.get_bool("SCANNER_EXTRA_CHECKS_RATING", True),
        tls_min_days=config.get_int("SCANNER_TLS_MIN_DAYS", DEFAULT_TLS_MIN_DAYS),
        use_updater_server=config.get_bool("SCANNER_USE_UPDATER_SERVER", True),
        use_release_schedule=config.get_bool("SCANNER_USE_RELEASE_SCHEDULE", True),
        supported_majors=_supported_majors(config),
        updater_server_url=config.get("SCANNER_UPDATER_URL") or UPDATER_SERVER_URL,
        vulnerability_files=tuple(config.get_list("SCANNER_VULNERABILITY_DB")),
        vulnerability_feed=config.get("SCANNER_VULNERABILITY_FEED"),
        include_bundled_db=config.get_bool("SCANNER_BUNDLED_DB", True),
        user_agent=config.get("SCANNER_USER_AGENT") or USER_AGENT,
    )

    changes = {key: value for key, value in overrides.items() if value is not None}
    if not changes:
        return settings
    return ScannerSettings(**{**settings.__dict__, **changes})


def serverinfo_settings_from_config(
    config: Configuration, **overrides: Any
) -> ServerInfoSettings:
    """Build :class:`ServerInfoSettings` from configuration and overrides."""
    mode = (config.get("SERVERINFO_MODE") or "auto").strip().lower()
    if mode not in MODES:
        mode = "auto"

    settings = ServerInfoSettings(
        mode=mode,
        url=config.get("SERVERINFO_URL"),
        token=config.get("SERVERINFO_TOKEN"),
        user=config.get("SERVERINFO_USER"),
        password=config.get("SERVERINFO_PASSWORD"),
        occ_command=config.get("SERVERINFO_OCC_COMMAND") or DEFAULT_OCC_COMMAND,
        occ_configured=bool(config.get("SERVERINFO_OCC_COMMAND")),
        container=config.get("SERVERINFO_CONTAINER"),
        container_user=config.get("SERVERINFO_CONTAINER_USER") or "www-data",
        docker_command=config.get("SERVERINFO_DOCKER_COMMAND") or "docker",
        timeout=config.get_int("SERVERINFO_TIMEOUT", config.get_int("TIMEOUT", DEFAULT_TIMEOUT_SECONDS)),
        occ_timeout=config.get_int("SERVERINFO_OCC_TIMEOUT", DEFAULT_OCC_TIMEOUT_SECONDS),
        verify_tls=config.get_bool("SERVERINFO_VERIFY_TLS", True),
        proxy=config.get("SERVERINFO_PROXY") or config.get("PROXY"),
    )

    changes = {key: value for key, value in overrides.items() if value is not None}
    if not changes:
        return settings
    return ServerInfoSettings(**{**settings.__dict__, **changes})
