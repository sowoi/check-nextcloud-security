"""
Layered configuration for check-nextcloud-security.

Values can come from three places, in increasing order of precedence:

1. A YAML configuration file (``--config``, ``CNS_CONFIG_FILE`` or one of the
   default locations in :data:`DEFAULT_CONFIG_PATHS`).
2. ``CNS_``-prefixed environment variables.
3. Command line flags (handled by the caller, which passes the values from
   here as argparse defaults).

Nested YAML keys map one to one onto environment variable names, so

.. code-block:: yaml

    webhook:
      url: https://example.com/hook
    scanner:
      port: 8080

is equivalent to ``CNS_WEBHOOK_URL`` and ``CNS_SCANNER_PORT``.

Any value may also be delivered by a secret provider, either through a
reference such as ``secret://nextcloud_token`` (see
:mod:`nextcloud_local_scan.secrets`) or through the ``*_file`` convention
(``CNS_SERVERINFO_TOKEN_FILE=/run/secrets/token``).
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .secrets import DEFAULT_SECRETS_DIR, SecretProvider, SecretResolutionError

LOGGER = logging.getLogger("check_nextcloud.config")

ENV_PREFIX = "CNS_"
FILE_SUFFIX = "_FILE"

DEFAULT_CONFIG_PATHS = (
    "./check-nextcloud-security.yml",
    "./check-nextcloud-security.yaml",
    "/etc/check-nextcloud-security/config.yml",
    "/etc/check-nextcloud-security/config.yaml",
)

TRUE_VALUES = {"1", "true", "yes", "on"}


class ConfigurationError(RuntimeError):
    """Raised when the configuration file cannot be read or parsed."""


def _flatten(data: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """
    Flatten a nested mapping into ENV-style keys.

    ``{"webhook": {"url": "x"}}`` becomes ``{"WEBHOOK_URL": "x"}``. Lists and
    scalars are kept as-is; the consumer decides how to stringify them.
    """
    flat: dict[str, Any] = {}
    for key, value in data.items():
        name = f"{prefix}{str(key).strip().upper().replace('-', '_')}"
        if isinstance(value, Mapping):
            flat.update(_flatten(value, f"{name}_"))
        else:
            flat[name] = value
    return flat


def _stringify(value: Any) -> str:
    """Render a YAML scalar the way the equivalent environment variable would look."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return ";".join(_stringify(item) for item in value)
    return str(value)


@dataclass
class Configuration:
    """Merged view over YAML file, environment variables and secret providers."""

    values: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    provider: SecretProvider = field(default_factory=SecretProvider)
    source: str | None = None
    environ: Mapping[str, str] = field(default_factory=lambda: os.environ)

    def get(self, name: str) -> str | None:
        """
        Return the configured value for an ENV-style name (without prefix).

        Environment variables win over the configuration file. For both
        sources a ``<NAME>_FILE`` variant is honoured and read through the
        secret provider.
        """
        key = name.strip().upper()

        env_value = self.environ.get(f"{ENV_PREFIX}{key}")
        if env_value is not None:
            return self._resolve(env_value, f"{ENV_PREFIX}{key}")

        env_file = self.environ.get(f"{ENV_PREFIX}{key}{FILE_SUFFIX}")
        if env_file:
            return self._read_file(env_file, f"{ENV_PREFIX}{key}{FILE_SUFFIX}")

        if key in self.values:
            return self._resolve(_stringify(self.values[key]), key)

        file_key = f"{key}{FILE_SUFFIX}"
        if file_key in self.values:
            return self._read_file(_stringify(self.values[file_key]), file_key)

        return None

    def get_bool(self, name: str, default: bool = False) -> bool:
        """Interpret a configured value as a boolean flag."""
        value = self.get(name)
        if value is None:
            return default
        return value.strip().lower() in TRUE_VALUES

    def get_int(self, name: str, default: int) -> int:
        """Interpret a configured value as an int, falling back to default."""
        value = self.get(name)
        if not value:
            return default
        try:
            return int(value)
        except ValueError:
            LOGGER.warning("Ignoring invalid %s=%r (expected an integer).", name, value)
            return default

    def get_float(self, name: str, default: float) -> float:
        """Interpret a configured value as a float, falling back to default."""
        value = self.get(name)
        if not value:
            return default
        try:
            return float(value)
        except ValueError:
            LOGGER.warning("Ignoring invalid %s=%r (expected a number).", name, value)
            return default

    def get_list(self, name: str) -> list[str]:
        """
        Return a configured value as a list of strings.

        YAML lists are flattened with ';' by :func:`_stringify`, which is the
        same separator used for the environment variable form.
        """
        value = self.get(name)
        if not value:
            return []
        return [part.strip() for part in value.split(";") if part.strip()]

    def _resolve(self, value: str, origin: str) -> str:
        try:
            resolved = self.provider.resolve(value)
        except SecretResolutionError as exc:
            raise ConfigurationError(f"{origin}: {exc}") from exc
        return str(resolved)

    def _read_file(self, path: str, origin: str) -> str:
        try:
            return self.provider.read_secret_file(path)
        except SecretResolutionError as exc:
            raise ConfigurationError(f"{origin}: {exc}") from exc


def _load_yaml(path: Path) -> dict[str, Any]:
    """Parse a YAML configuration file into a plain dictionary."""
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise ConfigurationError(
            f"Reading {path} requires PyYAML. Install it with 'pip install PyYAML'."
        ) from exc

    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"Cannot read configuration file {path}: {exc}") from exc

    try:
        data = yaml.safe_load(content) or {}
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"Cannot parse configuration file {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigurationError(
            f"Configuration file {path} must contain a mapping at the top level."
        )
    return data


def _discover_config_path(
    explicit: str | None, environ: Mapping[str, str]
) -> tuple[Path | None, bool]:
    """
    Locate the configuration file.

    Returns the path and whether it was requested explicitly (in which case a
    missing file is an error rather than a silent fallback to defaults).
    """
    candidate = explicit or environ.get(f"{ENV_PREFIX}CONFIG_FILE")
    if candidate:
        return Path(candidate).expanduser(), True
    for default in DEFAULT_CONFIG_PATHS:
        path = Path(default)
        if path.is_file():
            return path, False
    return None, False


def _build_provider(
    flat: Mapping[str, Any], environ: Mapping[str, str]
) -> SecretProvider:
    """Create the secret provider from the (unresolved) secrets.* settings."""

    def _setting(name: str, default: str) -> str:
        env_value = environ.get(f"{ENV_PREFIX}{name}")
        if env_value is not None:
            return env_value
        if name in flat:
            return _stringify(flat[name])
        return default

    allow_exec = _setting("SECRETS_ALLOW_EXEC", "false").strip().lower() in TRUE_VALUES
    try:
        timeout = int(_setting("SECRETS_EXEC_TIMEOUT", "10"))
    except ValueError:
        timeout = 10
    return SecretProvider(
        secrets_dir=_setting("SECRETS_DIR", DEFAULT_SECRETS_DIR),
        allow_exec=allow_exec,
        exec_timeout=timeout,
    )


def load_configuration(
    config_path: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> Configuration:
    """
    Load the configuration file (if any) and merge it with the environment.

    The returned object resolves secret references lazily, so a configuration
    that references an unavailable secret only fails when that particular
    value is actually requested.
    """
    environ = os.environ if environ is None else environ
    path, explicit = _discover_config_path(config_path, environ)

    raw: dict[str, Any] = {}
    source: str | None = None
    if path is not None:
        if path.is_file():
            raw = _load_yaml(path)
            source = str(path)
            LOGGER.debug("Loaded configuration from %s", path)
        elif explicit:
            raise ConfigurationError(f"Configuration file {path} does not exist.")

    flat = _flatten(raw)
    return Configuration(
        values=flat,
        raw=raw,
        provider=_build_provider(flat, environ),
        source=source,
        environ=environ,
    )
