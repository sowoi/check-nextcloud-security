"""
Local, self-hosted replacement for the scan.nextcloud.com checks.

The package provides three things:

* :mod:`nextcloud_local_scan.scanner` - the checks themselves, producing a
  document with the same shape as the public Scan API,
* :mod:`nextcloud_local_scan.serverinfo` - update information taken from the
  local Nextcloud instance via the *serverinfo* app,
* :mod:`nextcloud_local_scan.service` - a Scan API compatible HTTP service
  that runs in the local Docker container.

Configuration comes from a YAML file, ``CNS_``-prefixed environment
variables or a secret provider (see :mod:`nextcloud_local_scan.config`).
"""

from __future__ import annotations

from .config import Configuration, ConfigurationError, load_configuration
from .factory import scanner_settings_from_config, serverinfo_settings_from_config
from .scanner import ScanError, ScannerSettings, failed_extra_checks, scan
from .secrets import SecretProvider, SecretResolutionError
from .serverinfo import ServerInfoSettings, UpdateInfo, fetch_update_info
from .service import ScanStore, build_server, serve
from .vulndb import VulnerabilityDatabase, load_database

__all__ = [
    "Configuration",
    "ConfigurationError",
    "ScanError",
    "ScanStore",
    "ScannerSettings",
    "SecretProvider",
    "SecretResolutionError",
    "ServerInfoSettings",
    "UpdateInfo",
    "VulnerabilityDatabase",
    "build_server",
    "failed_extra_checks",
    "fetch_update_info",
    "load_configuration",
    "load_database",
    "scan",
    "scanner_settings_from_config",
    "serve",
    "serverinfo_settings_from_config",
]
