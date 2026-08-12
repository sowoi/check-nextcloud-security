"""
Update check against the local Nextcloud instance via ``serverinfo``.

Instead of asking scan.nextcloud.com whether a newer release exists, the
instance is asked directly. Two transports are supported:

``api``
    The OCS endpoint of the *serverinfo* app,
    ``/ocs/v2.php/apps/serverinfo/api/v1/info?skipUpdate=false``, authenticated
    with the monitoring token (``NC-Token``) or with admin credentials.

``occ``
    A local ``occ``/``nextcloud`` command, optionally executed inside a
    container. ``<occ> serverinfo`` is used first (JSON output when the
    installed serverinfo app supports it); if that subcommand is unavailable
    the check falls back to ``<occ> update:check``, which reports exactly the
    same update state.

``auto`` (the default) uses the API when a token or credentials are
configured and the local command otherwise.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
import subprocess  # nosec B404 - required to talk to a local occ installation
from dataclasses import dataclass, field
from typing import Any

import requests

LOGGER = logging.getLogger("check_nextcloud.serverinfo")

SERVERINFO_PATH = "/ocs/v2.php/apps/serverinfo/api/v1/info"
DEFAULT_OCC_COMMAND = "occ"
DEFAULT_OCC_TIMEOUT_SECONDS = 60

MODES = ("auto", "api", "occ", "off")

# 'Nextcloud 30.0.1 is available.' as printed by `occ update:check`.
_OCC_UPDATE_LINE = re.compile(r"([\w.-]+)\s+([0-9][0-9.]*)\s+is available", re.IGNORECASE)
# 'Update for files_antivirus to version 2.0.1 is available.'
_OCC_APP_LINE = re.compile(
    r"Update for ([\w_.-]+) to version ([0-9][0-9.]*)", re.IGNORECASE
)


@dataclass
class UpdateInfo:
    """Update state as reported by the local Nextcloud instance."""

    available: bool | None = None
    version: str | None = None
    available_version: str | None = None
    app_updates: dict[str, str] = field(default_factory=dict)
    last_checked_at: int | None = None
    source: str = "none"
    error: str | None = None

    @property
    def known(self) -> bool:
        """True when the instance actually answered with an update state."""
        return self.available is not None

    def as_dict(self) -> dict[str, Any]:
        """Render the update state for JSON output."""
        return {
            "available": self.available,
            "version": self.version,
            "availableVersion": self.available_version,
            "appUpdates": dict(self.app_updates),
            "lastCheckedAt": self.last_checked_at,
            "source": self.source,
            "error": self.error,
        }

    def summary(self) -> str:
        """One-line, human readable rendering used in the plugin output."""
        if self.error and not self.known:
            return f"Update check via {self.source} failed: {self.error}"
        if not self.known:
            return "Update check via serverinfo not performed"
        parts = []
        if self.available:
            target = self.available_version or "unknown version"
            parts.append(f"server update available: {target}")
        else:
            parts.append("server up to date")
        if self.app_updates:
            listed = ", ".join(
                f"{name} {version}" for name, version in sorted(self.app_updates.items())
            )
            parts.append(f"{len(self.app_updates)} app update(s): {listed}")
        installed = f", installed {self.version}" if self.version else ""
        return f"Update check ({self.source}{installed}): " + "; ".join(parts)


@dataclass(frozen=True)
class ServerInfoSettings:
    """Everything needed to reach the serverinfo app of one instance."""

    mode: str = "auto"
    url: str | None = None
    token: str | None = None
    user: str | None = None
    password: str | None = None
    occ_command: str = DEFAULT_OCC_COMMAND
    occ_configured: bool = False
    container: str | None = None
    container_user: str = "www-data"
    docker_command: str = "docker"
    timeout: int = 10
    occ_timeout: int = DEFAULT_OCC_TIMEOUT_SECONDS
    verify_tls: bool = True
    proxy: str | None = None

    @property
    def has_api_credentials(self) -> bool:
        """True when the OCS API can be authenticated."""
        return bool(self.token or (self.user and self.password))

    def effective_mode(self) -> str:
        """
        Resolve 'auto' into the transport that is actually usable.

        'auto' only enables the update check when something was configured:
        API credentials, an explicit occ command or a container name.
        Otherwise it stays off, so a monitoring host without access to the
        instance does not spawn a doomed subprocess on every run.
        """
        if self.mode != "auto":
            return self.mode
        if self.url and self.has_api_credentials:
            return "api"
        if self.occ_configured or self.container:
            return "occ"
        return "off"


def _base_url(settings: ServerInfoSettings, host: str | None) -> str | None:
    """Return the instance base URL, deriving it from the checked host."""
    if settings.url:
        return settings.url.rstrip("/")
    if host:
        return f"https://{host}"
    return None


def _dig(data: Any, *path: str) -> Any:
    """Walk nested dictionaries, returning None as soon as a key is missing."""
    current = data
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _parse_api_payload(payload: dict[str, Any]) -> UpdateInfo:
    """Extract the update state from an OCS serverinfo response."""
    system = _dig(payload, "ocs", "data", "nextcloud", "system") or {}
    update = system.get("update") if isinstance(system, dict) else None
    apps = system.get("apps") if isinstance(system, dict) else None

    info = UpdateInfo(source="api", version=system.get("version") if isinstance(system, dict) else None)

    if isinstance(update, dict):
        info.available = bool(update.get("available"))
        available_version = update.get("available_version")
        info.available_version = str(available_version) if available_version else None
        last_checked = update.get("lastupdatedat")
        info.last_checked_at = int(last_checked) if isinstance(last_checked, (int, float)) else None
    else:
        info.error = (
            "serverinfo did not return an update block "
            "(the app answers with skipUpdate=true by default)"
        )

    if isinstance(apps, dict):
        app_updates = apps.get("app_updates")
        if isinstance(app_updates, dict):
            info.app_updates = {str(name): str(version) for name, version in app_updates.items()}

    return info


def _fetch_via_api(settings: ServerInfoSettings, host: str | None) -> UpdateInfo:
    """Query the serverinfo OCS endpoint."""
    base = _base_url(settings, host)
    if not base:
        return UpdateInfo(source="api", error="No serverinfo URL configured.")

    url = f"{base}{SERVERINFO_PATH}"
    headers = {"OCS-APIRequest": "true", "Accept": "application/json"}
    if settings.token:
        headers["NC-Token"] = settings.token
    auth = (settings.user, settings.password) if settings.user and settings.password else None
    proxies = (
        {"http": settings.proxy, "https": settings.proxy} if settings.proxy else None
    )

    LOGGER.debug("Querying serverinfo API at %s", url)
    try:
        response = requests.get(
            url,
            params={"format": "json", "skipApps": "false", "skipUpdate": "false"},
            headers=headers,
            auth=auth,
            timeout=settings.timeout,
            verify=settings.verify_tls,
            proxies=proxies,
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.exceptions.RequestException, ValueError) as exc:
        return UpdateInfo(source="api", error=str(exc))

    if not isinstance(payload, dict):
        return UpdateInfo(source="api", error="Unexpected serverinfo response.")
    return _parse_api_payload(payload)


def _occ_argv(settings: ServerInfoSettings, arguments: list[str]) -> list[str]:
    """Build the argv for an occ invocation, wrapping it in docker exec if needed."""
    argv = shlex.split(settings.occ_command) + arguments
    if settings.container:
        prefix = shlex.split(settings.docker_command) + ["exec"]
        if settings.container_user:
            prefix += ["-u", settings.container_user]
        prefix.append(settings.container)
        argv = prefix + argv
    return argv


def _run_occ(settings: ServerInfoSettings, arguments: list[str]) -> tuple[int, str, str]:
    """Run an occ subcommand and return (returncode, stdout, stderr)."""
    argv = _occ_argv(settings, arguments)
    LOGGER.debug("Running %s", " ".join(argv))
    try:
        completed = subprocess.run(  # nosec B603 - argv built from configuration, no shell
            argv,
            capture_output=True,
            text=True,
            timeout=settings.occ_timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", str(exc)
    return completed.returncode, completed.stdout, completed.stderr


def _parse_occ_serverinfo(stdout: str) -> UpdateInfo | None:
    """Parse the JSON document printed by `occ serverinfo`."""
    stripped = stdout.strip()
    if not stripped.startswith(("{", "[")):
        return None
    try:
        document = json.loads(stripped)
    except ValueError:
        return None
    if not isinstance(document, dict):
        return None

    # `occ serverinfo` prints the same tree the OCS endpoint returns, either
    # wrapped in the OCS envelope or as the bare data object.
    system = _dig(document, "ocs", "data", "nextcloud", "system")
    if system is None:
        system = _dig(document, "nextcloud", "system")
    if system is None:
        system = document.get("system") if isinstance(document.get("system"), dict) else None
    if system is None:
        return None

    info = _parse_api_payload({"ocs": {"data": {"nextcloud": {"system": system}}}})
    info.source = "occ serverinfo"
    return info


def _parse_occ_update_check(stdout: str) -> UpdateInfo:
    """Parse the plain text output of `occ update:check`."""
    info = UpdateInfo(source="occ update:check", available=False)
    for line in stdout.splitlines():
        app_match = _OCC_APP_LINE.search(line)
        if app_match:
            info.app_updates[app_match.group(1)] = app_match.group(2)
            continue
        update_match = _OCC_UPDATE_LINE.search(line)
        if update_match:
            info.available = True
            info.available_version = update_match.group(2)
    return info


def _fetch_via_occ(settings: ServerInfoSettings) -> UpdateInfo:
    """Ask the local instance through its command line interface."""
    code, stdout, stderr = _run_occ(settings, ["serverinfo", "--output=json"])
    if code == 0:
        parsed = _parse_occ_serverinfo(stdout)
        if parsed is not None:
            return parsed

    LOGGER.debug("`serverinfo` did not yield JSON (exit %s), falling back to update:check", code)
    code, stdout, stderr = _run_occ(settings, ["update:check"])
    if code != 0:
        message = (stderr or stdout).strip().splitlines()
        return UpdateInfo(
            source="occ",
            error=message[-1] if message else f"occ exited with status {code}",
        )
    return _parse_occ_update_check(stdout)


def fetch_update_info(settings: ServerInfoSettings, host: str | None = None) -> UpdateInfo:
    """
    Ask the local Nextcloud instance whether updates are pending.

    Never raises: transport problems are reported through
    :attr:`UpdateInfo.error` so that a monitoring run still produces a result
    for the security part of the check.
    """
    mode = settings.effective_mode()
    if mode == "off":
        return UpdateInfo(source="disabled")

    if mode == "api":
        info = _fetch_via_api(settings, host)
        if info.known or settings.mode == "api":
            return info
        LOGGER.debug("serverinfo API unusable (%s), trying occ", info.error)
        fallback = _fetch_via_occ(settings)
        return fallback if fallback.known else info

    info = _fetch_via_occ(settings)
    if not info.known and settings.mode == "auto" and settings.has_api_credentials:
        LOGGER.debug("occ unusable (%s), trying serverinfo API", info.error)
        api_info = _fetch_via_api(settings, host)
        if api_info.known:
            return api_info
    return info
