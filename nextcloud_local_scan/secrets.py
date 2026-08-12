"""
Secret provider resolution for check-nextcloud-security.

Every configuration value (YAML file, environment variable or command line)
may reference an external secret instead of carrying the plain text value.
The supported reference schemes are:

``secret://NAME``
    Read ``<secrets_dir>/NAME`` (Docker/Podman/Kubernetes style secrets,
    ``/run/secrets`` by default).
``file:///absolute/path`` or ``file://relative/path``
    Read the given file.
``env://VARIABLE``
    Read the given environment variable.
``exec://command --arg``
    Run the command and use its stdout. Disabled unless explicitly allowed,
    because it executes arbitrary code from a configuration file.

In addition, the ``*_file`` convention is honoured by the configuration
loader: a key ``token_file`` supplies the value for ``token``.
"""

from __future__ import annotations

import logging
import os
import shlex
import subprocess  # nosec B404 - only used for the opt-in exec:// secret provider
from dataclasses import dataclass
from pathlib import Path

LOGGER = logging.getLogger("check_nextcloud.secrets")

DEFAULT_SECRETS_DIR = "/run/secrets"
SECRET_SCHEMES = ("secret://", "file://", "env://", "exec://")

DEFAULT_EXEC_TIMEOUT_SECONDS = 10


class SecretResolutionError(RuntimeError):
    """Raised when a secret reference cannot be resolved."""


@dataclass(frozen=True)
class SecretProvider:
    """Resolves secret references found in configuration values."""

    secrets_dir: str = DEFAULT_SECRETS_DIR
    allow_exec: bool = False
    exec_timeout: int = DEFAULT_EXEC_TIMEOUT_SECONDS

    def is_reference(self, value: object) -> bool:
        """Return True if value looks like a secret reference."""
        return isinstance(value, str) and value.startswith(SECRET_SCHEMES)

    def resolve(self, value: object) -> object:
        """
        Resolve a single value.

        Non-string values and plain strings are returned unchanged, so this
        can be applied to every configuration value without special casing.
        """
        if not isinstance(value, str) or not value.startswith(SECRET_SCHEMES):
            return value

        scheme, _, remainder = value.partition("://")
        remainder = remainder.strip()
        if not remainder:
            raise SecretResolutionError(f"Empty secret reference: {value!r}")

        if scheme == "secret":
            return self._read_file(Path(self.secrets_dir) / remainder, value)
        if scheme == "file":
            # 'file:///etc/x' leaves '/etc/x', 'file://relative/x' leaves 'relative/x'.
            return self._read_file(Path(remainder), value)
        if scheme == "env":
            resolved = os.environ.get(remainder)
            if resolved is None:
                raise SecretResolutionError(
                    f"Environment variable {remainder!r} referenced by {value!r} is not set."
                )
            return resolved
        if scheme == "exec":
            return self._run_command(remainder, value)

        raise SecretResolutionError(f"Unsupported secret scheme in {value!r}.")

    def read_secret_file(self, path: str) -> str:
        """Read a value from a file path given via the ``*_file`` convention."""
        return self._read_file(Path(path), f"file://{path}")

    def resolve_tree(self, data: object) -> object:
        """Recursively resolve every secret reference in a nested structure."""
        if isinstance(data, dict):
            return {key: self.resolve_tree(item) for key, item in data.items()}
        if isinstance(data, list):
            return [self.resolve_tree(item) for item in data]
        return self.resolve(data)

    def _read_file(self, path: Path, reference: str) -> str:
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SecretResolutionError(f"Cannot read secret {reference!r}: {exc}") from exc
        # Secret files written by editors or `echo` usually carry a trailing
        # newline that would otherwise become part of a token or password.
        return content.strip("\r\n")

    def _run_command(self, command: str, reference: str) -> str:
        if not self.allow_exec:
            raise SecretResolutionError(
                f"Secret reference {reference!r} uses exec:// but command execution is "
                "disabled. Enable it with secrets.allow_exec / CNS_SECRETS_ALLOW_EXEC=1."
            )
        argv = shlex.split(command)
        if not argv:
            raise SecretResolutionError(f"Empty command in {reference!r}.")
        LOGGER.debug("Resolving secret via command: %s", argv[0])
        try:
            completed = subprocess.run(  # nosec B603 - argv is split, no shell involved
                argv,
                capture_output=True,
                text=True,
                timeout=self.exec_timeout,
                check=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise SecretResolutionError(f"Command for {reference!r} failed: {exc}") from exc
        return completed.stdout.strip("\r\n")
