"""Tests for the layered configuration and the secret providers."""

import pytest

from nextcloud_local_scan.config import ConfigurationError, load_configuration
from nextcloud_local_scan.secrets import SecretProvider, SecretResolutionError


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def test_yaml_values_are_flattened_to_env_style_names(tmp_path):
    """Nested YAML keys map onto the same names as the environment variables."""
    config_file = _write(
        tmp_path,
        "config.yml",
        """
        host: cloud.example.com
        scan:
          backend: local
        webhook:
          url: https://hooks.example.com/nextcloud
        scanner:
          timeout: 25
          extra_checks: false
        """,
    )

    config = load_configuration(str(config_file), environ={})

    assert config.get("HOST") == "cloud.example.com"
    assert config.get("SCAN_BACKEND") == "local"
    assert config.get("WEBHOOK_URL") == "https://hooks.example.com/nextcloud"
    assert config.get_int("SCANNER_TIMEOUT", 10) == 25
    assert config.get_bool("SCANNER_EXTRA_CHECKS", True) is False


def test_environment_variables_take_precedence_over_the_file(tmp_path):
    """An environment variable always wins over the configuration file."""
    config_file = _write(tmp_path, "config.yml", "host: from-file.example.com\n")

    config = load_configuration(str(config_file), environ={"CNS_HOST": "from-env.example.com"})

    assert config.get("HOST") == "from-env.example.com"


def test_missing_explicit_config_file_is_an_error(tmp_path):
    """A configuration file requested by the user must exist."""
    with pytest.raises(ConfigurationError):
        load_configuration(str(tmp_path / "does-not-exist.yml"), environ={})


def test_lists_are_joined_with_semicolons(tmp_path):
    """YAML lists use the same separator as the environment variable form."""
    config_file = _write(
        tmp_path,
        "config.yml",
        "scanner:\n  vulnerability_db:\n    - /a.json\n    - /b.json\n",
    )

    config = load_configuration(str(config_file), environ={})

    assert config.get_list("SCANNER_VULNERABILITY_DB") == ["/a.json", "/b.json"]


def test_secret_reference_in_yaml_is_resolved_from_the_secrets_dir(tmp_path):
    """'secret://name' reads <secrets_dir>/name."""
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "nc_token").write_text("s3cr3t\n", encoding="utf-8")
    config_file = _write(
        tmp_path,
        "config.yml",
        f"secrets:\n  dir: {secrets_dir}\nserverinfo:\n  token: secret://nc_token\n",
    )

    config = load_configuration(str(config_file), environ={})

    assert config.get("SERVERINFO_TOKEN") == "s3cr3t"


def test_file_suffix_convention_reads_the_value_from_disk(tmp_path):
    """CNS_<NAME>_FILE supplies the value of CNS_<NAME>."""
    secret_file = _write(tmp_path, "password", "hunter2\n")

    config = load_configuration(
        None, environ={"CNS_SERVERINFO_PASSWORD_FILE": str(secret_file)}
    )

    assert config.get("SERVERINFO_PASSWORD") == "hunter2"


def test_unreadable_secret_raises_configuration_error(tmp_path):
    """A broken secret reference is reported instead of silently ignored."""
    config = load_configuration(None, environ={"CNS_SERVERINFO_TOKEN": "file:///nope/missing"})

    with pytest.raises(ConfigurationError):
        config.get("SERVERINFO_TOKEN")


def test_env_scheme_reads_environment_variables():
    """'env://VAR' resolves through the process environment."""
    provider = SecretProvider()

    import os

    os.environ["CNS_TEST_SECRET"] = "value-from-env"
    try:
        assert provider.resolve("env://CNS_TEST_SECRET") == "value-from-env"
    finally:
        del os.environ["CNS_TEST_SECRET"]


def test_exec_scheme_is_disabled_by_default():
    """Command execution must be opted into explicitly."""
    provider = SecretProvider()

    with pytest.raises(SecretResolutionError, match="disabled"):
        provider.resolve("exec://echo hello")


def test_exec_scheme_runs_the_command_when_allowed():
    """With allow_exec the command output becomes the value."""
    provider = SecretProvider(allow_exec=True)

    assert provider.resolve("exec://echo hello") == "hello"


def test_plain_values_pass_through_unchanged():
    """Values without a known scheme are never touched."""
    provider = SecretProvider()

    assert provider.resolve("just-a-password") == "just-a-password"
    assert provider.resolve(42) == 42
