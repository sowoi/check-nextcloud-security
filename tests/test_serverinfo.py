"""Tests for the serverinfo based update check."""

from unittest.mock import MagicMock

import requests

from nextcloud_local_scan.serverinfo import (
    ServerInfoSettings,
    _fetch_cli_php_version,
    _occ_argv,
    _parse_api_payload,
    _parse_occ_serverinfo,
    _parse_occ_update_check,
    _php_argv,
    fetch_update_info,
)

API_PAYLOAD = {
    "ocs": {
        "meta": {"status": "ok", "statuscode": 200},
        "data": {
            "nextcloud": {
                "system": {
                    "version": "30.0.2.2",
                    "update": {
                        "lastupdatedat": 1719244666,
                        "available": True,
                        "available_version": "30.0.4.0",
                    },
                    "apps": {
                        "num_installed": 53,
                        "num_updates_available": 1,
                        "app_updates": {"files_antivirus": "2.0.1"},
                    },
                }
            }
        },
    }
}


def test_api_payload_is_parsed():
    """Version, update state and app updates are read from the OCS answer."""
    info = _parse_api_payload(API_PAYLOAD)

    assert info.known is True
    assert info.available is True
    assert info.version == "30.0.2.2"
    assert info.available_version == "30.0.4.0"
    assert info.app_updates == {"files_antivirus": "2.0.1"}
    assert "30.0.4.0" in info.summary()


def test_api_payload_without_update_block_is_reported_as_unknown():
    """serverinfo answers without update data when skipUpdate is not disabled."""
    payload = {"ocs": {"data": {"nextcloud": {"system": {"version": "30.0.2.2"}}}}}

    info = _parse_api_payload(payload)

    assert info.known is False
    assert info.error


def test_occ_update_check_output_is_parsed():
    """The plain text of `occ update:check` yields the same information."""
    output = (
        "Nextcloud 30.0.4 is available. Get more information on how to update at "
        "https://nextcloud.com/changelog.\n"
        "Update for files_antivirus to version 2.0.1 is available.\n"
        "2 updates available\n"
    )

    info = _parse_occ_update_check(output)

    assert info.available is True
    assert info.available_version == "30.0.4"
    assert info.app_updates == {"files_antivirus": "2.0.1"}


def test_occ_update_check_reports_up_to_date():
    """No update lines means the instance is current."""
    info = _parse_occ_update_check("Everything up to date\n")

    assert info.available is False
    assert info.app_updates == {}


def test_occ_command_is_wrapped_in_docker_exec():
    """A container name turns the call into a docker exec invocation."""
    settings = ServerInfoSettings(
        occ_command="php /var/www/html/occ", container="nextcloud-app"
    )

    argv = _occ_argv(settings, ["update:check"])

    assert argv == [
        "docker",
        "exec",
        "-u",
        "www-data",
        "nextcloud-app",
        "php",
        "/var/www/html/occ",
        "update:check",
    ]


def test_auto_mode_stays_off_when_nothing_is_configured():
    """Without credentials or an occ command the update check is skipped."""
    assert ServerInfoSettings().effective_mode() == "off"
    assert fetch_update_info(ServerInfoSettings()).source == "disabled"


def test_auto_mode_uses_the_api_when_credentials_exist():
    """A URL plus token selects the OCS transport."""
    settings = ServerInfoSettings(url="https://cloud.example.com", token="t")

    assert settings.effective_mode() == "api"


def test_api_transport_errors_are_reported_not_raised(mocker):
    """A failing request never aborts the monitoring run."""
    mocker.patch(
        "nextcloud_local_scan.serverinfo.requests.get",
        side_effect=requests.exceptions.ConnectTimeout("timeout"),
    )
    settings = ServerInfoSettings(mode="api", url="https://cloud.example.com", token="t")

    info = fetch_update_info(settings, "cloud.example.com")

    assert info.known is False
    assert "timeout" in (info.error or "")
    assert "failed" in info.summary()


def test_api_request_asks_for_the_update_block(mocker):
    """skipUpdate must be disabled, otherwise serverinfo omits the data."""
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = API_PAYLOAD
    get = mocker.patch("nextcloud_local_scan.serverinfo.requests.get", return_value=response)
    settings = ServerInfoSettings(mode="api", url="https://cloud.example.com", token="secret")

    info = fetch_update_info(settings, "cloud.example.com")

    assert info.available is True
    assert get.call_args.kwargs["params"]["skipUpdate"] == "false"
    assert get.call_args.kwargs["headers"]["NC-Token"] == "secret"
    assert get.call_args.args[0].endswith("/ocs/v2.php/apps/serverinfo/api/v1/info")


def test_occ_transport_falls_back_to_update_check(mocker):
    """When `serverinfo` yields no JSON, `update:check` is used instead."""
    calls = []

    def _fake_run(settings, arguments):
        calls.append(arguments)
        if arguments[0] == "serverinfo":
            return 1, "", "Command 'serverinfo' is not defined."
        return 0, "Nextcloud 30.0.4 is available.\n", ""

    mocker.patch("nextcloud_local_scan.serverinfo._run_occ", side_effect=_fake_run)
    mocker.patch(
        "nextcloud_local_scan.serverinfo._fetch_cli_php_version", return_value="8.3.36"
    )
    settings = ServerInfoSettings(mode="occ", occ_command="occ")

    info = fetch_update_info(settings)

    assert calls == [["serverinfo", "--output=json"], ["update:check"]]
    assert info.available is True
    assert info.available_version == "30.0.4"
    assert info.php_version == "8.3.36"
    assert info.php_source == "cli"


def test_api_payload_carries_the_php_version():
    """serverinfo reports the PHP of the web SAPI under server.php.version."""
    payload = {"ocs": {"data": {**API_PAYLOAD["ocs"]["data"], "server": {"php": {"version": "8.3.12"}}}}}

    info = _parse_api_payload(payload)

    assert info.php_version == "8.3.12"
    assert info.php_source == "api"
    assert info.as_dict()["phpVersion"] == "8.3.12"


def test_api_payload_without_php_block_leaves_the_version_unknown():
    info = _parse_api_payload(API_PAYLOAD)

    assert info.php_version is None
    assert info.as_dict()["phpVersion"] is None


def test_occ_serverinfo_php_version_is_labelled_cli():
    document = (
        '{"nextcloud": {"system": {"version": "31.0.9", "update": {"available": false}}},'
        ' "server": {"php": {"version": "8.4.27"}}}'
    )

    info = _parse_occ_serverinfo(document)

    assert info is not None
    assert info.php_version == "8.4.27"
    assert info.php_source == "occ (cli)"


def test_php_argv_reuses_the_php_binary_of_the_occ_command():
    settings = ServerInfoSettings(occ_command="/usr/bin/php8.3 /var/www/html/occ")
    assert _php_argv(settings) == ["/usr/bin/php8.3", "-r", "echo PHP_VERSION;"]

    settings = ServerInfoSettings(occ_command="occ", container="nextcloud-app")
    assert _php_argv(settings) == [
        "docker", "exec", "-u", "www-data", "nextcloud-app", "php", "-r", "echo PHP_VERSION;",
    ]


def test_cli_php_version_rejects_garbage(mocker):
    completed = MagicMock(returncode=0, stdout="Could not open input file\n")
    mocker.patch("nextcloud_local_scan.serverinfo.subprocess.run", return_value=completed)

    assert _fetch_cli_php_version(ServerInfoSettings()) is None

    completed.stdout = "8.1.2-1ubuntu2.14\n"
    assert _fetch_cli_php_version(ServerInfoSettings()) == "8.1.2-1ubuntu2.14"


def test_api_php_version_survives_the_occ_fallback(mocker):
    """When the API lacks the update block, occ supplies it but the API PHP wins."""
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "ocs": {"data": {"nextcloud": {"system": {"version": "31.0.9"}},
                         "server": {"php": {"version": "8.3.12"}}}}
    }
    mocker.patch("nextcloud_local_scan.serverinfo.requests.get", return_value=response)
    mocker.patch(
        "nextcloud_local_scan.serverinfo._run_occ",
        side_effect=lambda s, a: (1, "", "") if a[0] == "serverinfo" else (0, "", ""),
    )
    mocker.patch(
        "nextcloud_local_scan.serverinfo._fetch_cli_php_version", return_value="8.3.36"
    )
    settings = ServerInfoSettings(url="https://cloud.example.com", token="t", occ_configured=True)

    info = fetch_update_info(settings, "cloud.example.com")

    assert info.source == "occ update:check"
    assert info.php_version == "8.3.12"
    assert info.php_source == "api"
