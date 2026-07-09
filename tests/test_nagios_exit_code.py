import pytest
from check_nextcloud_security import NagiosExitCode, _fail


@pytest.mark.parametrize(
    "member, expected_int",
    [
        (NagiosExitCode.OK, 0),
        (NagiosExitCode.WARNING, 1),
        (NagiosExitCode.CRITICAL, 2),
        (NagiosExitCode.UNKNOWN, 3),
    ],
)
def test_nagios_exit_code_values(member, expected_int):
    """
    Test that the NagiosExitCode enum matches the standard Nagios/Icinga
    plugin exit code contract (0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN).
    """
    assert int(member) == expected_int


def test_fail_prints_message_and_exits_with_given_code(capsys):
    """
    Test that the internal _fail helper prints the message to stdout and
    terminates the program with the requested exit code.
    """
    with pytest.raises(SystemExit) as e:
        _fail("CRITICAL: something went wrong", NagiosExitCode.CRITICAL)

    assert capsys.readouterr().out.strip() == "CRITICAL: something went wrong"
    assert e.value.code == 2


def test_fail_defaults_to_unknown_exit_code(capsys):
    """
    Test that _fail defaults to NagiosExitCode.UNKNOWN when no exit code is
    explicitly provided.
    """
    with pytest.raises(SystemExit) as e:
        _fail("UNKNOWN: unclear result")

    assert e.value.code == 3
