import pytest

from check_nextcloud_security import check_if_ip_or_host


def test_exits_on_ip(monkeypatch):
    """Should abort with exit(3) for IP address."""
    with pytest.raises(SystemExit) as e:
        check_if_ip_or_host("192.168.1.1")
    assert e.value.code == 3


def test_does_not_exit_on_hostname(monkeypatch):
    """Should NOT abort if hostname is passed."""
    check_if_ip_or_host("nextcloud.nextcloud.com")

@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.1",
        "::1",
        "2001:db8::1",
        "[2001:db8::1]",
        "fe80::1%eth0",
    ],
)
def test_exits_on_any_ip_literal(address):
    """IPv4 and IPv6 literals (also bracketed or zoned) are rejected."""
    with pytest.raises(SystemExit) as e:
        check_if_ip_or_host(address)
    assert e.value.code == 3


@pytest.mark.parametrize(
    "host",
    [
        "999.999.999.999",
        "1.2.3",
        "10.0.0.1.example.com",
        "nextcloud.example.com",
    ],
)
def test_does_not_exit_on_non_ip_values(host):
    """Values that only look like an IP are passed through as hostnames."""
    check_if_ip_or_host(host)
