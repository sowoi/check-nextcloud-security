from check_nextcloud_security import check_if_ip_or_host

import pytest

def test_exits_on_ip(monkeypatch):
    """Should abort with exit(3) for IP address."""
    with pytest.raises(SystemExit) as e:
        check_if_ip_or_host("192.168.1.1")
    assert e.value.code == 3


def test_does_not_exit_on_hostname(monkeypatch):
    """Should NOT abort if hostname is passed."""
    check_if_ip_or_host("nextcloud.nextcloud.com")