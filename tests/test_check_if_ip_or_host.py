from check_nextcloud_security import check_if_ip_or_host

import pytest

def test_exits_on_ip(monkeypatch):
    """Soll bei IP-Adresse mit exit(3) abbrechen."""
    with pytest.raises(SystemExit) as e:
        check_if_ip_or_host("192.168.1.1")
    assert e.value.code == 3


def test_does_not_exit_on_hostname(monkeypatch):
    """Soll NICHT abbrechen, wenn Hostname übergeben wird."""
    check_if_ip_or_host("nextcloud.nextcloud.com")



