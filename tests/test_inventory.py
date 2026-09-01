import pytest

from netauto.config import resolve_credentials
from netauto.errors import AuthError, NetautoError
from netauto.inventory import Inventory

YAML = """
devices:
  - name: core-sw-01
    platform: cisco_ios
    host: 10.0.0.11
    credentials: CORE_SW
    tags: [campus, core]
  - name: edge-rtr-01
    platform: juniper_junos
    host: 10.0.0.1
    tags: [wan]
"""


@pytest.fixture
def inv(tmp_path):
    p = tmp_path / "devices.yaml"
    p.write_text(YAML)
    return Inventory.load(p)


def test_loads_devices(inv):
    assert len(inv) == 2
    assert inv.get("core-sw-01").platform == "cisco_ios"


def test_select_by_tag(inv):
    assert [d.name for d in inv.select(tag="wan")] == ["edge-rtr-01"]


def test_credentials_prefix_defaults_to_name(inv):
    assert inv.get("edge-rtr-01").credentials_prefix == "EDGE_RTR_01"
    assert inv.get("core-sw-01").credentials_prefix == "CORE_SW"


def test_unknown_device_lists_known_ones(inv):
    with pytest.raises(NetautoError, match="core-sw-01"):
        inv.get("nope")


def test_missing_credentials_names_the_variable(monkeypatch):
    monkeypatch.delenv("TESTDEV_USERNAME", raising=False)
    monkeypatch.delenv("TESTDEV_PASSWORD", raising=False)
    with pytest.raises(AuthError, match="TESTDEV_USERNAME"):
        resolve_credentials("TESTDEV")


def test_credentials_come_from_environment(monkeypatch):
    monkeypatch.setenv("TESTDEV_USERNAME", "admin")
    monkeypatch.setenv("TESTDEV_PASSWORD", "s3cret")
    creds = resolve_credentials("TESTDEV")
    assert creds == {"username": "admin", "password": "s3cret"}


def test_inventory_file_holds_no_secrets(inv):
    """The inventory must never carry a password field."""
    for device in inv:
        assert "password" not in device.options
        assert "api_key" not in device.options
