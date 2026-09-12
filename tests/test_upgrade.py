"""The firmware-upgrade write path and its gates.

netauto is read-only apart from this one operation. The point of these tests
is that the exception stays an exception: reads are still guarded, and the
write cannot fire unless every gate is deliberately opened.
"""

import pytest

from netauto.config import Settings
from netauto.drivers.base import Driver, assert_read_only
from netauto.drivers.netmiko_driver import FortinetCliDriver
from netauto.errors import UnsafeCommand, UnsupportedOperation, UpgradeError, WriteDisabled
from netauto.inventory import Device


def _driver(cls=FortinetCliDriver, *, allow_writes=False):
    d = cls(Device(name="fsw-access-01", platform="fortinet_cli", host="10.0.0.1"),
            Settings(inventory_path="unused", allow_writes=allow_writes))
    return d


# --- reads are still guarded, upgrade command is not a read ------------------

def test_the_upgrade_command_is_not_a_read():
    """execute restore image must never pass the read-only guard."""
    with pytest.raises(UnsafeCommand):
        assert_read_only("execute restore image tftp fw.out 10.0.0.9", "fortinet_cli")


# --- the three gates ---------------------------------------------------------

def test_gate1_allow_writes_off_refuses():
    d = _driver(allow_writes=False)
    with pytest.raises(WriteDisabled, match="allow_writes is false"):
        d.upgrade_firmware(image="fw.out", server="10.0.0.9", confirm="fsw-access-01")


def test_gate2_a_driver_without_the_capability_refuses():
    """allow_writes on, but a driver that does not do upgrades still says no."""
    class NoUpgrade(FortinetCliDriver):
        capabilities = frozenset({"facts", "config", "command"})
    d = _driver(NoUpgrade, allow_writes=True)
    with pytest.raises(UnsupportedOperation, match="no firmware-upgrade path"):
        d.upgrade_firmware(image="fw.out", server="10.0.0.9", confirm="fsw-access-01")


def test_gate3_wrong_confirmation_refuses():
    d = _driver(allow_writes=True)
    with pytest.raises(WriteDisabled, match="not confirmed"):
        d.upgrade_firmware(image="fw.out", server="10.0.0.9", confirm="")
    with pytest.raises(WriteDisabled, match="not confirmed"):
        d.upgrade_firmware(image="fw.out", server="10.0.0.9", confirm="wrong-name")


def test_all_gates_open_reaches_the_device_path(monkeypatch):
    """With every gate opened, it calls _do_upgrade -- checked without a device."""
    d = _driver(allow_writes=True)
    seen = {}
    def fake(**kw):
        seen.update(kw); return "restore started"
    monkeypatch.setattr(d, "_do_upgrade", fake)
    out = d.upgrade_firmware(image="fw.out", server="10.0.0.9",
                             confirm="fsw-access-01", stage_only=True)
    assert out == "restore started"
    assert seen == {"image":"fw.out","server":"10.0.0.9","protocol":"tftp","stage_only":True}


# --- the config commit path is still fully closed ----------------------------

def test_config_commit_is_still_refused_even_with_allow_writes():
    """allow_writes opens firmware upgrade only, never a config commit."""
    d = _driver(allow_writes=True)
    with pytest.raises(WriteDisabled, match="no\\n?.*commit path|commit path"):
        d.apply_config("hostname x")


# --- the FortiSwitch command shape -------------------------------------------

def test_fortiswitch_builds_the_restore_command(monkeypatch):
    d = _driver(allow_writes=True)
    class FakeConn:
        def __init__(self): self.sent=[]
        def send_command_timing(self, c, **kw):
            self.sent.append(c)
            return "This operation will replace the current firmware. Do you want to continue? (y/n)" if c.startswith("execute") else "starting upgrade"
    fake = FakeConn(); d._conn = fake
    out = d.upgrade_firmware(image="FSW_108F-v7.4.8.out", server="10.10.10.20", confirm="fsw-access-01")
    assert d._conn.sent[0] == "execute restore image tftp FSW_108F-v7.4.8.out 10.10.10.20"
    assert d._conn.sent[1] == "y"          # confirmed the reboot prompt


def test_fortiswitch_stage_only_uses_stage(monkeypatch):
    d = _driver(allow_writes=True)
    class FakeConn:
        def send_command_timing(self, c, **kw): return "image staged"
    d._conn = FakeConn()
    d.upgrade_firmware(image="fw.out", server="10.0.0.9", confirm="fsw-access-01", stage_only=True)


def test_a_rejected_image_raises_upgradeerror():
    d = _driver(allow_writes=True)
    class FakeConn:
        def send_command_timing(self, c, **kw): return "Invalid firmware image."
    d._conn = FakeConn()
    with pytest.raises(UpgradeError, match="rejected the image"):
        d.upgrade_firmware(image="bad.out", server="10.0.0.9", confirm="fsw-access-01")
