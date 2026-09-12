"""Driver-level parsing, tested against captured real-gear output.

The connection paths need hardware, but the parsers are pure functions of the
text a device returned, so they test without one. The fixtures here are copied
verbatim from real equipment -- the README's standing caveat is that no
driver's parsing had met real gear, and this is where that starts to change.
"""

from netauto.config import Settings
from netauto.drivers.netmiko_driver import FortinetCliDriver
from netauto.inventory import Device


def _driver() -> FortinetCliDriver:
    # No open(): _parse_facts is pure and never touches the connection.
    return FortinetCliDriver(
        Device(name="fsw", platform="fortinet_cli", host="10.0.0.1"),
        Settings(inventory_path="unused"),
    )


# Verbatim from a FortiSwitch 108F on FortiSwitchOS 7.2.7 over SSH.
FSW_108F = (
    "Version: FortiSwitch-108F v7.2.7,build0479,240214 (GA)\n"
    "Serial-Number: S108FNTV24010522\n"
    "Boot: Warmboot\n"
    "BIOS version: 04000006\n"
    "System Part-Number: P26230-02\n"
    "Burn in MAC: 78:18:ec:e6:81:24\n"
    "Hostname: fsw-access-01\n"
    "Distribution: International\n"
    "Branch point: 479 \n"
    "System time: Wed Dec 31 20:13:26 1969\n"
)

# FortiGate shares the label set; the parser must serve it too.
FGT_60F = (
    "Version: FortiGate-60F v7.2.4,build1396,230131 (GA.F)\n"
    "Serial-Number: FGT60FTK21099999\n"
    "BIOS version: 05000000\n"
    "Hostname: fgt-edge\n"
    "System time: Mon Sep  1 10:00:00 2025\n"
)


def test_fortiswitch_status_is_parsed():
    f = _driver()._parse_facts(FSW_108F)
    assert f["model"] == "FortiSwitch-108F"
    assert f["os_version"] == "7.2.7"
    assert f["build"] == "0479"
    assert f["serial"] == "S108FNTV24010522"
    assert f["hostname"] == "fsw-access-01"
    assert f["part_number"] == "P26230-02"


def test_fortigate_shares_the_parser():
    f = _driver()._parse_facts(FGT_60F)
    assert f["model"] == "FortiGate-60F"
    assert f["os_version"] == "7.2.4"
    assert f["build"] == "1396"
    assert f["serial"] == "FGT60FTK21099999"
    assert f["hostname"] == "fgt-edge"


def test_version_line_yields_three_facts():
    """model, os_version and build all come from the one Version line."""
    f = _driver()._parse_facts("Version: FortiSwitch-108F v7.2.7,build0479,240214 (GA)\n")
    assert {"model", "os_version", "build"} <= f.keys()


def test_empty_and_junk_lines_are_ignored():
    f = _driver()._parse_facts("\nnonsense\nHostname: x\n: novalue\nKey:   \n")
    assert f == {"hostname": "x"}


def test_parser_does_not_touch_the_connection():
    """It runs before/without open(), so it must not reach for _conn."""
    d = _driver()
    assert d._conn is None
    d._parse_facts(FSW_108F)          # must not raise
    assert d._conn is None
