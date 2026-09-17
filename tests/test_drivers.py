"""Driver-level parsing, tested against captured real-gear output.

The connection paths need hardware, but the parsers are pure functions of the
text a device returned, so they test without one. The fixtures here are copied
verbatim from real equipment -- the README's standing caveat is that no
driver's parsing had met real gear, and this is where that starts to change.
"""

from ntc_templates.parse import parse_output

from netauto.config import Settings
from netauto.drivers import get_driver_class
from netauto.drivers.netmiko_driver import FortinetCliDriver, PanOsDriver
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
    assert f["vendor"] == "Fortinet"
    assert f["os_version"] == "7.2.7"
    assert f["build"] == "0479"
    assert f["serial"] == "S108FNTV24010522"
    assert f["hostname"] == "fsw-access-01"
    assert f["part_number"] == "P26230-02"


def test_fortigate_shares_the_parser():
    f = _driver()._parse_facts(FGT_60F)
    assert f["model"] == "FortiGate-60F"
    assert f["vendor"] == "Fortinet"
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


# -- PAN-OS ------------------------------------------------------------------
#
# Not captured from real gear, unlike the Fortinet fixtures above: no PAN-OS
# device has met this driver. The shape follows PAN-OS documentation and the
# ntc-templates parsers for the same commands, which reject a line they do not
# expect -- so the LLDP sample at least parses the way netmiko will parse it.

def _panos() -> PanOsDriver:
    return PanOsDriver(
        Device(name="fw", platform="paloalto_panos", host="10.0.0.1"),
        Settings(inventory_path="unused"),
    )


PANOS_SYSTEM_INFO = (
    "\n"
    "hostname: fw-edge-01\n"
    "ip-address: 10.0.0.1\n"
    "public-ip-address: unknown\n"
    "netmask: 255.255.255.0\n"
    "default-gateway: 10.0.0.254\n"
    "ipv6-address: unknown\n"
    "mac-address: 00:1b:17:00:01:10\n"
    "time: Wed Sep 17 10:00:00 2026\n"
    "uptime: 12 days, 3:04:05\n"
    "family: 400\n"
    "model: PA-440\n"
    "serial: 021201012345\n"
    "sw-version: 11.1.4-h7\n"
    "app-version: 8866-8930\n"
    "threat-version: 8866-8930\n"
    "platform-family: 400\n"
    "multi-vsys: off\n"
    "operational-mode: normal\n"
)


def test_panos_system_info_is_parsed():
    f = _panos()._parse_facts(PANOS_SYSTEM_INFO)
    assert f == {
        "hostname": "fw-edge-01",
        "management_ip": "10.0.0.1",
        "uptime": "12 days, 3:04:05",
        "family": "400",
        "model": "PA-440",
        "serial": "021201012345",
        "os_version": "11.1.4-h7",
        "app_version": "8866-8930",
        "threat_version": "8866-8930",
        "multi_vsys": "off",
        "vendor": "Palo Alto Networks",
    }


def test_panos_unknown_is_not_a_value():
    """An unlicensed VM-Series says "serial: unknown"; that is no serial."""
    f = _panos()._parse_facts("model: PA-VM\nserial: unknown\nsw-version: 11.1.4\n")
    assert "serial" not in f
    assert f["model"] == "PA-VM"


def test_panos_vendor_needs_a_model():
    """Output that parsed to nothing must not come back claiming a vendor."""
    assert _panos()._parse_facts("error: session expired\n\n") == {}


PANOS_LLDP = """\

Local information:
  Index 1
  Local interface:  ethernet1/1
  Local Port ID:  ethernet1/1

Neighbor information:
  Chassis type:  MAC address
  Chassis ID:  00:1c:73:aa:bb:cc
  Port type:  Interface name
  Port ID:  Ethernet1
  Port description:  to-fw-edge-01
  TTL:  120
  System name:  core-sw-01
  System description:  Arista Networks EOS version 4.30.1F
  System capabilities:
    Supported: Bridge, Router
    Enabled: Bridge, Router
  Management address type:  ipv4
  Management address:  10.0.0.2
  Interface number:  1
  Interface type: ifIndex
  oid:
"""


class _TemplateConn:
    """Stands in for a netmiko session, parsing with the real template."""

    def __init__(self, raw: str):
        self.raw = raw
        self.sent: list[str] = []

    def send_command(self, cmd, use_textfsm=False, read_timeout=None):
        self.sent.append(cmd)
        if not use_textfsm:
            return self.raw
        return parse_output(platform="paloalto_panos", command=cmd, data=self.raw)


def test_panos_lldp_template_fields_reach_the_neighbour_rows():
    """ntc-templates' names must be ones NetmikoDriver.neighbors picks from."""
    d = _panos()
    d._conn = _TemplateConn(PANOS_LLDP)
    assert d.neighbors() == [{
        "local_port": "ethernet1/1",
        "remote_host": "core-sw-01",
        "remote_port": "Ethernet1",
        "remote_description": "Arista Networks EOS version 4.30.1F",
        "remote_chassis_id": "00:1c:73:aa:bb:cc",
    }]
    assert d._conn.sent == ["show lldp neighbors all"]


def test_panos_is_registered_with_every_read():
    cls = get_driver_class("paloalto_panos")
    assert cls is PanOsDriver
    assert {"facts", "config", "command", "neighbors"} <= cls.capabilities
    assert "upgrade" not in cls.capabilities
