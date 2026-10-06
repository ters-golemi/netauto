"""Driver-level parsing, tested against captured real-gear output.

The connection paths need hardware, but the parsers are pure functions of the
text a device returned, so they test without one. The fixtures here are copied
verbatim from real equipment -- the README's standing caveat is that no
driver's parsing had met real gear, and this is where that starts to change.
"""

import pytest
from ntc_templates.parse import parse_output

from netauto.config import Settings
from netauto.drivers import get_driver_class
from netauto.drivers.netmiko_driver import FortinetCliDriver, PanOsDriver
from netauto.drivers.base import assert_read_only
from netauto.errors import DriverError, UnsafeCommand
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


# -- Cisco ACI -------------------------------------------------------------
#
# The APIC wraps every answer the same way -- imdata, a class name, an
# attributes dict -- so the unwrapping and the summarising are pure functions
# of that payload and test without a fabric. The attribute names below are the
# APIC's own; a typo in one is a driver that returns None for a real field,
# which is exactly what these pin down.

from netauto.drivers.aci_driver import (  # noqa: E402
    AciDriver, _attrs, _parse_fabric, _parse_neighbors,
)

# Shape of /api/class/fabricNode.json on a four-node fabric.
ACI_NODES = [
    {"fabricNode": {"attributes": {
        "id": "1", "name": "apic1", "role": "controller",
        "model": "APIC-SERVER-M3", "serial": "FCH1234V5XY",
        "version": "5.2(7f)", "fabricSt": "unknown", "adSt": "on"}}},
    {"fabricNode": {"attributes": {
        "id": "101", "name": "leaf-101", "role": "leaf",
        "model": "N9K-C93180YC-EX", "serial": "FDO9876ABCD",
        "version": "n9000-15.2(7f)", "fabricSt": "active", "adSt": "on"}}},
    {"fabricNode": {"attributes": {
        "id": "102", "name": "leaf-102", "role": "leaf",
        "model": "N9K-C93180YC-EX", "serial": "FDO9876ABCE",
        "version": "n9000-15.2(7f)", "fabricSt": "inactive", "adSt": "on"}}},
    {"fabricNode": {"attributes": {
        "id": "201", "name": "spine-201", "role": "spine",
        "model": "N9K-C9336PQ", "serial": "FDO5555XXXX",
        "version": "n9000-15.2(7f)", "fabricSt": "active", "adSt": "on"}}},
]


def test_aci_imdata_is_unwrapped_to_attributes():
    assert [a["name"] for a in _attrs(ACI_NODES, "fabricNode")] == [
        "apic1", "leaf-101", "leaf-102", "spine-201"
    ]


def test_aci_class_filter_excludes_other_classes():
    """A class query can return more than one class; only the asked-for one counts."""
    mixed = ACI_NODES + [{"fvTenant": {"attributes": {"name": "common"}}}]
    assert len(_attrs(mixed, "fabricNode")) == 4
    assert len(_attrs(mixed, "fvTenant")) == 1
    assert len(_attrs(mixed)) == 5


def test_aci_malformed_imdata_entries_are_skipped():
    """A bare string or a class with no attributes must not raise."""
    assert _attrs(["nonsense", {"fabricNode": {}}, {"fabricNode": {"attributes": 7}}]) == []
    assert _attrs([]) == [] and _attrs(None) == []


def test_aci_fabric_summary_counts_roles_and_finds_the_apic_version():
    f = _parse_fabric(_attrs(ACI_NODES, "fabricNode"))
    assert f["node_roles"] == {"controller": 1, "leaf": 2, "spine": 1}
    assert f["node_count"] == 4
    assert f["apic_version"] == "5.2(7f)"


def test_aci_summary_reports_a_switch_that_left_the_fabric():
    """fabricSt is how a decommissioned leaf shows up, and it must be surfaced."""
    f = _parse_fabric(_attrs(ACI_NODES, "fabricNode"))
    assert f["nodes_not_active"] == ["leaf-102=inactive"]


def test_aci_controller_fabric_state_is_not_read_as_a_fault():
    """A controller reports fabricSt "unknown" normally; it is not an alarm."""
    only_apic = _parse_fabric(_attrs(ACI_NODES[:1], "fabricNode"))
    assert only_apic["nodes_not_active"] == []


def test_aci_node_with_an_unexpected_role_is_still_counted():
    odd = [{"fabricNode": {"attributes": {"id": "9", "name": "x", "role": "tier-2-leaf"}}}]
    assert _parse_fabric(_attrs(odd, "fabricNode"))["node_roles"] == {"tier-2-leaf": 1}


def test_aci_neighbours_take_the_local_end_from_the_dn():
    """lldpAdjEp carries the remote end only; the local node and port are in the dn."""
    adj = [{"lldpAdjEp": {"attributes": {
        "dn": "topology/pod-1/node-101/sys/lldp/inst/if-[eth1/1]/adj-1",
        "sysName": "core-sw-01", "portIdV": "Ethernet1/5",
        "sysDesc": "Cisco NX-OS", "chassisIdV": "00:11:22:33:44:55"}}}]
    assert _parse_neighbors(_attrs(adj, "lldpAdjEp")) == [{
        "local_port": "node-101/eth1/1",
        "remote_host": "core-sw-01",
        "remote_port": "Ethernet1/5",
        "remote_description": "Cisco NX-OS",
        "remote_chassis_id": "00:11:22:33:44:55",
    }]


def test_aci_adjacency_without_a_local_port_is_dropped():
    """A link with no local end cannot be drawn, so it is not reported as one."""
    adj = [{"lldpAdjEp": {"attributes": {
        "dn": "topology/pod-1/node-999/sys/lldp/inst/adj-9", "sysName": "nowhere"}}}]
    assert _parse_neighbors(_attrs(adj, "lldpAdjEp")) == []


def test_aci_neighbour_falls_back_to_the_chassis_id_for_a_nameless_peer():
    adj = [{"lldpAdjEp": {"attributes": {
        "dn": "topology/pod-1/node-103/sys/lldp/inst/if-[eth1/9]/adj-1",
        "chassisIdV": "aa:bb:cc:dd:ee:ff", "portDesc": "uplink"}}}]
    n = _parse_neighbors(_attrs(adj, "lldpAdjEp"))[0]
    assert n["remote_host"] == "aa:bb:cc:dd:ee:ff"
    assert n["remote_port"] == "uplink"


def test_aci_is_registered_as_a_fabric_that_can_be_mapped():
    cls = get_driver_class("cisco_aci")
    assert cls is AciDriver
    # neighbors is the interesting one: one APIC call stands in for a session
    # per leaf, which is what makes net_topology usable on a fabric.
    assert {"facts", "config", "devices", "neighbors"} <= cls.capabilities
    assert "command" not in cls.capabilities
    assert "upgrade" not in cls.capabilities


def test_aci_refuses_a_command_and_says_where_to_go_instead():
    d = AciDriver(Device(name="aci", platform="cisco_aci", host="10.0.0.1"),
                  Settings(inventory_path="unused"))
    with pytest.raises(DriverError, match="cisco_nxos"):
        d.run_read("show version")


def test_aci_rejects_a_config_kind_the_fabric_does_not_have():
    d = AciDriver(Device(name="aci", platform="cisco_aci", host="10.0.0.1"),
                  Settings(inventory_path="unused"))
    with pytest.raises(DriverError, match="policy is the configuration"):
        d.get_config("startup")


def test_aci_without_a_host_or_base_url_says_so_before_connecting():
    d = AciDriver(Device(name="aci", platform="cisco_aci"),
                  Settings(inventory_path="unused"))
    with pytest.raises(DriverError, match="no host address"):
        d._base_url()


def test_aci_base_url_prefers_an_explicit_one_and_honours_a_port():
    settings = Settings(inventory_path="unused")
    plain = AciDriver(Device(name="a", platform="cisco_aci", host="10.0.0.1"), settings)
    assert plain._base_url() == "https://10.0.0.1"
    ported = AciDriver(
        Device(name="a", platform="cisco_aci", host="10.0.0.1", port=8443), settings)
    assert ported._base_url() == "https://10.0.0.1:8443"
    explicit = AciDriver(
        Device(name="a", platform="cisco_aci", host="10.0.0.1",
               options={"base_url": "https://apic.example.net/"}), settings)
    assert explicit._base_url() == "https://apic.example.net"


# -- Cisco Nexus Dashboard -------------------------------------------------
#
# ND reorganised these payloads twice, so the parsers are deliberately shape
# tolerant and the tests below are mostly about that tolerance: the same
# question answered three ways must produce one row shape.

from netauto.drivers.nexus_dashboard_driver import (  # noqa: E402
    DEFAULT_PATHS, NexusDashboardDriver, _flatten, _format_version, _items,
    _parse_sites,
)

ND_SITE = {
    "meta": {"name": "site-dc1", "modts": "2026-01-01"},
    "spec": {"name": "dc1", "siteType": "ACI", "host": "10.1.1.1"},
    "status": {"state": "Up", "siteVersion": "5.2(7f)"},
}


def test_nd_records_are_found_whatever_envelope_they_arrive_in():
    rows = [{"name": "a"}]
    assert _items({"items": rows}) == rows
    assert _items(rows) == rows
    assert _items({"sites": rows}) == rows
    assert _items({"somethingNew": rows}) == rows, "an unknown key must still be found"


def test_nd_junk_payloads_yield_no_records_rather_than_raising():
    assert _items("nope") == [] and _items({}) == [] and _items(None) == []
    assert _items({"items": "not a list"}) == []


def test_nd_envelopes_are_flattened_with_status_winning():
    """spec is what was asked for and status is what is true, so status wins."""
    flat = _flatten({"spec": {"state": "Up", "name": "dc1"},
                     "status": {"state": "Down"}})
    assert flat["state"] == "Down"
    assert flat["name"] == "dc1"


def test_nd_flatten_drops_nested_bodies_rather_than_stringifying_them():
    flat = _flatten({"spec": {"name": "dc1", "nested": {"deep": 1}, "list": [1, 2]}})
    assert flat == {"name": "dc1"}


def test_nd_version_is_read_from_every_shape_it_ships_in():
    assert _format_version({"major": 3, "minor": 1, "maintenance": 1, "patch": "d"}) == "3.1.1(d)"
    assert _format_version({"major": 3, "minor": 1, "maintenance": 1}) == "3.1.1"
    assert _format_version({"version": "4.2.1"}) == "4.2.1"
    assert _format_version("3.0.1") == "3.0.1"
    assert _format_version({}) is None
    assert _format_version(None) is None


def test_nd_sites_read_the_same_across_releases():
    """An ACI site and an NDFC site, named and stated by different keys."""
    rows = _parse_sites([ND_SITE, {
        "spec": {"siteName": "dc2", "type": "NDFC"},
        "status": {"connectivityStatus": "Down"},
    }])
    assert [r["name"] for r in rows] == ["dc1", "dc2"]
    assert [r["site_type"] for r in rows] == ["ACI", "NDFC"]
    assert [r["state"] for r in rows] == ["Up", "Down"]


def test_nd_every_probed_question_has_at_least_one_candidate_path():
    for key, paths in DEFAULT_PATHS.items():
        assert paths, f"{key} has no candidate paths to try"
        assert all(p.startswith("/") for p in paths), key


def test_nd_an_inventory_path_override_is_tried_alone():
    """Pinning a path must stop the probe guessing others and masking a typo."""
    d = NexusDashboardDriver(
        Device(name="nd", platform="cisco_nexus_dashboard", host="10.0.0.1",
               options={"api_paths": {"sites": "/my/own/sites"}}),
        Settings(inventory_path="unused"))
    assert d._candidates("sites") == ("/my/own/sites",)
    assert d._candidates("nodes") == DEFAULT_PATHS["nodes"]


def test_nd_is_registered_as_a_cluster_with_no_cli():
    cls = get_driver_class("cisco_nexus_dashboard")
    assert cls is NexusDashboardDriver
    assert {"facts", "config", "devices"} <= cls.capabilities
    assert "command" not in cls.capabilities
    # A cluster knows its sites, not their switches' LLDP tables.
    assert "neighbors" not in cls.capabilities


def test_nd_refuses_a_command_and_points_at_the_fabric_controller():
    d = NexusDashboardDriver(
        Device(name="nd", platform="cisco_nexus_dashboard", host="10.0.0.1"),
        Settings(inventory_path="unused"))
    with pytest.raises(DriverError, match="cisco_aci"):
        d.run_read("show version")


# -- NX-API ----------------------------------------------------------------


def test_nxos_over_nxapi_is_a_separate_platform_from_the_ssh_one():
    """Two transports to the same switch; neither may shadow the other."""
    from netauto.drivers import supported_platforms

    assert {"cisco_nxos", "cisco_nxos_api"} <= set(supported_platforms())
    ssh, api = get_driver_class("cisco_nxos"), get_driver_class("cisco_nxos_api")
    assert ssh.napalm_name == "nxos_ssh"
    assert api.napalm_name == "nxos"
    assert ssh is not api


def test_nxapi_keeps_the_cisco_guard_family():
    """A new platform string that fell through to "generic" would widen the guard."""
    from netauto.drivers.base import platform_family

    # NX-API reaches the same NX-OS CLI, so it is policed as Cisco.
    assert platform_family("cisco_nxos_api") == "cisco"


def test_the_controllers_are_not_policed_as_ios_devices():
    """Both controller strings start with "cisco" and neither speaks IOS.

    This asserted "cisco" for all three when the drivers landed, and that was
    wrong in two ways at once: it let the IOS compliance rules judge a policy
    export, and it told the command guard that a platform with no CLI accepts
    show commands. The family is the configuration language, not the vendor.
    """
    from netauto.drivers.base import READ_ALLOW, platform_family

    for platform, family in (("cisco_aci", "aci"),
                             ("cisco_nexus_dashboard", "nexusdashboard")):
        assert platform_family(platform) == family
        # Known to the guard, and known to permit nothing.
        assert family in READ_ALLOW
        assert READ_ALLOW[family] == ()
        with pytest.raises(UnsafeCommand):
            assert_read_only("show version", platform)
