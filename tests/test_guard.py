"""The command guard is the safety boundary, so it gets the most tests."""

import pytest

from netauto.drivers.base import assert_read_only, platform_family
from netauto.errors import UnsafeCommand


@pytest.mark.parametrize("platform,command", [
    ("cisco_ios", "show running-config"),
    ("cisco_ios", "show ip interface brief"),
    ("cisco_nxos", "show vlan brief"),
    ("juniper_junos", "show interfaces terse"),
    ("aruba_aoscx", "show vlan"),
    ("aruba_osswitch", "display interface"),
    ("fortinet_fortios", "get system status"),
    ("fortinet_fortios", "diagnose sys top"),
    ("fortinet_fortios", "execute ping 8.8.8.8"),
    ("paloalto_panos", "show system info"),
    ("paloalto_panos", "show config running"),
    ("paloalto_panos", "ping host 8.8.8.8"),
    ("paloalto_panos", "test security-policy-match from trust to untrust "
                       "source 10.0.0.5 destination 8.8.8.8 protocol 6 "
                       "destination-port 443"),
    ("paloalto_panos", "test routing fib-lookup virtual-router default ip 8.8.8.8"),
])
def test_read_commands_allowed(platform, command):
    assert assert_read_only(command, platform) == command


@pytest.mark.parametrize("command", [
    "configure terminal",
    "conf t",
    "write memory",
    "copy running-config startup-config",
    "reload",
    "delete flash:config.txt",
    "erase startup-config",
    "no ip http server",
    "set system services telnet",
    "commit",
    "rollback 1",
    "clear counters",
    "request system reboot",
    "execute factoryreset",
])
def test_write_commands_rejected(command):
    with pytest.raises(UnsafeCommand):
        assert_read_only(command, "cisco_ios")


@pytest.mark.parametrize("command", [
    "request restart system",
    "request system software install version 11.1.4",
    "commit force",
    "configure",
    "set cli pager off",
    "delete config saved backup.xml",
    "load config from backup.xml",
    "clear session all",
    "debug dataplane packet-diag set log on",
    "test vpn ike-sa gateway gw-1",
    "test authentication authentication-profile ldap username x password",
])
def test_panos_writes_and_active_tests_rejected(command):
    """PAN-OS test and debug are mostly active; only lookups get through."""
    with pytest.raises(UnsafeCommand):
        assert_read_only(command, "paloalto_panos")


@pytest.mark.parametrize("command", [
    "show version; reload",
    "show version && write memory",
    "show version | reload",
    "show version\nreload",
    "show version $(reload)",
    "show version `reload`",
])
def test_chaining_rejected(command):
    """A permitted prefix must not smuggle a second command through."""
    with pytest.raises(UnsafeCommand, match="chaining"):
        assert_read_only(command, "cisco_ios")


def test_unknown_command_rejected():
    """Default deny: anything not recognised as a read is refused."""
    with pytest.raises(UnsafeCommand):
        assert_read_only("frobnicate the widget", "cisco_ios")


def test_empty_rejected():
    with pytest.raises(UnsafeCommand):
        assert_read_only("   ", "cisco_ios")


@pytest.mark.parametrize("platform,expected", [
    ("cisco_ios", "cisco"), ("cisco_nxos", "cisco"), ("arista_eos", "cisco"),
    ("juniper_junos", "juniper"), ("aruba_aoscx", "aruba"),
    ("aruba_osswitch", "aruba"), ("fortinet_fortios", "fortinet"),
    ("paloalto_panos", "paloalto"),
    ("meraki", "generic"),
])
def test_platform_family(platform, expected):
    assert platform_family(platform) == expected
