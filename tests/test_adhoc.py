"""Ad-hoc sessions against discovered hosts.

The target gate carries the weight here. Handing an address to this module
makes the server offer its stored credentials to whatever answers, so the
tests that matter are the ones that try to get an address past it.
"""

import time

import pytest

from netauto import adhoc, scan
from netauto.drivers.base import READ_ALLOW, assert_read_only, platform_family
from netauto.errors import NetautoError, UnsafeCommand


@pytest.fixture
def swept():
    """A Discovered holding one host, as a sweep would have left it."""
    seen = adhoc.Discovered()
    seen.record([scan.Host(ip="192.168.1.9", mac="00:11:22:aa:bb:cc",
                           vendor="Cisco Systems",
                           ports=(scan.Port(22, True, "SSH-2.0-Cisco-1.25"),))])
    return seen


# --- the gate ---------------------------------------------------------------

def test_a_swept_private_address_is_connectable(swept):
    assert adhoc.assert_connectable("192.168.1.9", swept) == "192.168.1.9"


def test_an_address_no_sweep_found_is_refused(swept):
    """The whole point: a URL cannot nominate the target, a sweep must."""
    with pytest.raises(adhoc.ConnectRefused, match="not found by a sweep"):
        adhoc.assert_connectable("192.168.1.10", swept)


def test_a_routable_address_is_refused_even_when_swept():
    """Belt and braces: a sweep cannot reach the internet, but if one did."""
    seen = adhoc.Discovered()
    seen.record([scan.Host(ip="8.8.8.8")])
    with pytest.raises(adhoc.ConnectRefused, match="routable on the internet"):
        adhoc.assert_connectable("8.8.8.8", seen)


@pytest.mark.parametrize("ip", ["10.1.1.1", "172.16.0.1", "192.168.1.9",
                                "100.64.0.1", "127.0.0.1", "169.254.1.1"])
def test_every_unroutable_range_is_allowed(ip):
    """is_private would refuse the CGNAT one and it is a legitimate lab."""
    seen = adhoc.Discovered()
    seen.record([scan.Host(ip=ip)])
    assert adhoc.assert_connectable(ip, seen) == ip


def test_nonsense_is_refused(swept):
    with pytest.raises(adhoc.ConnectRefused, match="Not an address"):
        adhoc.assert_connectable("evil.example.com", swept)


def test_a_stale_address_stops_being_connectable():
    """A lease can move in an afternoon; the sweep is evidence with an age."""
    seen = adhoc.Discovered(ttl=0)
    seen.record([scan.Host(ip="192.168.1.9")])
    time.sleep(0.01)
    assert "192.168.1.9" not in seen
    with pytest.raises(adhoc.ConnectRefused, match="within the last"):
        adhoc.assert_connectable("192.168.1.9", seen)


def test_a_fresh_sweep_renews_an_address(swept):
    swept.record([scan.Host(ip="192.168.1.9")])
    assert adhoc.assert_connectable("192.168.1.9", swept)


def test_the_refusal_is_a_netauto_error(swept):
    """So every caller's existing except NetautoError renders it properly."""
    assert issubclass(adhoc.ConnectRefused, NetautoError)


# --- building the device ----------------------------------------------------

def test_the_device_is_addressed_by_ip_and_stored_nowhere(swept):
    dev = adhoc.build_device("192.168.1.9", "cisco_ios", "LAB", swept)
    assert dev.name == "192.168.1.9" and dev.host == "192.168.1.9"
    assert dev.platform == "cisco_ios"
    assert dev.credentials_prefix == "LAB"
    assert "ad-hoc" in dev.tags


def test_the_prefix_is_upper_cased_like_the_environment(swept):
    assert adhoc.build_device("192.168.1.9", "cisco_ios", "lab", swept).credentials_prefix == "LAB"


def test_no_credentials_is_refused_not_guessed(swept):
    """Device.credentials_prefix would fall back to the name -- '192_168_1_9'."""
    with pytest.raises(adhoc.ConnectRefused, match="credentials prefix"):
        adhoc.build_device("192.168.1.9", "cisco_ios", "  ", swept)


@pytest.mark.parametrize("prefix", ["9LAB", "lab; rm -rf /", "LAB-1", "LAB$"])
def test_a_prefix_that_is_not_a_variable_name_is_refused(swept, prefix):
    with pytest.raises(adhoc.ConnectRefused, match="Not a credentials prefix"):
        adhoc.build_device("192.168.1.9", "cisco_ios", prefix, swept)


def test_an_unknown_platform_is_refused(swept):
    with pytest.raises(adhoc.ConnectRefused, match="No driver"):
        adhoc.build_device("192.168.1.9", "cisco_catalyst", "LAB", swept)


@pytest.mark.parametrize("platform", ["meraki", "aruba_central"])
def test_cloud_tenants_cannot_be_dialled_at_an_address(swept, platform):
    """An org is not a box: there is nothing at that IP to connect to."""
    with pytest.raises(adhoc.ConnectRefused, match="cloud tenant"):
        adhoc.build_device("192.168.1.9", platform, "LAB", swept)


def test_cloud_tenants_are_not_offered():
    offered = adhoc.connectable_platforms()
    assert "meraki" not in offered and "aruba_central" not in offered
    assert "cisco_ios" in offered and "fortinet_fortios" in offered


def test_the_gate_runs_before_the_platform_check(swept):
    """An unswept address must not be told which platforms would work."""
    with pytest.raises(adhoc.ConnectRefused, match="not found by a sweep"):
        adhoc.build_device("192.168.1.99", "nonsense", "LAB", swept)


def test_the_segment_to_sweep_is_offered_for_an_unswept_address():
    assert adhoc.likely_segment("192.168.68.130") == "192.168.68.0/24"


@pytest.mark.parametrize("ip", ["8.8.8.8", "fe80::1", "nonsense", ""])
def test_no_segment_is_offered_where_a_sweep_would_not_help(ip):
    """A /24 means nothing for IPv6, and nothing routable is sweepable."""
    assert adhoc.likely_segment(ip) == ""


# --- guessing ---------------------------------------------------------------

@pytest.mark.parametrize("banner,expected", [
    ("SSH-2.0-Cisco-1.25", "cisco_ios"),
    ("SSH-2.0-OpenSSH_7.5p1 Juniper", "juniper_junos"),
    ("SSH-2.0-OpenSSH_6.5 FortiGate", "fortinet_cli"),
    ("SSH-2.0-Arista_1.0", "arista_eos"),
])
def test_a_banner_that_names_a_vendor_picks_the_platform(banner, expected):
    assert adhoc.guess_platform(banner=banner) == expected


def test_a_generic_banner_guesses_nothing():
    """Wrong is worse than blank: the operator has to choose."""
    assert adhoc.guess_platform(banner="SSH-2.0-OpenSSH_9.6") == ""
    assert adhoc.guess_platform() == ""


def test_the_mac_vendor_is_the_fallback():
    assert adhoc.guess_platform(vendor="Hewlett Packard Enterprise") == "aruba_aoscx"


def test_the_banner_beats_the_mac_vendor():
    """Who made the board says less than what the box says it runs."""
    assert adhoc.guess_platform(banner="SSH-2.0-Cisco-1.25",
                                vendor="Hewlett Packard") == "cisco_ios"


def test_the_guess_reads_a_swept_host(swept):
    assert adhoc.guess_for(swept.get("192.168.1.9")) == "cisco_ios"
    assert adhoc.guess_for(None) == ""


# --- credential prefixes ----------------------------------------------------

def test_prefixes_come_from_what_is_actually_exported():
    env = {"LAB_USERNAME": "u", "LAB_PASSWORD": "p", "CORE_SW_API_KEY": "k",
           "PATH": "/usr/bin", "NETAUTO_SECRET_KEY": "s"}
    assert adhoc.credential_prefixes(env) == ["CORE_SW", "LAB"]


def test_no_secret_value_is_returned():
    env = {"LAB_USERNAME": "admin", "LAB_PASSWORD": "hunter2"}
    assert "hunter2" not in str(adhoc.credential_prefixes(env))


# --- the guard reaches an ad-hoc session ------------------------------------

@pytest.mark.parametrize("platform", adhoc.connectable_platforms())
def test_every_offered_platform_is_one_the_guard_knows(platform):
    """A transient device is policed by its platform string and nothing else.

    Each driver calls assert_read_only(command, self.device.platform), so a
    platform in this dropdown that fell through to a family with a lax
    allowlist would be a way to reach a device without the guard meaning
    anything. Every one of them must refuse a write.
    """
    assert platform_family(platform) in READ_ALLOW
    assert assert_read_only("show version", platform)
    with pytest.raises(UnsafeCommand):
        assert_read_only("configure terminal", platform)
