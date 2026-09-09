"""The MCP tools, at the boundary an agent actually calls.

Covered here rather than in test_adhoc.py because a gate that holds in the
module and is skipped by the tool is a gate that does not hold. These call the
tool functions the way the server does, and read the JSON back.
"""

import contextlib
import json

import pytest

from netauto import mcp_server, scan
from netauto.errors import DriverError, UnsafeCommand


def raw(tool, **kwargs) -> str:
    """The JSON string a tool hands back, before it is parsed."""
    return getattr(tool, "fn", tool)(**kwargs)


def call(tool, **kwargs):
    """Invoke a tool the way the server does and parse its JSON."""
    return json.loads(raw(tool, **kwargs))


@pytest.fixture
def swept():
    """A sweep has happened in this process, so .9 is connectable."""
    mcp_server._discovered = type(mcp_server._discovered)()
    mcp_server._discovered.record([
        scan.Host(ip="192.168.1.9", mac="00:11:22:aa:bb:cc", vendor="Cisco Systems",
                  ports=(scan.Port(22, True, "SSH-2.0-Cisco-1.25"),))])
    return mcp_server._discovered


@pytest.fixture
def driver(monkeypatch):
    """Answer as a device would, and record the Device we were asked to dial."""
    dialled = []

    class FakeDriver:
        def facts(self):
            return {"vendor": "Cisco", "model": "C9300", "os_version": "17.9.4"}

        def get_config(self, kind):
            return "hostname undocumented-sw\n"

        def run_read(self, command):
            if "reload" in command:
                raise UnsafeCommand(f"Command {command!r} matches a denied pattern.")
            return f"output of {command}"

    @contextlib.contextmanager
    def fake_connect(device, settings):
        dialled.append(device)
        yield FakeDriver()

    monkeypatch.setattr(mcp_server, "connect", fake_connect)
    return dialled


# --- the gate, at the tool boundary -----------------------------------------

def test_an_unswept_address_is_refused(swept, driver):
    out = call(mcp_server.net_connect_adhoc, ip="192.168.1.50",
               platform="cisco_ios", credentials="LAB")
    assert out["error"] == "ConnectRefused"
    assert "not found by a sweep" in out["message"]
    assert not driver, "nothing may be dialled when the gate refuses"


def test_a_routable_address_is_refused(swept, driver):
    swept.record([scan.Host(ip="8.8.8.8")])
    out = call(mcp_server.net_connect_adhoc, ip="8.8.8.8",
               platform="cisco_ios", credentials="LAB")
    assert "routable on the internet" in out["message"]
    assert not driver


def test_a_cloud_tenant_cannot_be_dialled(swept, driver):
    out = call(mcp_server.net_connect_adhoc, ip="192.168.1.9",
               platform="meraki", credentials="LAB")
    assert "cloud tenant" in out["message"]
    assert not driver


def test_a_sweep_makes_an_address_connectable(driver):
    """The tool's own memory is what the gate reads, so the sweep must fill it."""
    mcp_server._discovered = type(mcp_server._discovered)()
    refused = call(mcp_server.net_connect_adhoc, ip="192.168.1.9",
                   platform="cisco_ios", credentials="LAB")
    assert refused["error"] == "ConnectRefused"
    mcp_server._discovered.record([scan.Host(ip="192.168.1.9")])
    allowed = call(mcp_server.net_connect_adhoc, ip="192.168.1.9",
                   platform="cisco_ios", credentials="LAB")
    assert "facts" in allowed


# --- what it returns ---------------------------------------------------------

def test_facts_identify_what_was_reached(swept, driver):
    out = call(mcp_server.net_connect_adhoc, ip="192.168.1.9",
               platform="cisco_ios", credentials="LAB")
    assert out["facts"]["model"] == "C9300"
    assert out["device"] == "192.168.1.9" and out["in_inventory"] is False
    assert out["credentials"] == "LAB"
    dev = driver[0]
    assert dev.host == "192.168.1.9" and dev.platform == "cisco_ios"


def test_the_config_is_opt_in(swept, driver):
    """A running config is large and full of secrets; it is asked for."""
    without = call(mcp_server.net_connect_adhoc, ip="192.168.1.9",
                   platform="cisco_ios", credentials="LAB")
    assert "config" not in without
    with_it = call(mcp_server.net_connect_adhoc, ip="192.168.1.9",
                   platform="cisco_ios", credentials="LAB", include_config=True)
    assert "undocumented-sw" in with_it["config"]


def test_a_command_runs_through_the_guard(swept, driver):
    out = call(mcp_server.net_connect_adhoc, ip="192.168.1.9", platform="cisco_ios",
               credentials="LAB", command="show version")
    assert out["output"] == "output of show version"


def test_a_refused_command_does_not_sink_the_identification(swept, driver):
    out = call(mcp_server.net_connect_adhoc, ip="192.168.1.9", platform="cisco_ios",
               credentials="LAB", command="reload")
    assert "denied pattern" in out["command_error"]
    assert "output" not in out
    assert out["facts"]["model"] == "C9300", "the facts are still worth having"


def test_an_unreachable_host_is_an_error_not_a_half_answer(swept, monkeypatch):
    def refuse(device, settings):
        raise DriverError(f"{device.name}: connection failed: timed out")

    monkeypatch.setattr(mcp_server, "connect", refuse)
    out = call(mcp_server.net_connect_adhoc, ip="192.168.1.9",
               platform="cisco_ios", credentials="LAB")
    assert out["error"] == "DriverError" and "timed out" in out["message"]


def test_no_secret_is_returned(swept, driver, monkeypatch):
    monkeypatch.setenv("LAB_PASSWORD", "hunter2")
    body = raw(mcp_server.net_connect_adhoc, ip="192.168.1.9",
               platform="cisco_ios", credentials="LAB", include_config=True)
    assert "hunter2" not in body, "the prefix is named; the value never is"


# --- the sweep feeds the gate ------------------------------------------------

def test_discovery_records_what_it_found(monkeypatch):
    mcp_server._discovered = type(mcp_server._discovered)()
    monkeypatch.setattr(scan, "arp_sweep",
                        lambda cidr, iface="": [scan.Host(ip="192.168.1.9")])
    out = call(mcp_server.net_discover_local, cidr="192.168.1.0/30")
    assert out["count"] == 1
    assert "192.168.1.9" in mcp_server._discovered
