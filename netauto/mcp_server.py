"""MCP server exposing the toolkit to an agent.

Read-first: every tool here either reads from a device or compares two texts.
There is no commit path -- net_config_diff produces a reviewable diff and stops,
which is the whole safety model. Run with:

    .venv/bin/python -m netauto.mcp_server
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from mcp.server.mcpserver import MCPServer

from netauto import diffing
from netauto.audit import audit_device
from netauto.checks import BUILTIN
from netauto.drivers import supported_platforms
from netauto.drivers.base import assert_read_only, platform_family
from netauto.errors import NetautoError
from netauto.session import connect, load_context

INSTRUCTIONS = """\
Multi-vendor network automation, read-only.

Covers Cisco IOS/IOS-XE/NX-OS/IOS-XR, Juniper Junos, Arista EOS, HPE Aruba
(AOS-CX, AOS-Switch, Central), Cisco Meraki and Fortinet FortiOS.

This server never changes a device. net_config_diff shows what a change would
do; applying it is a human step. Commands passed to net_run_show are checked
against a read-only allowlist and rejected if they are not clearly read-only.

Credentials are read from the environment at connect time and are never stored
in the inventory or returned by any tool.
"""

server = MCPServer(name="netauto", instructions=INSTRUCTIONS)


def _json(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, default=str)


def _error(exc: Exception) -> str:
    return _json({"error": type(exc).__name__, "message": str(exc)})


@server.tool()
def net_list_devices(tag: str = "", platform: str = "") -> str:
    """List inventory devices, optionally filtered by tag or platform.

    Args:
        tag: only devices carrying this tag.
        platform: only devices on this platform string.
    """
    try:
        settings, inventory = load_context()
        devices = inventory.select(tag=tag or None, platform=platform or None)
    except NetautoError as exc:
        return _error(exc)
    return _json(
        {
            "count": len(devices),
            "devices": [
                {
                    "name": d.name,
                    "platform": d.platform,
                    "family": platform_family(d.platform),
                    "host": d.host,
                    "tags": list(d.tags),
                    "credentials_env_prefix": d.credentials_prefix,
                }
                for d in devices
            ],
        }
    )


@server.tool()
def net_supported_platforms() -> str:
    """List every platform string this toolkit has a driver for."""
    return _json({"platforms": supported_platforms()})


@server.tool()
def net_device_facts(device: str) -> str:
    """Connect to a device and return vendor, model, OS version, serial and hostname.

    Args:
        device: inventory name of the device.
    """
    try:
        settings, inventory = load_context()
        dev = inventory.get(device)
        with connect(dev, settings) as driver:
            return _json(driver.facts())
    except NetautoError as exc:
        return _error(exc)


@server.tool()
def net_get_config(device: str, kind: str = "running") -> str:
    """Retrieve a device configuration as text.

    Args:
        device: inventory name of the device.
        kind: running, startup, or candidate where the platform supports it.
    """
    try:
        settings, inventory = load_context()
        dev = inventory.get(device)
        with connect(dev, settings) as driver:
            config = driver.get_config(kind)
    except NetautoError as exc:
        return _error(exc)
    return _json({"device": device, "kind": kind,
                  "lines": len(config.splitlines()), "config": config})


@server.tool()
def net_run_show(device: str, command: str) -> str:
    """Run one read-only command on a device.

    The command is checked against a per-vendor allowlist. Anything that could
    change state, or that chains multiple commands, is rejected before it is
    sent.

    Args:
        device: inventory name of the device.
        command: a single show/display/get command.
    """
    try:
        settings, inventory = load_context()
        dev = inventory.get(device)
        # Validate before connecting: an unsafe command should cost nothing and
        # must not report a credential problem in place of the real objection.
        assert_read_only(command, dev.platform)
        with connect(dev, settings) as driver:
            output = driver.run_read(command)
    except NetautoError as exc:
        return _error(exc)
    return _json({"device": device, "command": command, "output": output})


@server.tool()
def net_audit(device: str = "", tag: str = "") -> str:
    """Run the hardening ruleset against one device or a tagged group.

    Checks telnet exposure, SSH version, management-plane encryption, default
    SNMP communities, time sources and remote logging, using rules scoped to
    each platform's own syntax.

    Args:
        device: a single inventory device name.
        tag: audit every device carrying this tag instead.
    """
    try:
        settings, inventory = load_context()
        targets = [inventory.get(device)] if device else inventory.select(tag=tag or None)
    except NetautoError as exc:
        return _error(exc)
    if not targets:
        return _json({"error": "no devices matched", "device": device, "tag": tag})
    results = [audit_device(d, settings) for d in targets]
    totals = {"devices": len(results), "failed_rules": 0, "errors": 0}
    for r in results:
        if r.get("error"):
            totals["errors"] += 1
        totals["failed_rules"] += r.get("summary", {}).get("fail", 0)
    return _json({"ruleset": BUILTIN.name, "totals": totals, "results": results})


@server.tool()
def net_config_diff(device: str, candidate_config: str, kind: str = "running") -> str:
    """Diff a candidate configuration against what is on the device.

    Read-only: this shows what would change and commits nothing. Volatile lines
    and secrets are normalised out so the diff reflects real intent.

    Args:
        device: inventory name of the device.
        candidate_config: the proposed configuration text.
        kind: which stored config to compare against.
    """
    try:
        settings, inventory = load_context()
        dev = inventory.get(device)
        with connect(dev, settings) as driver:
            current = driver.get_config(kind)
    except NetautoError as exc:
        return _error(exc)
    family = platform_family(dev.platform)
    diff = diffing.unified(current, candidate_config, family=family,
                           from_label=f"{device}:{kind}", to_label=f"{device}:candidate")
    return _json({
        "device": device,
        "identical": not diff,
        "summary": diffing.summarize(diff),
        "diff": diff,
        "note": "Review only. This server has no commit path.",
    })


@server.tool()
def net_discover_local(cidr: str, interface: str = "") -> str:
    """Discover live hosts on a directly attached network by ARP.

    ARP is authoritative on a local segment: hosts answer it even when they drop
    ICMP. Requires arp-scan on the host running this server.

    Args:
        cidr: network to sweep, for example 192.168.1.0/24.
        interface: interface to scan from, when the host is multi-homed.
    """
    binary = shutil.which("arp-scan")
    if not binary:
        return _json({"error": "arp-scan is not installed on this host."})
    cmd = [binary, cidr, "--plain"]
    if interface:
        cmd += ["-I", interface]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
    except subprocess.TimeoutExpired:
        return _json({"error": f"arp-scan timed out sweeping {cidr}"})
    if proc.returncode != 0:
        return _json({"error": proc.stderr.strip() or f"arp-scan exited {proc.returncode}"})
    hosts = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            hosts.append({"ip": parts[0], "mac": parts[1].lower(),
                          "vendor": parts[2] if len(parts) > 2 else ""})
    return _json({"cidr": cidr, "count": len(hosts), "hosts": hosts})


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
