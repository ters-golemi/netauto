"""MCP server exposing the toolkit to an agent.

Read-first: every tool here either reads from a device or compares two texts.
There is no commit path -- net_config_diff produces a reviewable diff and stops,
which is the whole safety model. Run with:

    .venv/bin/python -m netauto.mcp_server
"""

from __future__ import annotations

import contextlib
import json
import re
from typing import Any

from mcp.server.mcpserver import MCPServer

from netauto import diffing, drawio, scan, topology
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

net_discover_local and net_scan_ports look at a network rather than a device.
The port check is a plain TCP connect that sends nothing; it reports what
answers, not what can be logged into.
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
def net_discover_local(cidr: str, interface: str = "", probe_ports: str = "") -> str:
    """Discover live hosts on a directly attached network by ARP.

    ARP is authoritative on a local segment: hosts answer it even when they drop
    ICMP. Requires arp-scan on the host running this server.

    Hosts already in the inventory come back with "known_as" set, so what is
    left is what nobody has documented.

    Args:
        cidr: network to sweep, for example 192.168.1.0/24.
        interface: interface to scan from, when the host is multi-homed.
        probe_ports: when set, also check which management ports each host
            answers on -- "22,23" for SSH and telnet, or "default" for the
            same two. Left empty, no port is dialled.
    """
    try:
        ports = scan.parse_ports("" if probe_ports.strip().lower() == "default"
                                 else probe_ports) if probe_ports.strip() else ()
        hosts = scan.arp_sweep(cidr, interface)
        if ports and hosts:
            hosts = scan.probe_hosts(hosts, ports)
        with contextlib.suppress(NetautoError):
            hosts = scan.annotate_known(hosts, load_context()[1])
    except NetautoError as exc:
        return _error(exc)
    return _json({"cidr": cidr, "count": len(hosts),
                  "probed_ports": list(ports),
                  "hosts": [h.as_dict() for h in hosts]})


@server.tool()
def net_scan_ports(hosts: str, ports: str = "") -> str:
    """Check which management ports given hosts answer on.

    A plain TCP connect per host and port, plus whatever banner the service
    volunteers -- SSH names its software before the client speaks, which is
    often enough to tell what the far end is. Nothing is sent, so nothing is
    changed. Unlike net_discover_local this needs no ARP, so it reaches any
    address that routes.

    Args:
        hosts: addresses or names to probe, comma or space separated.
        ports: ports to try, default SSH and telnet ("22,23").
    """
    targets = [h for h in re.split(r"[,\s]+", hosts.strip()) if h]
    if not targets:
        return _json({"error": "No hosts given."})
    try:
        wanted = scan.parse_ports(ports)
        results = scan.probe_hosts(targets, wanted)
        with contextlib.suppress(NetautoError):
            results = scan.annotate_known(results, load_context()[1])
    except NetautoError as exc:
        return _error(exc)
    return _json({"ports": list(wanted), "count": len(results),
                  "hosts": [h.as_dict() for h in results]})


@server.tool()
def net_topology(tag: str = "", fmt: str = "json") -> str:
    """Build a network topology graph from LLDP/CDP neighbour tables.

    Asks each device what is directly attached to it and merges the reports.
    Every link is seen from both ends, so links both ends agree on are marked
    confirmed; a link only one device reported is still returned, flagged.

    Neighbours with no inventory entry are included and marked known=false --
    often APs, phones and servers, sometimes undocumented switches. Devices
    that could not report neighbours appear under "gaps" with the reason, so a
    thin graph can be told apart from a small network.

    Args:
        tag: limit to devices carrying this inventory tag.
        fmt: "json" for the graph, or "drawio" for an editable diagram file
            with network stencils, orthogonal connectors and port labels.
    """
    try:
        settings, inventory = load_context()
        devices = inventory.select(tag=tag) if tag else list(inventory)
        if not devices:
            return _json({"error": f"No devices match tag {tag!r}." if tag
                          else "The inventory is empty."})
        graph = topology.build(inventory, settings, devices)
    except NetautoError as exc:
        return _error(exc)
    if fmt == "drawio":
        return drawio.render(graph)
    if fmt != "json":
        return _json({"error": f"Unknown fmt {fmt!r}. Use 'json' or 'drawio'."})
    return _json(topology.as_dict(graph))


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
