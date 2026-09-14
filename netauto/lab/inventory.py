"""Turn lab nodes into a netauto inventory.

The only real content here is the mapping from a netlab *device kind* to a
netauto *platform string*. netlab names a device by its image family (``iosv``,
``csr``, ``vsrx``); netauto names it by the driver that reads it (``cisco_ios``,
``juniper_junos``). Where the two overlap, a lab node becomes an ordinary
:class:`~netauto.inventory.Device` and every read path -- audit, checks,
workflows, topology -- works against it unchanged.

Where they do not overlap the node is *skipped*, not faked. netlab happily runs
FRR, VyOS and SR Linux; netauto has no driver for them, and an inventory entry
whose platform no driver can load would fail only later, on connect. Skipping
them here, and saying which were skipped, keeps the failure honest and early.

Nothing in this module connects to anything. It converts data structures.
"""

from __future__ import annotations

from dataclasses import dataclass

from netauto.inventory import Device, Inventory
from netauto.lab.snapshot import LabNode

#: netlab device kind -> netauto platform string. Only kinds netauto has a
#: driver for appear here; see netauto.drivers.REGISTRY for the platforms.
#: Extend this as drivers gain lab-able counterparts -- it is the one list to
#: touch when netlab adds an image netauto can already read.
KIND_TO_PLATFORM: dict[str, str] = {
    # Cisco IOS / IOS-XE -- napalm 'ios' reads them all
    "iosv": "cisco_ios",
    "iol": "cisco_ios",
    "ioll2": "cisco_ios",
    "csr": "cisco_ios",
    "cat8000v": "cisco_ios",
    # Cisco NX-OS
    "nxos": "cisco_nxos",
    # Cisco IOS XR
    "iosxr": "cisco_xr",
    # Arista EOS -- a native container, the cheapest thing to lab
    "eos": "arista_eos",
    # Juniper Junos -- vSRX / vMX / vJunos family, all read as junos
    "vsrx": "juniper_junos",
    "vmx": "juniper_junos",
    "vptx": "juniper_junos",
    "vjunos-switch": "juniper_junos",
    "vjunos-router": "juniper_junos",
    "vjunos-evolved": "juniper_junos",
}

#: netlab kinds netauto knowingly cannot drive, named so the "skipped" report
#: can distinguish "no driver, expected" from "kind we have never heard of".
#: Documentation only -- absence from KIND_TO_PLATFORM is what actually skips.
UNSUPPORTED_KINDS: frozenset[str] = frozenset(
    {"frr", "vyos", "srlinux", "cumulus", "linux", "routeros", "sonic"}
)


@dataclass(frozen=True)
class Mapped:
    """The result of mapping a lab: the devices we can drive, and the rest.

    ``skipped`` pairs each dropped node with why -- an unmappable kind, or no
    management IP -- so a caller (a REPL, later a GUI page) can show the lab as
    it really is rather than as a shorter list that hides the gaps.
    """

    devices: list[Device]
    skipped: list[tuple[LabNode, str]]

    @property
    def inventory(self) -> Inventory:
        """The drivable nodes as a netauto Inventory."""
        return Inventory(self.devices)


def platform_for(kind: str) -> str | None:
    """The netauto platform for a netlab device kind, or None if unsupported."""
    return KIND_TO_PLATFORM.get(kind)


def map_nodes(nodes: list[LabNode], *, credentials: str = "LAB") -> Mapped:
    """Map lab nodes to netauto devices, keeping the unmappable ones aside.

    ``credentials`` is the environment-variable prefix the lab devices share --
    ``LAB`` means netauto reads ``LAB_USERNAME`` / ``LAB_PASSWORD`` for every
    lab node, matching how netlab gives a topology one set of credentials. Lab
    devices are tagged ``lab`` so they can never be selected as if they were
    production inventory.
    """
    devices: list[Device] = []
    skipped: list[tuple[LabNode, str]] = []
    for node in nodes:
        platform = platform_for(node.kind)
        if platform is None:
            reason = (
                f"no netauto driver for netlab kind {node.kind!r}"
                if node.kind
                else "node has no device kind"
            )
            skipped.append((node, reason))
            continue
        if not node.mgmt_ip:
            skipped.append((node, "no management IP in snapshot"))
            continue
        devices.append(
            Device(
                name=node.name,
                platform=platform,
                host=node.mgmt_ip,
                credentials=credentials,
                tags=("lab",),
            )
        )
    return Mapped(devices=devices, skipped=skipped)


def from_snapshot(nodes: list[LabNode], *, credentials: str = "LAB") -> Inventory:
    """Convenience: the drivable nodes of a snapshot as an Inventory."""
    return map_nodes(nodes, credentials=credentials).inventory
