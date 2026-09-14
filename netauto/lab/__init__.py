"""Build and inspect virtual labs with netlab, then read them like real gear.

netauto inspects devices; it cannot stand a network up to inspect. netlab does
the opposite -- it builds and configures virtual topologies -- but does not
audit them afterward. This package is the join: it drives the external netlab
CLI to bring a lab up and down, and translates the running lab into a netauto
:class:`~netauto.inventory.Inventory`, so audit, checks, workflows and topology
all work against the lab unchanged.

netlab is optional. It is never a dependency of netauto and is never imported;
the wrapper runs the installed binary and degrades to a clear error where it is
absent. Call :func:`is_available` before offering a lab action.

The read-only stance is untouched: netlab writes only to the throwaway VMs and
containers it created and will destroy, and netauto's connection *to* lab
devices stays read-only -- it audits them, it does not configure them.

See docs/netlab-integration.md for the design.
"""

from __future__ import annotations

from netauto.lab.inventory import (
    KIND_TO_PLATFORM,
    Mapped,
    from_snapshot,
    map_nodes,
    platform_for,
)
from netauto.lab.runner import (
    bring_up,
    down,
    read_inventory,
    is_available,
    netlab_path,
    status,
    up,
    write_snapshot,
)
from netauto.lab.service import LabJob, LabJobStore, LabService
from netauto.lab.snapshot import LabNode

__all__ = [
    "KIND_TO_PLATFORM",
    "LabJob",
    "LabJobStore",
    "LabNode",
    "LabService",
    "Mapped",
    "bring_up",
    "down",
    "from_snapshot",
    "read_inventory",
    "is_available",
    "map_nodes",
    "netlab_path",
    "platform_for",
    "status",
    "up",
    "write_snapshot",
]
