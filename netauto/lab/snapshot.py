"""Read a netlab lab back into a handful of facts netauto can use.

netlab's own snapshot is a pickle -- an internal, version-coupled artifact we
have no business unpickling. What netlab *also* emits, and what this reads, is
the transformed topology as YAML (``netlab create -o yaml=<file>``): a stable,
documented data model with a top-level ``nodes`` dictionary keyed by node name.

From each node we need exactly three things -- its name, its netlab device kind
(``iosv``, ``eos``, ``nxos`` ...), and the management IP netlab handed it. That
is the whole seam between the two tools, and keeping it this small is the point:
when netlab changes its output, only this file has to learn the new shape.

The parser is deliberately tolerant about *where* the management address lives,
because netlab records it in more than one place -- ``ansible_host`` carries the
bare address, ``mgmt.ipv4`` the same address with a prefix length. We prefer the
bare one and strip a prefix from the other, so both a plain string and a CIDR
resolve to the same host.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from netauto.errors import LabError


@dataclass(frozen=True)
class LabNode:
    """One node in a running lab, reduced to what netauto needs to reach it."""

    name: str
    kind: str
    mgmt_ip: str | None


def _mgmt_ip(node: dict[str, Any]) -> str | None:
    """The node's management address, from whichever field netlab used.

    ``ansible_host`` is the bare address netlab tells Ansible to connect to, so
    it wins. Failing that, ``mgmt.ipv4`` holds the same address with a prefix
    length (``10.0.0.1/24``); strip it. A node with neither is returned with a
    None address rather than dropped, so the caller can report *which* node has
    no reachable management IP instead of silently losing it.
    """
    host = node.get("ansible_host")
    if isinstance(host, str) and host:
        return host.split("/", 1)[0]
    mgmt = node.get("mgmt")
    if isinstance(mgmt, dict):
        ipv4 = mgmt.get("ipv4")
        if isinstance(ipv4, str) and ipv4:
            return ipv4.split("/", 1)[0]
        # Some pool configurations record the address as an integer host part
        # under a named pool; that form has no bare address for us to use.
    return None


def parse(data: dict[str, Any]) -> list[LabNode]:
    """Turn a transformed-topology mapping into a list of :class:`LabNode`.

    Accepts the parsed YAML document. Raises :class:`LabError` if it does not
    look like a netlab topology -- an empty file, or one with no ``nodes`` -- so
    a truncated or wrong file fails loudly rather than yielding an empty lab
    that looks like a successful teardown.
    """
    if not isinstance(data, dict) or "nodes" not in data:
        raise LabError(
            "Not a netlab topology snapshot: expected a top-level 'nodes' key. "
            "Produce it with 'netlab create -o yaml=<file>'."
        )
    nodes = data["nodes"]
    # netlab's transformed model keys nodes by name; a pre-transform topology
    # may still carry a list. Handle both so a snapshot taken at either stage
    # parses, and name the node from its own field when we have only values.
    if isinstance(nodes, dict):
        items = [(name, node) for name, node in nodes.items()]
    elif isinstance(nodes, list):
        items = [(node.get("name"), node) for node in nodes if isinstance(node, dict)]
    else:
        raise LabError(f"'nodes' is neither a mapping nor a list: {type(nodes).__name__}")

    out: list[LabNode] = []
    for name, node in items:
        if not isinstance(node, dict):
            continue
        name = name or node.get("name")
        if not name:
            continue
        kind = node.get("device") or node.get("kind") or ""
        out.append(LabNode(name=str(name), kind=str(kind), mgmt_ip=_mgmt_ip(node)))
    if not out:
        raise LabError("netlab snapshot has a 'nodes' section but no usable nodes.")
    return out


def load(path: str | Path) -> list[LabNode]:
    """Read and parse a netlab topology YAML file."""
    path = Path(path)
    if not path.exists():
        raise LabError(
            f"netlab snapshot not found at {path}. Produce it with "
            f"'netlab create -o yaml={path.name}' in the lab directory."
        )
    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise LabError(f"netlab snapshot at {path} is not valid YAML: {exc}") from exc
    return parse(data or {})
