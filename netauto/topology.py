"""Topology discovery from LLDP/CDP neighbour tables.

Devices report what is directly attached to them, so the graph is assembled
from many partial views rather than read from one place. Two things follow
from that, and they are most of this module:

**Every link is seen twice.** A reports B on Gi1/0/1, B reports A on Gi0/1.
Those are one cable and must collapse to one edge, which means a link needs an
identity independent of who reported it.

**Neighbours are named by the device, not by your inventory.** LLDP gives you
the remote system name, which is whatever the far end calls itself -- a
hostname, an FQDN, sometimes a chassis MAC. Matching that back to an inventory
entry is a guess, and the guess is recorded so a diagram can show which nodes
are known and which were merely seen.

Read-only throughout: this asks devices what they can see and nothing else.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Iterable

from netauto.config import Settings
from netauto.errors import NetautoError, UnsupportedOperation
from netauto.inventory import Device, Inventory
from netauto.session import connect

log = logging.getLogger(__name__)

#: Tags that imply a tier, most significant first. Layout reads these before
#: falling back to link count, because an operator's own labels beat a guess.
TIER_TAGS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("edge", ("edge", "wan", "border", "internet")),
    ("core", ("core", "spine", "backbone")),
    ("distribution", ("distribution", "dist", "aggregation", "agg", "leaf")),
    ("access", ("access", "edge-switch", "user")),
)

TIER_ORDER = ("edge", "core", "distribution", "access", "discovered", "unknown")


def tier_for(device: Device | None, tags: Iterable[str] = ()) -> str:
    """Pick a tier from inventory tags, or 'unknown'."""
    have = {t.lower() for t in (device.tags if device else tags)}
    for tier, markers in TIER_TAGS:
        if have & set(markers):
            return tier
    return "unknown"


def normalise_host(name: str) -> str:
    """Reduce an LLDP system name to something comparable.

    Devices are inconsistent about case and about whether they report a bare
    hostname or an FQDN, so 'CORE-SW-01.example.com' and 'core-sw-01' have to
    land on the same node or the diagram doubles every device.
    """
    return (name or "").strip().lower().split(".")[0]


@dataclass
class Node:
    """One device in the diagram."""

    name: str
    #: True when this matched an inventory entry; False when only seen by LLDP.
    known: bool = False
    platform: str = ""
    tier: str = "unknown"
    model: str = ""
    description: str = ""

    @property
    def degree(self) -> int:
        return self._degree

    _degree: int = 0


@dataclass(frozen=True)
class Link:
    """One cable, after the two reported directions have been merged."""

    a: str
    a_port: str
    b: str
    b_port: str
    #: True when both ends independently reported the link.
    confirmed: bool = False

    @property
    def key(self) -> tuple[str, str]:
        """Endpoint-ordered identity, so A->B and B->A collapse."""
        return tuple(sorted((self.a, self.b)))  # type: ignore[return-value]


@dataclass
class Topology:
    """The assembled graph, plus what could not be collected."""

    nodes: dict[str, Node] = field(default_factory=dict)
    links: list[Link] = field(default_factory=list)
    #: device name -> why it contributed nothing.
    gaps: dict[str, str] = field(default_factory=dict)

    @property
    def known_nodes(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.known]

    @property
    def discovered_nodes(self) -> list[Node]:
        """Seen over LLDP but absent from the inventory."""
        return [n for n in self.nodes.values() if not n.known]

    def by_tier(self) -> dict[str, list[Node]]:
        out: dict[str, list[Node]] = {t: [] for t in TIER_ORDER}
        for node in sorted(self.nodes.values(), key=lambda n: n.name):
            out.setdefault(node.tier, []).append(node)
        return {t: v for t, v in out.items() if v}


def _collect_one(device: Device, settings: Settings) -> tuple[str, list[dict], str]:
    """Return (device name, neighbour rows, error). Never raises."""
    from netauto.drivers import get_driver_class

    try:
        driver_cls = get_driver_class(device.platform)
    except NetautoError as exc:
        return device.name, [], str(exc)

    if "neighbors" not in getattr(driver_cls, "capabilities", frozenset()):
        return device.name, [], (
            f"{device.platform} exposes no LLDP/CDP table through netauto"
        )
    try:
        with connect(device, settings) as driver:
            return device.name, driver.neighbors(), ""
    except UnsupportedOperation as exc:
        return device.name, [], str(exc)
    except NetautoError as exc:
        return device.name, [], str(exc)
    except Exception as exc:  # a vendor SDK raising something unmapped
        log.warning("neighbour collection failed for %s: %s", device.name, exc)
        return device.name, [], str(exc)


def _compatible(left: dict[str, Any], right: dict[str, Any], *, exact: bool) -> bool:
    """Could these two half-links be the same cable seen from both ends?

    `left` is what A said about B, `right` what B said about A, so A's local
    port should be B's remote port and vice versa.
    """
    if exact:
        return bool(left["local"] and left["remote"] and right["local"] and right["remote"]
                    and left["local"] == right["remote"]
                    and left["remote"] == right["local"])
    # A device may report its own port but not the neighbour's. A blank is
    # unknown, not a mismatch, so it matches anything.
    ends_agree = not left["local"] or not right["remote"] or left["local"] == right["remote"]
    peers_agree = not left["remote"] or not right["local"] or left["remote"] == right["local"]
    return ends_agree and peers_agree


def _merge_halves(entries: list[dict[str, Any]]) -> list[Link]:
    """Turn one pair's half-links into cables.

    A pair has at most two reporters, since a link has two ends. Exact port
    agreement is matched first so that a port-channel pairs Gi1/0/1 with its
    real partner rather than with whichever half happened to come first.
    """
    by_reporter: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        by_reporter.setdefault(entry["reporter"], []).append(entry)

    reporters = sorted(by_reporter)
    if len(reporters) == 1:
        # Only one end reported: every row is its own unconfirmed cable.
        return [Link(a=e["reporter"], a_port=e["local"], b=e["peer"],
                     b_port=e["remote"], confirmed=False)
                for e in by_reporter[reporters[0]]]

    left, right = by_reporter[reporters[0]], by_reporter[reporters[1]]
    links: list[Link] = []
    matched_left: set[int] = set()
    matched_right: set[int] = set()

    for exact in (True, False):
        for i, l in enumerate(left):
            if i in matched_left:
                continue
            for j, r in enumerate(right):
                if j in matched_right or not _compatible(l, r, exact=exact):
                    continue
                links.append(Link(
                    a=l["reporter"], a_port=l["local"] or r["remote"],
                    b=r["reporter"], b_port=r["local"] or l["remote"],
                    confirmed=True,
                ))
                matched_left.add(i)
                matched_right.add(j)
                break

    # Halves with no partner are still cables; one end simply did not see them.
    for i, l in enumerate(left):
        if i not in matched_left:
            links.append(Link(a=l["reporter"], a_port=l["local"], b=l["peer"],
                              b_port=l["remote"], confirmed=False))
    for j, r in enumerate(right):
        if j not in matched_right:
            links.append(Link(a=r["reporter"], a_port=r["local"], b=r["peer"],
                              b_port=r["remote"], confirmed=False))
    return links


def build(inventory: Inventory, settings: Settings,
          devices: list[Device] | None = None) -> Topology:
    """Collect neighbours across the inventory and assemble the graph."""
    targets = devices if devices is not None else list(inventory)
    topo = Topology()

    # Inventory entries are nodes whether or not they answer, so a device that
    # is down still appears in the diagram rather than vanishing from it.
    by_norm: dict[str, str] = {}
    for device in targets:
        key = normalise_host(device.name)
        node = Node(name=device.name, known=True, platform=device.platform,
                    tier=tier_for(device))
        topo.nodes[device.name] = node
        by_norm[key] = device.name

    if not targets:
        return topo

    workers = max(1, min(settings.max_concurrency, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda d: _collect_one(d, settings), targets))

    # Half-links grouped by endpoint pair. Grouping is not enough on its own
    # to identify a cable: a port-channel puts several cables between the same
    # two switches, so the halves within a pair still have to be matched up by
    # port before they can be merged.
    halves: dict[tuple[str, str], list[dict[str, Any]]] = {}

    for name, rows, error in results:
        if error:
            topo.gaps[name] = error
            continue
        for row in rows:
            remote_raw = str(row.get("remote_host", "") or "")
            remote_norm = normalise_host(remote_raw)
            if not remote_norm:
                continue  # a neighbour with no usable identity is not a node

            # Resolve to an inventory name when we can, so LLDP's idea of the
            # hostname does not create a duplicate of a device we already have.
            remote_name = by_norm.get(remote_norm)
            if remote_name is None:
                remote_name = remote_raw.strip()
                if remote_name not in topo.nodes:
                    topo.nodes[remote_name] = Node(
                        name=remote_name, known=False, tier="discovered",
                        description=str(row.get("remote_description", "") or "")[:200],
                    )
                by_norm[remote_norm] = remote_name

            pair = tuple(sorted((normalise_host(name), remote_norm)))
            halves.setdefault(pair, []).append({
                "reporter": name,
                "peer": remote_name,
                "local": str(row.get("local_port", "") or ""),
                "remote": str(row.get("remote_port", "") or ""),
            })

    for entries in halves.values():
        topo.links.extend(_merge_halves(entries))
    topo.links.sort(key=lambda link: (link.a, link.b))

    for link in topo.links:
        for end in (link.a, link.b):
            if end in topo.nodes:
                topo.nodes[end]._degree += 1

    # Anything the tags did not classify gets a tier from how well connected it
    # is: the busiest devices sit at the top, leaves at the bottom.
    if topo.links:
        degrees = sorted((n.degree for n in topo.nodes.values()), reverse=True)
        busiest = degrees[0] if degrees else 0
        for node in topo.nodes.values():
            if node.tier != "unknown":
                continue
            if busiest and node.degree >= max(3, busiest * 0.6):
                node.tier = "core"
            elif node.degree > 1:
                node.tier = "distribution"
            else:
                node.tier = "access"

    return topo


def as_dict(topo: Topology) -> dict[str, Any]:
    """Plain structures, for the MCP tool and the JSON export."""
    return {
        "nodes": [
            {"name": n.name, "known": n.known, "platform": n.platform,
             "tier": n.tier, "links": n.degree, "description": n.description}
            for n in sorted(topo.nodes.values(), key=lambda n: n.name)
        ],
        "links": [
            {"a": link.a, "a_port": link.a_port, "b": link.b,
             "b_port": link.b_port, "confirmed": link.confirmed}
            for link in topo.links
        ],
        "gaps": dict(sorted(topo.gaps.items())),
        "summary": {
            "devices": len(topo.known_nodes),
            "discovered": len(topo.discovered_nodes),
            "links": len(topo.links),
            "unreachable": len(topo.gaps),
        },
    }
