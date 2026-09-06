"""Serialise a Topology to draw.io XML.

draw.io is the diagram engine rather than something hand-rolled, because it
brings what "Visio-style" actually means: real network stencils, orthogonal
connectors that route around shapes, and a file you can open and rearrange.
It also reads and writes .vsdx, so a .drawio file is the practical route to
something editable in Visio.

The output is an mxfile with uncompressed mxGraphModel XML. draw.io accepts
that directly -- the base64+deflate encoding it sometimes writes is optional,
and skipping it keeps this readable and diffable in a repository.

Layout here is deliberately simple: tiers as rows, devices spread along each
row. It is a starting arrangement, not a claim to be optimal. Anything better
belongs in draw.io's own layout tools, which is rather the point of exporting
to it.
"""

from __future__ import annotations

from typing import Any
from xml.sax.saxutils import escape, quoteattr

from netauto.topology import TIER_ORDER, Node, Topology

#: draw.io's Cisco stencils. Chosen over the flat mxgraph.networks set because
#: those render a router and a switch as near-identical barrels -- the classic
#: Cisco iconography is what makes a device type readable at a glance, and is
#: what people mean by a Visio-style network diagram.
SHAPE_SWITCH = "mxgraph.cisco.switches.layer_3_switch"
SHAPE_ACCESS_SWITCH = "mxgraph.cisco.switches.workgroup_switch"
SHAPE_ROUTER = "mxgraph.cisco.routers.router"
SHAPE_FIREWALL = "mxgraph.cisco.security.firewall"
SHAPE_CLOUD = "mxgraph.cisco.storage.cloud"

#: Deliberately not a stencil. A device seen only over LLDP could be an AP, a
#: phone or a server, and picking an icon would assert something we do not
#: know. mxgraph.networks.unknown_device is not a real shape -- it renders as
#: a blank square -- so a plain dashed box it is, which reads as intentional.
SHAPE_UNKNOWN = ""

#: Tier -> fill. Cool colours up top, warmer at the access layer, so the
#: hierarchy reads at a glance even printed in greyscale.
TIER_FILL = {
    "edge": "#7B3F99",
    "core": "#1F6FB2",
    "distribution": "#2E8B76",
    "access": "#8A6D1F",
    "discovered": "#8C8C8C",
    "unknown": "#666666",
}

NODE_W, NODE_H = 78, 78
COL_GAP, ROW_GAP = 190, 175
MARGIN_X, MARGIN_Y = 60, 60


def shape_for(node: Node) -> str:
    """Pick a stencil from the platform, falling back to tier."""
    p = (node.platform or "").lower()
    if not node.known:
        return SHAPE_UNKNOWN
    if "forti" in p:
        return SHAPE_FIREWALL
    if "meraki" in p or "central" in p:
        return SHAPE_CLOUD
    if "xr" in p or "junos" in p or node.tier == "edge":
        return SHAPE_ROUTER
    if node.tier == "access":
        return SHAPE_ACCESS_SWITCH
    return SHAPE_SWITCH


def _node_style(node: Node) -> str:
    fill = TIER_FILL.get(node.tier, TIER_FILL["unknown"])
    shape = shape_for(node)
    if not shape:
        # Discovered devices: a dashed rounded box, no icon claimed.
        return (
            f"rounded=1;whiteSpace=wrap;html=1;dashed=1;dashPattern=6 4;"
            f"fillColor=none;strokeColor={fill};strokeWidth=2;"
            f"fontColor={fill};verticalAlign=middle;align=center;"
        )
    return (
        f"sketch=0;html=1;aspect=fixed;verticalLabelPosition=bottom;"
        f"verticalAlign=top;align=center;outlineConnect=0;"
        f"shape={shape};fillColor={fill};strokeColor=#FFFFFF;"
        f"strokeWidth=2;dashed=0;"
    )


def _edge_style(confirmed: bool) -> str:
    # Orthogonal routing with rounded corners is the thing that makes a
    # diagram read as Visio rather than as a scatter plot with lines.
    return (
        "edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;jettySize=auto;"
        "html=1;endArrow=none;startArrow=none;strokeWidth=2;"
        + ("strokeColor=#4D4D4D;" if confirmed else "strokeColor=#B3B3B3;dashed=1;")
    )


_LABEL_STYLE = ("edgeLabel;html=1;align=center;verticalAlign=middle;"
                "resizable=0;points=[];fontSize=9;fontColor=#555555;"
                "labelBackgroundColor=#FFFFFF;")


def _positions(topo: Topology) -> dict[str, tuple[int, int]]:
    """Tiered rows, each centred over the widest row."""
    tiers = topo.by_tier()
    ordered = [t for t in TIER_ORDER if t in tiers]
    widest = max((len(tiers[t]) for t in ordered), default=1)
    out: dict[str, tuple[int, int]] = {}
    for row, tier in enumerate(ordered):
        members = tiers[tier]
        # Centre the row so the hierarchy reads as a pyramid, not left-aligned.
        offset = (widest - len(members)) * COL_GAP // 2
        for col, node in enumerate(members):
            out[node.name] = (MARGIN_X + offset + col * COL_GAP,
                              MARGIN_Y + row * ROW_GAP)
    return out


def _cell_id(prefix: str, index: int) -> str:
    return f"{prefix}{index}"


def render(topo: Topology, title: str = "Network topology") -> str:
    """Return draw.io XML for this topology."""
    pos = _positions(topo)
    ids: dict[str, str] = {}
    parts: list[str] = []

    for i, node in enumerate(sorted(topo.nodes.values(), key=lambda n: n.name), start=1):
        cid = _cell_id("n", i)
        ids[node.name] = cid
        x, y = pos.get(node.name, (MARGIN_X, MARGIN_Y))
        label = node.name if node.known else f"{node.name}<br>(discovered)"
        tooltip = " · ".join(filter(None, [
            node.platform or ("seen over LLDP, not in inventory" if not node.known else ""),
            f"tier: {node.tier}",
            f"links: {node.degree}",
            node.description,
        ]))
        geometry = (
            f'          <mxGeometry x="{x}" y="{y}" width="{NODE_W}" '
            f'height="{NODE_H}" as="geometry" />\n'
        )
        # A UserObject wraps the cell so the vertex can carry a tooltip, which
        # is where the platform and link count live without cluttering the
        # drawing itself.
        parts.append(
            f'        <UserObject label={quoteattr(label)} '
            f'tooltip={quoteattr(tooltip)} id={quoteattr(cid)}>\n'
            f'          <mxCell style={quoteattr(_node_style(node))} '
            f'vertex="1" parent="1">\n'
            f'  {geometry.rstrip()}\n'
            f'          </mxCell>\n'
            f'        </UserObject>'
        )

    for i, link in enumerate(topo.links, start=1):
        src, dst = ids.get(link.a), ids.get(link.b)
        if not src or not dst:
            continue
        eid = _cell_id("e", i)
        parts.append(
            f'        <mxCell id={quoteattr(eid)} value="" '
            f'style={quoteattr(_edge_style(link.confirmed))} edge="1" parent="1" '
            f'source={quoteattr(src)} target={quoteattr(dst)}>\n'
            f'          <mxGeometry relative="1" as="geometry" />\n'
            f'        </mxCell>'
        )
        # Port labels pinned near each end: x=-1 is the source end, x=1 the
        # target end, which is how an engineer reads a patching diagram.
        for suffix, port, anchor in (("a", link.a_port, "-1"), ("b", link.b_port, "1")):
            if not port:
                continue
            parts.append(
                f'        <mxCell id={quoteattr(eid + suffix)} '
                f'value={quoteattr(port)} style={quoteattr(_LABEL_STYLE)} '
                f'vertex="1" connectable="0" parent={quoteattr(eid)}>\n'
                f'          <mxGeometry x="{anchor}" y="0" relative="1" as="geometry">\n'
                f'            <mxPoint as="offset" />\n'
                f'          </mxGeometry>\n'
                f'        </mxCell>'
            )

    body = "\n".join(parts)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<mxfile host="netauto" agent="netauto" type="device">\n'
        f'  <diagram id="netauto-topology" name={quoteattr(title)}>\n'
        '    <mxGraphModel dx="1422" dy="798" grid="1" gridSize="10" guides="1" '
        'tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" '
        'pageWidth="1169" pageHeight="826" math="0" shadow="0">\n'
        '      <root>\n'
        '        <mxCell id="0" />\n'
        '        <mxCell id="1" parent="0" />\n'
        f'{body}\n'
        '      </root>\n'
        '    </mxGraphModel>\n'
        '  </diagram>\n'
        '</mxfile>\n'
    )


def legend_note(topo: Topology) -> str:
    """One line describing what the reader is looking at."""
    d = len(topo.discovered_nodes)
    known, links = len(topo.known_nodes), len(topo.links)
    parts = [f"{known} inventory device{'s' if known != 1 else ''}",
             f"{links} link{'s' if links != 1 else ''}"]
    if d:
        parts.append(f"{d} discovered but not in inventory (dashed)")
    if topo.gaps:
        n = len(topo.gaps)
        parts.append(f"{n} device{'s' if n != 1 else ''} contributed nothing")
    return escape(", ".join(parts))
