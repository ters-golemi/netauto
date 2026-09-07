"""Render a topology as a PNG, for embedding in documents.

draw.io export stays the editable artefact; this is the picture that goes in
the Word document, because python-docx embeds rasters and vectors it
understands -- and SVG is not one of them.

Both renderers share `drawio._positions`. A second layout would drift from the
first, and then the diagram in the document would disagree with the diagram in
draw.io while both claimed to describe the same network. The colours come from
`drawio.TIER_FILL` for the same reason.
"""

from __future__ import annotations

import io

from netauto.drawio import COL_GAP, MARGIN_X, MARGIN_Y, NODE_H, NODE_W, ROW_GAP, TIER_FILL, _positions
from netauto.topology import Topology

#: Rendered at 2x and downsampled, which is what makes the text readable when
#: Word scales the picture into a page width.
SCALE = 2
FONT_SIZE = 12
PORT_FONT_SIZE = 9

#: Rows are pulled closer together than in draw.io. The draw.io export is
#: worked on at whatever zoom suits; this one has to fit a page, and at the
#: export's 175px row gap a five-tier network renders taller than it is wide
#: and lands in Word as a column of boxes running off the bottom of the page.
#: Only the vertical gap changes, so left-to-right order and tier rows are
#: still the layout drawio.py computed.
DOC_ROW_GAP = 118


def _font(size: int):
    """A real TrueType face where one exists, else Pillow's bitmap default.

    The default font ignores size entirely, so a diagram rendered with it is
    legible but cramped. It is a fallback, not a choice.
    """
    from PIL import ImageFont

    candidates = (
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
    )
    for path in candidates:
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _compress(positions: dict[str, tuple[int, int]]) -> dict[str, tuple[int, int]]:
    """Tighten the vertical gap and pull the drawing against its margins."""
    if not positions:
        return {}
    rows = sorted({y for _, y in positions.values()})
    row_index = {y: i for i, y in enumerate(rows)}
    left = min(x for x, _ in positions.values())
    return {
        name: (x - left + MARGIN_X, MARGIN_Y + row_index[y] * DOC_ROW_GAP)
        for name, (x, y) in positions.items()
    }


def _canvas_size(positions: dict[str, tuple[int, int]]) -> tuple[int, int]:
    if not positions:
        return (600, 200)
    right = max(x for x, _ in positions.values()) + NODE_W + MARGIN_X
    bottom = max(y for _, y in positions.values()) + NODE_H + MARGIN_Y
    return (max(right, 600), max(bottom, 200))


def render_png(topo: Topology, title: str = "Network topology") -> bytes:
    """Draw the topology and return PNG bytes."""
    from PIL import Image, ImageDraw

    positions = _compress(_positions(topo))
    width, height = _canvas_size(positions)
    img = Image.new("RGB", (width * SCALE, height * SCALE), "white")
    draw = ImageDraw.Draw(img)
    title_font = _font(FONT_SIZE * SCALE + 4)
    font = _font(FONT_SIZE * SCALE)
    small = _font(PORT_FONT_SIZE * SCALE)

    def pt(x: int, y: int) -> tuple[int, int]:
        return (x * SCALE, y * SCALE)

    def centre(name: str) -> tuple[int, int]:
        x, y = positions[name]
        return pt(x + NODE_W // 2, y + NODE_H // 2)

    draw.text(pt(MARGIN_X, 20), title, fill="#222222", font=title_font)

    # Links first, so the boxes sit on top of the lines rather than under them.
    for link in topo.links:
        if link.a not in positions or link.b not in positions:
            continue
        a, b = centre(link.a), centre(link.b)
        # An unconfirmed link is one only one end reported. Drawing it the same
        # as a confirmed one would overstate what was actually observed.
        if link.confirmed:
            draw.line([a, b], fill="#444444", width=2 * SCALE)
        else:
            _dashed(draw, a, b, fill="#999999", width=2 * SCALE)
        ports = f"{link.a_port} - {link.b_port}".strip(" -")
        if ports:
            # Nudged perpendicular to the link, because centred on it the
            # label and the line overprint and neither is readable.
            dx, dy = b[0] - a[0], b[1] - a[1]
            length = max(1.0, (dx * dx + dy * dy) ** 0.5)
            off = 9 * SCALE
            mid = (
                int((a[0] + b[0]) / 2 - dy / length * off),
                int((a[1] + b[1]) / 2 + dx / length * off),
            )
            draw.text(mid, ports, fill="#777777", font=small, anchor="mm")

    for name, (x, y) in positions.items():
        node = topo.nodes[name]
        fill = TIER_FILL.get(node.tier, TIER_FILL["unknown"])
        box = [pt(x, y), pt(x + NODE_W, y + NODE_H)]
        if node.known:
            draw.rounded_rectangle(box, radius=6 * SCALE, fill=fill, outline="#FFFFFF",
                                   width=2 * SCALE)
            text_fill = "#FFFFFF"
        else:
            # Discovered over LLDP but not in the inventory: hollow and dashed,
            # matching the draw.io export's claim that we know less about it.
            draw.rounded_rectangle(box, radius=6 * SCALE, fill="#FFFFFF",
                                   outline=fill, width=2 * SCALE)
            text_fill = fill
        draw.text(pt(x + NODE_W // 2, y + NODE_H // 2), _wrap(node.name),
                  fill=text_fill, font=font, anchor="mm", align="center")

    img = img.resize((width, height), Image.LANCZOS)
    out = io.BytesIO()
    img.save(out, format="PNG", optimize=True)
    return out.getvalue()


def _wrap(name: str, width: int = 11) -> str:
    """Break a device name so it fits the box, on separators where possible."""
    if len(name) <= width:
        return name
    parts, line, out = name.replace("_", "-").split("-"), "", []
    for part in parts:
        candidate = f"{line}-{part}" if line else part
        if len(candidate) > width and line:
            out.append(line)
            line = part
        else:
            line = candidate
    out.append(line)
    return "\n".join(out)


def _dashed(draw, a: tuple[int, int], b: tuple[int, int], *, fill: str, width: int,
            dash: int = 12) -> None:
    """Pillow has no dashed line, so step along the segment."""
    (x0, y0), (x1, y1) = a, b
    span = max(abs(x1 - x0), abs(y1 - y0))
    if not span:
        return
    steps = max(1, span // dash)
    on = True
    for i in range(steps):
        t0, t1 = i / steps, (i + 1) / steps
        if on:
            draw.line(
                [(x0 + (x1 - x0) * t0, y0 + (y1 - y0) * t0),
                 (x0 + (x1 - x0) * t1, y0 + (y1 - y0) * t1)],
                fill=fill, width=width,
            )
        on = not on
