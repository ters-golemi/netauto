"""Render a finished run as an editable Word document.

The output is a real .docx -- an Office Open XML package -- so it opens in
Word and LibreOffice and can be edited, tracked and commented on like any
other document. That is the point: a network document nobody can amend gets
replaced by a Word file somebody retypes, and the retyped one is what gets
circulated.

Everything here is built from the run. Nothing is invented to fill a section:
a device that could not be reached gets a row saying so rather than a blank,
and a diagram that could not be collected is a stated gap rather than a
missing page.
"""

from __future__ import annotations

import io
from typing import TYPE_CHECKING

from netauto import __version__
from netauto.workflows.spec import CONFIG_CHECK, DOCUMENTATION

if TYPE_CHECKING:
    from netauto.workflows.runner import DeviceResult, Run

SEVERITY_LABEL = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "info": "Info",
}


def _facts_row(result: "DeviceResult") -> tuple[str, ...]:
    f = result.facts or {}
    return (
        result.device,
        result.platform,
        str(f.get("vendor", "") or "-"),
        str(f.get("model", "") or "-"),
        str(f.get("os_version", "") or "-"),
        str(f.get("serial_number", f.get("serial", "")) or "-"),
    )


def _table(doc, headers: tuple[str, ...], rows: list[tuple[str, ...]]):
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    for cell, text in zip(table.rows[0].cells, headers):
        cell.text = text
        for para in cell.paragraphs:
            for run in para.runs:
                run.bold = True
    for row in rows:
        cells = table.add_row().cells
        for cell, text in zip(cells, row):
            cell.text = text
    return table


def build(run: "Run", *, title: str = "") -> bytes:
    """Render the run and return .docx bytes."""
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import Inches, Pt

    doc = Document()
    heading = title or (
        "Network Documentation" if run.kind == DOCUMENTATION
        else "Device Configuration Check"
    )
    doc.add_heading(heading, 0)

    subtitle = doc.add_paragraph()
    subtitle.alignment = WD_ALIGN_PARAGRAPH.LEFT
    piece = subtitle.add_run(
        f"{run.name} - {run.platform}\n"
        f"Generated {run.created_label} by {run.user} using netauto {__version__}"
    )
    piece.italic = True
    piece.font.size = Pt(10)

    # -- Scope -------------------------------------------------------------
    doc.add_heading("Scope", level=1)
    totals = run.totals()
    doc.add_paragraph(
        f"This document covers {totals['devices']} device(s) on the "
        f"{run.platform} platform, selected from the netauto inventory. "
        f"{totals['unreachable']} could not be reached and are listed "
        f"separately; their sections describe what was not collected rather "
        f"than presenting an empty result as a clean one."
    )
    doc.add_paragraph(
        "netauto is read-only. Nothing in this document was changed on any "
        "device, and the recommendations are proposals for your own change "
        "process."
    )

    # -- Summary -----------------------------------------------------------
    doc.add_heading("Summary of findings", level=1)
    _table(
        doc,
        ("Measure", "Count"),
        [
            ("Devices in scope", str(totals["devices"])),
            ("Devices reached", str(totals["devices"] - totals["unreachable"])),
            ("Unreachable", str(totals["unreachable"])),
            ("Checks passed", str(totals["pass"])),
            ("Findings needing attention", str(totals["fail"])),
            ("  of which critical", str(totals["critical"])),
            ("  of which high", str(totals["high"])),
        ],
    )

    # -- Diagram -----------------------------------------------------------
    if run.kind == DOCUMENTATION:
        doc.add_heading("Network topology", level=1)
        _add_diagram(doc, run, Inches)

    # -- Inventory ---------------------------------------------------------
    doc.add_heading("Device inventory", level=1)
    reachable = [r for r in run.results if r.reachable]
    if reachable:
        _table(
            doc,
            ("Device", "Platform", "Vendor", "Model", "OS version", "Serial"),
            [_facts_row(r) for r in reachable],
        )
    else:
        doc.add_paragraph("No device could be reached, so no inventory was collected.")

    unreachable = [r for r in run.results if not r.reachable]
    if unreachable:
        doc.add_heading("Devices not reached", level=2)
        doc.add_paragraph(
            "These devices are in scope but did not answer. Their absence is "
            "not a pass:"
        )
        _table(doc, ("Device", "Reason"),
               [(r.device, r.error) for r in unreachable])

    # -- Findings ----------------------------------------------------------
    doc.add_heading("Recommended improvements", level=1)
    any_findings = False
    for result in reachable:
        failed = result.failed_findings
        if not failed:
            continue
        any_findings = True
        doc.add_heading(result.device, level=2)
        for finding in failed:
            para = doc.add_paragraph(style="List Bullet")
            head = para.add_run(
                f"[{SEVERITY_LABEL.get(finding.severity, finding.severity)}] "
                f"{finding.rule_id} {finding.title}"
            )
            head.bold = True
            doc.add_paragraph(finding.detail or "")
            if finding.evidence:
                ev = doc.add_paragraph()
                run_ev = ev.add_run("\n".join(finding.evidence[:6]))
                run_ev.font.name = "Consolas"
                run_ev.font.size = Pt(9)
            if finding.remediation:
                doc.add_paragraph(f"Recommendation: {finding.remediation}")
            if finding.reference:
                cite = doc.add_paragraph()
                cite_run = cite.add_run(f"Source: {finding.reference}")
                cite_run.italic = True
                cite_run.font.size = Pt(9)
    if not any_findings and reachable:
        doc.add_paragraph(
            "Every applicable rule passed on every device reached. The rules "
            "evaluated are listed in the appendix."
        )

    # -- Appendix ----------------------------------------------------------
    doc.add_heading("Appendix: what was collected", level=1)
    if run.results and any(r.outputs for r in run.results):
        doc.add_paragraph("Read-only commands run on each device:")
        for command in sorted({c for r in run.results for c in r.outputs}):
            doc.add_paragraph(command, style="List Bullet")
    else:
        doc.add_paragraph(
            "No CLI commands were run. This platform exposes no command "
            "interface through netauto, so configuration and state were read "
            "through its API instead."
        )
    refused = {c: e for r in run.results for c, e in r.command_errors.items()}
    if refused:
        doc.add_heading("Commands the device refused", level=2)
        doc.add_paragraph(
            "Usually a feature the model does not have. Listed so the gap is "
            "visible rather than silent:"
        )
        _table(doc, ("Command", "Reason"),
               [(c, e[:200]) for c, e in sorted(refused.items())])

    out = io.BytesIO()
    doc.save(out)
    return out.getvalue()


def _add_diagram(doc, run: "Run", Inches) -> None:
    """Embed the topology PNG, or say why there is none."""
    topo = run.topology
    if topo is None or not getattr(topo, "nodes", None):
        doc.add_paragraph(
            "No topology diagram: neighbour discovery returned nothing for "
            "the devices in scope. LLDP or CDP has to be running, and the "
            "platform driver has to expose it."
        )
        return
    from docx.shared import Pt

    from netauto.diagram import render_png

    png = render_png(topo, title=f"{run.platform} topology")
    doc.add_picture(io.BytesIO(png), width=Inches(6.0))
    caption = doc.add_paragraph()
    label = caption.add_run(
        f"Collected {topo.collected_label or 'in this run'}. "
        f"Solid lines are links both ends reported; dashed lines were reported "
        f"by one end only. Hollow boxes were seen over LLDP but are not in the "
        f"inventory."
    )
    label.italic = True
    label.font.size = Pt(9)
    if topo.gaps:
        doc.add_paragraph(
            "Devices that contributed no neighbour data: "
            + ", ".join(f"{k} ({v})" for k, v in sorted(topo.gaps.items()))
        )
