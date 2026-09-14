"""Audit a running lab with netauto's own compliance rules.

This is the payoff of the whole integration. netauto already reads a device's
configuration and judges it against a ruleset; point that at a netlab-built lab
and a design is validated before it reaches real hardware -- the same rules,
the same findings, against a throwaway copy of the network.

Read-only, like every audit: it connects to each lab device, reads the running
configuration, and evaluates rules. It changes nothing, on the lab or anywhere.
Lab findings are deliberately kept out of the compliance metrics -- a lab is not
production, and its passes and failures are not the fleet's.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from netauto.audit import audit_device
from netauto.config import Settings
from netauto.lab import runner
from netauto.lab.snapshot import LabNode


@dataclass
class LabAudit:
    """The result of auditing every drivable node in a lab."""

    topology: str
    results: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    #: Nodes the lab has but netauto cannot drive, carried through so the audit
    #: page can say what it did not look at rather than quietly omitting it.
    skipped: list[tuple[LabNode, str]] = field(default_factory=list)


def summarize(results: list[dict[str, Any]]) -> dict[str, int]:
    """Roll per-device audit dicts into one set of totals for the page."""
    out = {"devices": len(results), "fail": 0, "pass": 0, "errors": 0,
           "critical": 0, "high": 0}
    for r in results:
        if r.get("error"):
            out["errors"] += 1
            continue
        s = r.get("summary", {})
        for k in ("fail", "pass", "critical", "high"):
            out[k] += s.get(k, 0)
    return out


def audit_lab(topology: str, settings: Settings, *,
              refresh: bool = False) -> LabAudit:
    """Audit every drivable node in a lab and return the findings.

    Reads the lab's inventory from its snapshot (``refresh=False`` parses the
    existing one without invoking netlab, so an up lab can be audited even where
    netlab is not installed), then runs the ruleset against each node exactly as
    the Audit page does. An unreachable node -- no route to it, or no ``LAB_*``
    credentials -- becomes an error entry, not a silent pass.
    """
    mapped = runner.read_inventory(topology, refresh=refresh)
    results = [audit_device(device, settings) for device in mapped.devices]
    return LabAudit(topology=str(topology), results=results,
                    summary=summarize(results), skipped=mapped.skipped)
