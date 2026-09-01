"""Run compliance rules across the inventory."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from netauto.checks import BUILTIN, Finding, Ruleset, run_ruleset
from netauto.config import Settings
from netauto.drivers.base import platform_family
from netauto.errors import NetautoError
from netauto.inventory import Device
from netauto.session import connect

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def audit_device(
    device: Device, settings: Settings, ruleset: Ruleset | None = None
) -> dict[str, Any]:
    """Pull one device's config and evaluate the ruleset against it."""
    ruleset = ruleset or BUILTIN
    family = platform_family(device.platform)
    try:
        with connect(device, settings) as driver:
            facts = driver.facts()
            config = driver.get_config("running")
    except NetautoError as exc:
        return {
            "device": device.name,
            "platform": device.platform,
            "error": str(exc),
            "findings": [],
        }
    findings = run_ruleset(ruleset, device.name, family, config, facts)
    findings.sort(key=lambda f: (f.status != "fail", SEVERITY_ORDER.get(f.severity, 9)))
    return {
        "device": device.name,
        "platform": device.platform,
        "facts": facts,
        "config_lines": len(config.splitlines()),
        "summary": summarize(findings),
        "findings": [asdict(f) for f in findings],
    }


def summarize(findings: list[Finding]) -> dict[str, int]:
    out = {"pass": 0, "fail": 0, "skip": 0, "critical": 0, "high": 0}
    for f in findings:
        out[f.status] = out.get(f.status, 0) + 1
        if f.failed and f.severity in ("critical", "high"):
            out[f.severity] += 1
    return out
