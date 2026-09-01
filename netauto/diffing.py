"""Configuration diffing.

Comparison only -- nothing here talks to a device or changes one. Vendor
configs carry volatile lines (timestamps, counters, encrypted secrets) that
would otherwise dominate a diff, so normalisation runs first.
"""

from __future__ import annotations

import difflib
import re

#: Lines dropped before comparison, per platform family.
NOISE = {
    "cisco": (
        r"^Building configuration",
        r"^Current configuration\s*:",
        r"^ntp clock-period",
        r"^!\s*Time:",
        r"^\s*$",
    ),
    "juniper": (r"^## Last commit:", r"^\s*$"),
    "aruba": (r"^Running configuration:", r"^\s*$"),
    "fortinet": (r"^#conf_file_ver=", r"^#buildno=", r"^\s*$"),
    "generic": (r"^\s*$",),
}

#: Secrets are masked rather than compared, so a rotated hash is not a "change".
SECRET_PATTERNS = (
    (re.compile(r"(secret\s+\d?\s*)(\S+)", re.IGNORECASE), r"\1<masked>"),
    (re.compile(r"(password\s+\d?\s*)(\S+)", re.IGNORECASE), r"\1<masked>"),
    (re.compile(r"(snmp-server community\s+)(\S+)", re.IGNORECASE), r"\1<masked>"),
    (re.compile(r'(set password\s+)(\S+)', re.IGNORECASE), r"\1<masked>"),
)


def normalize(config: str, family: str = "generic", *, mask_secrets: bool = True) -> list[str]:
    """Strip volatile lines and trailing whitespace, optionally masking secrets."""
    noise = [re.compile(p, re.IGNORECASE) for p in NOISE.get(family, NOISE["generic"])]
    out: list[str] = []
    for line in config.splitlines():
        line = line.rstrip()
        if any(p.search(line) for p in noise):
            continue
        if mask_secrets:
            for pattern, replacement in SECRET_PATTERNS:
                line = pattern.sub(replacement, line)
        out.append(line)
    return out


def unified(
    current: str,
    candidate: str,
    *,
    family: str = "generic",
    from_label: str = "running",
    to_label: str = "candidate",
    context: int = 3,
) -> str:
    """Return a unified diff, or an empty string when the two match."""
    a = normalize(current, family)
    b = normalize(candidate, family)
    diff = difflib.unified_diff(
        a, b, fromfile=from_label, tofile=to_label, lineterm="", n=context
    )
    return "\n".join(diff)


def summarize(diff_text: str) -> dict[str, int]:
    """Count added and removed lines in a unified diff."""
    added = removed = 0
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return {"added": added, "removed": removed, "changed": added + removed}
