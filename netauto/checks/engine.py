"""A small rule engine for configuration compliance.

A rule inspects configuration text plus whatever facts the driver returned and
reports pass, fail, or not-applicable. Rules never connect to anything, which
keeps them trivial to unit-test against captured configs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Literal

Status = Literal["pass", "fail", "skip"]
Severity = Literal["critical", "high", "medium", "low", "info"]


@dataclass(frozen=True)
class Finding:
    """The outcome of one rule against one device."""

    rule_id: str
    title: str
    status: Status
    severity: Severity
    device: str
    detail: str = ""
    evidence: tuple[str, ...] = ()
    #: What the rule is derived from, quoted in reports. A recommendation an
    #: operator cannot trace back to a vendor's own guidance is just an
    #: opinion, and reads like one in front of a change board.
    reference: str = ""
    remediation: str = ""

    @property
    def failed(self) -> bool:
        return self.status == "fail"


@dataclass(frozen=True)
class Rule:
    """One compliance rule."""

    id: str
    title: str
    severity: Severity
    #: Platform families this applies to; empty means all.
    families: frozenset[str] = frozenset()
    #: Called with (config_text, facts) -> (passed, detail, evidence)
    check: Callable[[str, dict], tuple[bool, str, tuple[str, ...]]] = field(
        default=lambda cfg, facts: (True, "", ())
    )
    remediation: str = ""
    #: The vendor guide, hardening document or benchmark this rule encodes.
    reference: str = ""

    def applies_to(self, family: str) -> bool:
        return not self.families or family in self.families


@dataclass(frozen=True)
class Ruleset:
    """A named collection of rules."""

    name: str
    rules: tuple[Rule, ...]

    def for_family(self, family: str) -> list[Rule]:
        return [r for r in self.rules if r.applies_to(family)]


def match_any(config: str, *patterns: str) -> tuple[str, ...]:
    """Return every config line matching any pattern, for use as evidence."""
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
    return tuple(
        line.strip()
        for line in config.splitlines()
        if any(p.search(line) for p in compiled)
    )


def run_ruleset(
    ruleset: Ruleset, device_name: str, family: str, config: str, facts: dict
) -> list[Finding]:
    """Evaluate every applicable rule against one device's configuration."""
    findings: list[Finding] = []
    for rule in ruleset.for_family(family):
        try:
            passed, detail, evidence = rule.check(config, facts)
            status: Status = "pass" if passed else "fail"
        except Exception as exc:  # a broken rule must not abort the audit
            passed, detail, evidence, status = False, f"rule error: {exc}", (), "skip"
        findings.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                status=status,
                severity=rule.severity,
                device=device_name,
                detail=detail,
                evidence=evidence,
                reference=rule.reference,
                remediation=rule.remediation,
            )
        )
    return findings
