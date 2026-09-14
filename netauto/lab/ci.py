"""A CI-shaped loop: bring a lab up, audit it, assert it is clean, tear it down.

The design doc's payoff turned into a gate. Point this at a netlab topology in
CI -- or run it by hand -- and it builds the lab, runs netauto's compliance
ruleset against it, and exits non-zero if the design regressed: a failing
finding at or above the chosen severity, or a node that did not come up. The lab
is torn down afterwards, pass or fail, unless you ask to keep it.

    python -m netauto.lab.ci labs/spine-leaf/topology.yml --fail-on high

Exit codes are the interface a CI job reads:
    0  clean          -- nothing failed at or above the threshold
    1  findings       -- the audit failed the gate; the design regressed
    2  infrastructure -- the lab could not be built or audited at all

It needs netlab and a provider on the runner, and ``LAB_*`` credentials in the
environment for the lab devices. See docs/netlab-integration.md.
"""

from __future__ import annotations

import argparse
import sys
from typing import TextIO

from netauto.config import Settings
from netauto.errors import LabError
from netauto.lab import runner
from netauto.lab.audit import LabAudit, audit_lab

#: Most severe first, matching netauto.audit. "info" is the least severe rung.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

#: Thresholds the gate accepts. "any" fails on a failing finding of any
#: severity; the named levels fail on that severity or worse.
FAIL_ON = ("any", "critical", "high", "medium", "low")

#: Exit codes, named so the flow reads.
OK, FINDINGS, INFRA = 0, 1, 2


def _severe_enough(severity: str, fail_on: str) -> bool:
    """Whether a failing finding of this severity trips the gate."""
    if fail_on == "any":
        return True
    return SEVERITY_ORDER.get(severity, 9) <= SEVERITY_ORDER[fail_on]


def gate(audit: LabAudit, fail_on: str) -> list[str]:
    """The reasons a lab fails the gate; empty means it passed.

    Two things fail a design: a node that could not be audited at all -- an
    unreachable device is not a passing device -- and a failing finding at or
    above the threshold. Everything else, including advisory findings below the
    line, is reported but does not fail the build.
    """
    reasons: list[str] = []
    for r in audit.results:
        if r.get("error"):
            reasons.append(f"{r['device']}: unreachable ({r['error']})")
            continue
        for f in r.get("findings", []):
            if f["status"] == "fail" and _severe_enough(f["severity"], fail_on):
                reasons.append(
                    f"{r['device']}: {f['severity']} {f['rule_id']} {f['title']}")
    return reasons


def _report(audit: LabAudit, out: TextIO) -> None:
    s = audit.summary
    print(f"audited {s.get('devices', 0)} node(s): {s.get('pass', 0)} pass, "
          f"{s.get('fail', 0)} fail, {s.get('errors', 0)} unreachable "
          f"({s.get('critical', 0)} critical, {s.get('high', 0)} high)", file=out)
    for node, reason in audit.skipped:
        print(f"  not audited: {node.name} -- {reason}", file=out)


def run(topology: str, settings: Settings | None = None, *,
        provider: str | None = None, fail_on: str = "high",
        keep: bool = False, out: TextIO = sys.stdout) -> int:
    """Build, audit, gate, and (unless keep) tear down. Returns an exit code."""
    settings = settings or Settings.load()

    print(f"==> netlab up: {topology}", file=out)
    try:
        runner.up(topology, provider=provider)
    except LabError as exc:
        print(f"lab did not come up: {exc}", file=out)
        return INFRA

    try:
        print("==> auditing the lab", file=out)
        audit = audit_lab(topology, settings, refresh=True)
        _report(audit, out)
        reasons = gate(audit, fail_on)
        if reasons:
            print(f"\nFAIL: {len(reasons)} issue(s) at or above '{fail_on}':",
                  file=out)
            for reason in reasons:
                print(f"  - {reason}", file=out)
            return FINDINGS
        print(f"\nPASS: clean at or above '{fail_on}'.", file=out)
        return OK
    except LabError as exc:
        print(f"could not audit the lab: {exc}", file=out)
        return INFRA
    finally:
        if keep:
            print("\n(leaving the lab up: --keep)", file=out)
        else:
            print("\n==> netlab down", file=out)
            try:
                runner.down(topology, cleanup=True)
            except LabError as exc:
                # Teardown trouble is worth shouting about, but it does not
                # change the verdict on the design, which is what the exit
                # code speaks to.
                print(f"warning: teardown failed: {exc}", file=out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="netauto.lab.ci",
        description="Bring a netlab lab up, audit it, assert it is clean, "
                    "tear it down.")
    parser.add_argument(
        "topology", help="the netlab topology (a directory's topology.yml, or "
                         "a *.yml file)")
    parser.add_argument(
        "--provider", help="override the topology's provider (clab or libvirt)")
    parser.add_argument(
        "--fail-on", choices=FAIL_ON, default="high",
        help="fail if a failing finding is at or above this severity, or 'any' "
             "for any failure (default: high)")
    parser.add_argument(
        "--keep", action="store_true",
        help="leave the lab up instead of tearing it down (for debugging)")
    args = parser.parse_args(argv)
    return run(args.topology, provider=args.provider, fail_on=args.fail_on,
               keep=args.keep)


if __name__ == "__main__":
    raise SystemExit(main())
