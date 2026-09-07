"""The ruleset the workflows compare against: vendor configuration guides.

This is the built-in hardening set plus the guidance that only makes sense
when you have run the show commands as well -- and, for every rule, a citation
for where it comes from.

The citation is the point. "Enable BPDU guard" is an opinion until it is "Cisco
Campus LAN design guide, edge port hardening", and an operator taking a report
to a change board needs the second one. Rules without a traceable source do not
belong here.

The built-in rules are annotated rather than rewritten. netauto's Audit page
and the Prometheus metrics keep running BUILTIN exactly as before, so adding
guidance here cannot move a dashboard or fire an alert; the workflows opt into
the larger set deliberately.
"""

from __future__ import annotations

import dataclasses
import re

from netauto.checks.builtin import ARUBA, BUILTIN, CISCO, FORTINET, JUNIPER, _absent, _present
from netauto.checks.engine import Rule, Ruleset, match_any

#: Where each built-in rule comes from. Keyed by rule id so a renumbering
#: fails loudly in the test suite rather than silently dropping a citation.
REFERENCES: dict[str, str] = {
    "NA-001": "Cisco Guide to Harden Cisco IOS Devices, management plane",
    "NA-002": "Cisco Guide to Harden Cisco IOS Devices, SSH configuration",
    "NA-003": "Cisco Guide to Harden Cisco IOS Devices, disable unused services",
    "NA-004": "Cisco Guide to Harden Cisco IOS Devices, password protection",
    "NA-005": "Cisco Guide to Harden Cisco IOS Devices, enable secret",
    "NA-006": "CIS Cisco IOS Benchmark, exec-timeout",
    "NA-010": "Juniper Junos Hardening Guide, disable telnet service",
    "NA-011": "Juniper Junos Hardening Guide, restrict root authentication",
    "NA-020": "Aruba AOS-CX Security Hardening Guide, management protocols",
    "NA-021": "Aruba AOS-CX Security Hardening Guide, web management",
    "NA-030": "Fortinet FortiOS Hardening Guide, administrative access",
    "NA-031": "Fortinet FortiOS Hardening Guide, admin idle timeout",
    "NA-100": "NIST SP 800-53 rev5 IA-5; vendor SNMP configuration guides",
    "NA-101": "NIST SP 800-53 rev5 AU-8, time stamps",
    "NA-102": "NIST SP 800-53 rev5 AU-9, protection of audit information",
}


def _annotated_builtins() -> tuple[Rule, ...]:
    """The built-in rules, each carrying the guide it encodes."""
    return tuple(
        dataclasses.replace(rule, reference=REFERENCES.get(rule.id, ""))
        for rule in BUILTIN.rules
    )


def _stanza_present(*patterns: str, ok: str, bad: str):
    """Rule body for guidance that spans lines, e.g. a setting inside a stanza.

    match_any searches line by line, which is right for almost every rule and
    silently wrong for the few that need to see a block. A pattern like
    "config log syslogd setting ... set status enable" matches nothing at all
    when each line is searched on its own, and the rule then fails on every
    config including correct ones. These search the whole text instead.
    """
    compiled = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns]

    def check(config: str, facts: dict) -> tuple[bool, str, tuple[str, ...]]:
        for rx in compiled:
            found = rx.search(config)
            if found:
                evidence = tuple(
                    line.strip() for line in found.group(0).splitlines() if line.strip()
                )
                return True, ok, evidence[:4]
        return False, bad, ()

    return check


def _snmp_rw(config: str, facts: dict) -> tuple[bool, str, tuple[str, ...]]:
    """Read-write SNMP is a configuration change path in a read-only world."""
    rw = re.compile(
        r"(snmp-server\s+community\s+\S+\s+rw\b"
        r"|set\s+snmp\s+community\s+\S+\s+authorization\s+read-write"
        r"|snmpv3\s+user\s+\S+.*\bread-write\b)",
        re.IGNORECASE,
    )
    hits = tuple(l.strip() for l in config.splitlines() if rw.search(l))
    if hits:
        return False, "SNMP is writable, which is a configuration path.", hits
    return True, "No read-write SNMP community or user found.", ()


EXTRA: tuple[Rule, ...] = (
    # -- Cisco / Arista ----------------------------------------------------
    Rule(
        id="NA-200", title="AAA is enabled",
        severity="high", families=CISCO,
        check=_present(
            r"^\s*aaa new-model", r"^\s*aaa authentication login",
            ok="AAA is configured.",
            bad="No AAA; authentication falls back to local lines only.",
        ),
        remediation="Enable aaa new-model and point authentication at TACACS+ or RADIUS, "
                    "keeping a local fallback account.",
        reference="Cisco Guide to Harden Cisco IOS Devices, AAA",
    ),
    Rule(
        id="NA-201", title="Legacy small services are disabled",
        severity="medium", families=CISCO,
        check=_absent(
            r"^\s*service (pad|finger|tcp-small-servers|udp-small-servers)\b",
            r"^\s*ip (source-route|finger|bootp server)\b",
            ok="No legacy small services enabled.",
            bad="A legacy service is enabled that has no modern use.",
        ),
        remediation="Disable pad, finger, small servers, bootp and ip source-route.",
        reference="Cisco Guide to Harden Cisco IOS Devices, disable unused services",
    ),
    Rule(
        id="NA-202", title="A login banner is set",
        severity="low", families=CISCO,
        check=_present(
            r"^\s*banner (login|motd)\b",
            ok="A login banner is configured.",
            bad="No login banner; unauthorised-access notice is absent.",
        ),
        remediation="Set a banner login carrying your organisation's access notice.",
        reference="CIS Cisco IOS Benchmark, banner configuration",
    ),
    Rule(
        id="NA-203", title="Management access is restricted by ACL",
        severity="high", families=CISCO,
        check=_present(
            r"^\s*access-class\s+\S+\s+in",
            r"^\s*ip ssh access-class",
            r"^\s*ip access-class\s+\S+\s+in",
            ok="VTY access is restricted by an access class.",
            bad="No access-class on the VTY lines; management is reachable from anywhere "
                "the routing table allows.",
        ),
        remediation="Apply an access-class to line vty restricting SSH to management subnets.",
        reference="Cisco Guide to Harden Cisco IOS Devices, restrict management access",
    ),
    Rule(
        id="NA-204", title="Edge ports have BPDU guard",
        severity="medium", families=CISCO,
        check=_present(
            r"^\s*spanning-tree portfast bpduguard default",
            r"^\s*spanning-tree bpduguard enable",
            ok="BPDU guard is enabled on edge ports.",
            bad="No BPDU guard; a switch plugged into an access port can take over the "
                "spanning tree.",
        ),
        remediation="Set spanning-tree portfast bpduguard default, and enable it per-port "
                    "on access ports.",
        reference="Cisco Campus LAN design guide, edge port hardening",
    ),
    Rule(
        id="NA-205", title="Log messages carry timestamps",
        severity="medium", families=CISCO,
        check=_present(
            r"^\s*service timestamps log",
            ok="Log messages are timestamped.",
            bad="Logs have no timestamps and cannot be correlated across devices.",
        ),
        remediation="Set service timestamps log datetime msec localtime show-timezone.",
        reference="NIST SP 800-53 rev5 AU-8, time stamps",
    ),
    Rule(
        id="NA-206", title="The auxiliary port is disabled",
        severity="low", families=CISCO,
        check=_stanza_present(
            r"^\s*line aux 0\b[\s\S]{0,200}?^\s*(no exec|transport input none)",
            ok="The aux port is disabled.",
            bad="The aux port does not explicitly disable exec or transport input.",
        ),
        remediation="Under line aux 0, set no exec and transport input none.",
        reference="CIS Cisco IOS Benchmark, aux port",
    ),
    # -- Juniper -----------------------------------------------------------
    Rule(
        id="NA-210", title="HTTP web management is disabled",
        severity="high", families=JUNIPER,
        check=_absent(
            r"^\s*set system services web-management http\b",
            r"^\s*http\s*\{",
            ok="No cleartext web management service.",
            bad="web-management http is enabled; management credentials cross the "
                "network in clear.",
        ),
        remediation="Delete system services web-management http and use https only.",
        reference="Juniper Junos Hardening Guide, web management",
    ),
    Rule(
        id="NA-211", title="A login message is set",
        severity="low", families=JUNIPER,
        check=_present(
            r"^\s*set system login message", r"^\s*message\s+\"",
            ok="A login message is configured.",
            bad="No login message; unauthorised-access notice is absent.",
        ),
        remediation="Set system login message with your access notice.",
        reference="Juniper Junos Hardening Guide, login banners",
    ),
    Rule(
        id="NA-212", title="Login sessions time out",
        severity="medium", families=JUNIPER,
        check=_present(
            r"idle-timeout\s+\d+",
            ok="An idle timeout is set on login classes.",
            bad="No idle-timeout on any login class; sessions persist indefinitely.",
        ),
        remediation="Set an idle-timeout on each system login class.",
        reference="Juniper Junos Hardening Guide, login classes",
    ),
    # -- Aruba -------------------------------------------------------------
    Rule(
        id="NA-220", title="Management sessions time out",
        severity="medium", families=ARUBA,
        check=_present(
            r"^\s*(console|telnet|ssh)?\s*idle-?timeout\s+\d+",
            r"^\s*cli-session\s+timeout\s+\d+",
            ok="An idle timeout is configured.",
            bad="No session idle timeout; an unattended session stays open.",
        ),
        remediation="Set a CLI session idle timeout.",
        reference="Aruba AOS-CX Security Hardening Guide, session management",
    ),
    Rule(
        id="NA-221", title="Loop protection is enabled",
        severity="medium", families=ARUBA,
        check=_present(
            r"^\s*loop-protect\b", r"^\s*spanning-tree\b",
            ok="Loop protection or spanning tree is configured.",
            bad="Neither loop-protect nor spanning-tree found; a cable loop would "
                "flood the switch.",
        ),
        remediation="Enable spanning-tree, or loop-protect on edge ports.",
        reference="Aruba AOS-CX configuration guide, loop protection",
    ),
    # -- Fortinet ----------------------------------------------------------
    Rule(
        id="NA-230", title="Administrative access is limited to trusted hosts",
        severity="high", families=FORTINET,
        check=_present(
            r"^\s*set trusthost\d*\s+\S+",
            ok="Administrator accounts restrict source addresses.",
            bad="No trusthost on any admin account; the management interface accepts "
                "logins from any reachable address.",
        ),
        remediation="Set trusthost entries on every admin account.",
        reference="Fortinet FortiOS Hardening Guide, trusted hosts",
    ),
    Rule(
        id="NA-231", title="Logs are sent to FortiAnalyzer or syslog",
        severity="high", families=FORTINET,
        check=_stanza_present(
            r"config log (fortianalyzer|syslogd) setting[\s\S]{0,200}?set status enable",
            ok="Remote logging is enabled.",
            bad="No remote log target enabled; local logs are lost on reboot.",
        ),
        remediation="Enable log fortianalyzer or log syslogd and set a server.",
        reference="Fortinet FortiOS Hardening Guide, logging",
    ),
    # -- Every platform ----------------------------------------------------
    Rule(
        id="NA-110", title="SNMP is not writable",
        severity="critical",
        check=_snmp_rw,
        remediation="Remove read-write communities. Use SNMPv3 read-only, and make "
                    "changes through your configuration process instead.",
        reference="NIST SP 800-53 rev5 CM-5; vendor SNMP configuration guides",
    ),
)


#: The ruleset the workflows evaluate. Built-ins first, so rule ids stay in
#: the order an operator already knows from the Audit page.
VENDOR = Ruleset(name="vendor-guides", rules=_annotated_builtins() + EXTRA)
