"""Built-in hardening rules.

Each rule is scoped to the platform families whose syntax it understands, so a
Junos config is never judged by IOS patterns. Rules are intentionally small and
readable: the point is that an operator can audit the auditor.
"""

from __future__ import annotations

import re

from netauto.checks.engine import Rule, Ruleset, match_any

CISCO = frozenset({"cisco"})
JUNIPER = frozenset({"juniper"})
ARUBA = frozenset({"aruba"})
FORTINET = frozenset({"fortinet"})


def _absent(*patterns: str, ok: str, bad: str):
    """Rule body: pass when no line matches any pattern."""

    def check(config: str, facts: dict) -> tuple[bool, str, tuple[str, ...]]:
        hits = match_any(config, *patterns)
        return (not hits, ok if not hits else bad, hits)

    return check


def _present(*patterns: str, ok: str, bad: str):
    """Rule body: pass when at least one line matches."""

    def check(config: str, facts: dict) -> tuple[bool, str, tuple[str, ...]]:
        hits = match_any(config, *patterns)
        return (bool(hits), ok if hits else bad, hits[:3])

    return check


def _time_source(config: str, facts: dict) -> tuple[bool, str, tuple[str, ...]]:
    """An NTP or SNTP time source, in any vendor's syntax.

    Cisco and Arista put the server on one line; Juniper uses `set system ntp`.
    FortiOS and FortiSwitch nest it -- `config system ntp` around a
    `config ntpserver` block whose entries carry `set server <ip>` -- which a
    line search cannot see. Found against the same FortiSwitch 108F, whose NTP
    was configured yet reported missing, the twin of the syslog gap.
    """
    line_hits = match_any(
        config,
        r"^\s*ntp server", r"^\s*set system ntp", r"^\s*sntp server",
        r"^\s*ntp\b.*server",
    )
    if line_hits:
        return True, "An NTP or SNTP server is configured.", line_hits[:3]
    block = re.search(r"config ntpserver\b.*?\bset server\s+\"?\d+\.\d+\.\d+\.\d+",
                      config, re.IGNORECASE | re.DOTALL)
    if block:
        server = re.search(r'set server\s+"?(\d+\.\d+\.\d+\.\d+)',
                           block.group(0), re.IGNORECASE)
        return True, "An NTP or SNTP server is configured.", (
            f'set server {server.group(1)}' if server else "ntp server configured",)
    return False, "No time source found; log timestamps cannot be correlated.", ()


def _remote_logging(config: str, facts: dict) -> tuple[bool, str, tuple[str, ...]]:
    """A remote syslog destination, in any vendor's syntax.

    Cisco, Juniper and Arista state it on one line, so a line search finds
    them. FortiOS and FortiSwitch spell it as a stanza -- `config log syslogd
    setting` carrying both `set status enable` and `set server <ip>` -- which a
    line-by-line search cannot see. A disabled syslogd block still prints in
    show full-configuration, so the enable and the server are checked together;
    the header alone means nothing. Found against a FortiSwitch 108F whose
    syslog was configured yet reported missing.
    """
    line_hits = match_any(
        config,
        r"^\s*logging (host|server)", r"^\s*logging \d+\.\d+\.\d+\.\d+",
        r"^\s*set system syslog", r"^\s*syslog\b",
    )
    if line_hits:
        return True, "A remote log destination is configured.", line_hits[:3]
    for block in re.finditer(r"config log syslogd\w* setting\b.*?\n\s*end",
                             config, re.IGNORECASE | re.DOTALL):
        text = block.group(0)
        server = re.search(r'^\s*set server\s+"?(\d+\.\d+\.\d+\.\d+)',
                           text, re.IGNORECASE | re.MULTILINE)
        enabled = re.search(r"^\s*set status enable\b", text,
                            re.IGNORECASE | re.MULTILINE)
        if server and enabled:
            return True, "A remote log destination is configured.", (server.group(0).strip(),)
    return (False,
            "No remote syslog destination; local logs are lost on reboot or compromise.",
            ())


def _weak_snmp(config: str, facts: dict) -> tuple[bool, str, tuple[str, ...]]:
    """Flag well-known default community strings in any vendor syntax."""
    weak = re.compile(
        r"(community|snmp-server community|set snmp community)\s+[\"']?"
        r"(public|private|cisco|admin|default)\b",
        re.IGNORECASE,
    )
    hits = tuple(l.strip() for l in config.splitlines() if weak.search(l))
    if hits:
        return False, "Default SNMP community string in use.", hits
    return True, "No default community strings found.", ()


BUILTIN = Ruleset(
    name="builtin-hardening",
    rules=(
        # -- Cisco / Arista ------------------------------------------------
        Rule(
            id="NA-001", title="Telnet is not accepted on VTY lines",
            severity="critical", families=CISCO,
            check=_absent(
                r"transport input .*\btelnet\b",
                r"^\s*ip telnet server",
                ok="No VTY line accepts telnet.",
                bad="At least one VTY line accepts telnet; credentials cross the wire in clear text.",
            ),
            remediation="Set 'transport input ssh' on every line vty block.",
        ),
        Rule(
            id="NA-002", title="SSH is restricted to version 2",
            severity="high", families=CISCO,
            check=_present(
                r"^\s*ip ssh version 2",
                ok="SSH is pinned to version 2.",
                bad="'ip ssh version 2' is absent, so SSHv1 may be negotiable.",
            ),
            remediation="Configure 'ip ssh version 2'.",
        ),
        Rule(
            id="NA-003", title="HTTP management server is disabled",
            severity="high", families=CISCO,
            check=_absent(
                r"^\s*ip http server\s*$",
                ok="Cleartext HTTP management is off.",
                bad="'ip http server' is enabled; management traffic is unencrypted.",
            ),
            remediation="Run 'no ip http server' and use 'ip http secure-server'.",
        ),
        Rule(
            id="NA-004", title="Stored passwords are encrypted",
            severity="medium", families=CISCO,
            check=_present(
                r"^\s*service password-encryption",
                ok="Password encryption service is enabled.",
                bad="'service password-encryption' is absent; type-0 passwords may be stored in clear.",
            ),
            remediation="Configure 'service password-encryption'.",
        ),
        Rule(
            id="NA-005", title="An enable secret is set",
            severity="high", families=CISCO,
            check=_present(
                r"^\s*enable secret",
                ok="Enable secret is configured.",
                bad="No 'enable secret'; privileged access may rely on a weaker 'enable password'.",
            ),
            remediation="Set 'enable secret' and remove any 'enable password'.",
        ),
        Rule(
            id="NA-006", title="EXEC sessions time out",
            severity="medium", families=CISCO,
            check=_present(
                r"^\s*exec-timeout (?!0 0)",
                ok="An EXEC timeout is configured.",
                bad="No non-zero exec-timeout found; idle sessions may persist indefinitely.",
            ),
            remediation="Set 'exec-timeout 10 0' or stricter on console and vty lines.",
        ),
        # -- Juniper -------------------------------------------------------
        Rule(
            id="NA-010", title="Telnet service is not enabled",
            severity="critical", families=JUNIPER,
            check=_absent(
                r"^\s*set system services telnet",
                r"^\s*telnet;",
                ok="Telnet service is not configured.",
                bad="The telnet service is enabled under system services.",
            ),
            remediation="Run 'delete system services telnet' and keep ssh only.",
        ),
        Rule(
            id="NA-011", title="Root login over SSH is restricted",
            severity="high", families=JUNIPER,
            check=_absent(
                r"root-login allow",
                ok="SSH root-login is not set to allow.",
                bad="'root-login allow' permits direct root SSH access.",
            ),
            remediation="Set 'system services ssh root-login deny'.",
        ),
        # -- Aruba ---------------------------------------------------------
        Rule(
            id="NA-020", title="Telnet server is disabled",
            severity="critical", families=ARUBA,
            check=_absent(
                r"^\s*telnet-server",
                r"^\s*telnet server enable",
                ok="Telnet server is not enabled.",
                bad="A telnet server is enabled on this switch.",
            ),
            remediation="Disable the telnet server and use SSH.",
        ),
        Rule(
            id="NA-021", title="HTTPS is used for web management",
            severity="medium", families=ARUBA,
            check=_absent(
                r"^\s*web-management plaintext",
                ok="Plaintext web management is not enabled.",
                bad="Plaintext web management is enabled.",
            ),
            remediation="Use 'web-management ssl' and disable plaintext.",
        ),
        # -- Fortinet ------------------------------------------------------
        Rule(
            id="NA-030", title="Management interfaces do not allow telnet or HTTP",
            severity="critical", families=FORTINET,
            check=_absent(
                r"set allowaccess .*\btelnet\b",
                r"set allowaccess .*\bhttp\b(?!s)",
                ok="No interface allows telnet or cleartext HTTP.",
                bad="An interface permits telnet or HTTP administrative access.",
            ),
            remediation="Restrict allowaccess to ssh, https and ping.",
        ),
        Rule(
            id="NA-031", title="Admin idle timeout is configured",
            severity="medium", families=FORTINET,
            check=_present(
                r"set admintimeout \d+",
                ok="An admin idle timeout is set.",
                bad="No 'set admintimeout' found; admin sessions may not expire.",
            ),
            remediation="Set 'config system global' -> 'set admintimeout 10'.",
        ),
        # -- Vendor-neutral --------------------------------------------------
        Rule(
            id="NA-100", title="No default SNMP community strings",
            severity="critical",
            check=_weak_snmp,
            remediation="Replace default communities, or move to SNMPv3 with auth and privacy.",
        ),
        Rule(
            id="NA-101", title="A time source is configured",
            severity="medium",
            check=_time_source,
            remediation="Configure at least two NTP servers.",
        ),
        Rule(
            id="NA-102", title="Logs are sent off the device",
            severity="high",
            check=_remote_logging,
            remediation="Send logs to a collector that the device itself cannot rewrite.",
        ),
    ),
)
