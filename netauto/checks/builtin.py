"""Built-in hardening rules.

Each rule is scoped to the platform families whose syntax it understands, so a
Junos config is never judged by IOS patterns. Rules are intentionally small and
readable: the point is that an operator can audit the auditor.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache

from netauto.checks.engine import Rule, Ruleset, match_any

CISCO = frozenset({"cisco"})
JUNIPER = frozenset({"juniper"})
ARUBA = frozenset({"aruba"})
FORTINET = frozenset({"fortinet"})
ACI = frozenset({"aci"})
MERAKI = frozenset({"meraki"})
CENTRAL = frozenset({"arubacentral"})

#: Families the three vendor-neutral rules at the end can reach a verdict on.
#: Every text-config family, plus ACI now that they know how to find NTP,
#: syslog and SNMP in a policy export.
#:
#: The tenants and the cluster are absent on purpose. These three rules read
#: a time source, a log destination and a community string out of text, and no
#: tenant export states them that way -- each was reported as failing all
#: three on exactly that non-evidence before they were scoped out. Meraki and
#: Central have their own rules over their own posture instead, which is where
#: their equivalent of SNMP and session policy is actually judged.
TEXT_CONFIG_FAMILIES = frozenset({
    "cisco", "juniper", "aruba", "fortinet", "paloalto", "generic", "aci",
})

#: Why a family has no rules, shown where a report would otherwise print an
#: empty findings table.
#:
#: The empty table is the whole reason this exists. A reader takes no rows as
#: "nothing to report", which is the opposite of what it means: nothing was
#: judged. The same trap as a documented grep that matches no line and reads
#: as "no commands were run".
#:
#: Not a permanent gap. Meraki and Central left this table by having their
#: drivers fetch the posture their APIs do expose, which is what the rules
#: above read. Nexus Dashboard would leave it the same way -- by reading the
#: cluster's own NTP and remote logging -- which is a driver change first,
#: since neither endpoint is fetched today.
NO_RULES_REASON: dict[str, str] = {
    "nexusdashboard": (
        "A Nexus Dashboard entry is a cluster, and its configuration export "
        "is the sites onboarded to it. It is a management platform rather "
        "than a network device and carries none of these settings, so none of "
        "the rules is applied. To audit a fabric, add an entry for its own "
        "controller -- cisco_aci for an ACI site."
    ),
}


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


# -- ACI: rules over a policy tree rather than lines ------------------------
#
# ACI has no text configuration. get_config returns the policy universe as
# JSON, so a line search finds nothing and every text rule fails on an absence
# it never measured. These rules read the managed objects instead.
#
# Two conventions, matching _absent and _present above so the whole ruleset
# reads the same way:
#
#   * a control that must be OFF passes when no object says it is on, so an
#     object missing from the export is not held against the fabric;
#   * a control that must be ON fails when nothing says it is, because an
#     export made with rsp-prop-include=config-only omits properties left at
#     their default -- a missing object means "not configured here", which for
#     a security control is the thing worth reporting.


@lru_cache(maxsize=4)
def _aci_index(config: str) -> dict[str, tuple[dict, ...]]:
    """Index an APIC policy export by managed-object class.

    The export nests arbitrarily deep -- polUni carries tenants, which carry
    VRFs, which carry more -- so every rule would otherwise walk the whole
    tree itself. Cached because a dozen rules are handed the same text in one
    audit and parsing a large fabric's export repeatedly is the only part of
    this file that would cost anything. Callers read and never mutate.

    Returns {} for anything that is not an APIC export, which is what makes
    these rules safe to leave in a ruleset that also sees text configs.
    """
    try:
        doc = json.loads(config)
    except (ValueError, TypeError):
        return {}
    found: dict[str, list[dict]] = {}

    def walk(node: object) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if not isinstance(node, dict):
            return
        for cls, body in node.items():
            if cls == "imdata":
                walk(body)
                continue
            if not isinstance(body, dict):
                continue
            attrs = body.get("attributes")
            if isinstance(attrs, dict):
                found.setdefault(cls, []).append(attrs)
            walk(body.get("children", []))

    walk(doc)
    return {cls: tuple(mos) for cls, mos in found.items()}


def _aci_evidence(cls: str, attr: str, mos: tuple[dict, ...]) -> tuple[str, ...]:
    """Evidence lines in the same shape the GUI shows for a config line."""
    return tuple(f"{cls}.{attr} = {mo.get(attr)!s}" for mo in mos)


def _aci_not_set_to(cls: str, attr: str, *bad: str, ok: str, bad_detail: str):
    """Rule body: pass unless some <cls> has attr set to one of bad."""
    unwanted = {v.lower() for v in bad}

    def check(config: str, facts: dict) -> tuple[bool, str, tuple[str, ...]]:
        hits = tuple(mo for mo in _aci_index(config).get(cls, ())
                     if str(mo.get(attr, "")).lower() in unwanted)
        if hits:
            return False, bad_detail, _aci_evidence(cls, attr, hits)[:3]
        return True, ok, ()

    return check


def _aci_set_to(cls: str, attr: str, *want: str, ok: str, bad_detail: str):
    """Rule body: pass when some <cls> has attr set to one of want."""
    wanted = {v.lower() for v in want}

    def check(config: str, facts: dict) -> tuple[bool, str, tuple[str, ...]]:
        mos = _aci_index(config).get(cls, ())
        hits = tuple(mo for mo in mos
                     if str(mo.get(attr, "")).lower() in wanted)
        if hits:
            return True, ok, _aci_evidence(cls, attr, hits)[:3]
        return False, bad_detail, _aci_evidence(cls, attr, mos)[:3]

    return check


def _aci_any_of(*classes: str, attr: str = "name", ok: str, bad_detail: str):
    """Rule body: pass when the export carries any object of these classes."""

    def check(config: str, facts: dict) -> tuple[bool, str, tuple[str, ...]]:
        index = _aci_index(config)
        hits: list[str] = []
        for cls in classes:
            for mo in index.get(cls, ()):
                hits.append(f"{cls}.{attr} = {mo.get(attr)!s}")
        return (bool(hits), ok if hits else bad_detail, tuple(hits)[:3])

    return check


def _aci_nonempty(cls: str, attr: str, *, ok: str, bad_detail: str):
    """Rule body: pass when some <cls> carries a non-blank attr.

    Distinct from _aci_set_to because the object existing is not the control:
    ACI ships a banner object whose message is the empty string, and an empty
    banner is the same as no banner.
    """

    def check(config: str, facts: dict) -> tuple[bool, str, tuple[str, ...]]:
        mos = _aci_index(config).get(cls, ())
        hits = tuple(mo for mo in mos if str(mo.get(attr, "")).strip())
        if hits:
            return True, ok, _aci_evidence(cls, attr, hits)[:1]
        return False, bad_detail, ()

    return check


def _aci_tls_versions(config: str, facts: dict) -> tuple[bool, str, tuple[str, ...]]:
    """Reject TLS 1.0 and 1.1 in the APIC's HTTPS policy.

    sslProtocols is a comma-separated list, and the deprecated names are
    prefixes of the current ones -- "TLSv1" sits inside "TLSv1.1" and
    "TLSv1.2" -- so the list is split and compared exactly rather than
    searched, which would flag a compliant TLSv1.2-only fabric.
    """
    policies = _aci_index(config).get("commHttps", ())
    if not policies:
        return (False,
                "No HTTPS policy found, so the offered TLS versions are unknown.",
                ())
    deprecated = {"tlsv1", "tlsv1.1"}
    hits: list[str] = []
    for policy in policies:
        offered = {v.strip().lower() for v in str(policy.get("sslProtocols", "")).split(",")}
        bad = sorted(offered & deprecated)
        if bad:
            hits.append(f"commHttps.sslProtocols = {policy.get('sslProtocols')}")
    if hits:
        return False, "The APIC still offers TLS 1.0 or 1.1 to management clients.", tuple(hits)[:3]
    return True, "Only current TLS versions are offered.", tuple(
        f"commHttps.sslProtocols = {p.get('sslProtocols')}" for p in policies)[:1]


def _aci_session_timeout(config: str, facts: dict) -> tuple[bool, str, tuple[str, ...]]:
    """A bounded GUI/API session lifetime.

    webtokenTimeoutSeconds is how long an idle APIC session survives. The
    ceiling here is an hour, matching the exec-timeout posture the IOS rules
    take rather than ACI's own maximum, which is considerably longer.
    """
    ceiling = 3600
    tokens = _aci_index(config).get("pkiWebTokenData", ())
    if not tokens:
        return False, "No web token policy found; the session lifetime is unknown.", ()
    hits: list[str] = []
    for token in tokens:
        raw = token.get("webtokenTimeoutSeconds")
        try:
            seconds = int(str(raw))
        except (TypeError, ValueError):
            continue
        if seconds > ceiling:
            hits.append(f"pkiWebTokenData.webtokenTimeoutSeconds = {seconds}")
    if hits:
        return (False,
                f"Idle APIC sessions survive longer than {ceiling // 60} minutes.",
                tuple(hits)[:3])
    return True, "The APIC session lifetime is bounded.", tuple(
        f"pkiWebTokenData.webtokenTimeoutSeconds = {t.get('webtokenTimeoutSeconds')}"
        for t in tokens)[:1]


# -- Cloud tenants: rules over an exported posture -------------------------
#
# A Meraki organization and a Central tenant have no configuration in the
# device sense, but they do have a security posture their API will state:
# login policy, SNMP, the admin list, user roles, the audit trail. The drivers
# fetch those alongside the inventory and these rules judge them.
#
# The third verdict matters more here than anywhere else. An API key or token
# carries its owner's access, so a section can be missing because the key
# cannot read it rather than because the setting is off. Every rule below
# returns None in that case, which reports the control as undetermined. The
# alternative was tried by accident and was worse: before the families were
# split, a Central tenant reported "Telnet server is disabled: PASS".


def _dig(body: object, path: str) -> object:
    """Follow a dotted path into nested dicts, or None if it is not there."""
    current = body
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


@lru_cache(maxsize=4)
def _tenant_doc(config: str) -> dict:
    """A tenant export parsed once, shared by every rule in one audit."""
    try:
        doc = json.loads(config)
    except (ValueError, TypeError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _tenant_section(config: str, name: str) -> tuple[object, str]:
    """A named section of a tenant export, and why it is unusable if it is.

    Returns (value, "") when the section is present and was fetched, and
    (None, reason) when it is absent or the driver recorded a fetch error in
    it. That reason becomes the skipped finding's detail, so it has to read as
    an explanation on its own.
    """
    doc = _tenant_doc(config)
    if name not in doc:
        return None, f"the export carries no {name!r} section, so this was not checked."
    value = doc[name]
    if isinstance(value, dict) and value.get("_error"):
        return None, (f"{name} could not be read, so this was not checked: "
                      f"{value['_error']}")
    return value, ""


def _flag(section: str, path: str, *, ok: str, bad_detail: str, want: bool = True):
    """Rule body: a boolean setting at a dotted path inside a section."""

    def check(config: str, facts: dict) -> tuple[bool | None, str, tuple[str, ...]]:
        body, why = _tenant_section(config, section)
        if why:
            return None, why, ()
        value = _dig(body, path)
        if value is None:
            return None, (f"{section}.{path} is not in the export, so this was "
                          f"not checked."), ()
        evidence = (f"{section}.{path} = {value!s}",)
        return (bool(value) is want, ok if bool(value) is want else bad_detail,
                evidence)

    return check


def _enforced_limit(section: str, flag: str, value_key: str, ceiling: int, *,
                    unit: str, ok: str, off_detail: str, loose_detail: str):
    """Rule body: a limit that must be switched on and within a ceiling.

    Two settings make one control -- Meraki states the enforcement and the
    number separately, and an enforced timeout of a fortnight is not a
    timeout. Checking only the flag would pass it.
    """

    def check(config: str, facts: dict) -> tuple[bool | None, str, tuple[str, ...]]:
        body, why = _tenant_section(config, section)
        if why:
            return None, why, ()
        enabled = _dig(body, flag)
        if enabled is None:
            return None, f"{section}.{flag} is not in the export, so this was not checked.", ()
        if not enabled:
            return False, off_detail, (f"{section}.{flag} = {enabled!s}",)
        raw = _dig(body, value_key)
        try:
            number = int(str(raw))
        except (TypeError, ValueError):
            return None, (f"{section}.{flag} is on but {value_key} is "
                          f"{raw!r}, which is not a number."), ()
        evidence = (f"{section}.{value_key} = {number} {unit}",)
        if number > ceiling:
            return False, loose_detail.format(number=number, ceiling=ceiling), evidence
        return True, ok, evidence

    return check


def _meraki_admin_two_factor(config: str, facts: dict) -> tuple[bool | None, str, tuple[str, ...]]:
    """Every administrator with full organization access must carry 2FA.

    Distinct from the organization-wide enforcement rule: enforcement can be
    off while some admins have it anyway, and it can be on while an admin
    added before it was switched on still does not. This reads the roster.
    """
    body, why = _tenant_section(config, "admins")
    if why:
        return None, why, ()
    if not isinstance(body, list):
        return None, "the admins section is not a list, so this was not checked.", ()
    if not body:
        return None, "the organization lists no administrators.", ()
    exposed = tuple(
        f"{a.get('name') or a.get('email') or '?'} ({a.get('email', 'no email')})"
        for a in body
        if isinstance(a, dict)
        and str(a.get("orgAccess", "")).lower() == "full"
        and not a.get("twoFactorAuthEnabled")
    )
    if exposed:
        return (False,
                "An administrator with full organization access has no second "
                "factor; that account alone can change every network.",
                exposed[:3])
    full = [a for a in body if isinstance(a, dict)
            and str(a.get("orgAccess", "")).lower() == "full"]
    if not full:
        return None, "no administrator holds full organization access.", ()
    return True, "Every full-access administrator has two-factor enabled.", (
        f"{len(full)} full-access admins, all with 2FA",)


def _central_audit_trail(config: str, facts: dict) -> tuple[bool | None, str, tuple[str, ...]]:
    """The trail must answer and actually hold events.

    Reachability alone cannot fail -- the driver records an unreachable trail
    as a fetch error, which is a skip, so a rule testing only that would be
    one of the two useless kinds this ruleset's tests exist to catch. An
    empty trail is the failure worth reporting: it means nothing is being
    retained, so no administrative action in the tenant can be reviewed.
    """
    body, why = _tenant_section(config, "auditLog")
    if why:
        return None, why, ()
    if not isinstance(body, dict):
        return None, "the auditLog section is not an object, so this was not checked.", ()
    count = body.get("total")
    if count is None:
        count = body.get("event_count")
    try:
        events = int(str(count))
    except (TypeError, ValueError):
        return None, (
            "the audit trail answered but reported no event count, so "
            "retention was not checked."
        ), ()
    evidence = (f"auditLog.total = {events}",)
    if events <= 0:
        return (False,
                "The audit trail is empty, so administrative actions in this "
                "tenant cannot be reviewed after the fact.",
                evidence)
    return True, "The tenant's audit trail answers and holds events.", evidence


def _central_users(config: str) -> tuple[list | None, str]:
    body, why = _tenant_section(config, "users")
    if why:
        return None, why
    rows = body.get("users") if isinstance(body, dict) else body
    if not isinstance(rows, list):
        return None, "the users section is not a list, so this was not checked."
    if not rows:
        return None, "the tenant lists no users."
    return [r for r in rows if isinstance(r, dict)], ""


def _central_roles(user: dict) -> list[str]:
    """Role names out of a Central user record, whatever shape it uses.

    Central has moved this between releases and between the cloud and the
    on-premises build, so several spellings are tried and an unrecognised
    record contributes nothing rather than a guess. A rule that found no
    roles at all reports itself undetermined instead of clearing the tenant.
    """
    roles: list[str] = []
    applications = user.get("applications")
    if isinstance(applications, list):
        for app in applications:
            if not isinstance(app, dict):
                continue
            role = app.get("role") or _dig(app, "info.role")
            if isinstance(role, str) and role:
                roles.append(role)
    for key in ("role", "roles"):
        value = user.get(key)
        if isinstance(value, str) and value:
            roles.append(value)
        elif isinstance(value, list):
            roles.extend(v for v in value if isinstance(v, str) and v)
    return roles


#: Role names that grant unrestricted administrative access in Central.
_CENTRAL_SUPERUSER = {"admin", "administrator", "super admin", "superadmin",
                      "global administrator", "account admin"}


def _central_admin_scope(config: str, facts: dict) -> tuple[bool | None, str, tuple[str, ...]]:
    """Least privilege: unrestricted admin should be the exception."""
    users, why = _central_users(config)
    if why:
        return None, why, ()
    recognised = 0
    unrestricted: list[str] = []
    for user in users:
        roles = _central_roles(user)
        if not roles:
            continue
        recognised += 1
        name = (user.get("username") or user.get("user_name")
                or user.get("email") or "unnamed user")
        if any(r.strip().lower() in _CENTRAL_SUPERUSER for r in roles):
            unrestricted.append(f"{name} = {', '.join(sorted(set(roles)))}")
    if not recognised:
        return None, (
            "no role information in the user records this Central release "
            "returns, so administrative scope was not checked."
        ), ()
    if unrestricted:
        return (False,
                f"{len(unrestricted)} of {recognised} users hold unrestricted "
                f"administrative access to the tenant.",
                tuple(unrestricted)[:3])
    return True, "No user holds unrestricted administrative access.", (
        f"{recognised} users, all scoped",)


def _central_device_groups(config: str, facts: dict) -> tuple[bool | None, str, tuple[str, ...]]:
    """A device in no group inherits no configuration policy."""
    body, why = _tenant_section(config, "devices")
    if why:
        return None, why, ()
    rows = body.get("devices") if isinstance(body, dict) else body
    if not isinstance(rows, list) or not rows:
        return None, "the tenant inventory is empty, so this was not checked.", ()
    seen = 0
    orphans: list[str] = []
    for device in rows:
        if not isinstance(device, dict):
            continue
        if "group_name" not in device and "group" not in device:
            continue
        seen += 1
        group = device.get("group_name") or device.get("group")
        if not str(group or "").strip():
            orphans.append(str(device.get("serial") or device.get("macaddr") or "?"))
    if not seen:
        return None, (
            "the inventory records carry no group field in this Central "
            "release, so group assignment was not checked."
        ), ()
    if orphans:
        return (False,
                f"{len(orphans)} of {seen} devices are in no group, so they "
                f"inherit no configuration policy from Central.",
                tuple(orphans)[:3])
    return True, "Every managed device is assigned to a group.", (
        f"{seen} devices, all grouped",)


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
    # ACI states it as policy: datetimeNtpProv providers under a datetimePol.
    providers = _aci_index(config).get("datetimeNtpProv", ())
    if providers:
        return True, "An NTP or SNTP server is configured.", tuple(
            f"datetimeNtpProv.name = {p.get('name')}" for p in providers)[:3]
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
    # ACI states it as policy. A syslogRemoteDest carries its own admin state
    # and a disabled destination still appears in the export, so the host and
    # the enable are read together -- the same trap as the FortiOS stanza.
    enabled = tuple(
        d for d in _aci_index(config).get("syslogRemoteDest", ())
        if str(d.get("adminState", "")).lower() == "enabled"
    )
    if enabled:
        return True, "A remote log destination is configured.", tuple(
            f"syslogRemoteDest.host = {d.get('host')}" for d in enabled)[:3]
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
    # ACI carries the community as an object name, which the line pattern
    # above cannot see: "snmpCommunityP" matches the word "community" but is
    # never followed by the string on the same line.
    defaults = {"public", "private", "cisco", "admin", "default"}
    aci_hits = tuple(
        f"snmpCommunityP.name = {c.get('name')}"
        for c in _aci_index(config).get("snmpCommunityP", ())
        if str(c.get("name", "")).lower() in defaults
    )
    if aci_hits:
        return False, "Default SNMP community string in use.", aci_hits
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
        # -- Cisco ACI -----------------------------------------------------
        #
        # A fabric, not a switch: these read the policy model. Every one is
        # scoped to the aci family, so adding them cannot change a verdict on
        # any other platform.
        Rule(
            id="NA-040", title="Telnet is disabled on the APIC",
            severity="critical", families=ACI,
            check=_aci_not_set_to(
                "commTelnet", "adminSt", "enabled",
                ok="Telnet is not enabled in the management access policy.",
                bad_detail="Telnet is enabled on the APIC; credentials cross the "
                           "wire in clear text.",
            ),
            remediation="Set Telnet to disabled under Fabric > Fabric Policies > "
                        "Pod Policies > Management Access.",
        ),
        Rule(
            id="NA-041", title="Cleartext HTTP access to the APIC is disabled",
            severity="high", families=ACI,
            check=_aci_not_set_to(
                "commHttp", "adminSt", "enabled",
                ok="HTTP access is not enabled; the GUI and API are HTTPS only.",
                bad_detail="HTTP is enabled on the APIC, so GUI and API traffic "
                           "-- including the login -- can cross the wire unencrypted.",
            ),
            remediation="Disable HTTP and keep HTTPS in the management access "
                        "policy. Redirect rather than serve both.",
        ),
        Rule(
            id="NA-042", title="Local password strength is enforced",
            severity="medium", families=ACI,
            check=_aci_set_to(
                "aaaUserEp", "pwdStrengthCheck", "yes",
                ok="Password strength checking is on for local users.",
                bad_detail="Password strength checking is not enabled, so local "
                           "APIC accounts may carry trivial passwords.",
            ),
            remediation="Enable the password strength check under Admin > AAA > "
                        "Security > User Management.",
        ),
        Rule(
            id="NA-043", title="Remote authentication is configured",
            severity="medium", families=ACI,
            check=_aci_any_of(
                "aaaTacacsPlusProvider", "aaaRadiusProvider", "aaaLdapProvider",
                ok="A remote authentication provider is configured.",
                bad_detail="No TACACS+, RADIUS or LDAP provider is configured, so "
                           "fabric access depends entirely on local APIC accounts.",
            ),
            remediation="Add a TACACS+ or RADIUS provider and a login domain, "
                        "keeping local accounts as the fallback only.",
        ),
        Rule(
            id="NA-044", title="VRFs enforce contracts",
            severity="high", families=ACI,
            check=_aci_not_set_to(
                "fvCtx", "pcEnfPref", "unenforced",
                ok="Every VRF in the export enforces contracts.",
                bad_detail="A VRF is set to unenforced, which permits all traffic "
                           "between its endpoint groups regardless of contracts -- "
                           "the segmentation ACI is deployed for is off in that VRF.",
            ),
            remediation="Set the VRF's policy control enforcement to enforced and "
                        "add the contracts the traffic actually needs.",
        ),
        Rule(
            id="NA-045", title="COOP authenticates fabric control messages",
            severity="medium", families=ACI,
            check=_aci_set_to(
                "coopPol", "type", "strict",
                ok="COOP is in strict mode, so spine control messages are authenticated.",
                bad_detail="COOP is in compatible mode, which accepts unauthenticated "
                           "endpoint updates between spines.",
            ),
            remediation="Set the COOP group policy to strict once every switch runs "
                        "a release that supports it.",
        ),
        Rule(
            id="NA-046", title="Subnet checking is enforced fabric-wide",
            severity="medium", families=ACI,
            check=_aci_set_to(
                "infraSetPol", "enforceSubnetCheck", "yes",
                ok="Subnet checking is enforced fabric-wide.",
                bad_detail="Enforce Subnet Check is off, so the fabric will learn "
                           "endpoints from outside a bridge domain's own subnets.",
            ),
            remediation="Enable Enforce Subnet Check under System > System Settings "
                        "> Fabric Wide Setting.",
        ),
        Rule(
            id="NA-047", title="A pre-login banner is presented",
            severity="low", families=ACI,
            check=_aci_nonempty(
                "aaaPreLoginBanner", "message",
                ok="A pre-login banner is configured.",
                bad_detail="No pre-login banner; the APIC offers no notice before "
                           "authentication.",
            ),
            remediation="Set an application-specific pre-login banner under "
                        "System > System Settings > APIC Connectivity Preferences.",
        ),
        Rule(
            id="NA-048", title="Deprecated TLS versions are not offered",
            severity="high", families=ACI,
            check=_aci_tls_versions,
            remediation="Restrict the HTTPS policy to TLSv1.2 and later, then "
                        "confirm no management client still needs the old versions.",
        ),
        Rule(
            id="NA-049", title="APIC sessions time out",
            severity="medium", families=ACI,
            check=_aci_session_timeout,
            remediation="Lower the web token timeout so an idle GUI or API session "
                        "expires within the hour.",
        ),
        # -- Cisco Meraki --------------------------------------------------
        #
        # The organization's own security posture, not its networks'. Each
        # reports undetermined rather than failing when the API key could not
        # read the section it needs.
        Rule(
            id="NA-050", title="Two-factor authentication is enforced",
            severity="critical", families=MERAKI,
            check=_flag(
                "loginSecurity", "enforceTwoFactorAuth",
                ok="Two-factor authentication is required of every dashboard admin.",
                bad_detail="Two-factor authentication is not enforced; a leaked "
                           "password is enough to reach every network in the org.",
            ),
            remediation="Enable two-factor authentication under Organization > "
                        "Settings > Authentication, or front the dashboard with SSO.",
        ),
        Rule(
            id="NA-051", title="Dashboard sessions time out",
            severity="medium", families=MERAKI,
            check=_enforced_limit(
                "loginSecurity", "enforceIdleTimeout", "idleTimeoutMinutes", 60,
                unit="minutes",
                ok="Idle dashboard sessions expire within the hour.",
                off_detail="No idle timeout is enforced, so a dashboard session "
                           "left open stays authenticated indefinitely.",
                loose_detail="The idle timeout is {number} minutes, longer than "
                             "the {ceiling} this rule allows.",
            ),
            remediation="Enforce an idle timeout of 60 minutes or less under "
                        "Organization > Settings > Authentication.",
        ),
        Rule(
            id="NA-052", title="Accounts lock out after failed logins",
            severity="medium", families=MERAKI,
            check=_enforced_limit(
                "loginSecurity", "enforceAccountLockout", "accountLockoutAttempts", 10,
                unit="attempts",
                ok="Accounts lock out after a bounded number of failed attempts.",
                off_detail="No account lockout is enforced, so dashboard passwords "
                           "can be guessed without limit.",
                loose_detail="Lockout allows {number} failed attempts, more than "
                             "the {ceiling} this rule allows.",
            ),
            remediation="Enforce account lockout after 10 attempts or fewer under "
                        "Organization > Settings > Authentication.",
        ),
        Rule(
            id="NA-053", title="SNMP v2c is not enabled",
            severity="high", families=MERAKI,
            check=_flag(
                "snmp", "v2cEnabled", want=False,
                ok="SNMP v2c is off; polling uses v3 or nothing.",
                bad_detail="SNMP v2c is enabled, and its community string is a "
                           "password sent in clear text over the internet.",
            ),
            remediation="Disable v2c and use SNMP v3 with authentication and "
                        "privacy under Organization > Settings.",
        ),
        Rule(
            id="NA-054", title="API keys are restricted by source address",
            severity="medium", families=MERAKI,
            check=_flag(
                "loginSecurity", "apiAuthentication.ipRestrictionsForKeys.enabled",
                ok="API keys are usable only from the listed source addresses.",
                bad_detail="API keys carry full organization access and are not "
                           "restricted by source address, so a leaked key works "
                           "from anywhere on the internet.",
            ),
            remediation="List the addresses your automation calls from under "
                        "Organization > Settings > API & webhooks.",
        ),
        Rule(
            id="NA-055", title="Full-access administrators carry a second factor",
            severity="high", families=MERAKI,
            check=_meraki_admin_two_factor,
            remediation="Require two-factor on every full-access account, or "
                        "reduce the account to the networks it actually needs.",
        ),
        # -- HPE Aruba Central ---------------------------------------------
        #
        # Thinner than Meraki by necessity: Central exposes no single
        # tenant-wide security-settings object, so these read the user roster,
        # the audit trail and the inventory. Each skips rather than guesses
        # when the payload is not the shape it expects, because Central has
        # moved these between releases and between cloud and on-premises.
        Rule(
            id="NA-060", title="The audit trail holds events",
            severity="medium", families=CENTRAL,
            check=_central_audit_trail,
            remediation="Grant the API token the audit-log scope, and export the "
                        "trail to a collector the tenant's own admins cannot edit.",
        ),
        Rule(
            id="NA-061", title="Administrative access is scoped",
            severity="high", families=CENTRAL,
            check=_central_admin_scope,
            remediation="Replace unrestricted admin roles with the narrowest role "
                        "that covers the work, per application and group.",
        ),
        Rule(
            id="NA-062", title="Every managed device is assigned to a group",
            severity="medium", families=CENTRAL,
            check=_central_device_groups,
            remediation="Move unassigned devices into a group so they inherit a "
                        "reviewed configuration rather than none.",
        ),
        # -- Vendor-neutral --------------------------------------------------
        Rule(
            id="NA-100", title="No default SNMP community strings",
            families=TEXT_CONFIG_FAMILIES,
            severity="critical",
            check=_weak_snmp,
            remediation="Replace default communities, or move to SNMPv3 with auth and privacy.",
        ),
        Rule(
            id="NA-101", title="A time source is configured",
            families=TEXT_CONFIG_FAMILIES,
            severity="medium",
            check=_time_source,
            remediation="Configure at least two NTP servers.",
        ),
        Rule(
            id="NA-102", title="Logs are sent off the device",
            families=TEXT_CONFIG_FAMILIES,
            severity="high",
            check=_remote_logging,
            remediation="Send logs to a collector that the device itself cannot rewrite.",
        ),
    ),
)
