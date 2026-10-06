"""Rules run against captured config text, so no device is needed."""

from netauto.checks import BUILTIN, run_ruleset

INSECURE_IOS = """\
hostname old-switch
enable password cisco
snmp-server community public RO
ip http server
line vty 0 4
 transport input telnet ssh
 exec-timeout 0 0
"""

HARDENED_IOS = """\
hostname good-switch
enable secret 9 $9$abcdef
service password-encryption
no ip http server
ip ssh version 2
snmp-server community S3cr3tStr1ng RO
ntp server 10.0.0.1
logging host 10.0.0.50
line vty 0 4
 transport input ssh
 exec-timeout 10 0
"""


def _by_id(findings):
    return {f.rule_id: f for f in findings}


def test_insecure_config_fails_expected_rules():
    findings = _by_id(run_ruleset(BUILTIN, "old-switch", "cisco", INSECURE_IOS, {}))
    assert findings["NA-001"].failed, "telnet on vty should fail"
    assert findings["NA-003"].failed, "ip http server should fail"
    assert findings["NA-100"].failed, "public community should fail"
    assert findings["NA-101"].failed, "no ntp should fail"
    assert findings["NA-102"].failed, "no remote logging should fail"


def test_hardened_config_passes():
    findings = _by_id(run_ruleset(BUILTIN, "good-switch", "cisco", HARDENED_IOS, {}))
    for rule_id in ("NA-001", "NA-002", "NA-003", "NA-004", "NA-005",
                    "NA-006", "NA-100", "NA-101", "NA-102"):
        assert not findings[rule_id].failed, f"{rule_id} should pass: {findings[rule_id].detail}"


def test_rules_are_family_scoped():
    """A Junos config must not be judged by IOS rules."""
    junos = "set system services ssh\nset system ntp server 10.0.0.1\n"
    ids = {f.rule_id for f in run_ruleset(BUILTIN, "rtr", "juniper", junos, {})}
    assert "NA-001" not in ids, "IOS vty rule leaked into a Junos audit"
    assert "NA-010" in ids, "Junos telnet rule should apply"


def test_failing_rule_reports_evidence():
    findings = _by_id(run_ruleset(BUILTIN, "old-switch", "cisco", INSECURE_IOS, {}))
    assert any("public" in e for e in findings["NA-100"].evidence)


# FortiOS/FortiSwitch spell remote logging as a stanza, not a line. Both blocks
# are copied from a real FortiSwitch 108F -- the configured one was reported as
# a false positive by NA-102 before _remote_logging learned the syntax.
FORTI_SYSLOG_ON = """\
config system global
    set hostname "fsw-access-01"
end
config log syslogd setting
    unset override
    set status enable
    set server "10.10.10.20"
    set mode udp
    set port 514
end
"""

FORTI_SYSLOG_OFF = """\
config system global
    set hostname "fsw-access-01"
end
config log syslogd setting
    set status disable
end
"""


def test_na102_detects_fortios_syslog_stanza():
    """A configured FortiOS syslog server must pass NA-102."""
    findings = _by_id(run_ruleset(BUILTIN, "fsw", "fortinet", FORTI_SYSLOG_ON, {}))
    assert not findings["NA-102"].failed, findings["NA-102"].detail
    assert any("10.10.10.20" in e for e in findings["NA-102"].evidence)


def test_na102_still_fails_a_disabled_syslogd_block():
    """The block prints even when disabled; the header alone must not pass."""
    findings = _by_id(run_ruleset(BUILTIN, "fsw", "fortinet", FORTI_SYSLOG_OFF, {}))
    assert findings["NA-102"].failed, "disabled syslogd should not count as remote logging"


# FortiOS/FortiSwitch NTP is a nested stanza, the twin of the syslog case.
# Copied from the FortiSwitch 108F after NTP was configured on it.
FORTI_NTP_ON = """\
config system ntp
    config ntpserver
        edit 1
            set server "216.239.35.0"
        next
        edit 2
            set server "216.239.35.4"
        next
    end
    set ntpsync enable
end
"""


def test_na101_detects_fortios_ntp_stanza():
    findings = _by_id(run_ruleset(BUILTIN, "fsw", "fortinet", FORTI_NTP_ON, {}))
    assert not findings["NA-101"].failed, findings["NA-101"].detail
    assert any("216.239.35.0" in e for e in findings["NA-101"].evidence)


# PAN-OS nests NTP in an ntp-servers block. The existing "ntp ... server"
# line pattern already matches both the block header and the address line, so
# PAN-OS needed no new syntax -- though a header with no address would pass.
PANOS_NTP_ON = """\
deviceconfig {
  system {
    hostname fw-edge-01;
    ntp-servers {
      primary-ntp-server {
        ntp-server-address 216.239.35.0;
      }
    }
  }
}
"""


def test_na101_passes_panos_ntp_block():
    findings = _by_id(run_ruleset(BUILTIN, "fw", "paloalto", PANOS_NTP_ON, {}))
    assert not findings["NA-101"].failed, findings["NA-101"].detail
    assert "ntp-server-address 216.239.35.0;" in findings["NA-101"].evidence


NO_NTP = """\
config system global
    set hostname "x"
end
"""


def test_na101_fails_when_no_ntp():
    findings = _by_id(run_ruleset(BUILTIN, "fsw", "fortinet", NO_NTP, {}))
    assert findings["NA-101"].failed


# -- ACI is not an IOS device ----------------------------------------------
#
# This is a regression test for a real fault, not a hypothetical. When the ACI
# driver landed, cisco_aci fell through platform_family's Cisco branch because
# the string starts with "cisco", so auditing a fabric ran the IOS ruleset
# against a JSON policy export and reported six failures -- among them "An
# enable secret is set" at high severity, for a platform that has no enable
# secret, no exec-timeout and no VTY lines. Every one of those was an absence
# the rule never measured.

import json

from netauto.checks.builtin import TEXT_CONFIG_FAMILIES
from netauto.drivers.base import platform_family

ACI_EXPORT = json.dumps({"imdata": [{"polUni": {
    "attributes": {"dn": "uni"},
    "children": [
        {"commTelnet": {"attributes": {"adminSt": "disabled"}}},
        {"commHttp": {"attributes": {"adminSt": "disabled"}}},
        {"commHttps": {"attributes": {"sslProtocols": "TLSv1.2,TLSv1.3"}}},
        {"aaaUserEp": {"attributes": {"pwdStrengthCheck": "yes"}}},
        {"aaaTacacsPlusProvider": {"attributes": {"name": "10.1.1.9"}}},
        {"aaaPreLoginBanner": {"attributes": {"message": "Authorised users only"}}},
        {"coopPol": {"attributes": {"name": "default", "type": "strict"}}},
        {"infraSetPol": {"attributes": {"enforceSubnetCheck": "yes"}}},
        {"pkiWebTokenData": {"attributes": {"webtokenTimeoutSeconds": "600"}}},
        {"datetimeNtpProv": {"attributes": {"name": "10.1.1.1"}}},
        {"syslogRemoteDest": {"attributes": {"host": "10.1.1.2",
                                             "adminState": "enabled"}}},
        {"snmpCommunityP": {"attributes": {"name": "s3cret-ro"}}},
        {"fvTenant": {"attributes": {"name": "Production"}, "children": [
            {"fvCtx": {"attributes": {"name": "prod-vrf", "pcEnfPref": "enforced"}}},
        ]}},
    ],
}}]})


def test_aci_has_its_own_family():
    assert platform_family("cisco_aci") == "aci"
    assert platform_family("cisco_nexus_dashboard") == "nexusdashboard"
    # The NX-OS platforms are still Cisco: a fabric is not a switch, but a
    # Nexus running NX-OS over either transport genuinely is an IOS-family box.
    assert platform_family("cisco_nxos") == "cisco"
    assert platform_family("cisco_nxos_api") == "cisco"


def test_no_ios_rule_is_aimed_at_an_aci_fabric():
    """The IOS rules must not even run, let alone fail, on a policy export."""
    ios_only = [r for r in BUILTIN.rules if r.families == frozenset({"cisco"})]
    assert ios_only, "expected some Cisco-only rules"
    for rule in ios_only:
        assert not rule.applies_to("aci"), f"{rule.id} still judges ACI"


def test_a_hardened_fabric_passes_every_aci_rule():
    findings = run_ruleset(BUILTIN, "aci-fabric-01", "aci", ACI_EXPORT, {})
    failed = [f for f in findings if f.status != "pass"]
    assert not failed, (
        "a compliant policy export should satisfy every ACI rule, but these "
        f"did not: {[(f.rule_id, f.detail) for f in failed]}"
    )


def test_the_nested_vrf_is_reached_and_not_just_the_top_level():
    """fvCtx sits under fvTenant, so a walker that stopped at the top would
    report a compliant fabric for a VRF it never looked at."""
    export = json.loads(ACI_EXPORT)
    tenant = export["imdata"][0]["polUni"]["children"][-1]
    tenant["fvTenant"]["children"][0]["fvCtx"]["attributes"]["pcEnfPref"] = "unenforced"
    findings = run_ruleset(BUILTIN, "aci", "aci", json.dumps(export), {})
    vrf = next(f for f in findings if f.rule_id == "NA-044")
    assert vrf.status == "fail"
    assert "unenforced" in vrf.evidence[0]


def test_an_empty_export_fails_the_controls_it_cannot_confirm():
    """Absent evidence is not compliance for a control that must be on.

    An export with nothing in it must not read as a hardened fabric. The
    must-be-off rules pass -- nothing says telnet is on -- while every
    must-be-on rule fails, which is the conservative half of the convention.
    """
    findings = run_ruleset(BUILTIN, "aci", "aci", '{"imdata": []}', {})
    by_id = {f.rule_id: f for f in findings}
    assert by_id["NA-040"].status == "pass"          # nothing enables telnet
    assert by_id["NA-042"].status == "fail"          # nothing enforces passwords
    assert by_id["NA-049"].status == "fail"          # no bounded session
    assert by_id["NA-101"].status == "fail"          # no time source


def test_nexus_dashboard_is_judged_by_nothing_it_cannot_answer():
    """ND's config is cluster state and carries no hardening settings at all.

    Before the families were split it was judged as an IOS device and failed
    six rules; the vendor-neutral three then failed it for a time source and
    remote logging its export does not describe either. The honest number of
    rules for it is zero until it has a ruleset of its own.
    """
    nd_cfg = json.dumps({"sites": [{"name": "dc1"}], "nodes": []})
    findings = run_ruleset(BUILTIN, "nd-01", "nexusdashboard", nd_cfg, {})
    assert findings == [], (
        f"Nexus Dashboard was judged by rules it cannot answer: "
        f"{[f.rule_id for f in findings]}"
    )
    assert "nexusdashboard" not in TEXT_CONFIG_FAMILIES


# -- the tenants are not switches ------------------------------------------
#
# Same fault as ACI, two more platforms. aruba_central matched the "aruba"
# test and was judged by AOS-CX switch rules against its device inventory;
# meraki fell through to "generic" and was failed by the vendor-neutral three
# for a time source, a log destination and a community string that an
# inventory export does not describe. Neither was ever measured.

from netauto.checks import NO_RULES_REASON

MERAKI_EXPORT = json.dumps({
    "networks": [{"id": "N_1", "name": "Branch 1", "productTypes": ["appliance"]}],
    "devices": [{"serial": "Q2XX-XXXX-XXXX", "model": "MX67", "name": "branch-1-mx"}],
})

CENTRAL_EXPORT = json.dumps({
    "devices": [{"serial": "CNXXXXXXXX", "macaddr": "00:11:22:33:44:55",
                 "model": "6300M", "type": "SWITCH"}],
    "total": 1,
})


def test_the_tenants_have_their_own_families():
    assert platform_family("meraki") == "meraki"
    assert platform_family("aruba_central") == "arubacentral"
    # The switch platforms that share a vendor name keep theirs.
    assert platform_family("aruba_aoscx") == "aruba"
    assert platform_family("aruba_osswitch") == "aruba"


def test_no_aruba_switch_rule_is_aimed_at_a_central_tenant():
    aruba_only = [r for r in BUILTIN.rules if r.families == frozenset({"aruba"})]
    assert aruba_only, "expected some Aruba-only rules"
    for rule in aruba_only:
        assert not rule.applies_to("arubacentral"), f"{rule.id} still judges Central"


def test_an_inventory_only_export_is_undetermined_not_failed():
    """The tenants have rules now, and an inventory-only export answers none.

    This is the property that keeps the rules honest. An export without the
    posture sections -- an API key that could not read them, an older driver --
    must skip every rule rather than fail it. Failing would be an alarm on
    evidence nobody gathered; passing would be worse.
    """
    for family, config in (("meraki", MERAKI_EXPORT),
                           ("arubacentral", CENTRAL_EXPORT)):
        findings = run_ruleset(BUILTIN, "tenant", family, config, {})
        assert findings, f"{family} should have rules by now"
        assert all(f.status == "skip" for f in findings), (
            f"{family} reached a verdict with no posture to read: "
            f"{[(f.rule_id, f.status) for f in findings]}"
        )
        for f in findings:
            assert f.detail, f"{f.rule_id} skipped without saying why"


def test_a_section_the_key_could_not_read_is_skipped_not_failed():
    """The driver records a fetch error in the section; that is not a verdict.

    A key scoped to one network cannot read organization login security. The
    control is then undetermined, not off -- this is the distinction the
    engine's third status exists for.
    """
    denied = json.dumps({
        "networks": [], "devices": [],
        "loginSecurity": {"_error": "APIError: 403 Forbidden"},
        "snmp": {"_error": "APIError: 403 Forbidden"},
        "admins": {"_error": "APIError: 403 Forbidden"},
    })
    findings = run_ruleset(BUILTIN, "meraki-org", "meraki", denied, {})
    assert findings and all(f.status == "skip" for f in findings)
    assert any("403" in f.detail for f in findings), (
        "the skip should carry the reason the section was unreadable"
    )
    assert not any(f.failed for f in findings)


def test_a_real_posture_export_reaches_real_verdicts():
    """And the opposite: given the posture, the rules do decide."""
    hardened = json.dumps({
        "networks": [], "devices": [],
        "loginSecurity": {
            "enforceTwoFactorAuth": True,
            "enforceIdleTimeout": True, "idleTimeoutMinutes": 30,
            "enforceAccountLockout": True, "accountLockoutAttempts": 5,
            "apiAuthentication": {"ipRestrictionsForKeys": {"enabled": True}},
        },
        "snmp": {"v2cEnabled": False, "v3Enabled": True},
        "admins": [{"name": "Ops", "email": "ops@example.net",
                    "orgAccess": "full", "twoFactorAuthEnabled": True}],
    })
    findings = run_ruleset(BUILTIN, "meraki-org", "meraki", hardened, {})
    assert all(f.status == "pass" for f in findings), (
        f"a hardened org should pass: "
        f"{[(f.rule_id, f.status, f.detail) for f in findings if f.status != 'pass']}"
    )

    sloppy = json.loads(hardened)
    sloppy["loginSecurity"]["enforceTwoFactorAuth"] = False
    sloppy["snmp"]["v2cEnabled"] = True
    sloppy["admins"][0]["twoFactorAuthEnabled"] = False
    by_id = {f.rule_id: f for f in
             run_ruleset(BUILTIN, "org", "meraki", json.dumps(sloppy), {})}
    assert by_id["NA-050"].status == "fail"
    assert by_id["NA-053"].status == "fail"
    assert by_id["NA-055"].status == "fail"
    assert "ops@example.net" in by_id["NA-055"].evidence[0]


def test_every_family_without_rules_explains_itself():
    """A family with no rules must say why, or a report shows an empty table.

    The empty table is the actual danger: no rows reads as a clean bill of
    health. Any family that stops having rules has to arrive here too.
    """
    from netauto.drivers import supported_platforms

    for platform in supported_platforms():
        family = platform_family(platform)
        if run_ruleset(BUILTIN, "x", family, "", {}):
            continue
        assert NO_RULES_REASON.get(family), (
            f"{platform} (family {family!r}) has no rules and no explanation, "
            f"so its audit renders an empty findings table that reads as a pass."
        )


def test_the_reason_reaches_the_report_only_when_there_is_nothing_to_show():
    """audit_device carries the reason, and drops it when rules did run."""
    from netauto.audit import audit_device
    from netauto.config import Settings
    from netauto.inventory import Device

    class _Driver:
        def __init__(self, config): self.config = config
        def __enter__(self): return self
        def __exit__(self, *exc): return None
        def facts(self): return {"name": "x"}
        def get_config(self, kind="running"): return self.config

    import netauto.audit as audit_mod

    original = audit_mod.connect
    try:
        audit_mod.connect = lambda dev, settings: _Driver('{"sites": []}')
        report = audit_device(Device(name="nd", platform="cisco_nexus_dashboard"),
                              Settings(inventory_path="unused"))
        assert report["findings"] == []
        assert "cluster" in report["no_rules_reason"]

        audit_mod.connect = lambda dev, settings: _Driver(ACI_EXPORT)
        report = audit_device(Device(name="fab", platform="cisco_aci"),
                              Settings(inventory_path="unused"))
        assert report["findings"], "ACI should have been judged"
        assert report["no_rules_reason"] == ""
    finally:
        audit_mod.connect = original
