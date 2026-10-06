"""Every vendor rule, fired in both directions.

A rule that cannot fail and a rule that cannot pass are equally useless, and
both look healthy from the outside -- the workflow runs, the report renders,
and the column is uniformly green or uniformly red. Two of these shipped
broken: NA-206 and NA-231 matched across lines while match_any searches one
line at a time, so they failed on every configuration including correct ones.

So each rule gets a configuration it should accept and one it should reject.
"""

from __future__ import annotations

import json

import pytest

from netauto.checks.vendor import EXTRA, REFERENCES, VENDOR
from netauto.checks import BUILTIN

RULES = {r.id: r for r in VENDOR.rules}

# (rule id, config that satisfies it, config that violates it)
CASES: list[tuple[str, str, str]] = [
    (
        "NA-200",
        "aaa new-model\naaa authentication login default group tacacs+ local\n",
        "hostname sw1\nusername admin privilege 15 secret 5 $1$x\n",
    ),
    (
        "NA-201",
        "hostname sw1\nno ip source-route\n",
        "service pad\nip source-route\n",
    ),
    (
        "NA-202",
        "banner login ^Authorised users only^\n",
        "hostname sw1\n",
    ),
    (
        "NA-203",
        "line vty 0 4\n access-class MGMT in\n transport input ssh\n",
        "line vty 0 4\n transport input ssh\n",
    ),
    (
        "NA-204",
        "spanning-tree portfast bpduguard default\n",
        "spanning-tree mode rapid-pvst\n",
    ),
    (
        "NA-205",
        "service timestamps log datetime msec localtime show-timezone\n",
        "service timestamps debug datetime\n",
    ),
    (
        "NA-206",
        "line aux 0\n no exec\n transport input none\n",
        "line aux 0\n exec-timeout 0 0\n",
    ),
    (
        "NA-210",
        "set system services ssh protocol-version v2\n",
        "set system services web-management http interface ge-0/0/0.0\n",
    ),
    (
        "NA-211",
        'set system login message "Authorised users only"\n',
        "set system host-name r1\n",
    ),
    (
        "NA-212",
        "set system login class ops idle-timeout 15\n",
        "set system login class ops permissions view\n",
    ),
    (
        "NA-220",
        "cli-session timeout 10\n",
        "hostname aruba-1\n",
    ),
    (
        "NA-221",
        "spanning-tree\nspanning-tree priority 4\n",
        "hostname aruba-1\nvlan 10\n",
    ),
    (
        "NA-230",
        "config system admin\n edit admin\n  set trusthost1 10.0.0.0 255.255.255.0\n",
        "config system admin\n edit admin\n  set accprofile super_admin\n",
    ),
    (
        "NA-231",
        "config log fortianalyzer setting\n    set status enable\n    set server 10.0.0.5\nend\n",
        "config log fortianalyzer setting\n    set status disable\nend\n",
    ),
    (
        "NA-110",
        "snmp-server community s3cret RO\n",
        "snmp-server community private rw\n",
    ),
]


# -- ACI, whose configuration is a policy tree -----------------------------
#
# The ACI rules read managed objects, not lines, so their cases are policy
# exports rather than config snippets. _mit() builds the nesting the real
# export has -- imdata, polUni, children -- because a rule that only worked
# on a flat object list would pass here and find nothing on a real fabric.


def _mit(*objects: dict) -> str:
    """A policy export carrying these managed objects under polUni."""
    return json.dumps({"imdata": [{"polUni": {
        "attributes": {"dn": "uni"},
        "children": list(objects),
    }}]})


def _mo(cls: str, **attributes: object) -> dict:
    return {cls: {"attributes": {k: str(v) for k, v in attributes.items()}}}


ACI_CASES: list[tuple[str, str, str]] = [
    ("NA-040",
     _mit(_mo("commTelnet", adminSt="disabled")),
     _mit(_mo("commTelnet", adminSt="enabled"))),
    ("NA-041",
     _mit(_mo("commHttp", adminSt="disabled")),
     _mit(_mo("commHttp", adminSt="enabled"))),
    ("NA-042",
     _mit(_mo("aaaUserEp", pwdStrengthCheck="yes")),
     _mit(_mo("aaaUserEp", pwdStrengthCheck="no"))),
    ("NA-043",
     _mit(_mo("aaaTacacsPlusProvider", name="10.1.1.9")),
     _mit(_mo("aaaUserEp", pwdStrengthCheck="yes"))),
    ("NA-044",
     _mit(_mo("fvCtx", name="prod", pcEnfPref="enforced")),
     _mit(_mo("fvCtx", name="lab", pcEnfPref="unenforced"))),
    ("NA-045",
     _mit(_mo("coopPol", name="default", type="strict")),
     _mit(_mo("coopPol", name="default", type="compatible"))),
    ("NA-046",
     _mit(_mo("infraSetPol", enforceSubnetCheck="yes")),
     _mit(_mo("infraSetPol", enforceSubnetCheck="no"))),
    ("NA-047",
     _mit(_mo("aaaPreLoginBanner", message="Authorised users only")),
     _mit(_mo("aaaPreLoginBanner", message=""))),
    ("NA-048",
     _mit(_mo("commHttps", sslProtocols="TLSv1.2,TLSv1.3")),
     _mit(_mo("commHttps", sslProtocols="TLSv1,TLSv1.1,TLSv1.2"))),
    ("NA-049",
     _mit(_mo("pkiWebTokenData", webtokenTimeoutSeconds="600")),
     _mit(_mo("pkiWebTokenData", webtokenTimeoutSeconds="7200"))),
    # The three vendor-neutral rules, in ACI's spelling rather than a line.
    ("NA-100",
     _mit(_mo("snmpCommunityP", name="s3cret-ro")),
     _mit(_mo("snmpCommunityP", name="public"))),
    ("NA-101",
     _mit(_mo("datetimeNtpProv", name="10.1.1.1")),
     _mit(_mo("fvTenant", name="Production"))),
    ("NA-102",
     _mit(_mo("syslogRemoteDest", host="10.1.1.2", adminState="enabled")),
     _mit(_mo("syslogRemoteDest", host="10.1.1.2", adminState="disabled"))),
]

CASES += ACI_CASES


# -- the cloud tenants, whose configuration is an exported posture ---------
#
# Same idea as the ACI cases: the fixture is the shape the driver builds, so a
# rule reading a field the export does not actually carry fails here rather
# than silently skipping forever against a real tenant.


def _org(**sections: object) -> str:
    """A Meraki organization export carrying these posture sections."""
    return json.dumps({"networks": [], "devices": [], **sections})


def _tenant(**sections: object) -> str:
    """A Central tenant export carrying these sections."""
    return json.dumps({"devices": [], **sections})


TENANT_CASES: list[tuple[str, str, str]] = [
    ("NA-050",
     _org(loginSecurity={"enforceTwoFactorAuth": True}),
     _org(loginSecurity={"enforceTwoFactorAuth": False})),
    ("NA-051",
     _org(loginSecurity={"enforceIdleTimeout": True, "idleTimeoutMinutes": 30}),
     _org(loginSecurity={"enforceIdleTimeout": False, "idleTimeoutMinutes": 30})),
    ("NA-052",
     _org(loginSecurity={"enforceAccountLockout": True, "accountLockoutAttempts": 5}),
     _org(loginSecurity={"enforceAccountLockout": True, "accountLockoutAttempts": 99})),
    ("NA-053",
     _org(snmp={"v2cEnabled": False, "v3Enabled": True}),
     _org(snmp={"v2cEnabled": True})),
    ("NA-054",
     _org(loginSecurity={"apiAuthentication":
                         {"ipRestrictionsForKeys": {"enabled": True}}}),
     _org(loginSecurity={"apiAuthentication":
                         {"ipRestrictionsForKeys": {"enabled": False}}})),
    ("NA-055",
     _org(admins=[{"name": "Ops", "email": "ops@example.net",
                   "orgAccess": "full", "twoFactorAuthEnabled": True}]),
     _org(admins=[{"name": "Ops", "email": "ops@example.net",
                   "orgAccess": "full", "twoFactorAuthEnabled": False}])),
    ("NA-060",
     _tenant(auditLog={"reachable": True, "total": 4210}),
     _tenant(auditLog={"reachable": True, "total": 0})),
    ("NA-061",
     _tenant(users={"users": [{"username": "ops",
                               "applications": [{"name": "nms",
                                                 "role": "read_only"}]}]}),
     _tenant(users={"users": [{"username": "ops",
                               "applications": [{"name": "nms",
                                                 "role": "admin"}]}]})),
    ("NA-062",
     _tenant(devices=[{"serial": "CN0001", "group_name": "branch-sites"}]),
     _tenant(devices=[{"serial": "CN0001", "group_name": ""}])),
]

CASES += TENANT_CASES


def test_every_new_rule_has_a_case():
    """A rule added without a case here is a rule nobody has fired."""
    covered = {rule_id for rule_id, _, _ in CASES}
    missing = {r.id for r in EXTRA} - covered
    assert not missing, f"vendor rules with no test case: {sorted(missing)}"


#: Families whose rules read a structured export rather than config text.
STRUCTURED = ("aci", "meraki", "arubacentral")


@pytest.mark.parametrize("family", STRUCTURED)
def test_every_structured_export_rule_has_a_case(family):
    """The same bar for the families with no text config to eyeball.

    A rule over a structured export is easier to get silently wrong than a
    line match: a mistyped class name or field finds nothing, which looks
    exactly like a compliant fabric or a well-run tenant. Both directions are
    the only thing that tells them apart.
    """
    covered = {rule_id for rule_id, _, _ in CASES}
    rules = {r.id for r in VENDOR.rules if r.applies_to(family)}
    assert rules, f"no rules apply to the {family} family"
    assert not rules - covered, (
        f"{family} rules with no test case: {sorted(rules - covered)}"
    )


@pytest.mark.parametrize("rule_id,good,bad", TENANT_CASES + ACI_CASES)
def test_a_structured_rule_never_skips_on_a_payload_it_understands(rule_id, good, bad):
    """Skip is for a control that could not be read, not one that was.

    A rule whose field name is wrong skips on both fixtures and would still
    satisfy the accept/reject tests above if those only checked truthiness.
    This pins the third status down: given a payload carrying the field, the
    verdict must be a real one.
    """
    for config, expected in ((good, True), (bad, False)):
        passed, detail, _ = RULES[rule_id].check(config, {})
        assert passed is not None, (
            f"{rule_id} could not read a payload built for it, which means the "
            f"field it looks for is not the one the fixture carries: {detail}"
        )
        assert passed is expected, f"{rule_id}: {detail}"


@pytest.mark.parametrize("rule_id,good,_bad", [(r, g, b) for r, g, b in CASES])
def test_rule_accepts_a_compliant_config(rule_id, good, _bad):
    passed, detail, _evidence = RULES[rule_id].check(good, {})
    assert passed, (
        f"{rule_id} ({RULES[rule_id].title}) rejected a configuration that "
        f"satisfies it: {detail}"
    )


@pytest.mark.parametrize("rule_id,_good,bad", [(r, g, b) for r, g, b in CASES])
def test_rule_rejects_a_violating_config(rule_id, _good, bad):
    passed, detail, _evidence = RULES[rule_id].check(bad, {})
    assert not passed, (
        f"{rule_id} ({RULES[rule_id].title}) accepted a configuration that "
        f"violates it: {detail}"
    )


def test_a_failing_rule_says_what_to_do_about_it():
    """A finding with no remediation is a complaint, not a recommendation."""
    for rule in VENDOR.rules:
        assert rule.remediation, f"{rule.id} has no remediation text"


def test_every_rule_cites_a_source():
    for rule in VENDOR.rules:
        assert rule.reference, f"{rule.id} cites no configuration guide"


def test_builtin_citations_track_builtin_rules():
    """REFERENCES is keyed by rule id, so a renumbering must fail loudly."""
    assert {r.id for r in BUILTIN.rules} == set(REFERENCES), (
        "checks/vendor.py REFERENCES has drifted from checks/builtin.py"
    )


def test_the_audit_page_ruleset_is_left_alone():
    """Workflows opt into the larger set; BUILTIN must not grow underneath it.

    The Prometheus metrics and their alerts are keyed on the built-in rules.
    Adding guidance for the workflows must not silently change what the Audit
    page reports or move a dashboard.
    """
    assert len(VENDOR.rules) > len(BUILTIN.rules)
    assert {r.id for r in BUILTIN.rules} < {r.id for r in VENDOR.rules}
