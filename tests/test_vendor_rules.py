"""Every vendor rule, fired in both directions.

A rule that cannot fail and a rule that cannot pass are equally useless, and
both look healthy from the outside -- the workflow runs, the report renders,
and the column is uniformly green or uniformly red. Two of these shipped
broken: NA-206 and NA-231 matched across lines while match_any searches one
line at a time, so they failed on every configuration including correct ones.

So each rule gets a configuration it should accept and one it should reject.
"""

from __future__ import annotations

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


def test_every_new_rule_has_a_case():
    """A rule added without a case here is a rule nobody has fired."""
    covered = {rule_id for rule_id, _, _ in CASES}
    missing = {r.id for r in EXTRA} - covered
    assert not missing, f"vendor rules with no test case: {sorted(missing)}"


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
