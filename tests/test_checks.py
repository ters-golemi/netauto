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
