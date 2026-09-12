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


NO_NTP = """\
config system global
    set hostname "x"
end
"""


def test_na101_fails_when_no_ntp():
    findings = _by_id(run_ruleset(BUILTIN, "fsw", "fortinet", NO_NTP, {}))
    assert findings["NA-101"].failed
