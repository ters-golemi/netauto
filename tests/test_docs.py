"""Claims the documentation makes about the code, checked against the code.

A doc command that silently returns nothing is worse than one that errors:
the reader takes the empty output as the answer. The activity-log grep in
INSTALL.md was wrong for exactly that reason -- it omitted the space that
json.dumps writes after the colon, so it matched no entry ever, and read as
"no commands were run".

The Grafana alerts table drifted the same way. Making audits manual rewrote
rules.yml -- one alert deleted, two added, two retimed -- and left the table
describing the old set, so the documented way to know a device was unreachable
named an alert Prometheus had never heard of.
"""

import re
from pathlib import Path

import pytest
import yaml

from netauto.web import activity

ROOT = Path(__file__).resolve().parent.parent
INSTALL = ROOT / "INSTALL.md"
GRAFANA_README = ROOT / "deploy" / "grafana" / "README.md"
RULES = ROOT / "deploy" / "grafana" / "rules.yml"


@pytest.fixture
def logged(tmp_path):
    path = tmp_path / "activity.log"
    activity.record("alice", "run-command", "core-sw-01", "show version", path=path)
    activity.record("bob", "login", "127.0.0.1", path=path)
    return path


def _documented_patterns() -> list[str]:
    """Every grep pattern INSTALL.md aims at the activity log."""
    text = INSTALL.read_text()
    return re.findall(r"grep '([^']+)' [^\n]*activity\.log", text)


def test_the_docs_actually_grep_the_log():
    assert _documented_patterns(), "no activity-log grep found in INSTALL.md"


def test_every_documented_grep_matches_a_real_entry(logged):
    """Each pattern must find the entry it claims to find."""
    lines = logged.read_text().splitlines()
    for pattern in _documented_patterns():
        assert any(pattern in line for line in lines), (
            f"INSTALL.md greps for {pattern!r}, which matches nothing that "
            f"activity.record writes: {lines[0]!r}"
        )


def _documented_alerts() -> dict[str, tuple[str, str]]:
    """The Grafana README's alerts table, as {name: (severity, description)}."""
    rows = re.findall(
        r"^\| `(Netauto\w+)` \| (\w+) \| (.+?) \|$",
        GRAFANA_README.read_text(),
        re.M,
    )
    return {name: (severity, text) for name, severity, text in rows}


def _real_alerts() -> dict[str, tuple[str, str]]:
    """The rules Prometheus actually loads, in the same shape."""
    groups = yaml.safe_load(RULES.read_text())["groups"]
    return {
        rule["alert"]: (rule["labels"]["severity"], rule["for"])
        for group in groups
        for rule in group["rules"]
    }


def test_the_docs_actually_tabulate_the_alerts():
    assert _documented_alerts(), "no alerts table found in the Grafana README"


def test_the_alerts_table_lists_exactly_the_rules_that_exist():
    documented, real = set(_documented_alerts()), set(_real_alerts())
    assert documented == real, (
        f"the Grafana README documents alerts that rules.yml does not define "
        f"({sorted(documented - real)}) and omits ones it does "
        f"({sorted(real - documented)})"
    )


def test_each_documented_alert_carries_its_real_severity_and_delay():
    documented = _documented_alerts()
    for name, (severity, delay) in _real_alerts().items():
        doc_severity, doc_text = documented[name]
        assert doc_severity == severity, (
            f"the README calls {name} {doc_severity!r}; rules.yml labels it "
            f"{severity!r}"
        )
        assert f"held {delay}" in doc_text, (
            f"{name} fires after {delay} in rules.yml, which the README row "
            f"does not say: {doc_text!r}"
        )
