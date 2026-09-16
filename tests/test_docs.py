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
README = ROOT / "README.md"
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

def test_no_document_pins_a_test_count():
    """A hand-maintained count is a claim that goes stale on the next commit.

    Both documents carried one and both were wrong: they said 384 while the
    suite ran 393, then 398, drifting through five commits including the two
    that added the tests. Nothing else in these files claims a number that
    changes every time anyone writes a test, so the rule is simply not to.
    """
    pattern = re.compile(r"\b\d{2,4}\s+(tests?\b|passed\b)", re.I)
    for doc in (README, INSTALL):
        found = pattern.findall(doc.read_text())
        assert not found, (
            f"{doc.name} pins a test count, which drifts the next time anyone "
            f"adds a test: {found}. Say what the suite needs instead."
        )


# -- screenshots -----------------------------------------------------------
#
# The GUI screenshots drifted without anyone noticing: the committed PNGs were
# a colour scheme and two navigation tabs behind the app they claimed to show.
# Nothing could have caught that, because nothing tied the README's images to
# the thing that produces them. docs/screenshots.py produces them now, and
# these tests keep the two lists from parting company again.

SCREENSHOTS = ROOT / "docs" / "screenshots.py"


def _generator():
    """docs/screenshots.py as a module, without running it."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("netauto_screenshots", SCREENSHOTS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def readme_images() -> set[str]:
    """Every docs/<name>.png the README embeds."""
    return set(re.findall(r"\]\(docs/([a-z0-9-]+)\.png\)", README.read_text()))


def test_the_readme_embeds_screenshots_to_check():
    assert len(readme_images()) > 5, "found almost no screenshots in the README"


def test_every_embedded_screenshot_exists():
    missing = sorted(n for n in readme_images()
                     if not (ROOT / "docs" / f"{n}.png").exists())
    assert not missing, f"the README embeds images that are not in docs/: {missing}"


def test_the_generator_and_the_readme_agree_on_which_pages_are_shown():
    """A screenshot nothing can regenerate is the one that goes stale.

    Both directions matter. A README image with no page in the generator
    cannot be refreshed; a page in the generator that the README never shows
    is work nobody sees. The diagram export is neither -- it is drawn by
    netauto.diagram, not photographed from the GUI.
    """
    drawn_not_photographed = {"netauto-lab-topology"}
    generated = set(_generator().PAGES)
    embedded = readme_images() - drawn_not_photographed

    assert generated == embedded, (
        f"only the README has: {sorted(embedded - generated)}; "
        f"only docs/screenshots.py has: {sorted(generated - embedded)}. "
        f"Add the page to PAGES, or embed the image, so every screenshot in "
        f"the README is one `python docs/screenshots.py` can refresh."
    )
