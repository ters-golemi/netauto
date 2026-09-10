"""Class names the templates build from data, against the stylesheet.

Two bugs of one shape reached a screenshot before anyone saw them. The
activity log renders one badge per action -- `class="act {{ e.action }}"` --
so an action called "login" picked up `.login`, the login *form's* rule, and
was laid out as a 400px flex column. An action called "workflow" picked up
`.workflow`, a section rule, and grew a border and four times the padding.

Both were invisible to every other test: the markup was right, the route was
right, and nothing renders CSS. What they had in common is that a value from
the data landed in the same namespace as a structural class, so that is what
this checks.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CSS = ROOT / "netauto" / "web" / "static" / "style.css"
TEMPLATES = ROOT / "netauto" / "web" / "templates"
APP = ROOT / "netauto" / "web" / "app.py"

#: Severity and status vocabularies, which reach `class="sev {{ ... }}"` and
#: `class="status {{ ... }}"`. Literal because that is how the templates and
#: the rules spell them.
SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
STATUSES = frozenset({"pass", "fail", "skip", "running", "done", "failed"})


def logged_actions() -> set[str]:
    """Every action name the GUI can write to the activity log."""
    text = APP.read_text()
    actions = set(re.findall(r'log\(request,\s*"([a-z-]+)"', text))
    actions |= set(re.findall(r'activity\.record\([^,]+,\s*"([a-z-]+)"', text))
    return actions


def bare_class_rules() -> set[str]:
    """Class names the stylesheet styles on their own, with no qualifier.

    These are the dangerous ones: a single class selector matches anything
    carrying that class, whatever element or page it is on.
    """
    return set(re.findall(r'^\.([a-z][a-z0-9-]*)\s*\{', CSS.read_text(), re.M))


def test_the_activity_log_writes_actions_the_test_can_see():
    """If the regex stops matching, the guard below silently passes."""
    actions = logged_actions()
    assert {"login", "login-failed", "discover", "audit", "workflow"} <= actions, (
        f"expected to find the known actions in app.py, got {sorted(actions)}"
    )


def test_the_stylesheet_has_bare_class_rules_to_check():
    assert len(bare_class_rules()) > 10, "the CSS parser found almost nothing"


@pytest.mark.parametrize("family,values", [
    ("act", "actions"),
    ("sev", "severities"),
    ("status", "statuses"),
])
def test_data_values_do_not_collide_with_structural_rules(family, values):
    """A value rendered into a class must not match a rule meant for a layout.

    The fix is never to rename the data. Scope the stylesheet rule to what it
    is actually for -- `.card.login` rather than `.login`, `div.workflow`
    rather than `.workflow` -- so it stops matching a badge that happens to
    share the name.
    """
    data = {"actions": logged_actions(), "severities": SEVERITIES,
            "statuses": STATUSES}[values]
    collisions = sorted(data & bare_class_rules())
    assert not collisions, (
        f"class=\"{family} {{{{ value }}}}\" can render {collisions}, which the "
        f"stylesheet also styles as a bare rule. Scope that rule to the element "
        f"it is for; see the note at the top of this file."
    )
