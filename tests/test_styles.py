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


def test_no_rule_overrides_the_width_of_a_field_that_declares_its_size():
    """A `size` attribute is the template saying how wide a field should be.

    The stylesheet pinned every `.inline input[size]` to a fixed 9ch. That was
    written for the ports box on the Discover page, which is short because it
    holds "22,23" -- but the selector also caught the two Software Upgrade
    fields, whose placeholders name a firmware image and a server. They were
    clipped to "firmwar" and "tftp/ftp s", and the only place it showed was a
    screenshot.

    The same shape as the collisions above: a selector matching more than the
    thing it was written for. The fix is not to drop the `size` attributes --
    they carry real intent, and three templates set them to three different
    values -- so the rule must leave the width alone.
    """
    rules = re.findall(r'([^{}]*input\[size\][^{}]*)\{([^}]*)\}', CSS.read_text())
    assert rules, "no rule targets input[size]; has the selector been renamed?"
    # Anchored to a property boundary: `min-width:0` is fine and is what stops
    # the 240px flex-basis above stretching these fields out.
    pinned = [sel.strip() for sel, body in rules
              if re.search(r'(?:^|;)\s*width\s*:', body)]
    assert not pinned, (
        f"{pinned} sets a width on inputs that declare their own size, which "
        f"clips whichever field is longest. Size them in the template."
    )
