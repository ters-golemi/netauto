"""Hold the netlab docs to the code.

A one-time cross-check found three doc/code drifts: a CI template that ran an
install command the repo cannot satisfy, a README claim about mapped platforms
that was not true, and a mapping table missing a row the code implements. The
first two are prose and live where a reader will re-read them; these two are the
ones a test can pin, so a future edit to the code that forgets the doc -- or the
other way round -- fails here rather than in front of a user.

Companion to tests/test_docs.py, which does the same for INSTALL and the README.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from netauto.lab.inventory import KIND_TO_PLATFORM, UNSUPPORTED_KINDS

ROOT = Path(__file__).resolve().parent.parent
DESIGN = ROOT / "docs" / "netlab-integration.md"
CI_TEMPLATE = ROOT / "docs" / "lab-audit.ci.yml"


def test_the_design_doc_mapping_table_lists_every_mapped_kind():
    """Every netlab kind the code maps must appear in the doc's table, so the
    table cannot quietly fall behind KIND_TO_PLATFORM."""
    doc = DESIGN.read_text()
    for kind in KIND_TO_PLATFORM:
        # The vjunos-switch/router/evolved family is shown as one `vjunos-*` row.
        covered = f"`{kind}`" in doc or (
            kind.startswith("vjunos-") and "vjunos-*" in doc)
        assert covered, (
            f"netlab kind {kind!r} is mapped in KIND_TO_PLATFORM but does not "
            f"appear in the design-doc mapping table")


def test_the_design_doc_shows_the_sample_skipped_kinds():
    """The kinds the samples exercise as skipped must be shown as skipped, so
    the 'listed but skipped' promise is documented, not just coded."""
    doc = DESIGN.read_text()
    for kind in ("frr", "vyos", "srlinux", "cumulus", "linux"):
        assert kind in UNSUPPORTED_KINDS  # guard: still actually unsupported
        assert f"`{kind}`" in doc, f"{kind!r} is not shown as skipped in the doc"


def test_the_ci_template_installs_something_the_repo_can_satisfy():
    """netauto is not a packaged distribution -- it has no setup.py/pyproject
    and runs from the checkout -- so the copyable workflow must not `pip install
    -e .`, which would fail on a real runner."""
    ci = CI_TEMPLATE.read_text()
    assert "pip install -e ." not in ci, (
        "the CI template runs 'pip install -e .', but netauto has no packaging; "
        "install requirements-app.txt and run from the checkout instead")
    assert "requirements-app.txt" in ci


def test_the_ci_template_is_valid_yaml_and_points_at_a_real_topology():
    ci = CI_TEMPLATE.read_text()
    assert yaml.safe_load(ci), "the CI template is not valid YAML"
    # The command line references a topology; it must be one the repo ships.
    assert (ROOT / "labs" / "spine-leaf" / "topology.yml").exists()
    assert "labs/spine-leaf/topology.yml" in ci
