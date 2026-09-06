"""Commands the documentation tells people to run.

A doc command that silently returns nothing is worse than one that errors:
the reader takes the empty output as the answer. The activity-log grep in
INSTALL.md was wrong for exactly that reason -- it omitted the space that
json.dumps writes after the colon, so it matched no entry ever, and read as
"no commands were run".
"""

import re
from pathlib import Path

import pytest

from netauto.web import activity

ROOT = Path(__file__).resolve().parent.parent
INSTALL = ROOT / "INSTALL.md"


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
