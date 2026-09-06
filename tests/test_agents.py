"""Agent definitions.

These are prose, so most of what they say cannot be tested. What can be
tested is that they refer to tools that exist: an agent granted
mcp__netauto__net_topology before that tool was written, or still granted one
after it is renamed, fails at run time with nothing to point at the cause.
"""

import re
from pathlib import Path

import pytest

from netauto import mcp_server

AGENTS = Path(__file__).resolve().parent.parent / "agents"
TOOL_PREFIX = "mcp__netauto__"


def _agent_files():
    return sorted(AGENTS.glob("*.md"))


def _frontmatter(path: Path) -> dict[str, str]:
    text = path.read_text()
    assert text.startswith("---\n"), f"{path.name} has no frontmatter"
    body = text.split("---\n", 2)[1]
    out = {}
    for line in body.splitlines():
        if ":" in line and not line.startswith(" "):
            key, _, value = line.partition(":")
            out[key.strip()] = value.strip()
    return out


def _netauto_tools(path: Path) -> list[str]:
    listed = _frontmatter(path).get("tools", "")
    return [t.strip()[len(TOOL_PREFIX):] for t in listed.split(",")
            if t.strip().startswith(TOOL_PREFIX)]


def test_there_are_agents_to_check():
    assert _agent_files(), "no agent definitions found"


@pytest.mark.parametrize("path", _agent_files(), ids=lambda p: p.stem)
def test_every_granted_tool_exists(path):
    """A tool named here but absent from the server fails only at run time."""
    for tool in _netauto_tools(path):
        assert callable(getattr(mcp_server, tool, None)), (
            f"{path.name} grants {TOOL_PREFIX}{tool}, which the MCP server "
            f"does not define"
        )


@pytest.mark.parametrize("path", _agent_files(), ids=lambda p: p.stem)
def test_every_tool_named_in_the_prose_is_granted(path):
    """Telling an agent to call a tool it was never given is a dead end."""
    text = path.read_text()
    body = text.split("---\n", 2)[2]
    granted = set(_netauto_tools(path))
    mentioned = set(re.findall(r"`(net_[a-z_]+)`", body))
    missing = {t for t in mentioned if t not in granted
               and callable(getattr(mcp_server, t, None))}
    assert not missing, f"{path.name} tells the agent to use {missing} without granting it"


def test_the_documenter_can_draw_a_topology():
    """Its description promises topology; the tool list has to back that up."""
    doc = AGENTS / "network-documenter.md"
    assert "topology" in _frontmatter(doc)["description"].lower()
    assert "net_topology" in _netauto_tools(doc)


def test_installed_copies_match_the_repo_when_they_exist():
    """The repo holds the canonical definitions; drift makes them a trap."""
    installed = AGENTS.parent.parent / ".claude" / "agents"
    if not installed.is_dir():
        pytest.skip("agents are not installed in this checkout")
    for path in _agent_files():
        copy = installed / path.name
        if copy.exists():
            assert copy.read_text() == path.read_text(), (
                f"{copy} has drifted from {path}; re-copy from agents/"
            )
