"""Shared fixtures and the one list of POST routes the GUI is allowed.

The write-route guard existed in three copies, one per test module, each
asserting the same literal set. Three copies of a safety allowlist is two
chances to widen it in one place and not the others, so it lives here.
"""

from __future__ import annotations

#: Every POST route the GUI may expose, and why it is not a device write.
#:
#: netauto has exactly one device-write path -- the Software Upgrade workflow's
#: firmware install, gated three ways and off by default -- reached through the
#: workflow-start route below. Every other route here changes only *server*
#: state (a session, a run), not a device. All POST because they are
#: non-idempotent and CSRF-protected; adding a path is the deliberate act, and
#: the guard is what makes it deliberate.
ALLOWED_POST_ROUTES: dict[str, str] = {
    "/login": "Creates a session.",
    "/logout": "Destroys a session.",
    "/workflows/{workflow_id}/start": (
        "Starts a workflow run. The configuration-check and documentation "
        "workflows only read, and every show command is checked against "
        "assert_read_only first. The Software Upgrade workflow can write -- a "
        "firmware install -- but only past three gates (allow_writes, the "
        "upgrade capability, and confirmation by device name); off by default "
        "it produces a runbook and touches nothing. The route changes server "
        "state (a run) either way, which is why it POSTs."
    ),
    "/workflows/runs/{run_id}/cancel": (
        "Sets a cancel flag on a run in memory. Touches no device."
    ),
}


def post_routes(app) -> set[str]:
    """Every path the app serves over POST."""
    return {
        route.path
        for route in app.routes
        if getattr(route, "methods", None) and "POST" in route.methods
    }


def assert_no_write_routes(app) -> None:
    """The GUI must expose no mutating device route."""
    unexpected = post_routes(app) - set(ALLOWED_POST_ROUTES)
    assert not unexpected, (
        f"POST routes that nobody has justified: {sorted(unexpected)}. "
        f"If one of these is safe, add it to ALLOWED_POST_ROUTES in "
        f"tests/conftest.py with the reason."
    )
