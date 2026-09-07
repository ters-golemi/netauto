"""Shared fixtures and the one list of POST routes the GUI is allowed.

The write-route guard existed in three copies, one per test module, each
asserting the same literal set. Three copies of a safety allowlist is two
chances to widen it in one place and not the others, so it lives here.
"""

from __future__ import annotations

#: Every POST route the GUI may expose, and why it is not a device write.
#:
#: netauto has no commit path: no route, POST or otherwise, changes a device.
#: These POST because they change something on the *server* -- a session, a
#: run -- and so must be CSRF-protected and non-idempotent. Adding a path here
#: is the deliberate act; the guard is what makes it deliberate.
ALLOWED_POST_ROUTES: dict[str, str] = {
    "/login": "Creates a session.",
    "/logout": "Destroys a session.",
    "/workflows/{workflow_id}/start": (
        "Starts a read-only workflow run. It opens sessions and reads; every "
        "command it can send is checked against assert_read_only first."
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
