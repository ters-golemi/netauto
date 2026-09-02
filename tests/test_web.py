"""Web GUI tests. Auth and attribution are the boundaries, so they carry coverage."""

import json

import pytest
from fastapi.testclient import TestClient

from netauto.web import activity
from netauto.web.app import create_app
from netauto.web.users import UserStore

PW = "correct-horse-battery-staple"


@pytest.fixture
def env(tmp_path, monkeypatch):
    users = tmp_path / "users.yaml"
    logfile = tmp_path / "activity.log"
    monkeypatch.setenv("NETAUTO_USERS_FILE", str(users))
    monkeypatch.setenv("NETAUTO_ACTIVITY_LOG", str(logfile))
    monkeypatch.setenv("NETAUTO_SECRET_KEY", "test-key-not-for-production")
    store = UserStore(users)
    store.add("alice", PW, admin=True)
    store.add("bob", PW)
    from netauto.web import app as appmod
    appmod._FAILURES.clear()
    return {"store": store, "log": logfile}


@pytest.fixture
def client(env):
    return TestClient(create_app(env["store"]))


def _login(client, user="alice", password=PW):
    token = client.get("/login").text.split('name="csrf_token" value="')[1].split('"')[0]
    return client.post("/login",
                       data={"username": user, "password_input": password,
                             "csrf_token": token},
                       follow_redirects=False)


def test_refuses_to_start_with_no_accounts(tmp_path):
    with pytest.raises(RuntimeError, match="No accounts exist"):
        create_app(UserStore(tmp_path / "empty.yaml"))


@pytest.mark.parametrize("path", ["/", "/devices", "/audit", "/discover",
                                  "/activity", "/devices/anything"])
def test_pages_require_a_session(client, path):
    r = client.get(path, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_correct_credentials_grant_access(client):
    r = _login(client)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert "alice" in client.get("/").text


def test_wrong_password_is_rejected(client):
    assert "Incorrect username or password" in _login(client, "alice", "nope").text
    assert client.get("/", follow_redirects=False).status_code == 303


def test_unknown_user_is_rejected(client):
    assert "Incorrect username or password" in _login(client, "mallory", PW).text


def test_login_without_csrf_token_is_rejected(client):
    r = client.post("/login", data={"username": "alice", "password_input": PW,
                                    "csrf_token": ""})
    assert "Session expired" in r.text


def test_logout_clears_the_session(client):
    _login(client)
    client.post("/logout", follow_redirects=False)
    assert client.get("/", follow_redirects=False).status_code == 303


def test_throttle_is_per_account_not_global(client):
    """Locking bob out must not lock alice out."""
    for _ in range(6):
        _login(client, "bob", "wrong")
    assert "Too many attempts" in _login(client, "bob", PW).text
    assert _login(client, "alice", PW).status_code == 303


def test_session_cookie_is_hardened(client):
    cookie = _login(client).headers.get("set-cookie", "")
    assert "httponly" in cookie.lower()
    assert "samesite=strict" in cookie.lower().replace(" ", "")


def test_admin_sees_activity(client):
    _login(client, "alice")
    r = client.get("/activity")
    assert r.status_code == 200 and "Recent actions" in r.text


def test_standard_account_is_denied_activity(client):
    _login(client, "bob")
    r = client.get("/activity")
    assert r.status_code == 200
    assert "restricted to administrators" in r.text
    assert "Recent actions" not in r.text


def test_actions_are_attributed(client, env):
    _login(client, "bob")
    client.get("/discover?cidr=203.0.113.0/30")
    entries = activity.tail(path=env["log"])
    actions = {(e["user"], e["action"]) for e in entries}
    assert ("bob", "login") in actions
    assert ("bob", "discover") in actions


def test_failed_logins_are_recorded(client, env):
    _login(client, "alice", "wrong")
    entries = activity.tail(path=env["log"])
    assert any(e["action"] == "login-failed" and e["user"] == "alice" for e in entries)


def test_activity_log_is_valid_jsonl(client, env):
    _login(client, "alice")
    for line in env["log"].read_text().splitlines():
        rec = json.loads(line)
        assert {"ts", "user", "action"} <= set(rec)


def test_health_needs_no_session(client):
    assert client.get("/health").json()["status"] == "ok"


def test_missing_inventory_is_reported_not_crashed(client):
    _login(client)
    assert "No inventory loaded" in client.get("/").text


def test_no_write_routes_exist(client):
    """The GUI must expose no mutating device route."""
    posts = {r.path for r in client.app.routes
             if getattr(r, "methods", None) and "POST" in r.methods}
    assert posts == {"/login", "/logout"}, f"unexpected POST routes: {posts}"
