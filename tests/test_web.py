"""Web GUI tests. Auth is the boundary, so it carries the coverage."""

import pytest
from fastapi.testclient import TestClient

from netauto.web.app import create_app

PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("NETAUTO_WEB_PASSWORD", PASSWORD)
    monkeypatch.setenv("NETAUTO_SECRET_KEY", "test-key-not-for-production")
    from netauto.web import app as appmod
    appmod._FAILURES.clear()
    return TestClient(create_app())


def _login(client, password=PASSWORD):
    page = client.get("/login")
    token = page.text.split('name="csrf_token" value="')[1].split('"')[0]
    return client.post("/login",
                       data={"password_input": password, "csrf_token": token},
                       follow_redirects=False)


def test_refuses_to_start_without_password(monkeypatch):
    monkeypatch.delenv("NETAUTO_WEB_PASSWORD", raising=False)
    with pytest.raises(RuntimeError, match="NETAUTO_WEB_PASSWORD"):
        create_app()


@pytest.mark.parametrize("path", ["/", "/devices", "/audit", "/discover",
                                  "/devices/anything"])
def test_pages_require_a_session(client, path):
    r = client.get(path, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_wrong_password_is_rejected(client):
    r = _login(client, "wrong")
    assert r.status_code == 200
    assert "Incorrect password" in r.text
    assert client.get("/", follow_redirects=False).status_code == 303


def test_correct_password_grants_access(client):
    r = _login(client)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert client.get("/").status_code == 200


def test_login_without_csrf_token_is_rejected(client):
    r = client.post("/login", data={"password_input": PASSWORD, "csrf_token": ""})
    assert "Session expired" in r.text
    assert client.get("/", follow_redirects=False).status_code == 303


def test_logout_clears_the_session(client):
    _login(client)
    assert client.get("/").status_code == 200
    client.post("/logout", follow_redirects=False)
    assert client.get("/", follow_redirects=False).status_code == 303


def test_repeated_failures_are_throttled(client):
    for _ in range(6):
        _login(client, "wrong")
    r = _login(client)          # correct password, but locked out
    assert "Too many attempts" in r.text


def test_session_cookie_is_hardened(client):
    r = _login(client)
    cookie = r.headers.get("set-cookie", "")
    assert "httponly" in cookie.lower()
    assert "samesite=strict" in cookie.lower().replace(" ", "")


def test_health_needs_no_session(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_missing_inventory_is_reported_not_crashed(client):
    """No devices.yaml is the normal first-run state, not a 500."""
    _login(client)
    r = client.get("/")
    assert r.status_code == 200
    assert "No inventory loaded" in r.text


def test_no_write_routes_exist(client):
    """The GUI must expose no mutating device route."""
    app = client.app
    posts = {r.path for r in app.routes
             if getattr(r, "methods", None) and "POST" in r.methods}
    assert posts == {"/login", "/logout"}, f"unexpected POST routes: {posts}"
