"""The Metrics tab.

The tab is a view onto another service, so the cases that matter are the ones
where that service is absent or unconfigured: an embedded iframe that fails
renders as an empty rectangle, and the page has to say why.
"""

import pytest
from conftest import assert_no_write_routes
from fastapi.testclient import TestClient

from netauto.web import app as appmod
from netauto.web.app import create_app, grafana_health
from netauto.web.users import UserStore

PW = "correct-horse-battery-staple"
GRAFANA = "http://127.0.0.1:3000"


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("NETAUTO_SECRET_KEY", "test-key-not-for-production")
    monkeypatch.setenv("NETAUTO_ACTIVITY_LOG", str(tmp_path / "activity.log"))
    monkeypatch.delenv("NETAUTO_METRICS_TOKEN", raising=False)
    s = UserStore(tmp_path / "users.yaml")
    s.add("alice", PW, admin=True)
    s.add("bob", PW)
    appmod._FAILURES.clear()
    return s


def _login(client, user="alice"):
    token = client.get("/login").text.split('name="csrf_token" value="')[1].split('"')[0]
    client.post("/login", data={"username": user, "password_input": PW,
                                "csrf_token": token})


def test_tab_requires_a_session(store, monkeypatch):
    monkeypatch.setenv("NETAUTO_GRAFANA_URL", GRAFANA)
    client = TestClient(create_app(store))
    r = client.get("/grafana", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_tab_hidden_when_grafana_is_not_configured(store, monkeypatch):
    monkeypatch.delenv("NETAUTO_GRAFANA_URL", raising=False)
    client = TestClient(create_app(store))
    _login(client)
    # No nav item that leads nowhere.
    assert 'href="/grafana"' not in client.get("/devices").text


def test_tab_shown_when_configured(store, monkeypatch):
    monkeypatch.setenv("NETAUTO_GRAFANA_URL", GRAFANA)
    monkeypatch.setattr(appmod, "grafana_health", lambda url, timeout=2.0: (True, "11.5.1"))
    client = TestClient(create_app(store))
    _login(client)
    assert 'href="/grafana"' in client.get("/devices").text


def test_tab_is_visible_to_standard_accounts(store, monkeypatch):
    """Compliance is not admin-only; the activity log is."""
    monkeypatch.setenv("NETAUTO_GRAFANA_URL", GRAFANA)
    monkeypatch.setattr(appmod, "grafana_health", lambda url, timeout=2.0: (True, ""))
    client = TestClient(create_app(store))
    _login(client, "bob")
    body = client.get("/grafana").text
    assert "<iframe" in body
    assert 'href="/activity"' not in body


def test_unconfigured_page_explains_itself(store, monkeypatch):
    monkeypatch.delenv("NETAUTO_GRAFANA_URL", raising=False)
    client = TestClient(create_app(store))
    _login(client)
    body = client.get("/grafana").text
    assert "not configured" in body
    assert "NETAUTO_GRAFANA_URL" in body
    assert "<iframe" not in body


def test_unreachable_grafana_explains_itself(store, monkeypatch):
    """A blank iframe is useless; the page must name the reason."""
    monkeypatch.setenv("NETAUTO_GRAFANA_URL", GRAFANA)
    monkeypatch.setattr(appmod, "grafana_health",
                        lambda url, timeout=2.0: (False, "Connection refused"))
    client = TestClient(create_app(store))
    _login(client)
    body = client.get("/grafana").text
    assert "Cannot reach Grafana" in body
    assert "Connection refused" in body
    assert "docker compose up -d" in body
    assert "<iframe" not in body


def test_embed_uses_kiosk_mode_and_the_provisioned_uid(store, monkeypatch):
    monkeypatch.setenv("NETAUTO_GRAFANA_URL", GRAFANA)
    monkeypatch.setattr(appmod, "grafana_health", lambda url, timeout=2.0: (True, ""))
    client = TestClient(create_app(store))
    _login(client)
    body = client.get("/grafana").text
    # kiosk suppresses Grafana's own nav, which would otherwise appear as a
    # second toolbar inside the page.
    assert "/d/netauto-compliance?kiosk" in body
    assert "<iframe" in body


def test_trailing_slash_in_url_does_not_double_up(store, monkeypatch):
    monkeypatch.setenv("NETAUTO_GRAFANA_URL", GRAFANA + "/")
    monkeypatch.setattr(appmod, "grafana_health", lambda url, timeout=2.0: (True, ""))
    client = TestClient(create_app(store))
    _login(client)
    assert "3000//d/" not in client.get("/grafana").text


def test_health_rejects_a_non_http_url():
    """Guards against a file:// or gopher:// value reaching urlopen."""
    ok, detail = grafana_health("file:///etc/passwd")
    assert not ok
    assert "http(s)" in detail


def test_health_treats_401_as_up():
    """Grafana answering 401 is still Grafana answering."""
    import urllib.error
    import urllib.request

    def raise_401(*a, **kw):
        raise urllib.error.HTTPError("u", 401, "Unauthorized", {}, None)

    original = urllib.request.urlopen
    urllib.request.urlopen = raise_401
    try:
        ok, detail = grafana_health(GRAFANA)
    finally:
        urllib.request.urlopen = original
    assert ok
    assert "401" in detail


def test_grafana_tab_adds_no_write_route(store, monkeypatch):
    monkeypatch.setenv("NETAUTO_GRAFANA_URL", GRAFANA)
    assert_no_write_routes(create_app(store))


def test_the_start_command_is_runnable_from_anywhere(store, monkeypatch):
    """A relative path is useless to someone reading a web page.

    "cd deploy/grafana" only works from the repo root, and a browser gives no
    clue what directory the server was started in -- so it fails with
    "Directory not found" for anyone who is anywhere else.
    """
    monkeypatch.setenv("NETAUTO_GRAFANA_URL", GRAFANA)
    monkeypatch.setattr(appmod, "grafana_health",
                        lambda url, timeout=2.0: (False, "Connection refused"))
    client = TestClient(create_app(store))
    _login(client)
    body = client.get("/grafana").text
    assert "cd /" in body, "the start command must use an absolute path"
    assert "cd deploy/grafana" not in body
    assert str(appmod.REPO_ROOT / "deploy" / "grafana") in body


def test_the_unconfigured_page_also_points_somewhere_real(store, monkeypatch):
    monkeypatch.delenv("NETAUTO_GRAFANA_URL", raising=False)
    client = TestClient(create_app(store))
    _login(client)
    assert str(appmod.REPO_ROOT / "deploy" / "grafana") in client.get("/grafana").text
