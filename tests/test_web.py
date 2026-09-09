"""Web GUI tests. Auth and attribution are the boundaries, so they carry coverage."""

import json

import pytest
from conftest import assert_no_write_routes
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


def test_missing_inventory_is_reported_not_crashed(client, monkeypatch):
    from netauto.errors import NetautoError
    from netauto.web import app as appmod

    # Patched rather than left to the filesystem: this asserted on the real
    # working-directory inventory, so it passed only until someone followed
    # step 6 of INSTALL.md and created inventory/devices.yaml.
    def missing():
        raise NetautoError("No inventory loaded from inventory/devices.yaml")

    monkeypatch.setattr(appmod, "load_context", missing)
    _login(client)
    assert "No inventory loaded" in client.get("/").text


def test_no_write_routes_exist(client):
    """The GUI must expose no mutating device route."""
    assert_no_write_routes(client.app)


# --- discovery and port scanning --------------------------------------------

@pytest.fixture
def swept(monkeypatch):
    """Stand in for arp-scan, which needs a real segment and raw sockets."""
    from netauto import scan

    monkeypatch.setattr(scan, "arp_sweep", lambda cidr, iface="": [
        scan.Host(ip="192.168.1.1", mac="00:11:22:aa:bb:cc", vendor="Cisco"),
        scan.Host(ip="192.168.1.9", mac="00:11:22:aa:bb:dd", vendor="Aruba"),
    ])
    calls: list[tuple] = []

    def fake_probe(hosts, ports, **kw):
        calls.append((list(hosts), tuple(ports)))
        return [scan.Host(ip=h.ip, mac=h.mac, vendor=h.vendor,
                          ports=(scan.Port(22, True, "SSH-2.0-Cisco-1.25"),
                                 scan.Port(23, h.ip.endswith(".9"))))
                for h in hosts]

    monkeypatch.setattr(scan, "probe_hosts", fake_probe)
    return calls


def test_sweep_without_probing_dials_nothing(client, swept):
    _login(client)
    body = client.get("/discover?cidr=192.168.1.0/30").text
    assert "192.168.1.1" in body
    assert swept == [], "no port was asked for, so none may be dialled"


def test_probe_reports_open_ports(client, swept):
    _login(client)
    body = client.get("/discover?cidr=192.168.1.0/30&probe=1&ports=22,23").text
    assert swept and swept[0][1] == (22, 23)
    assert "open" in body and "closed" in body


def test_probe_defaults_to_ssh_and_telnet(client, swept):
    _login(client)
    client.get("/discover?cidr=192.168.1.0/30&probe=1")
    assert swept[0][1] == (22, 23)


def test_bad_port_input_is_an_error_not_a_scan(client, swept):
    _login(client)
    body = client.get("/discover?cidr=192.168.1.0/30&probe=1&ports=ssh").text
    assert "Not a port number" in body
    assert swept == []


def test_scanned_ports_are_recorded_against_the_account(client, env, swept):
    _login(client, "bob")
    client.get("/discover?cidr=192.168.1.0/30&probe=1&ports=22,23")
    entry = next(e for e in activity.tail(path=env["log"]) if e["action"] == "discover")
    assert entry["user"] == "bob" and "ports=22,23" in entry["detail"]
