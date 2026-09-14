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
                                  "/activity", "/procedures", "/lab",
                                  "/devices/anything"])
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


def test_procedures_page_renders_with_the_upgrade_target(client):
    """The in-app procedures reference shows the gates and the recommended version."""
    _login(client)
    body = client.get("/procedures").text
    assert "Operational procedures" in body
    assert "Software Upgrade" in body and "allow_writes" in body
    assert "7.4.8" in body, "recommended target should come from the workflow spec"
    assert "Configuration backup" in body


def test_the_device_page_renders_for_a_logged_in_user(client):
    """It raised TypeError on every authenticated request, and only on those.

    page()'s template parameter was called "name", and a device page passes
    the device name as context. Nothing caught it because the only coverage
    /devices/<name> had was the logged-out redirect.
    """
    _login(client)
    r = client.get("/devices/core-sw-01")
    assert r.status_code == 200
    assert "core-sw-01" in r.text


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


# --- ad-hoc connections ------------------------------------------------------

@pytest.fixture
def connectable(client, swept, monkeypatch):
    """A sweep has happened, so 192.168.1.1 and .9 are connectable."""
    monkeypatch.setenv("LAB_USERNAME", "admin")
    monkeypatch.setenv("LAB_PASSWORD", "hunter2")
    _login(client)
    client.get("/discover?cidr=192.168.1.0/30&probe=1&ports=22,23")
    return client


def test_connect_requires_a_session(client):
    r = client.get("/connect?ip=192.168.1.9", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_connect_form_offers_only_what_can_work(connectable):
    body = connectable.get("/connect?ip=192.168.1.9").text
    assert "LAB" in body, "a prefix the environment actually carries"
    assert "hunter2" not in body, "the value behind it must never be rendered"
    assert "meraki" not in body, "a cloud tenant has no address to dial"
    assert "cisco_ios" in body


def test_connect_form_preselects_the_guess(connectable):
    """The sweep saw an SSH banner; the form should not make them guess."""
    body = connectable.get("/connect?ip=192.168.1.9").text
    assert 'value="cisco_ios" selected' in body


def test_the_form_says_up_front_that_a_host_was_not_swept(connectable):
    """Otherwise it invites you to pick a platform for a refusal."""
    body = connectable.get("/connect?ip=192.168.5.5").text
    assert "Not connectable" in body
    assert "not found by a sweep" in body
    assert "/discover?cidr=192.168.5.0/24" in body, "offer the sweep that would help"


def test_the_form_is_clean_for_an_address_that_was_swept(connectable):
    body = connectable.get("/connect?ip=192.168.1.9").text
    assert "Not connectable" not in body


def test_no_sweep_is_offered_for_a_routable_address(connectable):
    body = connectable.get("/connect?ip=8.8.8.8").text
    assert "routable on the internet" in body
    assert "/discover?cidr=" not in body


def test_the_refusal_is_not_shown_twice_after_submitting(connectable):
    """error and blocked carry the same sentence; only one may render."""
    body = connectable.get("/connect?ip=192.168.5.5&platform=cisco_ios"
                           "&credentials=LAB").text
    assert body.count("not found by a sweep") == 1
    assert "Not connectable" not in body and "Not connected" in body


def test_an_unswept_address_is_refused_by_the_route(connectable):
    body = connectable.get("/connect?ip=192.168.5.5&platform=cisco_ios"
                           "&credentials=LAB").text
    assert "not found by a sweep" in body


def test_a_routable_address_is_refused_by_the_route(connectable):
    body = connectable.get("/connect?ip=8.8.8.8&platform=cisco_ios"
                           "&credentials=LAB").text
    assert "routable on the internet" in body


@pytest.fixture
def dialled(monkeypatch):
    """Capture the Device a connection is opened with, without opening one."""
    import contextlib

    from netauto.web import app as appmod
    seen: list = []

    class FakeDriver:
        def facts(self):
            return {"vendor": "Cisco", "model": "C9300", "os_version": "17.9.4"}

        def get_config(self, kind):
            return "hostname undocumented-switch\n"

        def run_read(self, command):
            return f"output of {command}"

    @contextlib.contextmanager
    def fake_connect(device, settings):
        seen.append(device)
        yield FakeDriver()

    monkeypatch.setattr(appmod, "connect", fake_connect)
    return seen


def test_the_transient_device_is_the_address_itself(connectable, dialled):
    """Named for its address, because that is all that is known about it."""
    connectable.get("/connect?ip=192.168.1.9&platform=cisco_ios&credentials=LAB")
    dev = dialled[0]
    assert dev.name == "192.168.1.9" and dev.host == "192.168.1.9"
    assert dev.platform == "cisco_ios"
    assert dev.credentials_prefix == "LAB"


def test_an_ad_hoc_session_reads_like_any_device(connectable, dialled):
    body = connectable.get("/connect?ip=192.168.1.9&platform=cisco_ios&credentials=LAB").text
    assert "C9300" in body and "undocumented-switch" in body
    assert "Ad-hoc session" in body


def test_the_command_form_carries_the_session(connectable, dialled):
    """Without the hidden fields, Run would land on /connect with no identity."""
    body = connectable.get("/connect?ip=192.168.1.9&platform=cisco_ios"
                           "&credentials=LAB&show=show+version").text
    assert 'type="hidden" name="ip" value="192.168.1.9"' in body
    assert 'name="platform" value="cisco_ios"' in body


def test_connecting_is_attributed(connectable, env, dialled):
    connectable.get("/connect?ip=192.168.1.9&platform=cisco_ios&credentials=LAB")
    entry = next(e for e in activity.tail(path=env["log"]) if e["action"] == "connect")
    assert entry["target"] == "192.168.1.9"
    assert "cisco_ios" in entry["detail"] and "LAB" in entry["detail"]
    assert "hunter2" not in entry["detail"], "the log records the prefix, never the secret"


def test_a_failed_connection_reports_rather_than_crashes(connectable, monkeypatch):
    from netauto.errors import DriverError
    from netauto.web import app as appmod

    def refuse(device, settings):
        raise DriverError(f"{device.name}: connection failed: timed out")

    monkeypatch.setattr(appmod, "connect", refuse)
    body = connectable.get("/connect?ip=192.168.1.9&platform=cisco_ios"
                           "&credentials=LAB").text
    assert "connection failed" in body


def test_the_discover_page_offers_a_connection(connectable):
    body = connectable.get("/discover?cidr=192.168.1.0/30&probe=1&ports=22,23").text
    assert "/connect?ip=192.168.1.1" in body


def test_ad_hoc_sessions_add_no_write_route(client):
    """The guarantee in the footer is unchanged by any of this."""
    assert_no_write_routes(client.app)


def _csrf_from(html):
    return html.split('name="csrf_token" value="')[1].split('"')[0]


@pytest.fixture
def lab_ready(client, monkeypatch):
    """A logged-in client with netlab 'available' and one discoverable lab.

    Everything netlab is faked: no binary runs, no hypervisor is touched. The
    lab is 'down' (no snapshot) unless a test overrides lab_nodes_for.
    """
    from pathlib import Path

    from netauto.config import Settings
    from netauto.web import app as appmod

    topo = Path("/labs/demo/topology.yml")
    fake = Settings(inventory_path="unused", labs_dir=Path("/labs"))
    monkeypatch.setattr(appmod.Settings, "load", lambda *a, **k: fake)
    monkeypatch.setattr(appmod, "discover_topologies", lambda d: [topo])
    monkeypatch.setattr(appmod.lab_runner, "is_available", lambda: True)
    monkeypatch.setattr(appmod.lab_runner, "netlab_path", lambda: "/usr/bin/netlab")
    monkeypatch.setattr(appmod, "lab_nodes_for", lambda p: None)
    _login(client)
    return {"appmod": appmod, "monkeypatch": monkeypatch,
            "topo": topo, "id": "demo/topology.yml"}


def test_lab_page_says_netlab_is_absent_when_it_is(client, monkeypatch):
    from netauto.web import app as appmod
    monkeypatch.setattr(appmod.lab_runner, "is_available", lambda: False)
    _login(client)
    body = client.get("/lab").text
    assert "Lab" in body and "netlab is not installed" in body


def test_lab_page_lists_a_topology_and_its_mapped_nodes(lab_ready, client):
    from netauto.inventory import Device
    from netauto.lab.inventory import Mapped
    from netauto.lab.snapshot import LabNode

    mapped = Mapped(
        devices=[Device(name="r1", platform="cisco_ios", host="192.168.121.101",
                        credentials="LAB", tags=("lab",))],
        skipped=[(LabNode("x1", "frr", "192.168.121.105"),
                  "no netauto driver for netlab kind 'frr'")],
    )
    lab_ready["monkeypatch"].setattr(lab_ready["appmod"], "lab_nodes_for",
                                     lambda p: mapped)
    body = client.get("/lab").text
    assert "demo" in body and "r1" in body and "cisco_ios" in body
    assert "192.168.121.101" in body
    assert "x1" in body and "no netauto driver" in body  # skipped, shown honestly


def test_lab_up_starts_a_job_for_a_known_topology(lab_ready, client):
    started = []
    lab_ready["monkeypatch"].setattr(
        client.app.state.lab, "start",
        lambda action, topology, user: started.append((action, topology, user)))
    token = _csrf_from(client.get("/lab").text)
    r = client.post("/lab/up", data={"topology": lab_ready["id"],
                                      "csrf_token": token},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/lab"
    assert started == [("up", "/labs/demo/topology.yml", "alice")]


def test_lab_up_rejects_an_unknown_topology(lab_ready, client):
    token = _csrf_from(client.get("/lab").text)
    r = client.post("/lab/up", data={"topology": "../../etc/passwd",
                                     "csrf_token": token})
    assert "No such lab topology" in r.text


def test_lab_up_is_refused_when_netlab_is_absent(lab_ready, client):
    token = _csrf_from(client.get("/lab").text)
    lab_ready["monkeypatch"].setattr(lab_ready["appmod"].lab_runner,
                                     "is_available", lambda: False)
    r = client.post("/lab/up", data={"topology": lab_ready["id"],
                                     "csrf_token": token})
    assert "netlab is not installed" in r.text


def test_lab_up_requires_a_valid_csrf_token(lab_ready, client):
    r = client.post("/lab/up", data={"topology": lab_ready["id"],
                                     "csrf_token": "wrong"})
    assert "Invalid form token" in r.text


def test_lab_audit_starts_a_job_and_redirects_to_its_results(lab_ready, client):
    import types

    from netauto.inventory import Device
    from netauto.lab.inventory import Mapped

    lab_ready["monkeypatch"].setattr(
        lab_ready["appmod"], "lab_nodes_for",
        lambda p: Mapped(devices=[Device(name="r1", platform="cisco_ios",
                                         host="10.0.0.1", credentials="LAB")],
                         skipped=[]))
    started = []
    lab_ready["monkeypatch"].setattr(
        client.app.state.lab, "start",
        lambda action, topology, user: (
            started.append((action, topology, user))
            or types.SimpleNamespace(id="job123")))
    token = _csrf_from(client.get("/lab").text)
    r = client.post("/lab/audit", data={"topology": lab_ready["id"],
                                        "csrf_token": token},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/lab/audits/job123"
    assert started == [("audit", "/labs/demo/topology.yml", "alice")]


def test_lab_audit_is_refused_when_the_lab_is_down(lab_ready, client):
    # lab_ready leaves lab_nodes_for returning None -> the lab is down.
    token = _csrf_from(client.get("/lab").text)
    r = client.post("/lab/audit", data={"topology": lab_ready["id"],
                                        "csrf_token": token})
    assert "not up" in r.text


def test_lab_audit_page_renders_the_findings(lab_ready, client):
    from netauto.lab.service import AUDIT, DONE, LabJob

    job = LabJob(id="a1", action=AUDIT, topology="/labs/demo/topology.yml",
                 user="alice", status=DONE,
                 results=[{"device": "r1", "platform": "cisco_ios", "findings": [
                     {"rule_id": "SSH1", "title": "SSH v2 only", "severity": "high",
                      "status": "fail", "detail": "telnet is enabled",
                      "evidence": ["transport input telnet"]}]}],
                 summary={"devices": 1, "fail": 1, "pass": 0, "errors": 0})
    client.app.state.lab.store.add(job)
    body = client.get("/lab/audits/a1").text
    assert "Lab audit" in body and "r1" in body
    assert "SSH1" in body and "telnet is enabled" in body


def test_lab_audit_page_rejects_a_non_audit_job(lab_ready, client):
    from netauto.lab.service import DONE, LabJob, UP

    client.app.state.lab.store.add(
        LabJob(id="u1", action=UP, topology="t", user="alice", status=DONE))
    assert "No such lab audit" in client.get("/lab/audits/u1").text
