"""Metrics tests.

Two boundaries carry the weight here: the exposition format, because a single
unescaped quote makes Prometheus reject the whole scrape, and the token gate,
because this endpoint sits outside the login wall.
"""

import pytest
from fastapi.testclient import TestClient

from netauto import metrics
from netauto.metrics import Collector, DeviceResult, Snapshot, render
from netauto.web.app import create_app
from netauto.web.users import UserStore

PW = "correct-horse-battery-staple"
TOKEN = "test-scrape-token"


def _snapshot(**kw):
    base = dict(finished=1_700_000_000.0, seconds=1.5, cycles=1)
    base.update(kw)
    return Snapshot(**base)


def _device(**kw):
    base = dict(name="core-sw-01", platform="cisco_ios", reachable=True,
                seconds=2.0, config_lines=400,
                facts={"vendor": "Cisco", "model": "C9300",
                       "os_version": "17.9.4", "serial_number": "FCW123"},
                summary={"pass": 12, "fail": 3, "skip": 0, "critical": 1, "high": 2},
                findings=[{"rule_id": "no_telnet", "status": "fail",
                           "severity": "critical"},
                          {"rule_id": "ssh_v2", "status": "pass",
                           "severity": "high"}])
    base.update(kw)
    return DeviceResult(**base)


# -- exposition format ---------------------------------------------------


def test_empty_snapshot_still_renders_every_family():
    out = render(Snapshot())
    # Families are emitted even with no samples, so a blank inventory reads as
    # "zero devices" on a dashboard rather than as a broken exporter.
    for name in ("netauto_up", "netauto_devices_total", "netauto_device_up",
                 "netauto_rule_failed", "netauto_findings"):
        assert f"# TYPE {name} " in out
    assert "netauto_up 0" in out
    assert "netauto_devices_total 0" in out


def test_up_is_one_after_a_successful_cycle():
    assert "netauto_up 1" in render(_snapshot())


def test_collector_error_surfaces_and_clears_up():
    out = render(_snapshot(error="Inventory not found at devices.yaml"))
    assert "netauto_up 0" in out
    assert 'netauto_collector_error{error="Inventory not found at devices.yaml"} 1' in out


def test_reachable_device_emits_full_series():
    out = render(_snapshot(results=[_device()]))
    assert 'netauto_device_up{device="core-sw-01",platform="cisco_ios"} 1' in out
    assert 'netauto_device_config_lines{device="core-sw-01"} 400' in out
    assert 'netauto_findings{device="core-sw-01",status="fail"} 3' in out
    assert 'netauto_findings_failed{device="core-sw-01",severity="critical"} 1' in out
    assert 'rule_id="no_telnet",severity="critical"} 1' in out
    assert 'rule_id="ssh_v2",severity="high"} 0' in out


def test_unreachable_device_reports_down_without_inventing_facts():
    out = render(_snapshot(results=[_device(reachable=False, error="timeout",
                                            facts={}, summary={}, findings=[])]))
    assert 'netauto_device_up{device="core-sw-01",platform="cisco_ios"} 0' in out
    # No config, findings or identity should be claimed for a device we could
    # not reach -- a stale 'pass' is worse than a gap.
    assert "netauto_device_config_lines{" not in out
    assert "netauto_device_info{" not in out
    assert "netauto_findings{" not in out


def test_skipped_rules_are_omitted_not_reported_as_passing():
    out = render(_snapshot(results=[_device(findings=[
        {"rule_id": "junos_only", "status": "skip", "severity": "low"}])]))
    assert "junos_only" not in out


def test_none_facts_do_not_render_as_the_string_none():
    out = render(_snapshot(results=[_device(facts={"vendor": "Cisco",
                                                   "model": None,
                                                   "os_version": None})]))
    assert 'model=""' in out
    assert '"None"' not in out


@pytest.mark.parametrize("raw,expected", [
    ('sw"1', 'sw\\"1'),
    ("sw\\1", "sw\\\\1"),
    ("sw\n1", "sw\\n1"),
])
def test_label_values_are_escaped(raw, expected):
    """An unescaped quote in a device name would break the entire scrape."""
    out = render(_snapshot(results=[_device(name=raw)]))
    assert f'device="{expected}"' in out


def test_render_ends_with_a_newline():
    # Prometheus rejects a body whose final line is unterminated.
    assert render(Snapshot()).endswith("\n")


# -- collector -----------------------------------------------------------


def test_interval_floor_is_enforced(monkeypatch):
    """A tight loop here is a login to every switch, not just wasted CPU."""
    monkeypatch.setenv("NETAUTO_METRICS_INTERVAL", "5")
    assert Collector().interval == metrics.MIN_INTERVAL


def test_garbage_interval_stays_manual(monkeypatch):
    """An unreadable interval must not be guessed into device traffic."""
    monkeypatch.setenv("NETAUTO_METRICS_INTERVAL", "soon")
    assert Collector().interval == metrics.MANUAL_ONLY


def test_audits_are_manual_unless_an_interval_is_asked_for(monkeypatch):
    monkeypatch.delenv("NETAUTO_METRICS_INTERVAL", raising=False)
    assert Collector().interval == metrics.MANUAL_ONLY


@pytest.mark.parametrize("value", ["0", "-1", "  "])
def test_non_positive_intervals_mean_manual(monkeypatch, value):
    monkeypatch.setenv("NETAUTO_METRICS_INTERVAL", value)
    assert Collector().interval == metrics.MANUAL_ONLY


def test_an_explicit_interval_is_still_honoured(monkeypatch):
    """Opting in to a background sweep must still work."""
    monkeypatch.setenv("NETAUTO_METRICS_INTERVAL", "1800")
    assert Collector().interval == 1800


def test_manual_collector_starts_no_thread(monkeypatch):
    """Nothing may contact a device on a timer nobody asked for."""
    monkeypatch.delenv("NETAUTO_METRICS_INTERVAL", raising=False)

    def boom(*a, **kw):
        raise AssertionError("a manual collector must not poll")

    monkeypatch.setattr(metrics, "load_context", boom)
    c = Collector()
    c.start()
    try:
        assert c._thread is None
    finally:
        c.stop()


# -- fed by manual audits ------------------------------------------------


def test_record_folds_an_audit_into_the_snapshot():
    c = Collector(interval=0)
    snap = c.record([{"device": "sw1", "platform": "cisco_ios",
                      "summary": {"pass": 3, "fail": 1, "critical": 1},
                      "findings": [{"rule_id": "no_telnet", "status": "fail",
                                    "severity": "critical"}]}])
    assert [r.name for r in snap.results] == ["sw1"]
    assert snap.ready
    assert snap.results[0].audited_at > 0


def test_recording_one_device_does_not_drop_the_others():
    """An audit is usually scoped; replacing would read as the estate shrinking."""
    c = Collector(interval=0)
    c.record([{"device": "sw1", "platform": "cisco_ios", "summary": {"pass": 3}}])
    snap = c.record([{"device": "sw2", "platform": "cisco_ios", "summary": {"pass": 5}}])
    assert [r.name for r in snap.results] == ["sw1", "sw2"]


def test_re_auditing_a_device_replaces_its_result():
    c = Collector(interval=0)
    c.record([{"device": "sw1", "platform": "cisco_ios", "summary": {"fail": 4}}])
    snap = c.record([{"device": "sw1", "platform": "cisco_ios", "summary": {"fail": 0}}])
    assert len(snap.results) == 1
    assert snap.results[0].summary["fail"] == 0


def test_an_unreachable_device_records_as_down():
    c = Collector(interval=0)
    snap = c.record([{"device": "sw1", "platform": "cisco_ios", "error": "timeout"}])
    assert not snap.results[0].reachable
    assert snap.results[0].error == "timeout"


def test_each_device_carries_its_own_audit_time():
    """With manual audits devices go stale at different rates."""
    c = Collector(interval=0)
    c.record([{"device": "sw1", "platform": "cisco_ios", "summary": {"pass": 1}}])
    snap = c.record([{"device": "sw2", "platform": "cisco_ios", "summary": {"pass": 1}}])
    out = render(snap)
    assert 'netauto_device_last_audit_timestamp_seconds{device="sw1"}' in out
    assert 'netauto_device_last_audit_timestamp_seconds{device="sw2"}' in out


def test_a_report_with_no_device_name_is_ignored():
    c = Collector(interval=0)
    assert c.record([{"platform": "cisco_ios"}]).results == []


def test_missing_inventory_becomes_a_snapshot_not_a_crash(monkeypatch, tmp_path):
    from netauto.errors import NetautoError

    def boom():
        raise NetautoError("Inventory not found at nowhere.yaml")

    monkeypatch.setattr(metrics, "load_context", boom)
    snap = Collector(interval=60).collect_once()
    assert "Inventory not found" in snap.error
    assert snap.cycles == 1


def test_empty_inventory_yields_a_clean_cycle(monkeypatch):
    from netauto.config import Settings
    from netauto.inventory import Inventory

    monkeypatch.setattr(metrics, "load_context",
                        lambda: (Settings(inventory_path="x"), Inventory([])))
    snap = Collector(interval=60).collect_once()
    assert snap.error == ""
    assert snap.results == []
    assert snap.ready


# -- the endpoint --------------------------------------------------------


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("NETAUTO_SECRET_KEY", "test-key-not-for-production")
    monkeypatch.setenv("NETAUTO_ACTIVITY_LOG", str(tmp_path / "activity.log"))
    s = UserStore(tmp_path / "users.yaml")
    s.add("alice", PW, admin=True)
    return s


def test_metrics_absent_without_a_token(store, monkeypatch):
    monkeypatch.delenv("NETAUTO_METRICS_TOKEN", raising=False)
    client = TestClient(create_app(store))
    assert client.get("/metrics").status_code == 404


def test_metrics_rejects_a_wrong_token(store, monkeypatch):
    monkeypatch.setenv("NETAUTO_METRICS_TOKEN", TOKEN)
    client = TestClient(create_app(store))
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics",
                      headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_metrics_serves_with_the_right_token(store, monkeypatch):
    monkeypatch.setenv("NETAUTO_METRICS_TOKEN", TOKEN)
    client = TestClient(create_app(store))
    r = client.get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    assert "netauto_build_info" in r.text


def test_metrics_needs_no_session(store, monkeypatch):
    """Prometheus cannot log in, so the token must be sufficient on its own."""
    monkeypatch.setenv("NETAUTO_METRICS_TOKEN", TOKEN)
    client = TestClient(create_app(store))
    r = client.get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200


def test_scraping_never_touches_a_device(store, monkeypatch):
    """The endpoint reads the cache; only the collector opens sessions."""
    monkeypatch.setenv("NETAUTO_METRICS_TOKEN", TOKEN)

    def fail(*a, **kw):
        raise AssertionError("a scrape must not connect to a device")

    monkeypatch.setattr(metrics, "audit_device", fail)
    monkeypatch.setattr(metrics, "load_context", fail)
    client = TestClient(create_app(store))
    for _ in range(3):
        assert client.get("/metrics",
                          headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200


def test_collector_does_not_run_when_metrics_are_off(store, monkeypatch):
    monkeypatch.delenv("NETAUTO_METRICS_TOKEN", raising=False)
    app = create_app(store)
    assert app.state.collector is None


def test_running_an_audit_updates_the_metrics(store, monkeypatch):
    """The audit page is what feeds metrics now, so the wiring must hold."""
    monkeypatch.setenv("NETAUTO_METRICS_TOKEN", TOKEN)
    from netauto.web import app as appmod
    from netauto.config import Settings
    from netauto.inventory import Device, Inventory

    device = Device(name="sw1", platform="cisco_ios", host="10.0.0.1", credentials="X",
                    tags=("core",))
    monkeypatch.setattr(appmod, "load_context",
                        lambda: (Settings(inventory_path="x"), Inventory([device])))
    monkeypatch.setattr(appmod, "audit_device", lambda d, s: {
        "device": "sw1", "platform": "cisco_ios", "config_lines": 120,
        "facts": {"vendor": "Cisco"},
        "summary": {"pass": 9, "fail": 2, "critical": 1, "high": 1},
        "findings": [{"rule_id": "no_telnet", "status": "fail", "severity": "critical"}],
    })
    client = TestClient(create_app(store))
    token = client.get("/login").text.split('name="csrf_token" value="')[1].split('"')[0]
    client.post("/login", data={"username": "alice", "password_input": PW,
                                "csrf_token": token})

    before = client.get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"}).text
    assert 'netauto_device_up{device="sw1"' not in before

    client.get("/audit?tag=core")

    after = client.get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"}).text
    assert 'netauto_device_up{device="sw1",platform="cisco_ios"} 1' in after
    assert 'netauto_findings{device="sw1",status="fail"} 2' in after
    assert 'netauto_rule_failed{device="sw1",rule_id="no_telnet",severity="critical"} 1' in after
