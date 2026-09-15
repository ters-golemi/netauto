"""The netlab wrapper: snapshot parsing, platform mapping, and the CLI runner.

Phase 1 is testable without a hypervisor, and that is the whole point of the
seam. The snapshot parser and the mapper run against a captured fixture; the
runner runs against a faked netlab binary, asserting the argv it builds and how
it treats exit codes -- never touching libvirt, containerlab, or a device.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netauto.errors import LabError
from netauto.inventory import Device
from netauto.lab import inventory as lab_inventory
from netauto.lab import runner
from netauto.lab import snapshot as lab_snapshot

FIXTURE = Path(__file__).parent / "fixtures" / "netlab_snapshot.yml"


# --- snapshot parsing -------------------------------------------------------

def test_load_reads_every_node_from_the_fixture():
    nodes = lab_snapshot.load(FIXTURE)
    assert {n.name for n in nodes} == {"r1", "r2", "sw1", "fw1", "x1", "lb1", "ghost"}


def test_ansible_host_is_preferred_for_the_management_ip():
    nodes = {n.name: n for n in lab_snapshot.load(FIXTURE)}
    assert nodes["r1"].mgmt_ip == "192.168.121.101"
    assert nodes["r1"].kind == "iosv"


def test_management_ip_falls_back_to_mgmt_ipv4_with_the_prefix_stripped():
    # sw1 has no ansible_host, only mgmt.ipv4 = 192.168.121.103/24.
    nodes = {n.name: n for n in lab_snapshot.load(FIXTURE)}
    assert nodes["sw1"].mgmt_ip == "192.168.121.103"


def test_a_node_with_no_address_parses_with_a_none_ip_rather_than_vanishing():
    nodes = {n.name: n for n in lab_snapshot.load(FIXTURE)}
    assert nodes["ghost"].mgmt_ip is None


def test_parse_rejects_a_document_with_no_nodes():
    with pytest.raises(LabError, match="top-level 'nodes'"):
        lab_snapshot.parse({"provider": "clab"})


def test_parse_rejects_an_empty_document():
    with pytest.raises(LabError):
        lab_snapshot.parse({})


def test_parse_accepts_a_list_of_nodes_naming_each_from_its_field():
    nodes = lab_snapshot.parse(
        {"nodes": [{"name": "a", "device": "eos", "ansible_host": "10.0.0.9"}]}
    )
    assert nodes[0].name == "a" and nodes[0].mgmt_ip == "10.0.0.9"


def test_load_reports_a_missing_file_as_a_laberror():
    with pytest.raises(LabError, match="not found"):
        lab_snapshot.load(FIXTURE.parent / "does-not-exist.yml")


def test_load_reports_invalid_yaml_as_a_laberror(tmp_path):
    bad = tmp_path / "snap.yml"
    bad.write_text("nodes: [unterminated\n")
    with pytest.raises(LabError, match="not valid YAML"):
        lab_snapshot.load(bad)


# --- platform mapping -------------------------------------------------------

def test_the_drivable_kinds_map_to_the_right_platforms():
    assert lab_inventory.platform_for("iosv") == "cisco_ios"
    assert lab_inventory.platform_for("eos") == "arista_eos"
    assert lab_inventory.platform_for("nxos") == "cisco_nxos"
    assert lab_inventory.platform_for("vsrx") == "juniper_junos"


def test_every_mapped_platform_has_a_real_driver():
    from netauto.drivers import supported_platforms

    known = set(supported_platforms())
    for kind, platform in lab_inventory.KIND_TO_PLATFORM.items():
        assert platform in known, f"{kind} maps to unknown platform {platform}"


def test_unsupported_kinds_do_not_map():
    assert lab_inventory.platform_for("frr") is None
    assert lab_inventory.platform_for("vyos") is None
    assert lab_inventory.platform_for("srlinux") is None


def test_map_nodes_keeps_drivable_devices_and_sets_them_lab_scoped():
    mapped = lab_inventory.map_nodes(lab_snapshot.load(FIXTURE))
    by_name = {d.name: d for d in mapped.devices}
    # r1, r2, sw1, fw1 are drivable and have addresses; x1/lb1/ghost are not.
    assert set(by_name) == {"r1", "r2", "sw1", "fw1"}
    r1 = by_name["r1"]
    assert isinstance(r1, Device)
    assert r1.platform == "cisco_ios" and r1.host == "192.168.121.101"
    assert r1.tags == ("lab",)


def test_lab_devices_carry_the_lab_credential_prefix_by_default():
    mapped = lab_inventory.map_nodes(lab_snapshot.load(FIXTURE))
    assert all(d.credentials == "LAB" for d in mapped.devices)
    assert mapped.devices[0].credentials_prefix == "LAB"


def test_a_custom_credential_prefix_is_honoured():
    mapped = lab_inventory.map_nodes(lab_snapshot.load(FIXTURE), credentials="MYLAB")
    assert all(d.credentials == "MYLAB" for d in mapped.devices)


def test_skipped_nodes_are_reported_with_a_reason():
    mapped = lab_inventory.map_nodes(lab_snapshot.load(FIXTURE))
    reasons = {node.name: reason for node, reason in mapped.skipped}
    assert set(reasons) == {"x1", "lb1", "ghost"}
    assert "no netauto driver" in reasons["x1"]
    assert "no management IP" in reasons["ghost"]


def test_from_snapshot_returns_an_inventory_of_only_the_drivable_nodes():
    inv = lab_inventory.from_snapshot(lab_snapshot.load(FIXTURE))
    assert len(inv) == 4
    assert {d.name for d in inv} == {"r1", "r2", "sw1", "fw1"}


# --- the CLI runner (faked netlab) ------------------------------------------

@pytest.fixture
def fake_netlab(monkeypatch):
    """Replace netlab discovery and subprocess with a recorder.

    Returns a dict the test can read: `calls` is every argv passed to netlab,
    and the test sets `returncode`/`stdout`/`stderr` to steer the fake.
    """
    state = {"calls": [], "returncode": 0, "stdout": "ok", "stderr": ""}
    monkeypatch.setattr(runner.shutil, "which", lambda _: "/usr/bin/netlab")

    class FakeCompleted:
        def __init__(self):
            self.returncode = state["returncode"]
            self.stdout = state["stdout"]
            self.stderr = state["stderr"]

    def fake_run(argv, **kwargs):
        state["calls"].append((argv, kwargs))
        return FakeCompleted()

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    return state


def test_is_available_reflects_whether_netlab_is_on_path(monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda _: None)
    assert runner.is_available() is False
    monkeypatch.setattr(runner.shutil, "which", lambda _: "/usr/bin/netlab")
    assert runner.is_available() is True


def test_commands_refuse_to_run_when_netlab_is_absent(monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda _: None)
    with pytest.raises(LabError, match="not installed"):
        runner.up("topology.yml")


def test_up_builds_the_expected_argv_and_runs_in_the_lab_directory(fake_netlab):
    runner.up("labs/spine-leaf/topology.yml", provider="clab")
    (argv, kwargs), = fake_netlab["calls"]
    assert argv == ["/usr/bin/netlab", "up", "--provider", "clab"]
    assert kwargs["cwd"] == "labs/spine-leaf"


def test_a_non_default_topology_filename_is_passed_with_dash_t(fake_netlab):
    runner.up("labs/demo.yml")
    (argv, _), = fake_netlab["calls"]
    assert argv == ["/usr/bin/netlab", "up", "-t", "demo.yml"]


def test_down_with_cleanup_adds_the_flag(fake_netlab):
    runner.down("topology.yml", cleanup=True)
    (argv, _), = fake_netlab["calls"]
    assert argv == ["/usr/bin/netlab", "down", "--cleanup"]


def test_write_snapshot_uses_the_pinned_output_form(fake_netlab):
    path = runner.write_snapshot("topology.yml")
    (argv, _), = fake_netlab["calls"]
    assert argv == ["/usr/bin/netlab", "create", "-o", f"yaml={runner.SNAPSHOT_FILE}"]
    assert path.name == runner.SNAPSHOT_FILE


def test_a_nonzero_exit_surfaces_netlabs_stderr(fake_netlab):
    fake_netlab["returncode"] = 1
    fake_netlab["stderr"] = "libvirt: could not find image iosv"
    with pytest.raises(LabError, match="could not find image iosv"):
        runner.up("topology.yml")


def test_inventory_without_refresh_parses_an_existing_snapshot(fake_netlab, tmp_path):
    # Put a snapshot beside the topology; refresh=False must not call netlab.
    (tmp_path / runner.SNAPSHOT_FILE).write_text(FIXTURE.read_text())
    mapped = runner.read_inventory(tmp_path / "topology.yml", refresh=False)
    assert {d.name for d in mapped.devices} == {"r1", "r2", "sw1", "fw1"}
    assert fake_netlab["calls"] == []  # no netlab invocation when not refreshing


# --- the background lab service ---------------------------------------------

from netauto.lab import service as lab_service  # noqa: E402


def _inline(job):
    """A spawn that runs the job body synchronously, for deterministic tests."""
    job()


def test_up_runs_netlab_up_then_writes_the_snapshot(monkeypatch):
    calls = []
    monkeypatch.setattr(runner, "up", lambda t: calls.append(("up", t)) or "brought up")
    monkeypatch.setattr(runner, "write_snapshot",
                        lambda t: calls.append(("snapshot", t)))
    svc = lab_service.LabService()
    job = svc.start(lab_service.UP, "labs/demo/topology.yml", "alice", spawn=_inline)
    assert job.status == lab_service.DONE
    assert job.output == "brought up"
    assert calls == [("up", "labs/demo/topology.yml"),
                     ("snapshot", "labs/demo/topology.yml")]


def test_a_snapshot_failure_after_up_is_noted_not_fatal(monkeypatch):
    monkeypatch.setattr(runner, "up", lambda t: "up ok")
    def boom(_):
        raise LabError("no netlab to dump")
    monkeypatch.setattr(runner, "write_snapshot", boom)
    svc = lab_service.LabService()
    job = svc.start(lab_service.UP, "topology.yml", "alice", spawn=_inline)
    assert job.status == lab_service.DONE  # the lab is up; the dump merely failed
    assert "snapshot not written" in job.output


def test_down_runs_netlab_down_with_cleanup(monkeypatch):
    calls = []
    monkeypatch.setattr(runner, "down",
                        lambda t, cleanup=False: calls.append((t, cleanup)) or "torn down")
    svc = lab_service.LabService()
    job = svc.start(lab_service.DOWN, "topology.yml", "bob", spawn=_inline)
    assert job.status == lab_service.DONE and job.output == "torn down"
    assert calls == [("topology.yml", True)]


def test_a_failed_netlab_command_marks_the_job_failed(monkeypatch):
    def boom(_):
        raise LabError("libvirt is not running")
    monkeypatch.setattr(runner, "up", boom)
    svc = lab_service.LabService()
    job = svc.start(lab_service.UP, "topology.yml", "alice", spawn=_inline)
    assert job.status == lab_service.FAILED
    assert "libvirt is not running" in job.error


def test_running_for_guards_one_lab_per_topology():
    store = lab_service.LabJobStore()
    job = lab_service.LabJob(id="1", action=lab_service.UP,
                             topology="labs/demo/topology.yml", user="alice",
                             status=lab_service.RUNNING)
    store.add(job)
    # The route always hands running_for the same discovered path; a trailing
    # slash normalises, a different topology does not match.
    assert store.running_for("labs/demo/topology.yml") is job
    assert store.running_for("labs/demo/topology.yml/") is job
    assert store.running_for("labs/other/topology.yml") is None


def test_the_store_keeps_newest_first_and_evicts_finished():
    store = lab_service.LabJobStore(max_jobs=2)
    for i in range(3):
        store.add(lab_service.LabJob(id=str(i), action=lab_service.UP,
                                     topology=f"t{i}", user="a",
                                     status=lab_service.DONE,
                                     created_at=float(i)))
    ids = [j.id for j in store.list()]
    assert ids == ["2", "1"]  # newest first, oldest finished job evicted


# --- auditing a lab ---------------------------------------------------------

from netauto.lab import audit as lab_audit  # noqa: E402


def _dev(name, platform="cisco_ios", host="10.0.0.1"):
    return Device(name=name, platform=platform, host=host, credentials="LAB")


def test_audit_lab_audits_each_drivable_node(monkeypatch):
    from netauto.config import Settings

    mapped = lab_inventory.Mapped(
        devices=[_dev("r1", "cisco_ios"), _dev("r2", "arista_eos")],
        skipped=[(lab_snapshot.LabNode("x1", "frr", "10.0.0.9"),
                  "no netauto driver for netlab kind 'frr'")],
    )
    monkeypatch.setattr(lab_audit.runner, "read_inventory",
                        lambda t, refresh=False: mapped)
    audited = []

    def fake_audit(device, settings):
        audited.append(device.name)
        return {"device": device.name, "platform": device.platform,
                "summary": {"pass": 3, "fail": 1, "critical": 0, "high": 1}}

    monkeypatch.setattr(lab_audit, "audit_device", fake_audit)
    result = lab_audit.audit_lab("labs/demo/topology.yml",
                                 Settings(inventory_path="x"))
    assert audited == ["r1", "r2"]
    assert result.summary == {"devices": 2, "fail": 2, "pass": 6,
                              "errors": 0, "critical": 0, "high": 2}
    # The nodes netauto cannot drive are carried through, not dropped.
    assert result.skipped[0][0].name == "x1"


def test_audit_lab_counts_an_unreachable_node_as_an_error_not_a_pass(monkeypatch):
    from netauto.config import Settings

    mapped = lab_inventory.Mapped(devices=[_dev("r1")], skipped=[])
    monkeypatch.setattr(lab_audit.runner, "read_inventory",
                        lambda t, refresh=False: mapped)
    monkeypatch.setattr(lab_audit, "audit_device",
                        lambda d, s: {"device": d.name, "platform": d.platform,
                                      "error": "no route to host", "findings": []})
    result = lab_audit.audit_lab("t", Settings(inventory_path="x"))
    assert result.summary["errors"] == 1 and result.summary["pass"] == 0


def test_audit_action_runs_the_ruleset_and_stores_results(monkeypatch):
    fake = lab_audit.LabAudit(
        topology="t",
        results=[{"device": "r1", "summary": {"fail": 1, "pass": 2}}],
        summary={"devices": 1, "fail": 1, "pass": 2, "errors": 0},
    )
    monkeypatch.setattr(lab_audit, "audit_lab", lambda topo, settings: fake)
    svc = lab_service.LabService()
    job = svc.start(lab_service.AUDIT, "t", "alice", spawn=_inline)
    assert job.status == lab_service.DONE
    assert job.results == fake.results and job.summary == fake.summary
    assert "1 device audited" in job.output


# --- the CI gate ------------------------------------------------------------

import io  # noqa: E402

from netauto.lab import ci  # noqa: E402


def _audit(results, skipped=None):
    return lab_audit.LabAudit(
        topology="t", results=results,
        summary=lab_audit.summarize(results), skipped=skipped or [])


def _finding(rule, sev, status="fail"):
    return {"rule_id": rule, "title": rule, "severity": sev, "status": status}


def test_gate_fails_on_an_unreachable_node():
    audit = _audit([{"device": "r1", "error": "no route", "findings": []}])
    assert ci.gate(audit, "any") == ["r1: unreachable (no route)"]


def test_gate_fails_on_a_finding_at_or_above_the_threshold():
    audit = _audit([{"device": "r1", "findings": [_finding("SSH1", "high")]}])
    assert ci.gate(audit, "high")  # high >= high
    assert ci.gate(audit, "critical") == []  # high is below the critical floor


def test_gate_any_fails_on_a_finding_of_any_severity():
    audit = _audit([{"device": "r1", "findings": [_finding("X", "low")]}])
    assert ci.gate(audit, "any")
    assert ci.gate(audit, "high") == []  # low is below high


def test_gate_ignores_passing_findings():
    audit = _audit([{"device": "r1",
                     "findings": [_finding("OK", "critical", status="pass")]}])
    assert ci.gate(audit, "any") == []


@pytest.fixture
def ci_stubs(monkeypatch):
    """Fake netlab up/down; the test supplies the audit result."""
    calls = []
    monkeypatch.setattr(ci.runner, "up",
                        lambda t, provider=None: calls.append(("up", t, provider)))
    monkeypatch.setattr(ci.runner, "down",
                        lambda t, cleanup=False: calls.append(("down", t, cleanup)))
    return calls


def _run(topology="t", **kw):
    from netauto.config import Settings
    out = io.StringIO()
    code = ci.run(topology, Settings(inventory_path="x"), out=out, **kw)
    return code, out.getvalue()


def test_run_returns_ok_and_tears_down_on_a_clean_audit(ci_stubs, monkeypatch):
    monkeypatch.setattr(ci, "audit_lab", lambda t, s, refresh=False: _audit(
        [{"device": "r1", "findings": [_finding("OK", "high", status="pass")]}]))
    code, text = _run(fail_on="high")
    assert code == ci.OK and "PASS" in text
    assert ("down", "t", True) in ci_stubs


def test_run_returns_findings_and_still_tears_down_on_a_dirty_audit(ci_stubs, monkeypatch):
    monkeypatch.setattr(ci, "audit_lab", lambda t, s, refresh=False: _audit(
        [{"device": "r1", "findings": [_finding("SSH1", "critical")]}]))
    code, text = _run(fail_on="high")
    assert code == ci.FINDINGS and "FAIL" in text and "SSH1" in text
    assert ("down", "t", True) in ci_stubs  # torn down even on failure


def test_run_keep_leaves_the_lab_up(ci_stubs, monkeypatch):
    monkeypatch.setattr(ci, "audit_lab", lambda t, s, refresh=False: _audit([]))
    code, text = _run(keep=True)
    assert code == ci.OK
    assert not any(c[0] == "down" for c in ci_stubs)
    assert "--keep" in text


def test_run_returns_infra_when_the_lab_will_not_come_up(monkeypatch):
    def boom(t, provider=None):
        raise LabError("libvirt is not running")
    monkeypatch.setattr(ci.runner, "up", boom)
    downs = []
    monkeypatch.setattr(ci.runner, "down", lambda t, cleanup=False: downs.append(t))
    code, text = _run()
    assert code == ci.INFRA and "did not come up" in text
    assert downs == []  # nothing was brought up, so nothing is torn down


def test_run_returns_infra_but_still_tears_down_when_audit_errors(ci_stubs, monkeypatch):
    def boom(t, s, refresh=False):
        raise LabError("snapshot could not be written")
    monkeypatch.setattr(ci, "audit_lab", boom)
    code, text = _run()
    assert code == ci.INFRA
    assert ("down", "t", True) in ci_stubs  # finally still ran


def test_main_maps_arguments_to_run(monkeypatch):
    captured = {}
    def fake_run(topology, settings=None, **kw):
        captured.update(topology=topology, **kw)
        return ci.OK
    monkeypatch.setattr(ci, "run", fake_run)
    rc = ci.main(["labs/demo/topology.yml", "--fail-on", "any", "--provider", "clab"])
    assert rc == ci.OK
    assert captured["topology"] == "labs/demo/topology.yml"
    assert captured["fail_on"] == "any" and captured["provider"] == "clab"
    assert captured["keep"] is False


def test_the_mixed_vendor_sample_maps_as_documented():
    """Each node in the shipped mixed-vendor lab must map to a real driver, or
    be a kind netauto knowingly skips -- so the sample cannot claim a platform
    netauto does not actually drive."""
    import yaml

    topo = yaml.safe_load(Path("labs/mixed-vendor/topology.yml").read_text())
    platforms = set()
    for name, node in topo["nodes"].items():
        kind = node["device"]
        platform = lab_inventory.platform_for(kind)
        if platform is None:
            assert kind in lab_inventory.UNSUPPORTED_KINDS, (
                f"{name} uses {kind!r}, which is neither mapped nor a known "
                f"unsupported kind")
        else:
            platforms.add(platform)
    # The point of the sample is vendor spread across netauto's drivers.
    assert {"juniper_junos", "arista_eos", "cisco_nxos", "cisco_ios"} <= platforms
