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
    assert argv == ["/usr/bin/netlab", "create", "-o", f"yaml:{runner.SNAPSHOT_FILE}"]
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
