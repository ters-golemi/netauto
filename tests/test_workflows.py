"""The workflow module: specs, the runner, and the Word export.

The safety-critical test here is the first one. A workflow is a list of
commands that get sent to a device, so if the list could contain something the
read-only guard would refuse, the whole toolkit's central claim would be a
matter of whoever last edited a tuple. The guard decides, and this proves it
was asked.
"""

from __future__ import annotations

import io
import zipfile
from contextlib import contextmanager

import pytest

from netauto.config import Settings
from netauto.drivers.base import assert_read_only
from netauto.errors import DriverError, NetautoError, UnsafeCommand
from netauto.inventory import Device, Inventory
from netauto.workflows import runner, spec
from netauto.workflows.document import build as build_docx
from netauto.workflows.spec import CONFIG_CHECK, COMMANDS, DOCUMENTATION, REGISTRY, SOFTWARE_UPGRADE

IOS_CONFIG = """hostname core-sw-01
aaa new-model
service timestamps log datetime msec
banner login ^Authorised users only^
spanning-tree portfast bpduguard default
line aux 0
 no exec
 transport input none
line vty 0 4
 access-class MGMT in
 transport input ssh
 exec-timeout 10 0
snmp-server community s3cret RO
ntp server 10.0.0.1
logging host 10.0.0.2
ip http secure-server
no ip http server
enable secret 5 $1$abc
service password-encryption
ip ssh version 2
"""

WEAK_CONFIG = "hostname bad-sw\ntransport input telnet\nsnmp-server community public rw\n"


class FakeDriver:
    """A driver that answers from canned text, honouring the guard."""

    def __init__(self, config: str, *, capabilities=("facts", "config", "command"),
                 fail: str = "", refuse: tuple[str, ...] = ()):
        self.config = config
        self.capabilities = frozenset(capabilities)
        self.fail = fail
        self.refuse = refuse
        self.commands_run: list[str] = []

    def facts(self):
        return {"vendor": "Cisco", "model": "C9300", "os_version": "17.9.4",
                "serial_number": "FCW123", "hostname": "core-sw-01"}

    def get_config(self, kind="running"):
        return self.config

    def run_read(self, command):
        # The fake enforces the same guard the real drivers do, so a test that
        # smuggles a bad command fails here rather than passing quietly.
        assert_read_only(command, "cisco_ios")
        if command in self.refuse:
            raise DriverError(f"% Invalid input: {command}")
        self.commands_run.append(command)
        return f"output of {command}"


@pytest.fixture
def settings():
    return Settings(inventory_path="unused")


def _inventory(*devices: Device) -> Inventory:
    return Inventory(list(devices))


def _patch_connect(monkeypatch, drivers: dict[str, object]):
    @contextmanager
    def fake_connect(device, settings):
        got = drivers[device.name]
        if isinstance(got, Exception):
            raise got
        yield got

    monkeypatch.setattr(runner, "connect", fake_connect)


def _run(monkeypatch, workflow_id: str, devices, drivers, settings):
    """Execute a workflow inline so the test is deterministic."""
    wf = spec.get(workflow_id)
    _patch_connect(monkeypatch, drivers)
    service = runner.WorkflowService()
    inv = _inventory(*devices)
    return service.start(wf, inv, settings, list(devices), "tester",
                         spawn=lambda job: job())


# -- specs -----------------------------------------------------------------

def test_every_workflow_command_passes_the_read_only_guard():
    """The whole safety model, asserted rather than assumed."""
    checked = 0
    for platform, commands in COMMANDS.items():
        for command in commands:
            checked += 1
            try:
                assert_read_only(command, platform)
            except UnsafeCommand as exc:
                pytest.fail(f"{platform}: {command!r} is not read-only: {exc}")
    assert checked > 50, "command sets look suspiciously empty"


def test_there_are_three_workflows_for_every_supported_platform():
    from netauto.drivers import supported_platforms

    for platform in supported_platforms():
        kinds = {s.kind for s in spec.for_platform(platform)}
        assert kinds == {CONFIG_CHECK, DOCUMENTATION, SOFTWARE_UPGRADE}, platform
    assert len(REGISTRY) == 3 * len(supported_platforms())


def test_platforms_without_a_cli_say_why_rather_than_looking_unfinished():
    for platform in ("meraki", "aruba_central", "aruba_aoscx"):
        wf = spec.get(f"{CONFIG_CHECK}--{platform}")
        assert not wf.has_cli
        assert wf.no_cli_reason, f"{platform} has no commands and no explanation"


def test_no_command_can_chain():
    """The guard rejects pipes; this catches a well-meant edit that adds one."""
    for platform, commands in COMMANDS.items():
        for command in commands:
            assert "|" not in command, f"{platform}: {command!r} pipes"


# -- runner ----------------------------------------------------------------

def test_a_run_walks_every_step_and_collects_findings(monkeypatch, settings):
    device = Device(name="core-sw-01", platform="cisco_ios")
    driver = FakeDriver(IOS_CONFIG)
    run = _run(monkeypatch, f"{CONFIG_CHECK}--cisco_ios", [device],
               {"core-sw-01": driver}, settings)

    assert run.status == runner.DONE, run.error
    assert run.progress == 100
    assert [s.status for s in run.steps] == [runner.DONE] * 5
    assert driver.commands_run == list(COMMANDS["cisco_ios"])
    assert run.results[0].findings, "no rules were evaluated"


def test_an_unreachable_device_is_recorded_and_does_not_abort_the_run(
    monkeypatch, settings
):
    good = Device(name="core-sw-01", platform="cisco_ios")
    bad = Device(name="core-sw-02", platform="cisco_ios")
    run = _run(
        monkeypatch, f"{CONFIG_CHECK}--cisco_ios", [good, bad],
        {"core-sw-01": FakeDriver(IOS_CONFIG),
         "core-sw-02": NetautoError("authentication failed")},
        settings,
    )
    assert run.status == runner.DONE
    assert run.totals()["unreachable"] == 1
    unreachable = [r for r in run.results if not r.reachable]
    assert "authentication failed" in unreachable[0].error
    # The device that answered still produced findings.
    assert any(r.reachable and r.findings for r in run.results)


def test_one_refused_command_does_not_cost_the_whole_device(monkeypatch, settings):
    device = Device(name="core-sw-01", platform="cisco_ios")
    driver = FakeDriver(IOS_CONFIG, refuse=("show mlag", "show vlan brief"))
    run = _run(monkeypatch, f"{CONFIG_CHECK}--cisco_ios", [device],
               {"core-sw-01": driver}, settings)

    result = run.results[0]
    assert result.reachable
    assert "show vlan brief" in result.command_errors
    assert result.outputs, "the commands that worked were discarded too"
    assert run.step("commands").status == runner.DONE
    assert "refused" in run.step("commands").message


def test_a_platform_with_no_cli_skips_the_command_step_with_a_reason(
    monkeypatch, settings
):
    device = Device(name="mx-01", platform="meraki")
    driver = FakeDriver('{"networks": []}', capabilities=("facts", "config"))
    run = _run(monkeypatch, f"{CONFIG_CHECK}--meraki", [device],
               {"mx-01": driver}, settings)

    step = run.step("commands")
    assert step.status == runner.SKIPPED
    assert "no CLI" in step.message or "Dashboard API" in step.message
    assert run.status == runner.DONE


def test_findings_see_show_output_as_well_as_the_configuration(
    monkeypatch, settings
):
    """The corpus is config plus command output, so a rule can match either."""
    device = Device(name="core-sw-01", platform="cisco_ios")
    # The banner is absent from the config but present in show output.
    config = IOS_CONFIG.replace("banner login ^Authorised users only^\n", "")
    driver = FakeDriver(config)
    run = _run(monkeypatch, f"{CONFIG_CHECK}--cisco_ios", [device],
               {"core-sw-01": driver}, settings)
    corpus_seen = run.results[0].outputs
    assert corpus_seen, "no command output was collected to analyse"


def test_a_weak_configuration_produces_ranked_findings(monkeypatch, settings):
    device = Device(name="bad-sw", platform="cisco_ios")
    run = _run(monkeypatch, f"{CONFIG_CHECK}--cisco_ios", [device],
               {"bad-sw": FakeDriver(WEAK_CONFIG)}, settings)

    failed = run.results[0].failed_findings
    assert failed, "a deliberately weak config produced no findings"
    severities = [f.severity for f in failed]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    assert severities == sorted(severities, key=lambda s: order[s]), \
        "findings are not ranked worst-first"
    assert all(f.remediation for f in failed), "a finding with no recommendation"


def test_a_driver_that_explodes_fails_the_run_without_losing_it(
    monkeypatch, settings
):
    device = Device(name="core-sw-01", platform="cisco_ios")

    @contextmanager
    def boom(device, settings):
        raise RuntimeError("driver blew up")
        yield  # pragma: no cover

    monkeypatch.setattr(runner, "connect", boom)
    service = runner.WorkflowService()
    run = service.start(spec.get(f"{CONFIG_CHECK}--cisco_ios"), _inventory(device),
                        settings, [device], "tester", spawn=lambda job: job())
    assert run.status == runner.FAILED
    assert "driver blew up" in run.error
    assert service.store.get(run.id) is run, "a failed run must stay viewable"


def test_the_store_never_evicts_a_running_run():
    store = runner.RunStore(max_runs=2)
    live = runner.Run(id="live", workflow_id="w", kind=CONFIG_CHECK, platform="p",
                      name="n", user="u", targets=[], steps=[], status=runner.RUNNING)
    store.add(live)
    for i in range(5):
        store.add(runner.Run(id=f"old{i}", workflow_id="w", kind=CONFIG_CHECK,
                             platform="p", name="n", user="u", targets=[],
                             steps=[], status=runner.DONE))
    assert store.get("live") is live
    assert len(store.list()) <= 3


# -- Word export -----------------------------------------------------------

def _docx_text(data: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return z.read("word/document.xml").decode("utf-8")


def test_the_export_is_a_real_openable_docx(monkeypatch, settings):
    device = Device(name="core-sw-01", platform="cisco_ios")
    run = _run(monkeypatch, f"{CONFIG_CHECK}--cisco_ios", [device],
               {"core-sw-01": FakeDriver(WEAK_CONFIG)}, settings)
    data = build_docx(run)

    assert data[:2] == b"PK", "not a zip, so not a docx"
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = z.namelist()
        assert "word/document.xml" in names
        assert "[Content_Types].xml" in names
        assert z.testzip() is None

    # python-docx can read back what it wrote.
    from docx import Document
    reopened = Document(io.BytesIO(data))
    assert reopened.paragraphs


def test_the_document_names_the_findings_and_cites_a_source(monkeypatch, settings):
    device = Device(name="core-sw-01", platform="cisco_ios")
    run = _run(monkeypatch, f"{CONFIG_CHECK}--cisco_ios", [device],
               {"core-sw-01": FakeDriver(WEAK_CONFIG)}, settings)
    text = _docx_text(build_docx(run))

    assert "core-sw-01" in text
    assert "Recommendation:" in text
    assert "Source:" in text, "a recommendation with no traceable guidance"
    assert "read-only" in text


def test_an_unreachable_device_appears_in_the_document_rather_than_vanishing(
    monkeypatch, settings
):
    good = Device(name="core-sw-01", platform="cisco_ios")
    bad = Device(name="core-sw-02", platform="cisco_ios")
    run = _run(
        monkeypatch, f"{CONFIG_CHECK}--cisco_ios", [good, bad],
        {"core-sw-01": FakeDriver(IOS_CONFIG),
         "core-sw-02": NetautoError("connection timed out")},
        settings,
    )
    text = _docx_text(build_docx(run))
    assert "Devices not reached" in text
    assert "core-sw-02" in text
    assert "connection timed out" in text


def test_the_documentation_workflow_embeds_a_diagram(monkeypatch, settings):
    from netauto import topology as topology_mod
    from netauto.topology import Link, Node, Topology

    device = Device(name="core-sw-01", platform="cisco_ios")
    topo = Topology()
    topo.nodes["core-sw-01"] = Node(name="core-sw-01", known=True, tier="core")
    topo.nodes["acc-sw-01"] = Node(name="acc-sw-01", known=True, tier="access")
    topo.links = [Link("core-sw-01", "Gi1/1", "acc-sw-01", "Gi1/1", True)]
    monkeypatch.setattr(topology_mod, "build", lambda *a, **kw: topo)

    run = _run(monkeypatch, f"{DOCUMENTATION}--cisco_ios", [device],
               {"core-sw-01": FakeDriver(IOS_CONFIG)}, settings)
    assert run.status == runner.DONE
    assert [s.key for s in run.steps][-3:] == ["topology", "document", "export"]

    data = build_docx(run)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        images = [n for n in z.namelist() if n.startswith("word/media/")]
        assert images, "the documentation workflow produced no diagram"
        assert z.read(images[0])[:8] == bytes([137, 80, 78, 71, 13, 10, 26, 10])


def test_a_missing_diagram_is_stated_rather_than_left_blank(monkeypatch, settings):
    from netauto import topology as topology_mod
    from netauto.topology import Topology

    device = Device(name="core-sw-01", platform="cisco_ios")
    monkeypatch.setattr(topology_mod, "build", lambda *a, **kw: Topology())
    run = _run(monkeypatch, f"{DOCUMENTATION}--cisco_ios", [device],
               {"core-sw-01": FakeDriver(IOS_CONFIG)}, settings)
    text = _docx_text(build_docx(run))
    assert "No topology diagram" in text


# -- web routes ------------------------------------------------------------


@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from netauto.web import app as appmod
    from netauto.web.users import UserStore

    monkeypatch.setenv("NETAUTO_SECRET_KEY", "test-key-not-for-production")
    monkeypatch.setenv("NETAUTO_ACTIVITY_LOG", str(tmp_path / "activity.log"))
    monkeypatch.delenv("NETAUTO_METRICS_TOKEN", raising=False)
    # The page counts devices per platform, so it needs an inventory. Supply
    # one rather than reading whichever gitignored inventory/devices.yaml the
    # checkout happens to have -- see the same note in test_topology.py.
    monkeypatch.setattr(
        appmod, "load_context",
        lambda *a, **kw: (Settings(inventory_path="unused"),
                          Inventory([Device(name="sw", platform="cisco_ios",
                                            host="10.0.0.1", credentials="X")])))
    store = UserStore(tmp_path / "users.yaml")
    store.add("alice", "correct-horse-battery-staple", admin=True)
    appmod._FAILURES.clear()
    c = TestClient(appmod.create_app(store))
    token = c.get("/login").text.split('name="csrf_token" value="')[1].split('"')[0]
    c.post("/login", data={"username": "alice",
                           "password_input": "correct-horse-battery-staple",
                           "csrf_token": token})
    return c


@pytest.mark.parametrize("path", ["/workflows", "/workflows/runs/abc",
                                  "/workflows/runs/abc.docx"])
def test_workflow_routes_require_a_session(tmp_path, monkeypatch, path):
    from fastapi.testclient import TestClient

    from netauto.web.app import create_app
    from netauto.web.users import UserStore

    monkeypatch.setenv("NETAUTO_SECRET_KEY", "k")
    monkeypatch.setenv("NETAUTO_ACTIVITY_LOG", str(tmp_path / "a.log"))
    store = UserStore(tmp_path / "u.yaml")
    store.add("alice", "correct-horse-battery-staple", admin=True)
    c = TestClient(create_app(store), follow_redirects=False)
    assert c.get(path).status_code in (303, 401)


def test_the_workflows_tab_is_in_the_nav(client):
    assert '/workflows' in client.get("/devices").text


def test_the_page_lists_two_workflows_for_every_platform(client):
    body = client.get("/workflows").text
    assert "Device Configuration Check" in body
    assert "Network Documentation Maker" in body
    for platform in ("cisco_ios", "juniper_junos", "meraki", "fortinet_fortios"):
        assert platform in body


def test_starting_a_workflow_needs_the_csrf_token(client):
    r = client.post(f"/workflows/{CONFIG_CHECK}--cisco_ios/start",
                    data={"csrf_token": "wrong"}, follow_redirects=False)
    assert "Invalid form token" in r.text


def test_starting_a_workflow_with_no_matching_devices_says_so(client, monkeypatch):
    """A run over nothing would report a clean result, which would be a lie."""
    junos = Device(name="r1", platform="juniper_junos")
    monkeypatch.setattr(
        "netauto.web.app.load_context",
        lambda *a, **kw: (Settings(inventory_path="x"), _inventory(junos)))
    token = client.get("/workflows").text.split(
        'name="csrf_token" value="')[1].split('"')[0]
    r = client.post(f"/workflows/{CONFIG_CHECK}--cisco_ios/start",
                    data={"csrf_token": token}, follow_redirects=False)
    assert "No cisco_ios devices" in r.text


def test_an_unknown_run_explains_that_runs_are_not_persisted(client):
    body = client.get("/workflows/runs/deadbeef").text
    assert "memory" in body


def test_the_document_is_refused_while_the_run_is_still_going(client):
    app = client.app
    run = runner.Run(id="live1234", workflow_id=f"{CONFIG_CHECK}--cisco_ios",
                     kind=CONFIG_CHECK, platform="cisco_ios", name="n",
                     user="alice", targets=[], steps=[], status=runner.RUNNING)
    app.state.workflows.store.add(run)
    r = client.get("/workflows/runs/live1234.docx")
    assert r.status_code == 409
    assert "partial" in r.text


def test_a_finished_run_downloads_as_a_word_document(client, monkeypatch, settings):
    app = client.app
    device = Device(name="core-sw-01", platform="cisco_ios")
    _patch_connect(monkeypatch, {"core-sw-01": FakeDriver(WEAK_CONFIG)})
    run = app.state.workflows.start(
        spec.get(f"{CONFIG_CHECK}--cisco_ios"), _inventory(device), settings,
        [device], "alice", spawn=lambda job: job())

    r = client.get(f"/workflows/runs/{run.id}.docx")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith(
        "application/vnd.openxmlformats-officedocument")
    assert ".docx" in r.headers["content-disposition"]
    assert r.content[:2] == b"PK"


def test_the_status_endpoint_reports_progress(client, monkeypatch, settings):
    app = client.app
    device = Device(name="core-sw-01", platform="cisco_ios")
    _patch_connect(monkeypatch, {"core-sw-01": FakeDriver(IOS_CONFIG)})
    run = app.state.workflows.start(
        spec.get(f"{CONFIG_CHECK}--cisco_ios"), _inventory(device), settings,
        [device], "alice", spawn=lambda job: job())

    data = client.get(f"/workflows/runs/{run.id}/status").json()
    assert data["status"] == runner.DONE
    assert data["progress"] == 100
    assert [s["key"] for s in data["steps"]] == [
        "connect", "config", "commands", "analyse", "report"]


def test_the_run_page_shows_findings_and_their_sources(client, monkeypatch,
                                                       settings):
    app = client.app
    device = Device(name="core-sw-01", platform="cisco_ios")
    _patch_connect(monkeypatch, {"core-sw-01": FakeDriver(WEAK_CONFIG)})
    run = app.state.workflows.start(
        spec.get(f"{CONFIG_CHECK}--cisco_ios"), _inventory(device), settings,
        [device], "alice", spawn=lambda job: job())

    body = client.get(f"/workflows/runs/{run.id}").text
    assert "core-sw-01" in body
    assert "Source:" in body
    assert "Download the editable Word document" in body


def test_running_a_workflow_is_recorded_against_the_account(client, monkeypatch,
                                                            tmp_path):
    """Every device-touching action is attributable; workflows are no exception."""
    from netauto.web import activity

    device = Device(name="core-sw-01", platform="cisco_ios")
    monkeypatch.setattr(
        "netauto.web.app.load_context",
        lambda *a, **kw: (Settings(inventory_path="x"), _inventory(device)))
    _patch_connect(monkeypatch, {"core-sw-01": FakeDriver(IOS_CONFIG)})
    token = client.get("/workflows").text.split(
        'name="csrf_token" value="')[1].split('"')[0]
    client.post(f"/workflows/{CONFIG_CHECK}--cisco_ios/start",
                data={"csrf_token": token}, follow_redirects=False)

    logged = (tmp_path / "activity.log").read_text()
    assert '"action": "workflow"' in logged
    assert '"user": "alice"' in logged
