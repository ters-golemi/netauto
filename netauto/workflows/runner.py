"""Background execution of workflow runs.

A run opens a real session per device and executes a pipeline of steps, which
takes minutes across an estate -- far too long to hold an HTTP request open.
So a run is started, given an id, and polled.

Runs live in memory and nowhere else. The obvious improvement is to write them
under ~/.local/share/netauto so they survive a restart, and it is deliberately
not done: a run holds full running-configurations, which carry password
hashes, community strings and key material. netauto keeps credentials off
disk, the Audit page persists nothing, and a workflow that quietly wrote every
device's config into a state directory would undo that while looking like a
convenience. Documents are streamed to the browser for the same reason.

The cost is real and worth stating plainly: restarting netauto-web loses run
history. Re-run the workflow.
"""

from __future__ import annotations

import itertools
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from netauto.audit import SEVERITY_ORDER
from netauto.checks import Finding, run_ruleset
from netauto.checks.vendor import VENDOR
from netauto.config import Settings
from netauto.drivers.base import platform_family
from netauto.errors import NetautoError
from netauto.inventory import Device, Inventory
from netauto.session import connect
from netauto.workflows.spec import CONFIG_CHECK, DOCUMENTATION, SOFTWARE_UPGRADE, WorkflowSpec

#: How many finished runs to keep. Each holds every target's configuration in
#: memory, so this is a memory bound, not a tidiness preference.
MAX_RUNS = 20

PENDING, RUNNING, DONE, SKIPPED, FAILED = "pending", "running", "done", "skipped", "failed"


@dataclass
class StepState:
    key: str
    title: str
    detail: str
    status: str = PENDING
    message: str = ""

    @property
    def finished(self) -> bool:
        return self.status in (DONE, SKIPPED, FAILED)


@dataclass
class DeviceResult:
    """What one device contributed."""

    device: str
    platform: str
    error: str = ""
    facts: dict[str, Any] = field(default_factory=dict)
    config: str = ""
    outputs: dict[str, str] = field(default_factory=dict)
    command_errors: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    # Software Upgrade workflow
    current_version: str = ""
    target_version: str = ""
    needs_upgrade: bool | None = None
    upgrade_action: str = ""      # installed | staged | manual | skipped
    upgrade_message: str = ""
    runbook: str = ""

    @property
    def reachable(self) -> bool:
        return not self.error

    @property
    def config_lines(self) -> int:
        return len(self.config.splitlines())

    @property
    def failed_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.failed]

    def summary(self) -> dict[str, int]:
        out = {"pass": 0, "fail": 0, "skip": 0, "critical": 0, "high": 0}
        for f in self.findings:
            out[f.status] = out.get(f.status, 0) + 1
            if f.failed and f.severity in ("critical", "high"):
                out[f.severity] += 1
        return out


@dataclass
class Run:
    """One execution of one workflow."""

    id: str
    workflow_id: str
    kind: str
    platform: str
    name: str
    user: str
    targets: list[str]
    steps: list[StepState]
    status: str = PENDING
    error: str = ""
    created_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    results: list[DeviceResult] = field(default_factory=list)
    topology: Any = None
    #: Free-form workflow parameters. Software Upgrade reads image/server here.
    params: dict[str, Any] = field(default_factory=dict)
    _cancel: threading.Event = field(default_factory=threading.Event)

    # -- presentation ------------------------------------------------------

    @property
    def running(self) -> bool:
        return self.status == RUNNING

    @property
    def created_label(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.created_at))

    @property
    def duration(self) -> float:
        return (self.finished_at or time.time()) - self.created_at

    @property
    def progress(self) -> int:
        """Percentage of steps finished, for the progress bar."""
        if not self.steps:
            return 0
        return int(100 * sum(1 for s in self.steps if s.finished) / len(self.steps))

    def step(self, key: str) -> StepState:
        for s in self.steps:
            if s.key == key:
                return s
        raise KeyError(key)

    def totals(self) -> dict[str, int]:
        out = {"devices": len(self.results), "unreachable": 0, "fail": 0,
               "pass": 0, "critical": 0, "high": 0}
        for r in self.results:
            if not r.reachable:
                out["unreachable"] += 1
                continue
            s = r.summary()
            for k in ("fail", "pass", "critical", "high"):
                out[k] += s.get(k, 0)
        return out

    def cancel(self) -> None:
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()


class RunStore:
    """Every run this process has seen, newest first."""

    def __init__(self, max_runs: int = MAX_RUNS) -> None:
        self._runs: dict[str, Run] = {}
        self._lock = threading.Lock()
        self._max = max_runs

    def add(self, run: Run) -> None:
        with self._lock:
            self._runs[run.id] = run
            # Evict finished runs oldest-first. A running one is never evicted,
            # or its own thread would be writing into a discarded object.
            finished = sorted(
                (r for r in self._runs.values() if r.status in (DONE, FAILED)),
                key=lambda r: r.created_at,
            )
            while len(self._runs) > self._max and finished:
                del self._runs[finished.pop(0).id]

    def get(self, run_id: str) -> Run | None:
        return self._runs.get(run_id)

    def list(self) -> list[Run]:
        return sorted(self._runs.values(), key=lambda r: r.created_at, reverse=True)


def _mark(step: StepState, status: str, message: str = "") -> None:
    step.status = status
    step.message = message


def execute(run: Run, spec: WorkflowSpec, inventory: Inventory, settings: Settings,
            devices: list[Device]) -> None:
    """Run the pipeline. Called on a worker thread; never raises."""
    run.status = RUNNING
    try:
        if spec.kind == SOFTWARE_UPGRADE:
            _upgrade(run, spec, settings, devices)
        else:
            _collect(run, spec, devices, settings)
            if spec.kind == DOCUMENTATION:
                _document(run, spec, inventory, settings, devices)
        run.status = DONE
    except Exception as exc:  # a failed run must still be viewable
        run.status = FAILED
        run.error = f"{type(exc).__name__}: {exc}"
        for step in run.steps:
            if not step.finished:
                _mark(step, FAILED, "Run aborted.")
    finally:
        run.finished_at = time.time()


def _collect(run: Run, spec: WorkflowSpec, devices: list[Device],
             settings: Settings) -> None:
    """Steps 1-4: connect, pull config, run commands, evaluate the ruleset."""
    connect_step = run.step("connect")
    config_step = run.step("config")
    commands_step = run.step("commands")
    analyse_step = run.step("analyse")
    for s in (connect_step, config_step, commands_step, analyse_step):
        _mark(s, RUNNING)

    family = platform_family(spec.platform)
    for device in devices:
        if run.cancelled:
            break
        result = DeviceResult(device=device.name, platform=device.platform)
        run.results.append(result)
        try:
            with connect(device, settings) as driver:
                result.facts = driver.facts()
                result.config = driver.get_config("running")
                if spec.has_cli and "command" in driver.capabilities:
                    for command in spec.commands:
                        if run.cancelled:
                            break
                        try:
                            result.outputs[command] = driver.run_read(command)
                        except NetautoError as exc:
                            # One unsupported command must not cost the whole
                            # device: a feature absent on this model is normal.
                            result.command_errors[command] = str(exc)
        except NetautoError as exc:
            result.error = str(exc)
            continue

        # The show-command output is appended to the configuration text so a
        # rule can match either. Rules stay pure functions over text, and
        # nothing has to learn a second input shape.
        corpus = "\n".join([result.config, *result.outputs.values()])
        findings = run_ruleset(VENDOR, device.name, family, corpus, result.facts)
        findings.sort(key=lambda f: (f.status != "fail",
                                     SEVERITY_ORDER.get(f.severity, 9), f.rule_id))
        result.findings = findings

    reached = [r for r in run.results if r.reachable]
    _mark(connect_step, DONE, f"{len(reached)} of {len(run.results)} devices answered.")
    _mark(config_step, DONE,
          f"{sum(r.config_lines for r in reached)} configuration lines pulled.")
    if not spec.has_cli:
        _mark(commands_step, SKIPPED, spec.no_cli_reason)
    else:
        ran = sum(len(r.outputs) for r in reached)
        errs = sum(len(r.command_errors) for r in reached)
        _mark(commands_step, DONE,
              f"{ran} command outputs collected"
              + (f", {errs} refused by the device." if errs else "."))
    totals = run.totals()
    _mark(analyse_step, DONE,
          f"{len(VENDOR.for_family(family))} rules evaluated; "
          f"{totals['fail']} findings need attention.")
    # Only the configuration check ends at a report. The documentation
    # workflow carries on into topology, assembly and export, and has no such
    # step to mark.
    if spec.kind == CONFIG_CHECK:
        _mark(run.step("report"), DONE, "Report ready.")


def _document(run: Run, spec: WorkflowSpec, inventory: Inventory,
              settings: Settings, devices: list[Device]) -> None:
    """Steps 5-7: neighbours, assemble, export."""
    from netauto import topology as topology_mod

    topo_step = run.step("topology")
    _mark(topo_step, RUNNING)
    try:
        run.topology = topology_mod.build(inventory, settings, devices)
        node_count = len(run.topology.nodes)
        gap_count = len(run.topology.gaps)
        _mark(topo_step, DONE,
              f"{node_count} nodes, {len(run.topology.links)} links"
              + (f", {gap_count} devices contributed nothing." if gap_count else "."))
    except NetautoError as exc:
        # A missing diagram is a gap in the document, not a failed run.
        _mark(topo_step, FAILED, str(exc))

    _mark(run.step("document"), DONE,
          f"{len(run.results)} devices documented.")
    _mark(run.step("export"), DONE, "Word document ready to download.")


def _runbook(r: "DeviceResult", target: dict, image: str, server: str, proto: str) -> str:
    """A copy-pasteable runbook for the upgrade, whether or not netauto pushed it."""
    img = image or "<firmware-image.out>"
    srv = server or "<tftp-server-ip>"
    lines = [
        f"Upgrade runbook — {r.device}",
        f"  Current version : {r.current_version or 'unknown'}",
        f"  Target version  : {r.target_version or 'not defined'}",
        f"  Path            : {target.get('note','')}",
        "",
        "  1. Back up the running configuration (captured by this run: "
        f"{r.config_lines} lines).",
        "  2. Stage the image on a TFTP/FTP server the switch can reach, then verify:",
        f"       execute stage image {proto} {img} {srv}",
        "       execute verify image primary        # expect: No issue found!",
        "  3. Install (this reboots the switch):",
        f"       execute restore image {proto} {img} {srv}",
        "  4. After reboot, reconnect and confirm the version, then re-run the "
        "Configuration Check to confirm the config survived.",
        "  Rollback: boot the previous image from the boot menu, or re-restore the "
        "prior build; the configuration backup from step 1 is the known-good point.",
    ]
    return "\n".join(lines)


def _upgrade(run: Run, spec: WorkflowSpec, settings: Settings, devices: list[Device]) -> None:
    """Software Upgrade: snapshot, verify the path, optionally push, runbook.

    The only workflow that can write. The push happens in the 'upgrade' step and
    only when every gate is open (allow_writes, the upgrade capability, an image
    and server supplied); otherwise the step is skipped and the runbook carries
    the manual steps. Everything else here is read-only.
    """
    connect_step = run.step("connect"); snap = run.step("snapshot")
    verify = run.step("verify"); up = run.step("upgrade"); rb = run.step("runbook")
    for st in (connect_step, snap, verify, up, rb):
        _mark(st, RUNNING)

    target = spec.upgrade_target
    image = str(run.params.get("image", "")).strip()
    server = str(run.params.get("server", "")).strip()
    proto = str(run.params.get("protocol", "tftp")).strip() or "tftp"
    stage_only = bool(run.params.get("stage_only", False))

    for device in devices:
        if run.cancelled:
            break
        result = DeviceResult(device=device.name, platform=device.platform)
        run.results.append(result)
        result.target_version = target.get("version", "")
        try:
            with connect(device, settings) as driver:
                result.facts = driver.facts()
                result.current_version = str(result.facts.get("os_version", "") or "")
                result.config = driver.get_config("running")
                result.needs_upgrade = (bool(result.target_version)
                                        and result.current_version != result.target_version)
                # the write, only past every gate
                if not result.target_version:
                    result.upgrade_action = "skipped"
                    result.upgrade_message = "No recommended target for this platform."
                elif not result.needs_upgrade:
                    result.upgrade_action = "skipped"
                    result.upgrade_message = f"Already on {result.current_version}."
                elif not settings.allow_writes:
                    result.upgrade_action = "manual"
                    result.upgrade_message = ("allow_writes is off — install is a manual "
                                              "step. See the runbook.")
                elif "upgrade" not in driver.capabilities:
                    result.upgrade_action = "manual"
                    result.upgrade_message = "Driver has no upgrade path — manual step."
                elif not (image and server):
                    result.upgrade_action = "manual"
                    result.upgrade_message = ("No image/server supplied — install is a "
                                              "manual step. See the runbook.")
                else:
                    out = driver.upgrade_firmware(image=image, server=server,
                                                  protocol=proto, stage_only=stage_only,
                                                  confirm=device.name)
                    result.upgrade_action = "staged" if stage_only else "installed"
                    result.upgrade_message = out[:300]
        except NetautoError as exc:
            result.error = str(exc)
            if not result.upgrade_action:
                result.upgrade_action = "skipped"; result.upgrade_message = str(exc)
        result.runbook = _runbook(result, target, image, server, proto)

    reached = [r for r in run.results if r.reachable]
    _mark(connect_step, DONE, f"{len(reached)} of {len(run.results)} devices answered.")
    _mark(snap, DONE, f"{sum(r.config_lines for r in reached)} config lines backed up.")
    need = [r for r in reached if r.needs_upgrade]
    _mark(verify, DONE,
          f"target {target.get('version','—')}; {len(need)} of {len(reached)} need it.")
    did = [r for r in run.results if r.upgrade_action in ("installed", "staged")]
    manual = [r for r in run.results if r.upgrade_action == "manual"]
    if did:
        _mark(up, DONE, f"{len(did)} device(s) {did[0].upgrade_action}; rebooting where installed.")
    elif manual:
        _mark(up, SKIPPED, "Install left as a manual step — see the runbook.")
    else:
        _mark(up, SKIPPED, "Nothing to upgrade.")
    _mark(rb, DONE, "Runbook ready.")


class WorkflowService:
    """Starts runs on worker threads and hands out their state."""

    def __init__(self, store: RunStore | None = None) -> None:
        self.store = store or RunStore()
        self._counter = itertools.count(1)

    def start(self, spec: WorkflowSpec, inventory: Inventory, settings: Settings,
              devices: list[Device], user: str,
              spawn: Callable[[Callable[[], None]], None] | None = None) -> Run:
        run = Run(
            id=uuid.uuid4().hex[:12],
            workflow_id=spec.id,
            kind=spec.kind,
            platform=spec.platform,
            name=spec.name,
            user=user,
            targets=[d.name for d in devices],
            steps=[StepState(s.key, s.title, s.detail) for s in spec.steps],
        )
        self.store.add(run)

        def job() -> None:
            execute(run, spec, inventory, settings, devices)

        if spawn is not None:  # tests run the pipeline inline
            spawn(job)
        else:
            threading.Thread(target=job, name=f"workflow-{run.id}",
                             daemon=True).start()
        return run
