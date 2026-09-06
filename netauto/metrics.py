"""Prometheus metrics, for Grafana dashboards over compliance and reachability.

Auditing opens a real session per device, so a scrape must never drive it: at a
15-second scrape interval that would mean a login to every switch, forever. A
background collector audits on its own slow schedule and caches the result;
`/metrics` renders that cache. A scrape therefore costs nothing on the network
and cannot be used to hammer the estate.

The exposition format is written out by hand rather than pulled from
prometheus_client. What that library gives you is metric *types* for
instrumenting live code -- counters you increment as requests arrive. Here the
snapshot already exists and only needs serialising, which is three escape rules
and a f-string, so the dependency would buy nothing.

Still read-only: this connects to devices exactly the way the audit page does,
through the same driver layer, and asks them for nothing else.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from netauto import __version__
from netauto.audit import audit_device
from netauto.errors import NetautoError
from netauto.session import load_context

log = logging.getLogger(__name__)

# Audits are manual by default: every cycle opens a session per device, and
# nobody wants their estate logged into on a timer they did not ask for.
# Metrics are fed by the audits an operator actually runs. Setting
# NETAUTO_METRICS_INTERVAL to a number of seconds opts in to a background
# sweep as well, for anyone who does want one.
MANUAL_ONLY = 0
MIN_INTERVAL = 60

NAMESPACE = "netauto"


# -- the snapshot --------------------------------------------------------


@dataclass
class DeviceResult:
    """One device's outcome from the last cycle."""

    name: str
    platform: str
    reachable: bool
    error: str = ""
    seconds: float = 0.0
    facts: dict[str, Any] = field(default_factory=dict)
    config_lines: int = 0
    summary: dict[str, int] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    #: Unix time this device was last audited. With manual audits, devices go
    #: stale at different rates, so staleness is per device rather than global.
    audited_at: float = 0.0


@dataclass
class Snapshot:
    """What the last completed cycle produced. Rendered as-is by `render`."""

    results: list[DeviceResult] = field(default_factory=list)
    finished: float = 0.0
    seconds: float = 0.0
    cycles: int = 0
    error: str = ""

    @property
    def ready(self) -> bool:
        return self.cycles > 0


# -- the collector -------------------------------------------------------


def _result_from_report(report: dict[str, Any], *, seconds: float = 0.0,
                        audited_at: float = 0.0) -> DeviceResult:
    """Convert one audit_device report into a metrics result.

    audit_device reports an unreachable device with an "error" key rather than
    by raising, so reachability is read from the report body.
    """
    error = report.get("error", "")
    return DeviceResult(
        name=report["device"],
        platform=report.get("platform", ""),
        reachable=not error,
        error=error,
        seconds=seconds,
        facts=report.get("facts") or {},
        config_lines=report.get("config_lines", 0),
        summary=report.get("summary") or {},
        findings=report.get("findings") or [],
        audited_at=audited_at or time.time(),
    )


def _interval_from_env() -> int:
    """Seconds between background sweeps, or 0 for manual-only (the default)."""
    raw = os.environ.get("NETAUTO_METRICS_INTERVAL", "").strip()
    if not raw:
        return MANUAL_ONLY
    try:
        value = int(raw)
    except ValueError:
        log.warning("NETAUTO_METRICS_INTERVAL=%r is not a number; staying manual", raw)
        return MANUAL_ONLY
    if value <= 0:
        return MANUAL_ONLY
    if value < MIN_INTERVAL:
        # A tight loop here is device load, not just CPU.
        log.warning("NETAUTO_METRICS_INTERVAL=%ds is below the %ds floor; using the floor",
                    value, MIN_INTERVAL)
        return MIN_INTERVAL
    return value


class Collector:
    """Holds the last audit result per device, for the metrics endpoint.

    Nothing here contacts a device on its own unless an interval was asked
    for. The usual path is `record`, called with the results of an audit an
    operator ran.
    """

    def __init__(self, interval: int | None = None) -> None:
        self.interval = interval if interval is not None else _interval_from_env()
        self._snapshot = Snapshot()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def snapshot(self) -> Snapshot:
        with self._lock:
            return self._snapshot

    def collect_once(self) -> Snapshot:
        """Audit every device once. Never raises: failure becomes a snapshot."""
        started = time.time()
        try:
            settings, inventory = load_context()
            devices = list(inventory)
        except NetautoError as exc:
            # A missing inventory or bad config is a state to display, not a
            # crash that takes the collector thread down with it.
            snap = Snapshot(finished=time.time(), seconds=time.time() - started,
                            cycles=self.snapshot.cycles + 1, error=str(exc))
            self._store(snap)
            return snap

        results: list[DeviceResult] = []
        if devices:
            workers = max(1, min(settings.max_concurrency, len(devices)))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                results = list(pool.map(lambda d: self._audit(d, settings), devices))

        snap = Snapshot(
            results=sorted(results, key=lambda r: r.name),
            finished=time.time(),
            seconds=time.time() - started,
            cycles=self.snapshot.cycles + 1,
        )
        self._store(snap)
        return snap

    def _audit(self, device: Any, settings: Any) -> DeviceResult:
        started = time.time()
        try:
            report = audit_device(device, settings)
        except Exception as exc:  # a driver raising something unmapped
            log.warning("audit of %s failed: %s", device.name, exc)
            return DeviceResult(name=device.name, platform=device.platform,
                                reachable=False, error=str(exc),
                                seconds=time.time() - started)
        return _result_from_report(report, seconds=time.time() - started,
                                   audited_at=time.time())

    def record(self, reports: list[dict[str, Any]]) -> Snapshot:
        """Fold the results of an audit into the snapshot.

        Merged per device rather than replacing wholesale, because an audit is
        usually scoped to one device or one tag. Replacing would drop every
        device the operator did not just look at, and Prometheus would read
        that as the estate shrinking.
        """
        merged = {r.name: r for r in self.snapshot.results}
        now = time.time()
        for report in reports:
            name = report.get("device")
            if not name:
                continue
            merged[name] = _result_from_report(report, audited_at=now)
        snap = Snapshot(
            results=sorted(merged.values(), key=lambda r: r.name),
            finished=now,
            seconds=0.0,
            cycles=self.snapshot.cycles + 1,
        )
        self._store(snap)
        return snap

    def _store(self, snap: Snapshot) -> None:
        with self._lock:
            self._snapshot = snap

    # -- background thread ------------------------------------------------

    def _loop(self) -> None:  # only runs when an interval was configured
        while not self._stop.is_set():
            try:
                self.collect_once()
            except Exception:  # never let the thread die on us
                log.exception("metrics collection cycle failed")
            self._stop.wait(self.interval)

    def start(self) -> None:
        """Start the background sweep, if one was asked for."""
        if not self.interval:
            log.info("metrics collector is manual: audits feed it, nothing polls")
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="netauto-metrics",
                                        daemon=True)
        self._thread.start()
        log.info("metrics collector started, auditing every %ds", self.interval)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)
            self._thread = None


# -- exposition ----------------------------------------------------------

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def _label_value(value: Any) -> str:
    """Escape a label value: backslash, double quote, newline."""
    return (str(value).replace("\\", "\\\\")
                      .replace('"', '\\"')
                      .replace("\n", "\\n"))


def _help_text(value: str) -> str:
    """Escape HELP text: backslash and newline only, quotes are literal."""
    return value.replace("\\", "\\\\").replace("\n", "\\n")


def _number(value: float) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    return repr(float(value))


class _Writer:
    """Accumulates metric families in exposition order."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def family(self, name: str, kind: str, help_text: str,
               samples: list[tuple[dict[str, Any], float]]) -> None:
        """One metric family. Emitted even when empty, so absence is visible."""
        full = f"{NAMESPACE}_{name}"
        self.lines.append(f"# HELP {full} {_help_text(help_text)}")
        self.lines.append(f"# TYPE {full} {kind}")
        for labels, value in samples:
            if labels:
                rendered = ",".join(f'{k}="{_label_value(v)}"'
                                    for k, v in labels.items())
                self.lines.append(f"{full}{{{rendered}}} {_number(value)}")
            else:
                self.lines.append(f"{full} {_number(value)}")

    def render(self) -> str:
        return "\n".join(self.lines) + "\n"


def render(snapshot: Snapshot) -> str:
    """Render a snapshot as Prometheus text exposition format."""
    w = _Writer()

    w.family("up", "gauge",
             "1 when the exporter has a completed audit cycle to report.",
             [({}, 1 if snapshot.ready and not snapshot.error else 0)])
    w.family("build_info", "gauge", "Netauto version, as a label.",
             [({"version": __version__}, 1)])
    w.family("collector_error", "gauge",
             "1 when the last cycle failed before reaching any device.",
             [({"error": snapshot.error}, 1)] if snapshot.error else [])
    w.family("devices_total", "gauge", "Devices in the inventory.",
             [({}, len(snapshot.results))])
    w.family("audit_cycles_total", "counter",
             "Audit cycles completed since start.", [({}, snapshot.cycles)])
    newest = max((r.audited_at for r in snapshot.results), default=snapshot.finished)
    w.family("last_audit_timestamp_seconds", "gauge",
             "Unix time of the most recent audit of any device.", [({}, newest)])
    w.family("audit_cycle_seconds", "gauge",
             "Wall-clock duration of the last cycle.", [({}, snapshot.seconds)])

    results = snapshot.results
    w.family("device_up", "gauge",
             "1 when the last audit connected to the device, 0 when it did not.",
             [({"device": r.name, "platform": r.platform}, 1 if r.reachable else 0)
              for r in results])
    w.family("device_audit_seconds", "gauge",
             "Time taken to audit each device.",
             [({"device": r.name}, r.seconds) for r in results])
    # Audits are manual, so devices go stale at different rates. A single
    # global timestamp would hide a device nobody has looked at for months.
    w.family("device_last_audit_timestamp_seconds", "gauge",
             "Unix time each device was last audited.",
             [({"device": r.name}, r.audited_at) for r in results])
    w.family("device_config_lines", "gauge",
             "Lines in the retrieved running config.",
             [({"device": r.name}, r.config_lines)
              for r in results if r.reachable])

    # An info metric: the value is always 1, the facts ride as labels. Only
    # emitted for reachable devices, since facts come from the device itself.
    info = []
    for r in results:
        if not r.reachable:
            continue
        # Drivers report unknown facts as None, which would otherwise render as
        # the literal label value "None".
        def fact(*names: str) -> str:
            for n in names:
                value = r.facts.get(n)
                if value is not None:
                    return str(value)
            return ""

        info.append(({
            "device": r.name,
            "platform": r.platform,
            "vendor": fact("vendor"),
            "model": fact("model"),
            "os_version": fact("os_version"),
            "serial": fact("serial_number", "serial"),
        }, 1))
    w.family("device_info", "gauge",
             "Device identity from the last audit; value is always 1.", info)

    w.family("findings", "gauge",
             "Rule outcomes on the last audit, by status.",
             [({"device": r.name, "status": status}, r.summary.get(status, 0))
              for r in results if r.reachable
              for status in ("pass", "fail", "skip")])
    w.family("findings_failed", "gauge",
             "Failing rules on the last audit, by severity.",
             [({"device": r.name, "severity": severity},
               r.summary.get(severity, 0))
              for r in results if r.reachable
              for severity in ("critical", "high")])

    # Per-rule state is what makes a dashboard actionable: it names the rule
    # that broke, not just a count. 15 rules times the estate size.
    rules = []
    for r in results:
        for f in r.findings:
            if f.get("status") == "skip":
                continue
            rules.append(({
                "device": r.name,
                "rule_id": f.get("rule_id", ""),
                "severity": f.get("severity", ""),
            }, 1 if f.get("status") == "fail" else 0))
    w.family("rule_failed", "gauge",
             "1 when a rule failed on a device, 0 when it passed.", rules)

    return w.render()
