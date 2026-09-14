"""Run netlab up/down as background jobs the GUI can watch.

Bringing a lab up takes minutes -- netlab provisions VMs or containers and runs
Ansible against them -- so the web request cannot wait for it. This is the same
shape as the workflow runner: a job runs on a worker thread, its state lives in
a small in-memory store, and a page polls for progress.

A job here orchestrates *ephemeral lab infrastructure*; it does not write to any
managed device. That distinction is the whole reason the lab pages are separate
from Devices and Audit, and it is why this module lives under netauto.lab rather
than beside the device workflows.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from netauto.errors import LabError
from netauto.lab import runner

#: Finished jobs kept for display. Small: a job holds only netlab's text output.
MAX_JOBS = 20

PENDING, RUNNING, DONE, FAILED = "pending", "running", "done", "failed"

#: The actions a job can be. "up" also writes the snapshot so the lab's nodes
#: can be listed afterwards; "down" tears the lab back down and cleans up.
UP, DOWN = "up", "down"


@dataclass
class LabJob:
    """One netlab up or down, and how it went."""

    id: str
    action: str
    topology: str
    user: str
    status: str = PENDING
    output: str = ""
    error: str = ""
    created_at: float = field(default_factory=time.time)
    finished_at: float = 0.0

    @property
    def running(self) -> bool:
        return self.status == RUNNING

    @property
    def created_label(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.created_at))

    @property
    def duration(self) -> float:
        return (self.finished_at or time.time()) - self.created_at


class LabJobStore:
    """Every lab job this process has run, newest first."""

    def __init__(self, max_jobs: int = MAX_JOBS) -> None:
        self._jobs: dict[str, LabJob] = {}
        self._lock = threading.Lock()
        self._max = max_jobs

    def add(self, job: LabJob) -> None:
        with self._lock:
            self._jobs[job.id] = job
            finished = sorted(
                (j for j in self._jobs.values() if j.status in (DONE, FAILED)),
                key=lambda j: j.created_at,
            )
            while len(self._jobs) > self._max and finished:
                del self._jobs[finished.pop(0).id]

    def get(self, job_id: str) -> LabJob | None:
        return self._jobs.get(job_id)

    def list(self) -> list[LabJob]:
        return sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)

    def running_for(self, topology: str) -> LabJob | None:
        """A job already in flight for this topology, if any.

        One lab per topology at a time: starting an ``up`` while another ``up``
        or ``down`` is still running would race two netlab processes over the
        same generated files.
        """
        norm = str(Path(topology))
        for job in self._jobs.values():
            if job.running and str(Path(job.topology)) == norm:
                return job
        return None


def _run_action(job: LabJob) -> None:
    """The worker body: run the netlab command and record its outcome."""
    job.status = RUNNING
    try:
        if job.action == UP:
            out = runner.up(job.topology)
            # Dump the snapshot so the lab's nodes can be listed without a
            # second, manual step. A lab that came up but whose snapshot failed
            # to write is still up -- note it in the output, do not fail the job.
            try:
                runner.write_snapshot(job.topology)
            except LabError as exc:
                out += f"\n\n[snapshot not written: {exc}]"
            job.output = out
        elif job.action == DOWN:
            job.output = runner.down(job.topology, cleanup=True)
        else:  # defensive: the routes only ever pass UP or DOWN
            raise LabError(f"unknown lab action {job.action!r}")
        job.status = DONE
    except LabError as exc:
        job.status = FAILED
        job.error = str(exc)
    finally:
        job.finished_at = time.time()


class LabService:
    """Starts lab jobs on worker threads and hands out their state."""

    def __init__(self, store: LabJobStore | None = None) -> None:
        self.store = store or LabJobStore()

    def start(self, action: str, topology: str, user: str,
              spawn: Callable[[Callable[[], None]], None] | None = None) -> LabJob:
        job = LabJob(id=uuid.uuid4().hex[:12], action=action,
                     topology=str(topology), user=user)
        self.store.add(job)

        def body() -> None:
            _run_action(job)

        if spawn is not None:  # tests run the job inline
            spawn(body)
        else:
            threading.Thread(target=body, name=f"lab-{job.id}",
                             daemon=True).start()
        return job
