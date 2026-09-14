"""Drive the external netlab CLI: bring a lab up, read it, tear it down.

This is a subprocess wrapper and nothing more. netlab is a heavyweight tool --
it wants libvirt or containerlab, Ansible, device images -- none of which belong
in netauto's dependencies, so netauto never imports netlab; it runs the
installed binary and reads what it writes.

Everything a lab needs lives in one *lab directory*: the topology file, and the
files netlab generates beside it. So every command here runs with ``cwd`` set to
that directory, exactly as an operator would ``cd`` into it before typing
``netlab up``.

Two things are deliberately *out* of scope. This does not configure lab devices
-- netlab's Ansible run does that -- and it does not write to any managed
device. Bringing a lab up provisions throwaway VMs and containers netlab itself
will destroy; it is orchestration of ephemeral infrastructure, a different thing
from netauto's managed-device read-only stance, which is untouched.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

from netauto.errors import LabError
from netauto.inventory import Inventory
from netauto.lab import inventory as lab_inventory
from netauto.lab import snapshot as lab_snapshot

log = logging.getLogger(__name__)

#: The file the snapshot command writes and the parser reads, inside the lab
#: directory. Named, not chosen per-call, so write_snapshot() and
#: read_inventory() agree without passing it around.
SNAPSHOT_FILE = "netlab.snapshot.yml"


def netlab_path() -> str | None:
    """Absolute path to the netlab binary, or None if it is not installed."""
    return shutil.which("netlab")


def is_available() -> bool:
    """Whether netlab can be run at all on this host."""
    return netlab_path() is not None


def _require_netlab() -> str:
    path = netlab_path()
    if path is None:
        raise LabError(
            "netlab is not installed or not on PATH. Install it with "
            "'pip install networklab' and a provider (libvirt or containerlab). "
            "See docs/netlab-integration.md."
        )
    return path


def _run(args: list[str], *, workdir: Path, timeout: int | None = None) -> str:
    """Run a netlab subcommand in ``workdir``; return stdout or raise LabError.

    netlab's own diagnostics go to stderr; on failure we surface them rather
    than a bare exit code, because "image not found" or "libvirt not running"
    is what the operator needs, not "returned 1".
    """
    netlab = _require_netlab()
    try:
        proc = subprocess.run(
            [netlab, *args],
            cwd=str(workdir),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:  # netlab vanished between check and run
        raise LabError(f"could not execute netlab: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise LabError(
            f"netlab {' '.join(args)} timed out after {timeout}s"
        ) from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise LabError(
            f"netlab {' '.join(args)} failed (exit {proc.returncode}): {detail}"
        )
    return proc.stdout


def _lab_dir(topology: str | Path) -> tuple[Path, list[str]]:
    """Resolve a topology path to its lab directory and the args to name it.

    netlab defaults to ``topology.yml`` in the current directory; when the file
    is named otherwise it is passed with ``-t``. Returning both keeps every
    command consistent about *where* it runs and *which* topology it means.
    """
    path = Path(topology)
    workdir = path.parent if path.parent != Path("") else Path(".")
    args = [] if path.name == "topology.yml" else ["-t", path.name]
    return workdir, args


def up(topology: str | Path, *, provider: str | None = None,
       timeout: int | None = 1800) -> str:
    """Bring a lab up from a topology file. Returns netlab's output.

    Blocks until netlab finishes provisioning and configuring, which for VM
    providers is minutes -- hence the generous default timeout. ``provider``
    overrides the topology's provider (``clab`` or ``libvirt``); left None,
    the topology decides.
    """
    workdir, targs = _lab_dir(topology)
    args = ["up", *targs]
    if provider:
        args += ["--provider", provider]
    return _run(args, workdir=workdir, timeout=timeout)


def down(topology: str | Path, *, cleanup: bool = False,
         timeout: int | None = 600) -> str:
    """Tear a lab down. With ``cleanup`` also removes generated files."""
    workdir, targs = _lab_dir(topology)
    args = ["down", *targs]
    if cleanup:
        args.append("--cleanup")
    return _run(args, workdir=workdir, timeout=timeout)


def status(topology: str | Path, *, timeout: int | None = 60) -> str:
    """Return netlab's status output for the lab (raw text)."""
    workdir, targs = _lab_dir(topology)
    return _run(["status", *targs], workdir=workdir, timeout=timeout)


def write_snapshot(topology: str | Path, *, timeout: int | None = 120) -> Path:
    """Ask netlab to dump the transformed topology as YAML; return its path.

    This is the pinned seam: the ``-o yaml:<file>`` form is what the snapshot
    parser expects. If a netlab release changes it, this one line changes with
    it and the parser's fixtures verify the shape independently.
    """
    workdir, targs = _lab_dir(topology)
    _run(["create", *targs, "-o", f"yaml:{SNAPSHOT_FILE}"],
         workdir=workdir, timeout=timeout)
    return workdir / SNAPSHOT_FILE


def read_inventory(topology: str | Path, *, credentials: str = "LAB",
                   refresh: bool = True) -> lab_inventory.Mapped:
    """Read the running lab and map it to a netauto inventory.

    With ``refresh`` (the default) it regenerates the snapshot first, so the
    inventory reflects the lab as it stands. Pass ``refresh=False`` to parse an
    existing ``netlab.snapshot.yml`` without invoking netlab -- useful once the
    lab is up and unchanging.
    """
    workdir, _ = _lab_dir(topology)
    path = write_snapshot(topology) if refresh else workdir / SNAPSHOT_FILE
    nodes = lab_snapshot.load(path)
    return lab_inventory.map_nodes(nodes, credentials=credentials)


def bring_up(topology: str | Path, *, provider: str | None = None,
             credentials: str = "LAB") -> Inventory:
    """Bring the lab up and hand back the drivable devices as an Inventory.

    The one-call path for a REPL: ``up`` then ``read_inventory``. Skipped nodes
    are logged; call :func:`read_inventory` directly to inspect them.
    """
    up(topology, provider=provider)
    mapped = read_inventory(topology, credentials=credentials)
    for node, reason in mapped.skipped:
        log.warning("lab node %s skipped: %s", node.name, reason)
    return mapped.inventory
