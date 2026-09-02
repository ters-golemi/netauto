"""Append-only activity log.

Per-user accounts only mean something if actions are attributable, so every
device-touching request is recorded with the account that made it. Written as
JSON lines: trivially greppable, and safe to append to from multiple workers.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

MAX_TAIL = 500


def default_path() -> Path:
    env = os.environ.get("NETAUTO_ACTIVITY_LOG")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent.parent / "activity.log"


def record(user: str, action: str, target: str = "", detail: str = "",
           path: Path | None = None) -> None:
    """Append one entry. Never raises: logging must not break a request."""
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "user": user,
        "action": action,
        "target": target,
        "detail": detail,
    }
    try:
        p = path or default_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    except OSError:
        pass


def tail(limit: int = 200, path: Path | None = None) -> list[dict[str, Any]]:
    """Most recent entries, newest first. Unparseable lines are skipped."""
    p = path or default_path()
    if not p.exists():
        return []
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out: list[dict[str, Any]] = []
    for line in reversed(lines[-MAX_TAIL:]):
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
        if len(out) >= limit:
            break
    return out
