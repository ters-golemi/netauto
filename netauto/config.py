"""Settings and credential resolution.

Credentials are never read from the inventory file. Each device names an
environment-variable prefix, and the actual secrets are resolved at connect
time from the process environment. That keeps the inventory safe to commit.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from netauto.errors import AuthError

DEFAULT_CONFIG_NAMES = ("config.yaml", "config.yml")


@dataclass(frozen=True)
class Settings:
    """Runtime settings, loaded from config.yaml."""

    inventory_path: Path
    allow_writes: bool = False
    connect_timeout: int = 30
    command_timeout: int = 60
    max_concurrency: int = 8
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path | None = None, root: Path | None = None) -> "Settings":
        root = Path(root or Path(__file__).resolve().parent.parent)
        if path is None:
            for name in DEFAULT_CONFIG_NAMES:
                candidate = root / name
                if candidate.exists():
                    path = candidate
                    break
        data: dict[str, Any] = {}
        if path is not None and Path(path).exists():
            data = yaml.safe_load(Path(path).read_text()) or {}

        inventory = data.get("inventory_path", "inventory/devices.yaml")
        inventory_path = Path(inventory)
        if not inventory_path.is_absolute():
            inventory_path = root / inventory_path

        known = {"inventory_path", "allow_writes", "connect_timeout",
                 "command_timeout", "max_concurrency"}
        return cls(
            inventory_path=inventory_path,
            allow_writes=bool(data.get("allow_writes", False)),
            connect_timeout=int(data.get("connect_timeout", 30)),
            command_timeout=int(data.get("command_timeout", 60)),
            max_concurrency=int(data.get("max_concurrency", 8)),
            extra={k: v for k, v in data.items() if k not in known},
        )


def resolve_credentials(prefix: str, *, require: tuple[str, ...] = ("USERNAME", "PASSWORD")) -> dict[str, str]:
    """Read credentials for a device from the environment.

    A device whose credentials prefix is ``CORE_SW`` is authenticated with
    ``CORE_SW_USERNAME`` and ``CORE_SW_PASSWORD``; API-only platforms use
    ``CORE_SW_API_KEY`` instead. Missing values raise rather than silently
    attempting an anonymous connection.
    """
    prefix = prefix.upper().rstrip("_")
    creds: dict[str, str] = {}
    missing: list[str] = []
    for key in require:
        var = f"{prefix}_{key}"
        value = os.environ.get(var)
        if value is None:
            missing.append(var)
        else:
            creds[key.lower()] = value
    if missing:
        raise AuthError(
            f"Missing environment variable(s): {', '.join(missing)}. "
            f"Export them before connecting; they are never stored in the inventory."
        )
    # Optional extras, passed through when present.
    for key in ("ENABLE_PASSWORD", "API_KEY", "API_TOKEN", "ORG_ID", "CLIENT_ID", "CLIENT_SECRET"):
        value = os.environ.get(f"{prefix}_{key}")
        if value is not None:
            creds[key.lower()] = value
    return creds
