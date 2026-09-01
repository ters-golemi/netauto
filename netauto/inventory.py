"""Vendor-neutral device inventory.

The inventory is a plain YAML file listing devices by name, with the platform
string that selects a driver. It holds no secrets -- only a pointer to the
environment-variable prefix that carries them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import yaml

from netauto.errors import NetautoError


@dataclass(frozen=True)
class Device:
    """One managed device."""

    name: str
    platform: str
    host: str | None = None
    port: int | None = None
    credentials: str = ""
    tags: tuple[str, ...] = ()
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def credentials_prefix(self) -> str:
        """Environment prefix for this device's secrets."""
        return self.credentials or self.name.upper().replace("-", "_").replace(".", "_")


class Inventory:
    """A collection of devices loaded from YAML."""

    def __init__(self, devices: list[Device]) -> None:
        self._devices = {d.name: d for d in devices}

    @classmethod
    def load(cls, path: str | Path) -> "Inventory":
        path = Path(path)
        if not path.exists():
            raise NetautoError(
                f"Inventory not found at {path}. Copy inventory/devices.example.yaml "
                f"to {path.name} and list your devices."
            )
        raw = yaml.safe_load(path.read_text()) or {}
        entries = raw.get("devices", raw if isinstance(raw, list) else [])
        devices: list[Device] = []
        for entry in entries:
            if not isinstance(entry, dict) or "name" not in entry or "platform" not in entry:
                raise NetautoError(f"Inventory entry needs 'name' and 'platform': {entry!r}")
            known = {"name", "platform", "host", "port", "credentials", "tags"}
            devices.append(
                Device(
                    name=entry["name"],
                    platform=entry["platform"],
                    host=entry.get("host"),
                    port=entry.get("port"),
                    credentials=entry.get("credentials", ""),
                    tags=tuple(entry.get("tags", ())),
                    options={k: v for k, v in entry.items() if k not in known},
                )
            )
        return cls(devices)

    def get(self, name: str) -> Device:
        try:
            return self._devices[name]
        except KeyError:
            known = ", ".join(sorted(self._devices)) or "<inventory is empty>"
            raise NetautoError(f"Unknown device {name!r}. Known devices: {known}") from None

    def select(self, *, tag: str | None = None, platform: str | None = None) -> list[Device]:
        """Filter devices by tag and/or platform."""
        out = list(self._devices.values())
        if tag:
            out = [d for d in out if tag in d.tags]
        if platform:
            out = [d for d in out if d.platform == platform]
        return out

    def __iter__(self) -> Iterator[Device]:
        return iter(self._devices.values())

    def __len__(self) -> int:
        return len(self._devices)
