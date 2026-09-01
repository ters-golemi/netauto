"""HPE Aruba AOS-CX via the REST API (pyaoscx).

AOS-CX exposes a versioned REST API rather than a stable CLI contract, so this
driver talks REST and maps show-style commands onto it where it can. Written
against pyaoscx 2.6; not yet exercised against physical hardware.
"""

from __future__ import annotations

import json
from typing import Any

from netauto.config import resolve_credentials
from netauto.drivers.base import Driver, assert_read_only
from netauto.errors import AuthError, DriverError

DEFAULT_API_VERSION = "10.09"


class AosCxDriver(Driver):
    """Aruba AOS-CX switches."""

    capabilities = frozenset({"facts", "config"})

    def open(self) -> None:
        from pyaoscx.session import Session

        if not self.device.host:
            raise DriverError(f"Device {self.device.name!r} has no host address.")
        creds = resolve_credentials(self.device.credentials_prefix)
        api_version = str(self.device.options.get("api_version", DEFAULT_API_VERSION))
        try:
            session = Session(self.device.host, api_version)
            session.open(creds["username"], creds["password"])
        except Exception as exc:
            message = str(exc).lower()
            if "auth" in message or "401" in message:
                raise AuthError(f"{self.device.name}: authentication failed: {exc}") from exc
            raise DriverError(f"{self.device.name}: connection failed: {exc}") from exc
        self._conn = session

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def _require(self) -> Any:
        if self._conn is None:
            raise DriverError(f"{self.device.name}: driver is not open.")
        return self._conn

    def facts(self) -> dict[str, Any]:
        from pyaoscx.device import Device as AosDevice

        session = self._require()
        try:
            dev = AosDevice(session)
            dev.get()
        except Exception as exc:
            raise DriverError(f"{self.device.name}: device query failed: {exc}") from exc
        return {
            "name": self.device.name,
            "platform": self.device.platform,
            "vendor": "HPE Aruba",
            "model": getattr(dev, "platform_name", None),
            "os_version": getattr(dev, "firmware_version", None),
            "hostname": getattr(dev, "hostname", None),
            "serial_number": getattr(dev, "serial_number", None),
        }

    def get_config(self, kind: str = "running") -> str:
        from pyaoscx.configuration import Configuration

        if kind not in ("running", "startup"):
            raise DriverError(f"AOS-CX exposes running and startup configs, not {kind!r}.")
        session = self._require()
        try:
            config = Configuration(session)
            data = config.get_full_config(config_name=f"{kind}-config")
        except Exception as exc:
            raise DriverError(f"{self.device.name}: config retrieval failed: {exc}") from exc
        return data if isinstance(data, str) else json.dumps(data, indent=2, sort_keys=True)

    def run_read(self, command: str) -> str:
        assert_read_only(command, self.device.platform)
        raise DriverError(
            "AOS-CX has no CLI transport in this driver. Use get_config, or add an "
            "aruba_osswitch inventory entry to reach the same switch over SSH."
        )
