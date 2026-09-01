"""Cisco, Juniper and Arista via napalm.

napalm gives one interface over IOS/IOS-XE, NX-OS, IOS-XR, Junos and EOS, so a
single wrapper covers most of the CLI/NETCONF estate. Driver classes are built
per platform by make_napalm_driver so the registry can stay declarative.
"""

from __future__ import annotations

from typing import Any

from netauto.config import resolve_credentials
from netauto.drivers.base import Driver, assert_read_only
from netauto.errors import AuthError, DriverError

#: napalm's get_config keys, by the kind names this toolkit exposes.
_CONFIG_KINDS = {"running": "running", "startup": "startup", "candidate": "candidate"}


class NapalmDriver(Driver):
    """Wraps a napalm network driver. Subclassed per platform."""

    napalm_name: str = ""
    capabilities = frozenset({"facts", "config", "command", "interfaces"})

    def open(self) -> None:
        from napalm import get_network_driver

        if not self.device.host:
            raise DriverError(f"Device {self.device.name!r} has no host address.")
        creds = resolve_credentials(self.device.credentials_prefix)
        optional: dict[str, Any] = dict(self.device.options.get("optional_args", {}))
        if self.device.port:
            optional.setdefault("port", self.device.port)
        if "enable_password" in creds:
            optional.setdefault("secret", creds["enable_password"])

        driver_cls = get_network_driver(self.napalm_name)
        self._conn = driver_cls(
            hostname=self.device.host,
            username=creds["username"],
            password=creds["password"],
            timeout=self.settings.connect_timeout,
            optional_args=optional,
        )
        try:
            self._conn.open()
        except Exception as exc:  # napalm raises a wide range of vendor errors
            self._conn = None
            message = str(exc)
            if "authentication" in message.lower() or "password" in message.lower():
                raise AuthError(f"{self.device.name}: authentication failed: {exc}") from exc
            raise DriverError(f"{self.device.name}: connection failed: {exc}") from exc

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:  # a failed close must not mask the real error
                pass
            self._conn = None

    def _require(self) -> Any:
        if self._conn is None:
            raise DriverError(f"{self.device.name}: driver is not open.")
        return self._conn

    def facts(self) -> dict[str, Any]:
        conn = self._require()
        try:
            raw = conn.get_facts()
        except Exception as exc:
            raise DriverError(f"{self.device.name}: get_facts failed: {exc}") from exc
        return {
            "name": self.device.name,
            "platform": self.device.platform,
            "vendor": raw.get("vendor"),
            "model": raw.get("model"),
            "os_version": raw.get("os_version"),
            "serial_number": raw.get("serial_number"),
            "hostname": raw.get("hostname"),
            "fqdn": raw.get("fqdn"),
            "uptime_seconds": raw.get("uptime"),
            "interface_count": len(raw.get("interface_list", []) or []),
        }

    def get_config(self, kind: str = "running") -> str:
        conn = self._require()
        key = _CONFIG_KINDS.get(kind)
        if key is None:
            raise DriverError(f"Unknown config kind {kind!r}. Use running, startup or candidate.")
        try:
            configs = conn.get_config(retrieve=key)
        except Exception as exc:
            raise DriverError(f"{self.device.name}: get_config failed: {exc}") from exc
        return configs.get(key, "") or ""

    def run_read(self, command: str) -> str:
        conn = self._require()
        cmd = assert_read_only(command, self.device.platform)
        try:
            result = conn.cli([cmd])
        except Exception as exc:
            raise DriverError(f"{self.device.name}: {cmd!r} failed: {exc}") from exc
        return result.get(cmd, "") or ""

    def interfaces(self) -> dict[str, Any]:
        """Interface state, where the platform supports it."""
        conn = self._require()
        try:
            return conn.get_interfaces()
        except Exception as exc:
            raise DriverError(f"{self.device.name}: get_interfaces failed: {exc}") from exc


def make_napalm_driver(napalm_name: str) -> type[NapalmDriver]:
    """Build a NapalmDriver subclass bound to one napalm platform."""
    return type(
        f"Napalm_{napalm_name}_Driver",
        (NapalmDriver,),
        {"napalm_name": napalm_name, "__doc__": f"napalm driver for {napalm_name}."},
    )
