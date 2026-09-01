"""CLI-only platforms via netmiko.

Used where napalm has no driver: Aruba's AOS-Switch line and FortiGate's SSH
CLI. Configuration retrieval is a plain show command, so the per-platform
detail lives in two class attributes rather than in code.
"""

from __future__ import annotations

from typing import Any

from netauto.config import resolve_credentials
from netauto.drivers.base import Driver, assert_read_only
from netauto.errors import AuthError, DriverError


class NetmikoDriver(Driver):
    """Generic netmiko wrapper. Subclass and set device_type."""

    device_type: str = ""
    running_config_command: str = "show running-config"
    facts_command: str = "show version"
    capabilities = frozenset({"facts", "config", "command"})

    def open(self) -> None:
        from netmiko import ConnectHandler
        from netmiko.exceptions import NetmikoAuthenticationException

        if not self.device.host:
            raise DriverError(f"Device {self.device.name!r} has no host address.")
        creds = resolve_credentials(self.device.credentials_prefix)
        params: dict[str, Any] = {
            "device_type": self.device_type,
            "host": self.device.host,
            "username": creds["username"],
            "password": creds["password"],
            "conn_timeout": self.settings.connect_timeout,
        }
        if self.device.port:
            params["port"] = self.device.port
        if "enable_password" in creds:
            params["secret"] = creds["enable_password"]
        try:
            self._conn = ConnectHandler(**params)
        except NetmikoAuthenticationException as exc:
            raise AuthError(f"{self.device.name}: authentication failed: {exc}") from exc
        except Exception as exc:
            raise DriverError(f"{self.device.name}: connection failed: {exc}") from exc

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.disconnect()
            except Exception:
                pass
            self._conn = None

    def _require(self) -> Any:
        if self._conn is None:
            raise DriverError(f"{self.device.name}: driver is not open.")
        return self._conn

    def facts(self) -> dict[str, Any]:
        output = self.run_read(self.facts_command)
        return {
            "name": self.device.name,
            "platform": self.device.platform,
            "hostname": getattr(self._require(), "base_prompt", None),
            "version_output": output.strip(),
        }

    def get_config(self, kind: str = "running") -> str:
        if kind != "running":
            raise DriverError(
                f"{type(self).__name__} retrieves the running config only, not {kind!r}."
            )
        return self.run_read(self.running_config_command)

    def run_read(self, command: str) -> str:
        conn = self._require()
        cmd = assert_read_only(command, self.device.platform)
        try:
            return conn.send_command(cmd, read_timeout=self.settings.command_timeout)
        except Exception as exc:
            raise DriverError(f"{self.device.name}: {cmd!r} failed: {exc}") from exc


class ArubaOsSwitchDriver(NetmikoDriver):
    """HPE Aruba AOS-Switch, formerly ProCurve."""

    device_type = "hp_procurve"
    running_config_command = "show running-config"
    facts_command = "show system-information"


class FortinetCliDriver(NetmikoDriver):
    """FortiGate over SSH. The REST driver is usually the better choice."""

    device_type = "fortinet"
    running_config_command = "show full-configuration"
    facts_command = "get system status"
