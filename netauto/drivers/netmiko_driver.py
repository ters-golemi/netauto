"""CLI-only platforms via netmiko.

Used where napalm has no driver: Aruba's AOS-Switch line and FortiGate's SSH
CLI. Configuration retrieval is a plain show command, so the per-platform
detail lives in two class attributes rather than in code.
"""

from __future__ import annotations

from typing import Any

from netauto.config import resolve_credentials
from netauto.drivers.base import Driver, assert_read_only
from netauto.errors import AuthError, DriverError, UnsupportedOperation


class NetmikoDriver(Driver):
    """Generic netmiko wrapper. Subclass and set device_type."""

    device_type: str = ""
    running_config_command: str = "show running-config"
    facts_command: str = "show version"
    neighbors_command: str = "show lldp neighbors detail"
    capabilities = frozenset({"facts", "config", "command", "neighbors"})

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

    def neighbors(self) -> list[dict[str, Any]]:
        """LLDP neighbours, parsed by TextFSM rather than by hand.

        netmiko ships ntc-templates, so use_textfsm gives structured rows for
        the platforms that have a template. Hand-rolled regex over LLDP output
        is a losing game -- the column widths and field order move between
        vendors and firmware revisions.

        The command still goes through assert_read_only, so this cannot become
        a way around the guard.
        """
        conn = self._require()
        cmd = assert_read_only(self.neighbors_command, self.device.platform)
        try:
            parsed = conn.send_command(cmd, use_textfsm=True,
                                       read_timeout=self.settings.command_timeout)
        except Exception as exc:
            raise DriverError(
                f"{self.device.name}: {cmd!r} failed: {exc}"
            ) from exc

        # With no matching template TextFSM hands back the raw string. Refusing
        # is better than shipping a half-parsed diagram that looks authoritative.
        if not isinstance(parsed, list):
            raise UnsupportedOperation(
                f"{self.device.name}: no TextFSM template matched {cmd!r} for "
                f"device type {self.device_type!r}, so neighbours cannot be read "
                f"reliably. Retrieve it with net_run_show and read it by eye."
            )

        def pick(row: dict[str, Any], *names: str) -> str:
            """Field names differ per template; take the first that is filled."""
            for n in names:
                value = row.get(n)
                if value:
                    return str(value).strip()
            return ""

        out: list[dict[str, Any]] = []
        for row in parsed:
            if not isinstance(row, dict):
                continue
            out.append({
                "local_port": pick(row, "local_interface", "local_port", "interface"),
                "remote_host": pick(row, "neighbor", "neighbor_name", "system_name",
                                    "device_id", "chassis_id"),
                "remote_port": pick(row, "neighbor_interface", "neighbor_port_id",
                                    "port_id", "remote_port"),
                "remote_description": pick(row, "system_description", "neighbor_description"),
                "remote_chassis_id": pick(row, "chassis_id"),
            })
        return out


class ArubaOsSwitchDriver(NetmikoDriver):
    """HPE Aruba AOS-Switch, formerly ProCurve."""

    device_type = "hp_procurve"
    running_config_command = "show running-config"
    facts_command = "show system-information"
    # ProCurve says "lldp info remote-device", not "lldp neighbors"; this is
    # the form ntc-templates has a parser for.
    neighbors_command = "show lldp info remote-device"


class FortinetCliDriver(NetmikoDriver):
    """FortiGate over SSH. The REST driver is usually the better choice."""

    device_type = "fortinet"
    running_config_command = "show full-configuration"
    facts_command = "get system status"
    # No estate-wide LLDP command here worth relying on: FortiOS exposes
    # neighbours per-port ("diagnose lldprx port neighbor-details port-name
    # <port>"), so there is nothing to enumerate a whole device with. Declared
    # unsupported rather than guessed at -- the topology run reports it as a
    # gap instead of silently drawing a firewall with no links.
    capabilities = frozenset({"facts", "config", "command"})
