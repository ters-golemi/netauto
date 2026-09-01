"""Fortinet FortiGate via the FortiOS REST API (fortiosapi).

Token authentication is preferred: create an API user in FortiOS with a
read-only profile and export the token. Username/password is supported as a
fallback. Written against fortiosapi 1.0.5; not exercised against a live unit.
"""

from __future__ import annotations

import json
from typing import Any

from netauto.config import resolve_credentials
from netauto.drivers.base import Driver, assert_read_only
from netauto.errors import AuthError, DriverError


class FortiOsDriver(Driver):
    """A FortiGate appliance."""

    capabilities = frozenset({"facts", "config", "command"})

    def open(self) -> None:
        from fortiosapi import FortiOSAPI

        if not self.device.host:
            raise DriverError(f"Device {self.device.name!r} has no host address.")
        verify = bool(self.device.options.get("verify_tls", True))
        vdom = str(self.device.options.get("vdom", "root"))
        api = FortiOSAPI()
        try:
            token = resolve_credentials(
                self.device.credentials_prefix, require=("API_TOKEN",)
            )["api_token"]
        except AuthError:
            creds = resolve_credentials(self.device.credentials_prefix)
            try:
                api.login(
                    self.device.host, creds["username"], creds["password"],
                    verify=verify, timeout=self.settings.connect_timeout, vdom=vdom,
                )
            except Exception as exc:
                raise AuthError(f"{self.device.name}: FortiOS login failed: {exc}") from exc
        else:
            try:
                api.tokenlogin(
                    self.device.host, token, verify=verify,
                    timeout=self.settings.connect_timeout, vdom=vdom,
                )
            except Exception as exc:
                raise AuthError(f"{self.device.name}: FortiOS token login failed: {exc}") from exc
        self._conn = api
        self._vdom = vdom

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.logout()
            except Exception:
                pass
            self._conn = None

    def _require(self) -> Any:
        if self._conn is None:
            raise DriverError(f"{self.device.name}: driver is not open.")
        return self._conn

    def facts(self) -> dict[str, Any]:
        api = self._require()
        try:
            status = api.monitor("system", "status", vdom=self._vdom)
        except Exception as exc:
            raise DriverError(f"{self.device.name}: system status failed: {exc}") from exc
        results = (status or {}).get("results", {}) if isinstance(status, dict) else {}
        return {
            "name": self.device.name,
            "platform": self.device.platform,
            "vendor": "Fortinet",
            "model": (status or {}).get("model") if isinstance(status, dict) else None,
            "os_version": (status or {}).get("version") if isinstance(status, dict) else None,
            "serial_number": (status or {}).get("serial") if isinstance(status, dict) else None,
            "hostname": results.get("hostname"),
            "vdom": self._vdom,
        }

    def get_config(self, kind: str = "running") -> str:
        if kind != "running":
            raise DriverError(f"FortiOS exposes the running config only, not {kind!r}.")
        api = self._require()
        try:
            backup = api.monitor(
                "system", "config/backup", vdom=self._vdom,
                parameters={"scope": "global"},
            )
        except Exception as exc:
            raise DriverError(f"{self.device.name}: config backup failed: {exc}") from exc
        if isinstance(backup, str):
            return backup
        if isinstance(backup, dict) and isinstance(backup.get("results"), str):
            return backup["results"]
        return json.dumps(backup, indent=2, sort_keys=True, default=str)

    def run_read(self, command: str) -> str:
        """Map a 'get <path> <name>' style command onto the REST CMDB API."""
        api = self._require()
        cmd = assert_read_only(command, self.device.platform)
        parts = cmd.split()
        if parts[0].lower() != "get" or len(parts) < 3:
            raise DriverError(
                f"The FortiOS REST driver accepts 'get <path> <name>', for example "
                f"'get system interface'. Received {cmd!r}. For arbitrary CLI, add a "
                f"fortinet_cli inventory entry instead."
            )
        path, name = parts[1], parts[2]
        try:
            result = api.get(path, name, vdom=self._vdom)
        except Exception as exc:
            raise DriverError(f"{self.device.name}: {cmd!r} failed: {exc}") from exc
        return json.dumps(result, indent=2, sort_keys=True, default=str)
