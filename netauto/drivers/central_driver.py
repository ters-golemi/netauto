"""HPE Aruba Central via its cloud REST API (pycentral).

Central manages sites rather than a single box, so an inventory entry here is a
Central tenant. Facts describe the tenant; get_config returns the device
inventory as JSON. Written against pycentral 1.4; not exercised against a live
tenant.
"""

from __future__ import annotations

import json
from typing import Any

from netauto.config import resolve_credentials
from netauto.drivers.base import Driver
from netauto.errors import AuthError, DriverError


class ArubaCentralDriver(Driver):
    """An Aruba Central tenant."""

    capabilities = frozenset({"facts", "config"})

    def open(self) -> None:
        from pycentral.base import ArubaCentralBase

        creds = resolve_credentials(
            self.device.credentials_prefix, require=("CLIENT_ID", "CLIENT_SECRET")
        )
        base_url = self.device.options.get("base_url")
        if not base_url:
            raise DriverError(
                f"{self.device.name}: Aruba Central needs a regional 'base_url' in the "
                f"inventory, for example https://apigw-eucentral3.central.arubanetworks.com"
            )
        central_info = {
            "base_url": base_url,
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
        }
        token = creds.get("api_token")
        if token:
            central_info["token"] = {"access_token": token}
        else:
            username = creds.get("username")
            password = creds.get("password")
            if username and password:
                central_info["username"] = username
                central_info["password"] = password
        try:
            self._conn = ArubaCentralBase(central_info=central_info, ssl_verify=True)
        except Exception as exc:
            raise AuthError(f"{self.device.name}: Central authentication failed: {exc}") from exc

    def close(self) -> None:
        self._conn = None

    def _call(self, path: str, params: dict[str, Any] | None = None) -> Any:
        if self._conn is None:
            raise DriverError(f"{self.device.name}: driver is not open.")
        try:
            response = self._conn.command(
                apiMethod="GET", apiPath=path, apiParams=params or {}
            )
        except Exception as exc:
            raise DriverError(f"{self.device.name}: {path} failed: {exc}") from exc
        if isinstance(response, dict) and response.get("code", 200) >= 400:
            raise DriverError(f"{self.device.name}: {path} returned {response.get('code')}")
        return response.get("msg") if isinstance(response, dict) else response

    def facts(self) -> dict[str, Any]:
        data = self._call("platform/device_inventory/v1/devices", {"limit": 1})
        total = data.get("total") if isinstance(data, dict) else None
        return {
            "name": self.device.name,
            "platform": self.device.platform,
            "vendor": "HPE Aruba",
            "management": "Aruba Central (cloud)",
            "base_url": self.device.options.get("base_url"),
            "device_count": total,
        }

    def get_config(self, kind: str = "running") -> str:
        if kind != "running":
            raise DriverError(f"Central exposes its device inventory only, not {kind!r}.")
        data = self._call("platform/device_inventory/v1/devices", {"limit": 1000})
        return json.dumps(data, indent=2, sort_keys=True, default=str)

    def run_read(self, command: str) -> str:
        raise DriverError(
            "Aruba Central is an API-managed platform with no CLI. Query the managed "
            "devices directly, or extend this driver with the Central endpoint you need."
        )
