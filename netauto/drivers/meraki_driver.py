"""Cisco Meraki via the cloud Dashboard API.

Meraki has no device CLI at all -- everything goes through the cloud API, and
an inventory entry here is an organization rather than a box. Written against
the meraki SDK 4.4; needs a real org API key to exercise.
"""

from __future__ import annotations

import json
from typing import Any

from netauto.config import resolve_credentials
from netauto.drivers.base import Driver
from netauto.errors import AuthError, DriverError


class MerakiDriver(Driver):
    """A Meraki organization."""

    capabilities = frozenset({"facts", "config", "devices"})

    def open(self) -> None:
        import meraki

        creds = resolve_credentials(self.device.credentials_prefix, require=("API_KEY",))
        try:
            self._conn = meraki.DashboardAPI(
                api_key=creds["api_key"],
                output_log=False,
                print_console=False,
                suppress_logging=True,
                single_request_timeout=self.settings.command_timeout,
            )
        except Exception as exc:
            raise AuthError(f"{self.device.name}: Meraki API setup failed: {exc}") from exc

    def close(self) -> None:
        self._conn = None

    def _require(self) -> Any:
        if self._conn is None:
            raise DriverError(f"{self.device.name}: driver is not open.")
        return self._conn

    def _org_id(self) -> str:
        """Resolve the organization: explicit in inventory, or the only one available."""
        org_id = self.device.options.get("org_id")
        if org_id:
            return str(org_id)
        dashboard = self._require()
        try:
            orgs = dashboard.organizations.getOrganizations()
        except Exception as exc:
            raise DriverError(f"{self.device.name}: could not list organizations: {exc}") from exc
        if len(orgs) != 1:
            names = ", ".join(f"{o['name']}={o['id']}" for o in orgs)
            raise DriverError(
                f"{self.device.name}: this key sees {len(orgs)} organizations. "
                f"Set 'org_id' in the inventory. Available: {names}"
            )
        return str(orgs[0]["id"])

    def facts(self) -> dict[str, Any]:
        dashboard = self._require()
        org_id = self._org_id()
        try:
            org = dashboard.organizations.getOrganization(org_id)
            devices = dashboard.organizations.getOrganizationDevices(org_id, total_pages="all")
            networks = dashboard.organizations.getOrganizationNetworks(org_id, total_pages="all")
        except Exception as exc:
            raise DriverError(f"{self.device.name}: Meraki query failed: {exc}") from exc
        models: dict[str, int] = {}
        for dev in devices:
            models[dev.get("model", "unknown")] = models.get(dev.get("model", "unknown"), 0) + 1
        return {
            "name": self.device.name,
            "platform": self.device.platform,
            "vendor": "Cisco Meraki",
            "management": "Meraki Dashboard (cloud)",
            "organization": org.get("name"),
            "org_id": org_id,
            "network_count": len(networks),
            "device_count": len(devices),
            "models": models,
        }

    def get_config(self, kind: str = "running") -> str:
        """Meraki has no text config; this returns the org's device and network state."""
        if kind != "running":
            raise DriverError(f"Meraki exposes current state only, not {kind!r}.")
        dashboard = self._require()
        org_id = self._org_id()
        try:
            payload = {
                "networks": dashboard.organizations.getOrganizationNetworks(
                    org_id, total_pages="all"
                ),
                "devices": dashboard.organizations.getOrganizationDevices(
                    org_id, total_pages="all"
                ),
            }
        except Exception as exc:
            raise DriverError(f"{self.device.name}: Meraki export failed: {exc}") from exc
        return json.dumps(payload, indent=2, sort_keys=True, default=str)

    def run_read(self, command: str) -> str:
        raise DriverError(
            "Meraki devices have no CLI. Everything is the Dashboard API -- use "
            "get_config for network and device state, or extend this driver."
        )
