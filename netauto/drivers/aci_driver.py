"""Cisco ACI via the APIC REST API.

An inventory entry here is an APIC cluster, not a switch. ACI's management
plane is the controller: the leaves and spines are configured from the policy
model, so `facts` describes the fabric and `get_config` exports the policy
tree rather than a device's text configuration.

Talks to the API with `requests` directly. The APIC API is a thin, stable
contract -- POST credentials to aaaLogin, read managed objects by class -- and
the vendor SDKs around it either need per-release wheels from Cisco's site
(cobra) or are thinly maintained (acitoolkit), so neither earns a pinned
dependency here.

Written against the APIC 5.2/6.0 REST API; not exercised against a live
fabric.
"""

from __future__ import annotations

import json
import re
from typing import Any

from netauto.config import resolve_credentials
from netauto.drivers.base import Driver
from netauto.errors import AuthError, DriverError

#: The whole policy universe, configuration properties only. Operational
#: state is excluded deliberately: a config export that carried fault counts
#: and packet statistics would differ on every read, so nothing could diff it.
CONFIG_PATH = "/api/mo/uni.json?rsp-subtree=full&rsp-prop-include=config-only"

#: Where a node id and an interface hide inside an lldpAdjEp dn, e.g.
#: topology/pod-1/node-101/sys/lldp/inst/if-[eth1/1]/adj-1
_DN_NODE = re.compile(r"/node-(\d+)/")
_DN_PORT = re.compile(r"/if-\[([^\]]+)\]")


def _attrs(imdata: list[dict[str, Any]], cls: str = "") -> list[dict[str, Any]]:
    """Pull the attribute dicts out of an APIC imdata list.

    Every APIC response is ``{"imdata": [{"<className>": {"attributes": {...}}}]}``.
    Unwrapping it is the first thing every caller would otherwise do by hand.
    """
    out: list[dict[str, Any]] = []
    for item in imdata or []:
        if not isinstance(item, dict):
            continue
        for name, body in item.items():
            if cls and name != cls:
                continue
            if isinstance(body, dict) and isinstance(body.get("attributes"), dict):
                out.append(body["attributes"])
    return out


def _parse_fabric(nodes: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarise fabricNode attributes into counts and a controller version.

    Pure: takes the attribute dicts, returns the summary. The role names are
    the APIC's own -- controller, leaf, spine -- and an unexpected one is
    counted under its own name rather than dropped.
    """
    roles: dict[str, int] = {}
    unhealthy: list[str] = []
    version = None
    for node in nodes:
        role = node.get("role") or "unknown"
        roles[role] = roles.get(role, 0) + 1
        if role == "controller" and not version:
            version = node.get("version")
        # fabricSt is the fabric membership state; "unknown" shows up on a
        # node that has been decommissioned but not removed from the policy.
        state = node.get("fabricSt")
        if state and state not in ("active", "unknown") and role != "controller":
            unhealthy.append(f"{node.get('name') or node.get('id')}={state}")
    return {
        "node_roles": roles,
        "node_count": len(nodes),
        "apic_version": version,
        "nodes_not_active": unhealthy,
    }


def _parse_neighbors(adjacencies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """lldpAdjEp attributes to the neighbour shape the topology code wants.

    The local end is not a property of the adjacency -- it is encoded in the
    dn -- so the node id and interface are read back out of it. An entry whose
    dn carries neither is skipped: a link with no local end cannot be drawn.
    """
    out: list[dict[str, Any]] = []
    for adj in adjacencies:
        dn = adj.get("dn", "") or ""
        node = _DN_NODE.search(dn)
        port = _DN_PORT.search(dn)
        if not (node and port):
            continue
        out.append({
            "local_port": f"node-{node.group(1)}/{port.group(1)}",
            "remote_host": adj.get("sysName", "") or adj.get("chassisIdV", "") or "",
            "remote_port": adj.get("portIdV", "") or adj.get("portDesc", "") or "",
            "remote_description": adj.get("sysDesc", "") or "",
            "remote_chassis_id": adj.get("chassisIdV", "") or "",
        })
    return out


class AciDriver(Driver):
    """A Cisco ACI fabric, reached through its APIC."""

    capabilities = frozenset({"facts", "config", "devices", "neighbors"})

    # -- lifecycle ---------------------------------------------------------

    def open(self) -> None:
        import requests

        base = self._base_url()
        creds = resolve_credentials(self.device.credentials_prefix)
        session = requests.Session()
        session.verify = bool(self.device.options.get("verify_tls", True))
        payload = {"aaaUser": {"attributes": {
            "name": creds["username"], "pwd": creds["password"],
        }}}
        # A login domain other than the local one is named inline in the
        # username: apic:<domain>\<user>. Spelled out in the inventory as
        # login_domain so nobody has to remember the escaping.
        domain = self.device.options.get("login_domain")
        if domain:
            payload["aaaUser"]["attributes"]["name"] = (
                f"apic:{domain}\\{creds['username']}"
            )
        try:
            response = session.post(
                f"{base}/api/aaaLogin.json", json=payload,
                timeout=self.settings.connect_timeout,
            )
        except Exception as exc:
            session.close()
            raise DriverError(f"{self.device.name}: cannot reach APIC at {base}: {exc}") from exc
        if response.status_code in (400, 401, 403):
            session.close()
            raise AuthError(
                f"{self.device.name}: APIC rejected the credentials "
                f"({response.status_code}). Check the username, password and "
                f"login_domain, and that the account has read access."
            )
        if response.status_code >= 400:
            session.close()
            raise DriverError(
                f"{self.device.name}: aaaLogin returned {response.status_code}."
            )
        # The token arrives twice: as an attribute and as the APIC-cookie the
        # session now holds. The cookie is what authenticates later calls, so
        # the session carries it and nothing needs to be stored by hand.
        token = _attrs(response.json().get("imdata", []), "aaaLogin")
        if not token:
            session.close()
            raise AuthError(
                f"{self.device.name}: aaaLogin succeeded but returned no token."
            )
        self._conn = session
        self._base = base
        self._refresh_seconds = token[0].get("refreshTimeoutSeconds")

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.post(f"{self._base}/api/aaaLogout.json", json={},
                                timeout=self.settings.connect_timeout)
            except Exception:
                pass  # a failed logout must not mask the real error
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def _base_url(self) -> str:
        base = self.device.options.get("base_url")
        if base:
            return str(base).rstrip("/")
        if not self.device.host:
            raise DriverError(
                f"Device {self.device.name!r} has no host address. Give the APIC's "
                f"address as 'host', or a full 'base_url'."
            )
        port = f":{self.device.port}" if self.device.port else ""
        return f"https://{self.device.host}{port}"

    # -- queries -----------------------------------------------------------

    def _get(self, path: str, cls: str = "") -> list[dict[str, Any]]:
        """GET an APIC path and return the unwrapped attribute dicts."""
        if self._conn is None:
            raise DriverError(f"{self.device.name}: driver is not open.")
        try:
            response = self._conn.get(
                f"{self._base}{path}", timeout=self.settings.command_timeout
            )
        except Exception as exc:
            raise DriverError(f"{self.device.name}: {path} failed: {exc}") from exc
        if response.status_code >= 400:
            raise DriverError(
                f"{self.device.name}: {path} returned {response.status_code}."
            )
        try:
            return _attrs(response.json().get("imdata", []), cls)
        except ValueError as exc:
            raise DriverError(
                f"{self.device.name}: {path} did not return JSON: {exc}"
            ) from exc

    def facts(self) -> dict[str, Any]:
        nodes = self._get("/api/class/fabricNode.json", "fabricNode")
        summary = _parse_fabric(nodes)
        # The fabric domain names the fabric itself, which is the one piece of
        # identity an APIC has that a node does not carry.
        controllers = self._get("/api/class/infraCont.json", "infraCont")
        tenants = self._get("/api/class/fvTenant.json", "fvTenant")
        return {
            "name": self.device.name,
            "platform": self.device.platform,
            "vendor": "Cisco",
            "management": "Cisco ACI (APIC)",
            "model": "ACI fabric",
            "os_version": summary["apic_version"],
            "hostname": self.device.host,
            "fabric_domain": controllers[0].get("fbDmNm") if controllers else None,
            "tenant_count": len(tenants),
            **{k: v for k, v in summary.items() if k != "apic_version"},
        }

    def get_config(self, kind: str = "running") -> str:
        """The policy universe as JSON. ACI has no text running-config."""
        if kind != "running":
            raise DriverError(
                f"ACI exposes its policy model only, not {kind!r}. The fabric has no "
                f"startup or candidate configuration -- policy is the configuration."
            )
        if self._conn is None:
            raise DriverError(f"{self.device.name}: driver is not open.")
        try:
            response = self._conn.get(
                f"{self._base}{CONFIG_PATH}", timeout=self.settings.command_timeout
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            raise DriverError(f"{self.device.name}: policy export failed: {exc}") from exc
        return json.dumps(payload, indent=2, sort_keys=True, default=str)

    def devices(self) -> list[dict[str, Any]]:
        """Every node the fabric knows: controllers, leaves and spines."""
        return [
            {
                "name": n.get("name"),
                "node_id": n.get("id"),
                "role": n.get("role"),
                "model": n.get("model"),
                "serial_number": n.get("serial"),
                "os_version": n.get("version"),
                "fabric_state": n.get("fabricSt"),
                "admin_state": n.get("adSt"),
            }
            for n in self._get("/api/class/fabricNode.json", "fabricNode")
        ]

    def neighbors(self) -> list[dict[str, Any]]:
        """LLDP adjacencies across the whole fabric, not one switch.

        An APIC entry stands for every node at once, so local_port is
        qualified with the node id -- node-101/eth1/1 -- and the topology code
        gets one call where it would otherwise need a session per leaf.
        """
        return _parse_neighbors(self._get("/api/class/lldpAdjEp.json", "lldpAdjEp"))

    def run_read(self, command: str) -> str:
        raise DriverError(
            "This driver speaks the APIC REST API and has no CLI transport. Fabric "
            "state comes from net_device_facts and net_get_config; for a shell on an "
            "individual leaf or spine, add a cisco_nxos inventory entry for it."
        )
