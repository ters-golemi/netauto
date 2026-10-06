"""Cisco Nexus Dashboard via its platform REST API.

An inventory entry here is an ND cluster. Nexus Dashboard is not a network
device at all -- it is the platform that onboards fabrics and hosts the
services that manage them (Insights, Orchestrator, Fabric Controller) -- so
`facts` describes the cluster and `get_config` exports the onboarded sites and
cluster nodes rather than any device configuration.

Talks to the API with `requests` directly: authentication is a single POST
that returns a JWT, and everything after it is a GET with a bearer token.

**The platform paths move between releases.** ND reorganised its API at 3.x
and again at 4.2, so this driver probes a short list of known paths per
question instead of hardcoding one and failing on the next release. Pin the
right ones for your cluster with `api_paths` in the inventory when you know
them -- an explicit path is tried alone, and a failure then names it.

Written against the Nexus Dashboard platform API as documented for 3.1 and
4.2; not exercised against a live cluster.
"""

from __future__ import annotations

import json
from typing import Any

from netauto.config import resolve_credentials
from netauto.drivers.base import Driver
from netauto.errors import AuthError, DriverError

#: Candidate paths per question, newest release first. Overridden per device
#: by the inventory's `api_paths`, which takes a single path per key.
DEFAULT_PATHS: dict[str, tuple[str, ...]] = {
    "version": (
        "/api/config/version",
        "/nexus/infra/api/platform/v1/version",
    ),
    "clusters": (
        "/nexus/infra/api/platform/v1/clusters",
        "/api/config/class/cluster",
    ),
    "nodes": (
        "/nexus/infra/api/platform/v1/nodes",
        "/api/config/class/node",
    ),
    "sites": (
        "/nexus/infra/api/sitemanagement/v4/sites",
        "/nexus/infra/api/sitemanagement/v1/sites",
        "/api/config/class/site",
    ),
}


def _items(payload: Any) -> list[dict[str, Any]]:
    """The list of records out of an ND response, whatever it wrapped them in.

    ND answers with ``{"items": [...]}`` on the platform API, a bare list on
    some endpoints, and a single-key envelope on others. Rather than branch
    per endpoint, take the first list of dicts on offer.
    """
    if isinstance(payload, list):
        return [p for p in payload if isinstance(p, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("items", "sites", "nodes", "clusters", "value"):
        value = payload.get(key)
        if isinstance(value, list):
            return [v for v in value if isinstance(v, dict)]
    for value in payload.values():
        if isinstance(value, list) and all(isinstance(v, dict) for v in value):
            return list(value)
    return []


def _flatten(record: dict[str, Any]) -> dict[str, Any]:
    """Merge an ND record's spec/status/meta envelopes into one flat dict.

    ND splits a record into what was asked for (spec) and what is true
    (status), with the name sometimes only in meta. Readers want one dict, and
    status wins on a clash because it describes the cluster as it is.
    """
    flat: dict[str, Any] = {
        k: v for k, v in record.items()
        if k not in ("spec", "status", "meta") and not isinstance(v, (dict, list))
    }
    for envelope in ("meta", "spec", "status"):
        body = record.get(envelope)
        if isinstance(body, dict):
            flat.update({k: v for k, v in body.items() if not isinstance(v, (dict, list))})
    return flat


def _format_version(payload: Any) -> str | None:
    """ND's version, which is a string on some releases and parts on others."""
    if isinstance(payload, str):
        return payload or None
    if not isinstance(payload, dict):
        return None
    for key in ("version", "product_version", "productVersion"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    parts = [payload.get(k) for k in ("major", "minor", "maintenance")]
    if all(p is not None for p in parts):
        version = ".".join(str(p) for p in parts)
        patch = payload.get("patch") or payload.get("build")
        return f"{version}{f'({patch})' if patch else ''}"
    return None


def _parse_sites(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Onboarded fabrics, in a shape that does not depend on the ND release."""
    out: list[dict[str, Any]] = []
    for record in records:
        flat = _flatten(record)
        out.append({
            "name": flat.get("name") or flat.get("siteName"),
            "site_type": flat.get("siteType") or flat.get("type"),
            "host": flat.get("host") or flat.get("url") or flat.get("apicUrl"),
            "state": flat.get("state") or flat.get("connectivityStatus")
                     or flat.get("health"),
            "os_version": flat.get("siteVersion") or flat.get("version"),
            "latitude": flat.get("latitude"),
            "longitude": flat.get("longitude"),
        })
    return out


class NexusDashboardDriver(Driver):
    """A Cisco Nexus Dashboard cluster."""

    capabilities = frozenset({"facts", "config", "devices"})

    # -- lifecycle ---------------------------------------------------------

    def open(self) -> None:
        import requests

        base = self._base_url()
        creds = resolve_credentials(self.device.credentials_prefix)
        session = requests.Session()
        session.verify = bool(self.device.options.get("verify_tls", True))
        payload = {
            "userName": creds["username"],
            "userPasswd": creds["password"],
            "domain": str(self.device.options.get("login_domain", "local")),
        }
        try:
            response = session.post(
                f"{base}/login", json=payload,
                timeout=self.settings.connect_timeout,
            )
        except Exception as exc:
            session.close()
            raise DriverError(
                f"{self.device.name}: cannot reach Nexus Dashboard at {base}: {exc}"
            ) from exc
        if response.status_code in (400, 401, 403):
            session.close()
            raise AuthError(
                f"{self.device.name}: Nexus Dashboard rejected the credentials "
                f"({response.status_code}). Check the username, password and the "
                f"login domain -- {payload['domain']!r} here, which must be a "
                f"domain configured on the cluster."
            )
        if response.status_code >= 400:
            session.close()
            raise DriverError(f"{self.device.name}: /login returned {response.status_code}.")
        try:
            token = (response.json() or {}).get("jwttoken")
        except ValueError as exc:
            session.close()
            raise DriverError(
                f"{self.device.name}: /login did not return JSON: {exc}"
            ) from exc
        if not token:
            session.close()
            raise AuthError(
                f"{self.device.name}: /login succeeded but returned no jwttoken."
            )
        session.headers["Authorization"] = f"Bearer {token}"
        self._conn = session
        self._base = base
        #: Which candidate answered, per key. Cached so a cluster is probed
        #: once per connection rather than once per question.
        self._resolved: dict[str, str] = {}

    def close(self) -> None:
        if self._conn is not None:
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
                f"Device {self.device.name!r} has no host address. Give the cluster's "
                f"management address as 'host', or a full 'base_url'."
            )
        port = f":{self.device.port}" if self.device.port else ""
        return f"https://{self.device.host}{port}"

    # -- queries -----------------------------------------------------------

    def _candidates(self, key: str) -> tuple[str, ...]:
        """The paths to try for one question, inventory override winning."""
        override = (self.device.options.get("api_paths") or {}).get(key)
        if override:
            return (str(override),)
        return DEFAULT_PATHS[key]

    def _probe(self, key: str, *, required: bool = True) -> Any:
        """GET the first candidate path for `key` that answers.

        A 404 means this release does not have that path, so the next
        candidate is tried. Anything else is a real failure and stops the
        search -- a 403 on the right path must not be reported as a missing
        endpoint.
        """
        if self._conn is None:
            raise DriverError(f"{self.device.name}: driver is not open.")
        if key in self._resolved:
            paths: tuple[str, ...] = (self._resolved[key],)
        else:
            paths = self._candidates(key)
        tried: list[str] = []
        for path in paths:
            tried.append(path)
            try:
                response = self._conn.get(
                    f"{self._base}{path}", timeout=self.settings.command_timeout
                )
            except Exception as exc:
                raise DriverError(f"{self.device.name}: {path} failed: {exc}") from exc
            if response.status_code == 404:
                continue
            if response.status_code >= 400:
                raise DriverError(
                    f"{self.device.name}: {path} returned {response.status_code}."
                )
            try:
                payload = response.json()
            except ValueError as exc:
                raise DriverError(
                    f"{self.device.name}: {path} did not return JSON: {exc}"
                ) from exc
            self._resolved[key] = path
            return payload
        if not required:
            return None
        raise DriverError(
            f"{self.device.name}: no {key} endpoint answered. Tried: "
            f"{', '.join(tried)}. Nexus Dashboard moved these paths between "
            f"releases -- set api_paths.{key} in the inventory to the one your "
            f"cluster serves."
        )

    def facts(self) -> dict[str, Any]:
        version = _format_version(self._probe("version", required=False))
        clusters = _items(self._probe("clusters", required=False))
        nodes = _items(self._probe("nodes", required=False))
        sites = _items(self._probe("sites"))
        cluster = _flatten(clusters[0]) if clusters else {}
        return {
            "name": self.device.name,
            "platform": self.device.platform,
            "vendor": "Cisco",
            "management": "Cisco Nexus Dashboard (cluster)",
            "model": "Nexus Dashboard",
            "os_version": version or cluster.get("version"),
            "hostname": cluster.get("name") or self.device.host,
            "cluster_name": cluster.get("name"),
            "node_count": len(nodes) or None,
            "site_count": len(sites),
            "sites": [s["name"] for s in _parse_sites(sites) if s["name"]],
        }

    def get_config(self, kind: str = "running") -> str:
        """The onboarded sites and cluster nodes. ND has no device config."""
        if kind != "running":
            raise DriverError(
                f"Nexus Dashboard exposes current cluster state only, not {kind!r}."
            )
        payload = {
            "sites": _parse_sites(_items(self._probe("sites"))),
            "nodes": [_flatten(n) for n in _items(self._probe("nodes", required=False))],
        }
        return json.dumps(payload, indent=2, sort_keys=True, default=str)

    def devices(self) -> list[dict[str, Any]]:
        """The fabrics onboarded to this cluster, not their individual switches.

        ND knows a site by its controller; enumerating the switches inside one
        means asking that controller. Add a cisco_aci entry for an ACI site,
        or cisco_nxos entries for a standalone fabric's switches.
        """
        return _parse_sites(_items(self._probe("sites")))

    def run_read(self, command: str) -> str:
        raise DriverError(
            "Nexus Dashboard is a management platform with no device CLI. Use "
            "net_device_facts for cluster and site state, or reach a fabric's own "
            "controller -- a cisco_aci entry for ACI, cisco_nxos for a switch."
        )
