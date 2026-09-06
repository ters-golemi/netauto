# Grafana dashboards for netauto

Compliance drift and device reachability over time, from the netauto audit
collector.

## How it fits together

```
netauto-web ──> background collector ──> cached snapshot
   (localhost:8080)   every 15 min          │
                                            v
                                       GET /metrics  <── Prometheus (30s)
                                                             │
                                                             v
                                                          Grafana
                                                      (localhost:3000)
```

The split matters. **Scraping never touches a device.** `audit_device()` opens
a real SSH or NETCONF session per device, so if Prometheus drove that directly,
a 30-second scrape interval would mean a login to every switch in the estate
twice a minute, forever. Instead a background thread audits on its own slow
schedule and caches the result; `/metrics` serialises the cache and returns in
microseconds.

So there are two intervals, and they mean different things:

| Setting | Where | Controls |
|---|---|---|
| `NETAUTO_METRICS_INTERVAL` | `~/.config/netauto/netauto.env` | How often devices are actually audited. Default 900s, floor 60s. |
| `scrape_interval` | `prometheus.yml` | How often Prometheus re-reads the cache. Free. Default 30s. |

Raising the scrape interval will not give you fresher data. Only the first one
does, and it costs a session per device per cycle.

## Prerequisites

Docker must be running and usable without sudo:

```bash
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"   # then log out and back in
```

## Running it

```bash
cd deploy/grafana
docker compose up -d
docker compose ps
```

Grafana lands on <http://127.0.0.1:3000>, Prometheus on
<http://127.0.0.1:9090>. Sign in to Grafana with `admin` and the password in
`.env`; the **Netauto → Netauto Compliance** dashboard is provisioned already.

Check Prometheus found the target at
<http://127.0.0.1:9090/targets> — `netauto` should read `UP`. If it reads
`401`, the token in `scrape-token` does not match `NETAUTO_METRICS_TOKEN`.

To stop, or to remove the stored history as well:

```bash
docker compose down          # keeps 90 days of metrics
docker compose down -v       # deletes them
```

## Why host networking

Both containers run with `network_mode: host`, which is unusual enough to
explain. Netauto binds `127.0.0.1` only. A container on a normal bridge network
cannot reach the host's loopback — `host.docker.internal` resolves to the
host's *external* address, where nothing is listening. The alternatives were to
expose netauto on `0.0.0.0` (defeats the point) or to bind it to the Docker
bridge (couples the app to Docker). Host networking keeps netauto on loopback
and unexposed.

The cost is that Docker's port publishing does not apply, so each container
binds its own address explicitly: `GF_SERVER_HTTP_ADDR` for Grafana and
`--web.listen-address` for Prometheus. Both are on loopback. Verify with:

```bash
ss -tlnp | grep -E '3000|9090'
```

If either shows `0.0.0.0`, the setting was lost and the service is exposed.

## Secrets

Two generated files, both gitignored, both `0600`:

- `scrape-token` — must equal `NETAUTO_METRICS_TOKEN` in
  `~/.config/netauto/netauto.env`. Mounted read-only into Prometheus.
- `.env` — the Grafana admin password, read by Compose.

To rotate the scrape token, write a new value into both places and restart
both sides:

```bash
python3 -c 'import secrets;print(secrets.token_urlsafe(32),end="")' > scrape-token
sed -i "s|^NETAUTO_METRICS_TOKEN=.*|NETAUTO_METRICS_TOKEN=$(cat scrape-token)|" \
  ~/.config/netauto/netauto.env
systemctl --user restart netauto-web
docker compose restart prometheus
```

`/metrics` is not behind the login wall, because Prometheus cannot hold a
session cookie. The token is the entire access control, so treat it as one:
anyone holding it can read your device names, models, OS versions and serials.
With no token set, the endpoint returns 404 and the collector does not run at
all — metrics are opt-in.

## The metrics

| Metric | Type | Labels |
|---|---|---|
| `netauto_up` | gauge | — |
| `netauto_build_info` | gauge | `version` |
| `netauto_collector_error` | gauge | `error` |
| `netauto_devices_total` | gauge | — |
| `netauto_audit_cycles_total` | counter | — |
| `netauto_last_audit_timestamp_seconds` | gauge | — |
| `netauto_audit_cycle_seconds` | gauge | — |
| `netauto_device_up` | gauge | `device`, `platform` |
| `netauto_device_audit_seconds` | gauge | `device` |
| `netauto_device_config_lines` | gauge | `device` |
| `netauto_device_info` | gauge | `device`, `platform`, `vendor`, `model`, `os_version`, `serial` |
| `netauto_findings` | gauge | `device`, `status` |
| `netauto_findings_failed` | gauge | `device`, `severity` |
| `netauto_rule_failed` | gauge | `device`, `rule_id`, `severity` |

Two conventions worth knowing:

**Unreachable devices report `netauto_device_up 0` and nothing else.** No
config size, no findings, no identity. A stale `pass` for a device nobody could
reach is worse than a gap in the graph, so the series simply stop.

**Skipped rules are omitted from `netauto_rule_failed`,** rather than reported
as passing. A Junos rule against an IOS box is not a pass; it is not
applicable, and a dashboard should not count it as compliance.

Cardinality is `devices × 15 rules` for the per-rule series, which stays small
for any estate a serial audit loop can get through.

## Alerts

`rules.yml` carries four, deliberately slack: a device is not down because one
cycle missed it, and a compliance finding is usually months old and should not
page anyone at 03:00.

| Alert | Fires when |
|---|---|
| `NetautoExporterDown` | no completed cycle for 15m |
| `NetautoAuditStale` | last cycle older than 40m |
| `NetautoDeviceUnreachable` | a device has failed audits for 45m |
| `NetautoCriticalFindingAppeared` | critical count rose vs. an hour ago, held 30m |

The last one compares against `offset 1h` on purpose: it fires on a *new*
critical finding, not on a standing backlog you already know about.

No notification channel is configured — the alerts show in Prometheus at
<http://127.0.0.1:9090/alerts> and nowhere else until you add an Alertmanager
or wire Grafana's own alerting to them.

## Editing the dashboard

`allowUiUpdates: false` is set, so edits made in the Grafana UI are overwritten
from disk within 30 seconds. That is deliberate — the dashboard belongs in
version control. To change it: edit it in the UI, use **Dashboard settings →
JSON Model** to copy the JSON, save it over
`dashboards/netauto-compliance.json`, and commit.

## What this does not do

It shows what the audit collector can see, which is compliance and
reachability. It is not interface statistics, traffic, or SNMP polling —
netauto has no telemetry path and does not poll counters. If you want link
utilisation, that is a different exporter alongside this one.

The dashboards have been validated against the exposition format and an
unreachable device. Nothing here has been exercised against a real audited
device, because the vendor drivers themselves have not been — see the README's
closing section.
