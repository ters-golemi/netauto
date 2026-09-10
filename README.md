# netauto

![read-only](https://img.shields.io/badge/devices-read--only-brightgreen)
![MCP](https://img.shields.io/badge/interface-MCP%20%2B%20web%20GUI-blue)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)

Multi-vendor network automation, exposed to agents over MCP. **Read-only by
design**: it reads device state, audits configuration, and diffs proposed
changes. It has no commit path.

Covers Cisco (IOS, IOS-XE, NX-OS, IOS-XR), Juniper Junos, Arista EOS,
HPE Aruba (AOS-CX, AOS-Switch, Central), Cisco Meraki and Fortinet FortiOS.

## Installing

For a server install on Ubuntu — service user, systemd, TLS, firewall — follow
[INSTALL.md](INSTALL.md). The quick start below is for a workstation.

## Quick start

```bash
cd ~/Work/netauto
cp config.example.yaml config.yaml
cp inventory/devices.example.yaml inventory/devices.yaml   # then edit
export CORE_SW_USERNAME=admin CORE_SW_PASSWORD='...'       # per device prefix
.venv/bin/python -m pytest tests/ -q
```

The MCP server is registered in `~/Work/.mcp.json` and starts automatically in
Claude Code sessions rooted at `~/Work`. To run it by hand:

```bash
.venv/bin/python -m netauto.mcp_server
```

## The safety model

Four independent layers, because one is not enough:

1. **No commit path exists.** `Driver.apply_config` raises `WriteDisabled` and
   no driver overrides it. `allow_writes` in `config.yaml` gates future write
   support; today it gates nothing, which is the point.
2. **Command allowlist.** `net_run_show` accepts only commands matching a
   per-vendor read allowlist, rejects a deny-list of state-changing verbs, and
   refuses command chaining (`;`, `&&`, `|`, newlines, `$(...)`, backticks).
   Unrecognised commands are refused rather than forwarded — default deny.
   Validation happens *before* connecting, so a bad command costs no session.
3. **Credentials never touch disk.** The inventory names an environment prefix;
   secrets resolve from the process environment at connect time. A device with
   prefix `CORE_SW` needs `CORE_SW_USERNAME` and `CORE_SW_PASSWORD`. No tool
   returns a credential.
4. **Ad-hoc targets are gated.** Connecting to a host that is not in the
   inventory makes the server offer its stored credentials to whatever answers,
   so the address must be one this process found in a sweep within the last
   hour, and must not be routable on the internet. Anything else is an
   inventory entry, which takes access to the server's filesystem.

## MCP tools

| Tool | Does |
|---|---|
| `net_list_devices` | Inventory, filterable by tag or platform |
| `net_supported_platforms` | The 12 platform strings with drivers |
| `net_device_facts` | Vendor, model, OS version, serial, hostname |
| `net_get_config` | Running/startup/candidate config as text |
| `net_run_show` | One allowlisted read-only command |
| `net_audit` | Hardening ruleset against a device or tag group |
| `net_config_diff` | Candidate vs running — review only, no commit |
| `net_discover_local` | ARP sweep of a directly attached segment, optionally probing management ports |
| `net_scan_ports` | Which of SSH, telnet and friends given hosts answer on |
| `net_connect_adhoc` | Read from a discovered host, without adding it to the inventory |
| `net_topology` | LLDP/CDP graph, as JSON or an editable draw.io file |

## Agents

The repo holds the canonical definitions in `agents/`. Claude Code loads them
from the project's `.claude/agents/` directory, so install them with:

```bash
mkdir -p ~/Work/.claude/agents
cp agents/*.md ~/Work/.claude/agents/
cp mcp.json.example ~/Work/.mcp.json   # then edit the paths if not under ~/Work
```

Three subagents:

- **network-auditor** — compliance across the estate; ranks by exploitability,
  reports unreachable devices separately from passing ones.
- **network-troubleshooter** — fault diagnosis; proposes fixes as diffs and
  stops there.
- **network-documenter** — inventories and baselines keyed to hardware rather
  than to leased addresses.

## Web GUI

A self-hosted browser interface so a team can use the toolkit without the CLI.
It runs *inside* the network it manages -- it needs reachability to the gear and
holds the device credentials in its own environment.

```bash
.venv/bin/python -m netauto.web.manage add adis --admin    # first account
export NETAUTO_SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')"
export NETAUTO_WEB_HOST=0.0.0.0        # omit for localhost only
./run-web.sh
```

Pages: overview, device list, per-device facts and running config, a read-only
command box, compliance audit by group, ARP discovery with an optional
SSH/telnet port check, ad-hoc sessions against discovered hosts, LLDP
topology with a
draw.io export, Workflows, an activity log, and a Metrics tab embedding the
Grafana dashboard when one is configured.

### Accounts

Per-user, so every action is attributable. Accounts live in `users.yaml` as
bcrypt hashes at `0600`; the file is re-read on each lookup, so adding or
removing a user takes effect without a restart.

```bash
python -m netauto.web.manage add <name> [--admin]
python -m netauto.web.manage list
python -m netauto.web.manage passwd <name>
python -m netauto.web.manage remove <name>
python -m netauto.web.manage admin <name> [--revoke]
```

Passwords are prompted for, never passed as arguments, so they stay out of
shell history and the process table. Minimum length is 10 characters, and the
last admin cannot be removed. Admins can read the activity log; standard
accounts cannot.

### Activity log

Every device-touching action is appended to `activity.log` as JSON lines with
the account that made it -- logins, failed logins, device inspections, commands
run, commands refused, audits and discovery sweeps. Greppable directly, or
viewable at `/activity` by an admin.

### Access control

Bcrypt verification with a dummy comparison for unknown users so response time
does not reveal which accounts exist. Signed `HttpOnly` `SameSite=Strict`
session cookies, a CSRF token on the login form, and a five-attempt lockout
keyed to *(client address, username)* -- so locking out one account cannot lock
out the team.

**It serves plain HTTP.** On a shared network, passwords and retrieved configs
cross the wire in clear text. For anything beyond a trusted management VLAN,
put it behind a reverse proxy with TLS and set `https_only=True` on the session
middleware in `netauto/web/app.py`.

**Still read-only.** A test asserts the only POST routes in the whole
application are `/login` and `/logout`; every device route is a GET that reads.

## Workflows

Two multi-step pipelines, one pair per supported platform -- 24 in all, under
the **Workflows** tab. They are per-platform because the useful part is the
show-command set, and that does not generalise.

**Device Configuration Check** connects, pulls the running configuration and
the platform's read-only command set, compares both against the vendor-guide
ruleset, and reports what to improve -- each finding with a severity, the
evidence from the config, a recommendation, and the guide it comes from.

**Network Documentation Maker** does all of that, then maps LLDP/CDP
neighbours and writes an editable Word document: inventory, findings, and a
topology diagram embedded as a picture.

```
Configuration check:   connect -> config + show output -> compare -> report
Documentation maker:   ... the above ... -> neighbours -> assemble -> .docx
```

Runs happen in the background: start one, watch the steps, come back to it.
A run over an estate takes minutes because each device is a real session, so
holding an HTTP request open for it was never going to work.

Three things worth knowing before relying on it:

**The command sets are data, and the guard still decides.** Every command a
workflow can send lives in `netauto/workflows/spec.py` as a plain tuple, and
the test suite runs every one of them through `assert_read_only` for its
platform. A workflow cannot widen what netauto may send to a device; only an
edit to `READ_ALLOW` can, and that is a deliberate change to the guard itself.
The guard rejects `|` as chaining, which is why nothing here pipes -- no
`| display set`, no `| section`.

**Three platforms have no CLI.** Meraki, Aruba Central and AOS-CX expose no
command interface through their drivers, so those workflows pull state through
the API and mark the show-command step "skipped" with the reason. An empty
command set for them is a statement about the platform, not an omission.

**Runs are held in memory and nowhere else.** They contain full running
configurations -- password hashes, community strings, key material -- and
netauto keeps that off disk. Documents are built on demand and streamed. The
cost is real: restarting the service discards run history, and you re-run the
workflow.

Workflows evaluate a larger ruleset than the Audit page: `checks/vendor.py`,
which is the built-in rules annotated with their sources plus the guidance that
only makes sense once you have the show output too. The Audit page and the
Prometheus metrics keep running `BUILTIN` unchanged, so this cannot move a
dashboard or fire an alert.

## Discovery, port scanning and ad-hoc sessions

Two stages, because they answer different questions. `arp-scan` finds live
hosts on a directly attached segment -- authoritative there, since hosts answer
ARP even when they drop ICMP, and useless off it. Tick *check ports* and each
host that answered is then dialled on the listed ports, SSH and telnet by
default:

```
# in the GUI: Discover -> 192.168.1.0/24, check ports, 22,23
# as an agent tool:
net_discover_local(cidr="192.168.1.0/24", probe_ports="22,23")
net_scan_ports(hosts="192.168.1.1, 192.168.1.9")   # no ARP, so any routed address
```

The probe is an ordinary TCP `connect()` and, at most, a read of whatever the
service volunteers first. It sends nothing, needs no privileges, and learns
nothing a client dialling the port would not. SSH names its software before
the client speaks, so an open 22 usually comes back with the far end's banner
-- often enough to tell a Cisco from an OpenSSH host. Telnet opens with binary
option negotiation, which is reported as no banner rather than as mojibake.

An open telnet port is flagged separately from an open SSH port: it carries
credentials in clear text, so it is a finding rather than an inventory fact.
Addresses already in the inventory are named in a column of their own, which
makes the interesting rows the ones that are *not* -- hosts on the wire that
nobody documented.

Bounded on purpose: at most a /22 per sweep, 16 ports, and 4096 probes in
total. An unbounded range times an unbounded port list is how a scan turns
into an hour-long page load.

### Connecting to what the sweep found

A discovered host that answers on 22 gets a *connect* link, which opens the
ordinary device page against it -- facts, running configuration, and the same
guarded command box a managed device gets. The Device is built for that one
request and stored nowhere; the platform is pre-selected from the SSH banner
and MAC vendor, and the credentials come from an environment prefix the server
already carries, chosen by name. No secret is typed into the browser.

```
Discover -> 192.168.1.9 [connect] -> platform: aruba_aoscx   (guessed)
                                     credentials: LAB        (from the environment)
```

The prefixes offered are read out of the environment, so the list is exactly
what this server can authenticate with -- export `LAB_USERNAME` and
`LAB_PASSWORD` before starting it and `LAB` appears. Only names are read.

What this deliberately is not: a shell. The guard polices one command at a
time, and an interactive session is a stream, so there is no terminal here and
the footer's promise holds on this page too. It is also not a way to manage a
device -- audits, metrics and workflows all read the inventory, so a host worth
keeping belongs in `inventory/devices.yaml`.

Agents get the same thing through `net_connect_adhoc`, gated identically and
per process -- an agent that has not swept has nothing it may connect to:

```python
net_discover_local(cidr="192.168.1.0/24", probe_ports="22")
net_connect_adhoc(ip="192.168.1.9", platform="aruba_aoscx", credentials="LAB")
net_connect_adhoc(ip="192.168.1.9", platform="aruba_aoscx", credentials="LAB",
                  command="show vlan", include_config=True)
```

Facts always come back, because they are how you confirm you reached what you
thought you did. A refused command or an unsupported config is reported beside
them rather than sinking the call.

The target gate is the part to understand before exposing this. See the safety
model above: a swept, unroutable address, or nothing.

## Topology diagrams

Builds a network diagram from what the devices themselves report over LLDP/CDP,
and exports it as a **draw.io** file — network stencils, orthogonal connectors
and port labels already placed. draw.io reads and writes `.vsdx`, so that file
is also the route to something editable in Visio.

```bash
# in the GUI: Topology -> Discover links -> Download .drawio
.venv/bin/python -c "
from netauto import drawio, topology
from netauto.session import load_context
s, inv = load_context()
print(drawio.render(topology.build(inv, s)))" > topology.drawio
```

Every link is reported twice, once from each end. Links both ends agree on are
drawn solid; a link only one device reported is drawn dashed, because a
one-sided report usually means the far end has LLDP off rather than that the
cable is imaginary.

Neighbours with no inventory entry are drawn dashed and labelled *discovered* —
typically APs, phones and servers, occasionally a switch nobody wrote down.
Devices that could not report neighbours at all are listed separately with the
reason, so a thin diagram can be told from a small network.

Tiers come from inventory tags (`core`, `edge`, `distribution`, `access` and
their synonyms) and fall back to link count when a device carries none. LLDP
must be enabled on the devices; nothing appears for a link neither end
advertises.

Every member of a port-channel is kept as its own cable rather than merged
into one, since redundancy between core switches is usually the point of
looking. The exported file carries a caption with the collection time — an
undated network diagram is worse than none a year later.

## Metrics and Grafana

A Prometheus endpoint at `/metrics`, with a provisioned Grafana dashboard for
compliance drift and device reachability over time. See
[deploy/grafana/README.md](deploy/grafana/README.md).

```bash
cd deploy/grafana && docker compose up -d     # Grafana on 127.0.0.1:3000
```

Metrics are opt-in: with `NETAUTO_METRICS_TOKEN` unset the endpoint returns 404
and no collector runs. Prometheus cannot hold a session cookie, so that token
is the whole access control on the endpoint.

**Nothing polls your devices.** Audits are manual, and the audits you run
from the Audit page are what feed the metrics -- merged per device, so
auditing one switch does not blank the rest. `/metrics` serves that cache, so
scraping it costs nothing on the network. Set `NETAUTO_METRICS_INTERVAL` to a
number of seconds only if you do want a background sweep as well.

## Platforms and transports

| Platform string | Transport | Library |
|---|---|---|
| `cisco_ios`, `cisco_xe` | SSH CLI | napalm |
| `cisco_nxos`, `cisco_xr` | SSH CLI | napalm |
| `arista_eos` | eAPI | napalm |
| `juniper_junos` | NETCONF | napalm / PyEZ |
| `aruba_aoscx` | REST | pyaoscx |
| `aruba_osswitch` | SSH CLI | netmiko |
| `aruba_central` | Cloud REST | pycentral |
| `meraki` | Cloud REST | meraki |
| `fortinet_fortios` | REST | fortiosapi |
| `fortinet_cli` | SSH CLI | netmiko |

Meraki and Aruba Central are cloud tenants, not boxes: an inventory entry is an
organization or tenant, and neither has a CLI. `net_run_show` refuses on both
with an explanation rather than a generic failure.

## Compliance rules

15 rules in `netauto/checks/builtin.py`, scoped by platform family so a Junos
config is never judged by IOS syntax: telnet exposure, SSH version, cleartext
management, password encryption, enable secrets, session timeouts, root-login
policy, default SNMP communities, time sources, remote logging. This is what
the Audit page and the Prometheus metrics evaluate.

`netauto/checks/vendor.py` adds 15 more for the workflows -- AAA, legacy
services, management ACLs, BPDU guard, log timestamps, banners, Junos web
management and idle timeouts, Aruba loop protection, FortiOS trusted hosts and
remote logging, and writable SNMP -- and gives all 30 a citation, so a
recommendation can be traced to the guide it came from rather than read as an
opinion.

Rules take config text plus facts and return pass/fail with evidence. They
connect to nothing, so they unit-test against captured configs. Each vendor
rule is fired in both directions in `tests/test_vendor_rules.py`: a rule that
cannot fail and a rule that cannot pass both look healthy from the outside.

## Testing

384 tests, no hardware required. The command guard has the heaviest coverage
since it is the safety boundary — including chaining-escape attempts and
default-deny behaviour.

```bash
.venv/bin/python -m pytest tests/ -q
```

## What is not verified

The vendor drivers are written against each SDK's documented API and are
exercised by import and signature checks, but **only the local ARP discovery
path has been run against real equipment**. The port probe is tested against
real sockets on the loopback -- a listener that answers, one that stays silent,
a closed port -- but has not been pointed at production gear. An ad-hoc session
has never opened against a real device either: the target gate and the
transient Device are covered, and everything past them is the same driver code
as an inventory device, which is the code that has not met real gear. That includes the LLDP topology
path: the graph assembly and draw.io output are covered by tests against
captured neighbour tables, but no driver's `neighbors()` has met real gear. Cisco, Juniper, Aruba, Meraki and
Fortinet paths need a first run against actual gear or a lab; expect to adjust
response parsing, particularly `aoscx_driver.get_config` and the Central
endpoint paths, which vary by firmware and region.

The workflows inherit all of that, and add their own. Every command set is
checked against the read-only guard and the pipelines are tested end to end
against fake drivers, but **no workflow has run against real equipment**. The
show commands are written from vendor documentation, so expect some to be
refused by a given model or software train -- the runner treats that as a
per-command gap rather than a failed device, which is exactly the case that
needs a real run to shake out. The rules themselves are tested against
representative config snippets, not captured production configs, so their
false-positive rate is unmeasured.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Copyright 2026 Adis Cato.
