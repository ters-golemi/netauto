# netauto

Multi-vendor network automation, exposed to agents over MCP. **Read-only by
design**: it reads device state, audits configuration, and diffs proposed
changes. It has no commit path.

Covers Cisco (IOS, IOS-XE, NX-OS, IOS-XR), Juniper Junos, Arista EOS,
HPE Aruba (AOS-CX, AOS-Switch, Central), Cisco Meraki and Fortinet FortiOS.

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

Three independent layers, because one is not enough:

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
| `net_discover_local` | ARP sweep of a directly attached segment |

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
policy, default SNMP communities, time sources, remote logging.

Rules take config text plus facts and return pass/fail with evidence. They
connect to nothing, so they unit-test against captured configs.

## Testing

54 tests, no hardware required. The command guard has the heaviest coverage
since it is the safety boundary — including chaining-escape attempts and
default-deny behaviour.

```bash
.venv/bin/python -m pytest tests/ -q
```

## What is not verified

The vendor drivers are written against each SDK's documented API and are
exercised by import and signature checks, but **only the local ARP discovery
path has been run against real equipment**. Cisco, Juniper, Aruba, Meraki and
Fortinet paths need a first run against actual gear or a lab; expect to adjust
response parsing, particularly `aoscx_driver.get_config` and the Central
endpoint paths, which vary by firmware and region.
