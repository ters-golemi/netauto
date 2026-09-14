# Design: netlab integration

**Status:** proposal · **Scope:** a `netauto.lab` module that builds virtual
lab topologies with [netlab](https://netlab.tools) and feeds them into
netauto's existing read paths.

netauto today inspects **real** devices: read facts, audit config, diff, run
show commands. It has no way to *stand up* a network to inspect. netlab is the
opposite tool — it builds and configures virtual topologies from YAML but does
not audit or reason about them afterward. This proposes joining the two so the
loop is **build → inspect → validate → tear down**, with netauto as the
inspection and validation layer over a netlab-built lab.

---

## Goals

- Bring a lab up and down from netauto, given a netlab topology file.
- **Auto-populate a netauto `Inventory`** from the running lab, so the lab's
  devices appear in Discover / Devices / Audit exactly like real gear — no new
  drivers, no hand-written inventory.
- Run netauto's existing **audit / compliance / workflow** engine against the
  lab, so a design can be validated before it touches physical hardware, and
  so the same checks can run in CI.

## Non-goals

- Reimplementing netlab. netlab stays a separate, out-of-process tool; we
  orchestrate it, we do not vendor it.
- Making netlab a hard dependency of netauto. The core stays light and
  read-only; lab support is **optional** and a no-op where netlab is absent.
- Supporting every netlab device kind. Only the platforms netauto already has
  drivers for are wired in (see the mapping table).

---

## How netlab works (the parts we touch)

netlab is a **Python 3.10+ CLI tool** (`pip install networklab`). It is an
orchestrator, not a library — there is no stable public Python API, so we
integrate by **running its CLI and parsing the files it emits**.

- Input: a **YAML topology** describing nodes, links, and features (addressing,
  OSPF/BGP, VXLAN, VRFs are generated for you).
- Backends: **libvirt/KVM + Vagrant** (VMs) or **Docker + containerlab**
  (containers). Config is pushed with **Ansible**.
- Commands: `netlab up`, `netlab down`, `netlab status`, `netlab connect`,
  `netlab exec`, `netlab inspect`.
- Output we consume: the **transformed topology as YAML**. netlab's *native*
  snapshot is a pickle (`netlab.snapshot.pickle`) — version-coupled and not
  ours to unpickle — so instead we ask netlab to dump the same data model as
  YAML with `netlab create -o yaml:netlab.snapshot.yml`. That gives a top-level
  `nodes` dictionary keyed by node name, each carrying its device kind and
  **management IP** (`ansible_host`, or `mgmt.ipv4` with a prefix).

This is the whole integration seam: run `netlab up`, dump and read the topology
YAML for `name → (kind, mgmt IP)`, map kinds to netauto platforms, build an
`Inventory`. The `-o yaml:` form is the one pinned line; the parser is verified
against captured fixtures independently, so a netlab release that changes the
output is a contained fix.

---

## Where it sits in netauto

```
              docs/netlab-integration.md  (this doc)

  topology.yml ──▶ netlab up ──▶ running lab (mgmt network, SSH-reachable IPs)
                       │
                       ▼
              netlab create -o yaml  ▸  netlab.snapshot.yml
                       │
        netauto.lab: parse snapshot ──▶ platform mapping ──▶ netauto Inventory
                       │
                       ▼
     existing read paths — connect() ▸ audit ▸ checks ▸ workflows ▸ topology
                       │
                       ▼
                 netlab down  (tear the lab back down)
```

The point is that **nothing downstream of the inventory is new**. Once a lab
node is an `netauto.inventory.Device` with a platform and a host IP,
`netauto.audit`, `netauto.checks`, `netauto.workflows`, and `netauto.topology`
work against it unchanged. The whole integration is the left column: a wrapper
around netlab's CLI plus a snapshot→inventory translator.

---

## The read-only question

netauto's promise is that it does not write to **managed devices** — its one
device write is the gated firmware upgrade. netlab plainly writes: `netlab up`
provisions VMs/containers and Ansible pushes full configurations.

These are different risk classes and the design keeps them visibly separate:

- The gated firmware upgrade writes to **production gear you operate**. That is
  why it sits behind three gates and is off by default.
- netlab writes to **ephemeral lab infrastructure that netlab itself created
  and will destroy** — throwaway VMs and containers on a hypervisor, not
  managed inventory.

So the framing is: **netauto never gains a new write path to a managed
device.** The lab module *orchestrates disposable infrastructure*; it does not
loosen the device-write stance. To keep that legible:

- The lab module is its **own package and its own GUI page**, labelled "lab",
  never mixed into Devices/Audit for real inventory.
- netauto's connection to lab devices remains **read-only** — it audits them,
  it does not configure them (netlab/Ansible does the configuring).
- Lab inventory is kept distinct from the real `inventory/devices.yaml` (a
  separate file or an in-memory inventory), so a lab node can never be confused
  for a production device.

---

## Module design: `netauto.lab`

A thin wrapper. netauto stays Python; netlab stays a subprocess.

```
netauto/lab/
  __init__.py     # is_available(), and the public re-exports
  runner.py       # up/down/status/write_snapshot/read_inventory: the netlab CLI
  snapshot.py     # parse the topology YAML -> list[LabNode]
  inventory.py    # LabNodes -> netauto Devices (the platform mapping)
```

- **`runner.up(topology, provider=None)`** — shells out to `netlab up` in the
  topology's directory, returns when the lab is converged (or raises `LabError`
  with netlab's own diagnostic). `down()` runs `netlab down`; `status()` wraps
  `netlab status`; `write_snapshot()` runs the pinned `netlab create -o yaml:`.
  `is_available()` probes for the binary, so a caller can offer a lab action
  only where netlab is installed.
- **`snapshot.load(path)`** — parses the topology YAML into
  `LabNode(name, kind, mgmt_ip)` records. This is the parser pinned to a tested
  netlab version and treated as the integration seam.
- **`inventory.map_nodes(nodes)`** — returns `Mapped(devices, skipped)`: each
  drivable node becomes a `Device(name=…, platform=…, host=mgmt_ip, tags=("lab",))`,
  and every unmappable node is kept aside *with a reason* rather than dropped or
  faked. `from_snapshot()` is the shortcut to just the drivable `Inventory`.
- Credentials come from the environment as everywhere else in netauto; lab nodes
  share one prefix (`LAB` by default), matching how netlab gives a topology one
  set of credentials.

### Platform mapping (the labbable subset)

Only netlab kinds with an existing netauto driver are wired in. The rest are
skipped, honestly, with a note in the lab view.

| netlab device kind | netauto platform | Notes |
| --- | --- | --- |
| `iosv`, `iol`, `csr`, `cat8000v` | `cisco_ios` | via napalm `ios` |
| `nxos` | `cisco_nxos` | via napalm `nxos_ssh` |
| `eos` (Arista cEOS/vEOS) | `arista_eos` | native container — cheap to lab |
| `vsrx`, `vptx` (Juniper) | `juniper_junos` | VM via vrnetlab |
| `frr`, `vyos`, `srlinux`, `cumulus` | *(none)* | no netauto driver — skipped |

Aruba, Meraki and Fortinet have no first-class netlab images, so the lab side
covers the Cisco / Juniper / Arista routing-and-switching subset — still the
bulk of the driver matrix. This is a coverage gap to state plainly, not to hide.

---

## GUI: a Lab page

A single new page, `/lab`, kept clearly scoped as lab, not production:

- Pick a topology file, choose a provider (libvirt or clab), **Bring up** /
  **Tear down**, and watch convergence status.
- Once up, list the lab nodes with their mapped platform and mgmt IP, and link
  straight to Audit / Topology **on the lab inventory**.
- Show netlab's availability up front: if netlab (or a provider) is not
  installed, the page says so and links here rather than offering a button that
  can only fail.

Bringing a lab up is a non-idempotent server action, so it POSTs and is
CSRF-protected like the other write-to-server routes — and it is added to
`ALLOWED_POST_ROUTES` in `tests/conftest.py` with the reason that it
orchestrates ephemeral lab infra, **not** a managed-device write.

---

## Dependencies and optionality

netlab pulls in libvirt/KVM or Docker+containerlab, Ansible, Vagrant, and
device images — all **host-level**, none installable from netauto's package.
Therefore:

- netlab is **not** added to netauto's dependencies. `netauto.lab.is_available()`
  probes for the `netlab` binary at runtime.
- Where netlab is absent, the module and the page degrade to an explanatory
  no-op. netauto stays installable and light for its read-only appliance role.
- A tested netlab version is pinned in the docs; the snapshot parser is the one
  place that knows netlab's output format, so a netlab upgrade is a single,
  contained thing to re-verify.

---

## Testing

The wrapper is testable **without a hypervisor**, which is what keeps this
mergeable in CI:

- `runner` is tested with the netlab CLI faked (a stub on `PATH` or a patched
  subprocess) — assert the argv we build and how we parse exit codes/output.
- `snapshot` and `inventory` are tested against a **captured**
  `netlab.snapshot.yml` fixture — assert the `name → (platform, mgmt IP)`
  mapping, both management-IP forms, and that unmappable kinds are skipped with
  a reason, not fatal.
- The GUI page is tested like the others: requires a session, and renders the
  "netlab not available" state as well as a populated node list.
- One optional, **marked** end-to-end test (`@pytest.mark.netlab`) actually runs
  `netlab up`/`down` on a tiny two-node container topology, skipped unless a
  `NETAUTO_NETLAB_E2E` env flag and netlab are present. It never runs in the
  default suite.

---

## Phasing

1. **`runner` + `snapshot` + `inventory`** — CLI wrapper and snapshot→inventory
   translation, with fixtures and unit tests. No GUI yet; usable from a REPL.
   *(Done — `netauto/lab/`, `tests/test_lab.py`.)*
2. **`/lab` GUI page** — bring up / tear down / node list, availability
   handling, POST-route allowlist entry.
   *(Done — the `/lab` routes in `web/app.py`, `web/templates/lab.html`,
   `netauto/lab/service.py`, and the `labs_dir` setting. Topologies are
   discovered under `labs_dir`; netlab up/down run as background jobs the page
   polls; where netlab is absent the page says so and the routes refuse.)*
3. **Validation loop** — a one-click "audit this lab" that runs the existing
   compliance checks against the lab inventory and shows the findings, i.e. the
   "test the design" payoff.
   *(Done — `netauto/lab/audit.py` (`audit_lab`), the `audit` action in
   `service.py`, the `/lab/audit` and `/lab/audits/{id}` routes, and
   `web/templates/lab_audit.html`. It reuses `audit_device`, so every rule and
   finding is the one netauto already produces; it reads the on-disk snapshot
   and connects read-only, so no netlab is needed to audit an up lab, and lab
   findings are kept out of the compliance metrics.)*
4. *(Later, optional)* a CI recipe: up → audit → assert clean → down, as a
   template others can copy for design regression testing.
   *(Done — `netauto/lab/ci.py` and the workflow template `docs/lab-audit.ci.yml`;
   see the CI recipe below.)*

## CI recipe

The audit loop, made into a gate. `netauto.lab.ci` builds a lab, audits it, and
exits non-zero if the design regressed:

```
python -m netauto.lab.ci labs/spine-leaf/topology.yml --fail-on high
```

It brings the lab up, runs the same compliance ruleset the Audit page runs,
tears the lab back down (pass or fail, unless `--keep`), and turns the result
into an exit code a CI job reads:

| Exit | Meaning |
| --- | --- |
| `0` | clean — nothing failed at or above `--fail-on` |
| `1` | findings — the audit failed the gate; the design regressed |
| `2` | infrastructure — the lab could not be built or audited at all |

Two things fail the gate: a node that could not be audited (an unreachable
device is not a passing device), and a failing finding at or above `--fail-on`
(`any`, or a severity floor; default `high`). Advisory findings below the line
are reported but do not fail the build.

`docs/lab-audit.ci.yml` is a **copyable GitHub Actions workflow** — kept out of
`.github/workflows/` deliberately, because it needs a self-hosted runner with
netlab and a provider, which the default hosted runners lack. Copy it into a
repository that has such a runner, point it at a topology, and set
`LAB_USERNAME` / `LAB_PASSWORD` in secrets.

## Open questions

- **Lab credentials**: seed from netlab's defaults, or require the operator to
  set a `LAB_*` prefix explicitly? (Leaning explicit, to match netauto's
  env-credential model.)
- **Where lab inventory lives**: purely in memory for the session, or written
  to a separate `inventory/lab.yaml`? (Leaning in-memory first, to keep it from
  ever mixing with production inventory.)
- **Provider default**: containerlab is faster and lighter and covers cEOS /
  the container kinds; libvirt is needed for the Cisco/Juniper VM images.
  Default to clab and let the topology/flags opt into libvirt.

## Out of scope

- Writing configuration to lab devices from netauto (netlab/Ansible owns that).
- Managing device images, hypervisor setup, or netlab installation.
- Any change to netauto's managed-device read-only guarantee.
