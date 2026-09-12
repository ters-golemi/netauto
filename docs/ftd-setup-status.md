# Cisco Firepower 1010 (FTD) — Setup Status

Progress record for the NetAuto lab firewall. This is the **actual state**, not
the intended design; the target configuration is
`docs/ftd-config-template.yaml`, and the build order is
`docs/lab-management-bringup.md` → `docs/lab-data-plane.md`. The management plane
was built over the console; the **data plane is now built and deployed via the
FDM REST API** — see below.

Companion to the lab design docs, recording how far the FTD build has
actually got. Device serial and UUID are omitted; addresses are the lab's
documented RFC1918 plan, matching the other docs here.

---

## Device identity

| Attribute | Value |
| --- | --- |
| Model | Cisco Firepower 1010 Threat Defense |
| FTD software | 7.0.1 (build 84) |
| FXOS platform | 2.10(1.175) |
| Serial | *(redacted — real unit)* |
| VDB | 338 |
| Firewall mode | routed |
| Management | Local — Firepower Device Manager (FDM), on-box |
| Hostname | ftd-edge-01 |

---

## What has been done

Reached over the **console** (RJ-45/USB, 9600 8N1). netauto has no FTD driver,
so none of this was automated — every step was manual at the CLI.

1. **Factory reset** — performed with the reset button; the unit rebooted into
   a clean first-boot.
2. **Admin password** — set at first login (the default `admin`/`Admin123` is
   forced to change on first boot).
3. **First-boot wizard, completed:**
   - EULA accepted.
   - IPv4 configured, IPv6 left at DHCP (harmless; not used).
   - **Manage the device locally? → yes** — FDM on-box management, not FMC.
   - Firewall mode came up **routed**.
4. **Management plane** (the part the FTD CLI configures):
   - `configure network hostname ftd-edge-01`
   - `configure network ipv4 manual 10.10.99.10 255.255.255.0 data-interfaces`
   - `configure network dns servers 8.8.8.8`
5. **FDM bootstrap** — the NetAuto host was cabled to the FTD **MGMT port** on
   `10.10.99.20/24`, making `https://10.10.99.10` reach FDM. FDM initial setup
   (EULA + provisioning) was finalised via the API, unblocking config.
6. **Data plane, built and deployed via the FDM REST API** — the whole of
   `ftd-config-template.yaml`: interfaces, VLAN SVIs, the trunk, security zones,
   NAT, the access policy and DHCP. Deployed successfully; 0 pending changes.

### Management interface (`show network`)

| Field | Value |
| --- | --- |
| Interface | management0 (Management1/1) |
| IPv4 | 10.10.99.10 / 255.255.255.0, **Manual** |
| Gateway | `data-interfaces` (mgmt traffic egresses via the data path; backplane next-hop 169.254.1.1) |
| DNS | 8.8.8.8 |
| Link | Up |

> The hostname change reported *"Deploy changes from Firepower Device Manager to
> complete."* From here, **FDM is the control point** — even small changes are
> finalised by an FDM deploy.

### Interface state (`show interface ip brief`)

| Interface | Address | Method | Status | Role |
| --- | --- | --- | --- | --- |
| Ethernet1/1 | unassigned | DHCP | down/down | outside / WAN — cabled to modem, link not up |
| Ethernet1/8 | trunk | — | up | 802.1Q trunk (native VLAN1, tagged 10/20/30) to FortiSwitch port1 |
| Vlan10 | 10.10.10.1/24 | manual | up | users, users-zone |
| Vlan20 | 10.10.20.1/24 | manual | up | servers, servers-zone |
| Vlan30 | 10.10.30.1/24 | manual | up | wifi, wifi-zone |
| Vlan1 | 192.168.95.1 | manual | up | native VLAN of the trunk; carries nothing |
| Ethernet1/2–1/7 | — | — | disabled | unused |
| Management1/1 | 10.10.99.10 | manual | up | dedicated OOB management (FDM) |

---

## Data plane — built and deployed (FDM REST API)

The FTD CLI configures only the management plane; interfaces, VLANs, NAT and
access rules are FDM-only. These were scripted against `/api/fdm/latest` and
**deployed** — the running config now holds all of `ftd-config-template.yaml`:

- **Interfaces:** Ethernet1/1 → outside (DHCP, default route); Ethernet1/8 →
  802.1Q trunk, native VLAN1, tagged 10/20/30; Ethernet1/2–1/7 disabled.
- **VLAN SVIs:** VLAN10 `10.10.10.1/24` (users), VLAN20 `10.10.20.1/24`
  (servers), VLAN30 `10.10.30.1/24` (wifi) — one security zone each.
- **NAT:** three dynamic PAT rules (users/servers/wifi → outside interface).
- **Access policy:** default block; 7 rules, blocks first — wifi isolation both
  ways, users↔servers, and per-VLAN internet.
- **DHCP servers:** VLAN10 `.100–.200`, VLAN30 `.100–.200`, DNS `8.8.8.8`.

### Deviations from the template (all benign, FDM 7.0.1 specifics)

- **Block rules use `LOG_NONE`.** FDM 7.0.1 rejects per-flow logging on a block
  rule (`acRuleLogEndNotAllowedWithDeny`). The explicit rules and their hit
  counters — the template's stated audit value — are unaffected.
- **VLAN1 kept** as the trunk's native VLAN rather than deleted; functionally
  equivalent and avoids removing an interface.
- The factory **inside DHCP pool** (Vlan1, 192.168.95.x) was left in place;
  inert, since VLAN1 carries nothing.

### API specifics worth recording

Points where the FP1010/FDM API differed from a naive reading of the template:
a VLAN SVI needs an explicit `hardwareName` (`Vlan10`); the trunk fields are
`trunkModeNativeVlan` (required) and `trunkModeAllowedVlans`; static DHCP DNS
requires clearing the container's auto-config `interface`; the DHCP field is
`enableDHCP`.

## Not yet verified

- **Inter-VLAN routing and client DHCP** have not been tested end to end: the
  NetAuto host is on the isolated MGMT segment, not a data VLAN. Move it to a
  FortiSwitch access port (VLAN 10) to confirm a `10.10.10.100–.200` lease and
  the `10.10.10.1` gateway.
- **Internet** waits on the WAN link (below).

---

## Remaining

**WAN link is down.** Ethernet1/1 is set to DHCP + default route but shows
down/down — the modem link is not up. No config change needed; it pulls a lease
once the modem's LAN port links. (Deferred by the operator.) Until then the data
plane is fully configured but has no internet egress; inter-VLAN routing does
not depend on it.

The FDM-reachability blocker is resolved: FDM was reached out-of-band on the
MGMT port (`10.10.99.10`) and the data plane deployed through it. In-band FDM on
VLAN10 (`10.10.10.1`) now also exists, per the template.

---

## How this relates to the rest of the lab

- The **FortiSwitch 108F** is fully configured, in netauto's inventory
  (`fsw-access-01`, 10.10.10.12), reachable over SSH, and audits clean. Its
  uplink (port1) is cabled to this FTD's Ethernet1/8, and the FTD-side trunk
  (VLANs 10/20/30) is now deployed — both ends of the trunk are configured.
- The FTD is **not** in netauto's inventory and has **no driver**; netauto
  cannot read or audit it. Its documentation is this file and the template.
- Reference: `docs/ftd-config-template.yaml` (target config),
  `docs/lab-management-bringup.md`, `docs/lab-data-plane.md`.
