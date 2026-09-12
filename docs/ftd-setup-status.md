# Cisco Firepower 1010 (FTD) — Setup Status

Progress record for the NetAuto lab firewall, as configured over the console so
far. This is the **actual state**, not the intended design; the target
configuration is `docs/ftd-config-template.yaml`, and the build order is
`docs/lab-management-bringup.md` → `docs/lab-data-plane.md`.

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
4. **Management plane** (the only part the FTD CLI can configure — see below):
   - `configure network hostname ftd-edge-01`
   - `configure network ipv4 manual 10.10.99.10 255.255.255.0 data-interfaces`
   - `configure network dns servers 8.8.8.8`

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
| Ethernet1/1 | unassigned | DHCP | **down/down** | outside / WAN — cabled to modem, link not up |
| Ethernet1/8 | unassigned | — | **up/up** | trunk to FortiSwitch 108F port1 |
| Vlan1 | 192.168.95.1 | manual | up | factory-default inside (to be replaced) |
| Ethernet1/2–1/7 | unassigned | — | down | unused / default |
| Management1/1 | — | — | up | dedicated OOB management port |

---

## What remains — the data plane (FDM-only)

The FTD CLI configures the management plane and runs `show` commands. **It does
not configure interfaces, VLANs, NAT, or access rules** — there is no
`configure terminal` to paste. All of the following is done in the **FDM GUI**
or via the **FDM REST API**, and none of it is built yet. Target per
`docs/ftd-config-template.yaml`:

- **Interfaces:** Ethernet1/1 → outside (DHCP, default route); Ethernet1/8 →
  802.1Q trunk carrying VLANs 10/20/30; delete the default Vlan1 inside.
- **VLAN SVIs:** VLAN10 `10.10.10.1/24` (users), VLAN20 `10.10.20.1/24`
  (servers), VLAN30 `10.10.30.1/24` (wifi) — one security zone each.
- **NAT:** three dynamic PAT rules (users/servers/wifi → outside).
- **Access policy:** default block, 7 rules (wifi isolation both ways,
  users↔servers, and per-VLAN internet).
- **DHCP servers:** VLAN10 and VLAN30 pools.
- **Management access:** FDM reachable in-band on VLAN10 (10.10.10.1) from the
  NetAuto host 10.10.10.20/32.

---

## Blockers to finishing

1. **FDM is not reachable over IP yet.** The data plane is FDM-only, and FDM
   needs an IP path. The bootstrap (per `lab-management-bringup.md`) is to put
   the NetAuto host on the management segment and reach FDM on Management1/1 —
   i.e. **connect the host to the FTD MGMT port**, host on 10.10.99.20/24, then
   browse `https://10.10.99.10`. In-band FDM (10.10.10.1) is unavailable until
   the very data plane it would configure exists — the chicken-and-egg the OOB
   management port is there to break.
2. **WAN link is down.** Ethernet1/1 is correctly set to DHCP + default route
   but shows down/down — the modem link is not up. No config change needed;
   it will pull a lease once the modem's LAN port links. (Deferred by the
   operator.)

---

## How this relates to the rest of the lab

- The **FortiSwitch 108F** is fully configured, in netauto's inventory
  (`fsw-access-01`, 10.10.10.12), reachable over SSH, and audits clean. Its
  uplink (port1) is already cabled to this FTD's Ethernet1/8 — the trunk link
  is up, awaiting the FTD-side trunk/VLAN config above.
- The FTD is **not** in netauto's inventory and has **no driver**; netauto
  cannot read or audit it. Its documentation is this file and the template.
- Reference: `docs/ftd-config-template.yaml` (target config),
  `docs/lab-management-bringup.md`, `docs/lab-data-plane.md`.
