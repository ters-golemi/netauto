# Lab data plane

VLANs, trunking and firewall policy for the single-switch lab.

Assumes both devices are addressed and reachable per
[lab-management-bringup.md](lab-management-bringup.md).

netauto has no commit path, so nothing here is applied by it. This is a manual
build. What netauto does afterwards is read and audit the result.

## Addressing

| VLAN | Name | Subnet | Gateway | Client addressing |
| --- | --- | --- | --- | --- |
| 10 | Users + management | 10.10.10.0/24 | 10.10.10.1 | DHCP .100–.200 |
| 20 | Servers | 10.10.20.0/24 | 10.10.20.1 | Static |
| 30 | WiFi | 10.10.30.0/24 | 10.10.30.1 | DHCP .100–.200 |

Outside: Ethernet1/1, DHCP from the ISP. DNS `8.8.8.8` throughout.

Static reservations on VLAN 10, all below the DHCP pool: FDM `.1`, FortiSwitch
`.12`, access point `.13`, NetAuto host `.20`.

There is no VLAN 40 and no VLAN 99 in the data plane. Both existed in earlier
revisions — VLAN 40 held users while VLAN 10 was a dedicated management VLAN,
and VLAN 99 was the out-of-band segment. Neither survives the move to in-band
management.

## Physical

```
Internet ── Eth1/1 ── [ Firepower 1010 ] ── Eth1/8 ══ port1 ── [ FortiSwitch 108F ]
                        Mgmt1/1 (unplugged)          trunk 10,20,30
```

Single trunk. The firewall is a router-on-a-stick for three VLANs.

## FortiSwitch 108F

| Port | Mode | Native | Tagged | Connects to |
| --- | --- | --- | --- | --- |
| port1 | Trunk | 1 (unused) | 10, 20, 30 | FTD Ethernet1/8 |
| port2 | Disabled | — | — | Freed when the Mgmt1/1 cable came out |
| port3 | Access | 10 | — | NetAuto host / admin PC |
| port4 | Trunk | 10 | 30 | Access point |
| port5 | Access | 10 | — | Wired user |
| port6 | Access | 20 | — | Server |
| port7–8 | Disabled | — | — | Spare |

VLAN 1 is the trunk's native VLAN and carries nothing, so untagged frames
arriving on port1 are discarded at the firewall.

Port4 gives the AP its management address untagged on VLAN 10 and tags only the
SSID VLAN, which is how most APs expect to be trunked. Confirm your AP's
behaviour before cabling — some present management tagged as well.

Full configuration: [fsw-config-template.cfg](fsw-config-template.cfg).

## Cisco Firepower 1010

FDM work. FTD's CLI configures the management plane and runs `show` commands; it
does not configure interfaces, NAT or access rules. There is no CLI config to
paste. Full spec: [ftd-config-template.yaml](ftd-config-template.yaml).

Switch-port and trunk configuration on the 1010 needs FTD 6.5 or later. Check
`show version` first — on an older train the hardware switch is access-mode only
and each VLAN would need its own physical link.

### Interfaces

| Interface | Mode | Configuration | Zone |
| --- | --- | --- | --- |
| Ethernet1/1 | Firewall | IPv4 DHCP, obtain default route | outside-zone |
| Ethernet1/8 | Switch port | Trunk, allowed 10/20/30, native 1 | — |
| Ethernet1/2–1/7 | — | Disabled | — |
| VLAN10 | Routed | 10.10.10.1/24, name `users` | users-zone |
| VLAN20 | Routed | 10.10.20.1/24, name `servers` | servers-zone |
| VLAN30 | Routed | 10.10.30.1/24, name `wifi` | wifi-zone |
| Management1/1 | OOB | 10.10.99.10/24, cable out | — |

One zone per VLAN. Zones are what the access rules match on, so collapsing two
VLANs into a shared zone would silently merge their policy.

### Management access

FDM is reached on the VLAN10 interface address, `10.10.10.1`, from
`10.10.10.20/32` over HTTPS and SSH.

This is to-the-box traffic. It is **not** evaluated by the access control policy
below — it is configured separately under management access, and it is easy to
believe an access rule is protecting it when nothing is.

The source is a /32 deliberately. Management shares the users VLAN now, so
permitting `10.10.10.0/24` would make every user machine an administrative
source. That single scoping decision is what keeps this design from being
materially weaker than the out-of-band one it replaced.

### NAT

| Source zone | Source network | Destination zone | Translation |
| --- | --- | --- | --- |
| users-zone | 10.10.10.0/24 | outside-zone | Interface PAT |
| servers-zone | 10.10.20.0/24 | outside-zone | Interface PAT |
| wifi-zone | 10.10.30.0/24 | outside-zone | Interface PAT |

Every rule names outside-zone as destination, so inter-VLAN traffic matches none
of them and is routed untranslated. NAT between internal VLANs would break
return paths and make the logs useless.

No inbound NAT. Nothing here publishes a service to the internet.

### Access control policy

Default action: **Block**. First match wins.

| # | Name | Source zone | Destination zone | Action |
| --- | --- | --- | --- | --- |
| 1 | wifi-to-internal-block | wifi-zone | users-zone, servers-zone | Block |
| 2 | internal-to-wifi-block | users-zone, servers-zone | wifi-zone | Block |
| 3 | users-to-servers | users-zone | servers-zone | Allow |
| 4 | servers-to-users | servers-zone | users-zone | Allow |
| 5 | users-to-internet | users-zone | outside-zone | Allow |
| 6 | servers-to-internet | servers-zone | outside-zone | Allow |
| 7 | wifi-to-internet | wifi-zone | outside-zone | Allow |

All rules logged.

Rules 1 and 2 are redundant against the default block and are kept deliberately.
They state the isolation as policy rather than leaving it as a side effect of the
default action, and they give an auditable hit counter — an implicit deny proves
nothing in a report. They matter more than they used to: management lives on
VLAN 10, so rule 1 is what keeps wireless clients away from the administrative
segment.

Rules 3 and 4 both exist because FDM rules are directional. Inspection is
stateful, so return traffic needs no rule of its own; only a connection opened
from the other side does.

WiFi isolation is bidirectional. One consequence worth knowing: the access point
has to be administered from a wired VLAN 10 host, not over the wireless it
serves.

### DHCP

| Interface | Pool | Gateway | DNS |
| --- | --- | --- | --- |
| VLAN10 | 10.10.10.100 – .200 | 10.10.10.1 | 8.8.8.8 |
| VLAN30 | 10.10.30.100 – .200 | 10.10.30.1 | 8.8.8.8 |

VLAN20 gets no DHCP server. Server addresses that move are their own category of
outage.

Handing out `8.8.8.8` rather than the interface address means clients resolve
against Google directly, so the firewall is not acting as a resolver and there is
no to-the-box DNS exception to reason about.

## Verification

Confirm the trunk before blaming the policy.

```bash
# from a VLAN 10 client
ip addr                       # expect 10.10.10.100-200
ping 10.10.10.1               # gateway
ping 8.8.8.8                  # internet via PAT
ping 10.10.20.x               # servers, expect success
ping 10.10.30.x               # wifi, expect timeout

# from a VLAN 30 client
ping 10.10.30.1               # gateway
ping 8.8.8.8                  # internet, expect success
ping 10.10.10.x               # expect timeout
ping 10.10.20.x               # expect timeout

# management scoping — from a VLAN 10 host that is NOT 10.10.10.20
curl -k --max-time 5 https://10.10.10.1     # expect refused or timeout
ssh admin@10.10.10.12                       # expect refused
```

That last pair is the one to actually run. A VLAN 30 client reaching 8.8.8.8 but
not 10.10.10.x shows the policy works; an untrusted VLAN 10 host being refused by
both management interfaces shows the part the policy does not cover.

If everything times out including 8.8.8.8, suspect the trunk or the PAT rule
before the access policy.

In FDM, hit counters on rules 1 and 2 should be zero on a healthy network and
non-zero the moment something misbehaves.

## Open items

**PoE.** The plain 108F has no PoE; the POE and FPOE variants do. If yours is
the plain one, the access point needs an injector.

**AP management reachability.** VLAN 10 is routed and NATs to the internet, so a
cloud-managed AP can phone home. This was not true of the previous design, where
the management VLAN had no gateway at all.
