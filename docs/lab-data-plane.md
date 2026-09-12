# Lab data plane

Access switch VLANs and Firepower 1010 routing, NAT and security policy.

Assumes the management plane from [lab-management-bringup.md](lab-management-bringup.md)
is already built and reachable. That is what makes this document safe to execute:
every step below can strand the data path without stranding the devices.

netauto has no commit path, so nothing here is applied by it. This is a manual
build. What netauto does afterwards is read and audit the result.

## Addressing

| VLAN | Name | Subnet | Gateway (FTD) | Client addressing |
| --- | --- | --- | --- | --- |
| 10 | Users | 10.10.10.0/24 | 10.10.10.1 | DHCP, .100–.200 |
| 20 | Servers | 10.10.20.0/24 | 10.10.20.1 | Static |
| 30 | WiFi | 10.10.30.0/24 | 10.10.30.1 | DHCP, .100–.200 |
| 99 | Management | 10.10.99.0/24 | none (flat L2) | Static, already built |

Outside: Ethernet1/1, DHCP from the ISP.
DNS: `8.8.8.8`, handed to clients by DHCP and used by the FTD itself.

### Why these numbers

The third octet matches the VLAN ID, which makes an address readable without a
lookup. More usefully, the three data subnets all fall inside **10.10.0.0/18**
(10.10.0.0 – 10.10.63.255), while management at 10.10.99.0/24 sits outside that
block, in 10.10.64.0/18.

That separation is the point. A single object covering every data VLAN cannot
accidentally include the management segment, in a firewall rule or in netauto's
discovery scoping. Management was not renumbered because it is already deployed
and is the only path to the devices.

Room to grow inside 10.10.0.0/18: VLANs 40 through 63 map straight onto
10.10.40.0/24 – 10.10.63.0/24 with no re-planning.

## HPE Instant On 1930

| Port | Mode | VLAN membership | PVID |
| --- | --- | --- | --- |
| 1 | Trunk to Firepower | 10, 20, 30 tagged | 1 |
| 2 | Access — Users | 10 untagged | 10 |
| 3 | Access — Servers | 20 untagged | 20 |
| 4 | Access — WiFi | 30 untagged | 30 |
| 24 | Access — Management | 99 untagged | 99 |
| 5–23 | Unused | — | — |

Create VLANs 10, 20 and 30 under *Switching → VLAN* first, then set port
membership. Remove ports 2, 3 and 4 from VLAN 1 as you assign them.

VLAN 1 stays as the trunk's native VLAN and carries nothing. Untagged frames
arriving on port 1 are then discarded at the firewall, which is the behaviour to
want.

**Do not touch port 24 or the VLAN 99 IP interface.** The switch has no console
port and no CLI; that path is the only way in. If you lose it the recovery is
the reset button and a rebuild from scratch.

If port 4 feeds a real access point rather than a single test client, it
probably needs to be a trunk — most APs tag their SSID VLANs rather than
presenting one untagged. Confirm before cabling.

## Cisco Firepower 1010

All of this is FDM work. FTD's CLI configures the management plane and runs
`show` commands; it does not configure interfaces, NAT or access rules. There is
no CLI config to paste. See [ftd-config-template.yaml](ftd-config-template.yaml)
for the same content in a form you can diff and version.

Switch-port and trunk configuration on the 1010 needs FTD 6.5 or later. Check
`show version` first — on an older train the hardware switch is access-mode only
and each VLAN would need its own physical link to the Aruba.

### Step 0 — delete the VLAN1 inside interface

The management build left an inside interface on VLAN1. It has to go before
VLAN10 can take 10.10.10.0/24, and its switch ports have to be freed before
Ethernet1/2 can become a trunk.

This is the step the out-of-band work paid for. You are deleting the interface
you would previously have been managing through, and the box stays reachable on
Management1/1 throughout.

### Interfaces

| Interface | Mode | Configuration | Zone |
| --- | --- | --- | --- |
| Ethernet1/1 | Firewall | IPv4 DHCP, obtain default route | outside-zone |
| Ethernet1/2 | Switch port | Trunk, allowed VLANs 10/20/30, native 1 | — |
| Ethernet1/3–1/8 | — | Disabled | — |
| VLAN10 | Routed | 10.10.10.1/24, name `users` | users-zone |
| VLAN20 | Routed | 10.10.20.1/24, name `servers` | servers-zone |
| VLAN30 | Routed | 10.10.30.1/24, name `wifi` | wifi-zone |
| Management1/1 | OOB | 10.10.99.10/24 — unchanged | — |

One zone per VLAN. Zones are what the access rules match on, so collapsing two
VLANs into a shared zone would silently merge their policy.

### NAT

Three dynamic PAT rules, each translating to the outside interface address:

| Source zone | Source network | Destination zone | Translation |
| --- | --- | --- | --- |
| users-zone | 10.10.10.0/24 | outside-zone | Interface PAT |
| servers-zone | 10.10.20.0/24 | outside-zone | Interface PAT |
| wifi-zone | 10.10.30.0/24 | outside-zone | Interface PAT |

Because every rule names outside-zone as the destination, inter-VLAN traffic
does not match any of them and is routed untranslated. That is what you want —
NAT between internal VLANs would break return paths and make the logs useless.

No inbound NAT. Nothing in this design publishes a service to the internet. If
VLAN 20 later needs to host something reachable from outside, that is a separate
decision with its own exposure, not an extension of this rule set.

### Access control policy

Default action: **Block**. Rules evaluate top to bottom, first match wins.

| # | Name | Source zone | Destination zone | Action | Log |
| --- | --- | --- | --- | --- | --- |
| 1 | wifi-to-internal-block | wifi-zone | users-zone, servers-zone | Block | Yes |
| 2 | internal-to-wifi-block | users-zone, servers-zone | wifi-zone | Block | Yes |
| 3 | users-to-servers | users-zone | servers-zone | Allow | Yes |
| 4 | servers-to-users | servers-zone | users-zone | Allow | Yes |
| 5 | users-to-internet | users-zone | outside-zone | Allow | Yes |
| 6 | servers-to-internet | servers-zone | outside-zone | Allow | Yes |
| 7 | wifi-to-internet | wifi-zone | outside-zone | Allow | Yes |

Rules 1 and 2 are redundant against the default block. Keep them anyway. They
state the isolation as policy rather than leaving it as a side effect of the
default action, and they are the rules you will want to see hit counters on when
somebody asks whether guest isolation is actually working. An implicit deny
proves nothing in an audit.

Rules 3 and 4 both exist because FDM rules are directional. Inspection is
stateful, so return traffic needs no rule of its own — only a new connection
opened from the other side does.

WiFi isolation is bidirectional, so nothing on VLAN 10 or 20 can reach VLAN 30
either. Casting, printing and managing an AP from a user machine will not work
across this boundary by design. If the AP itself needs managing, give it an
address on VLAN 99 rather than poking a hole here.

### DHCP

| Interface | Pool | Gateway | DNS |
| --- | --- | --- | --- |
| VLAN10 | 10.10.10.100 – .200 | 10.10.10.1 | 8.8.8.8 |
| VLAN30 | 10.10.30.100 – .200 | 10.10.30.1 | 8.8.8.8 |

VLAN20 gets no DHCP server. Server addresses that move are their own category
of outage.

Handing out `8.8.8.8` rather than the interface address means clients resolve
against Google directly. That traffic is ordinary VLAN-to-outside flow and is
covered by rules 5, 6 and 7 — the firewall is not acting as a resolver, so there
is no to-the-box DNS exception to reason about. It also means WiFi clients never
need to talk to the FTD at all.

## Verification

Order matters: confirm the trunk before blaming the policy.

```bash
# on the Aruba, from a VLAN 10 client
ip addr                       # expect 10.10.10.100-200
ping 10.10.10.1               # gateway
ping 8.8.8.8                  # internet via PAT
ping 10.10.20.x               # server VLAN, expect success
ping 10.10.30.x               # WiFi VLAN, expect timeout

# from a VLAN 30 client
ping 10.10.30.1               # gateway
ping 8.8.8.8                  # internet, expect success
ping 10.10.10.x               # expect timeout
ping 10.10.20.x               # expect timeout
```

A VLAN 30 client that can reach 8.8.8.8 but not 10.10.10.x is the whole design
working. If everything times out including 8.8.8.8, suspect the trunk or the
PAT rule before the access policy.

In FDM, the hit counters on rules 1 and 2 should be zero on a healthy network
and non-zero the moment something misbehaves — worth watching during testing.

## What netauto sees

The FTD still has no driver, so none of this policy is readable by the toolkit.
The Aruba has no driver either. The value of this build for netauto testing is
the discovery path: `net_discover_local` against each data subnet should find
the gateway and the attached hosts.

```bash
net_discover_local(cidr="10.10.10.0/24", probe_ports="22,443")
net_discover_local(cidr="10.10.20.0/24", probe_ports="22,443")
net_discover_local(cidr="10.10.30.0/24", probe_ports="22,443")
```

That requires the NetAuto host to be directly attached to each segment, since
`arp-scan` is only authoritative on a connected segment. From its position on
VLAN 99 it will see nothing on the data VLANs. Either give it an interface on
the trunk, or accept that discovery testing happens on the management segment
only.

This is worth knowing before reading an empty sweep as a bug in the tool.
