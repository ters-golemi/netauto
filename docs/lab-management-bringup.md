# Lab device bring-up

Getting the two lab devices addressed and reachable, before any VLAN or policy
work.

Earlier revisions of this document described an out-of-band management plane on
VLAN 99, spanning a FortiSwitch and an HPE Instant On 1930. That design is gone.
The Aruba was dropped, the FortiSwitch became the access switch, and management
now rides VLAN 10 in-band alongside user traffic. What that costs is recorded
below.

netauto has no commit path, so nothing here is applied by it. This is a manual
build. What netauto does afterwards is read and audit the result.

## What changed, and what it costs

**Management is in-band.** One switch carries both planes. A bad switch config
takes out your access to the devices along with the data path. The mitigation is
that the FortiSwitch has a console port, so recovery is a cable rather than a
factory reset — which was not true of the Aruba.

**Management shares the users VLAN.** Anything on VLAN 10 can reach the switch
and firewall management interfaces. Two lines of configuration hold that back:
`trusthost1` on the switch and the FDM management-access rule, both scoped to
the NetAuto host as a /32. Without them this design is materially weaker than
the one it replaced. They are not optional hardening.

**Management1/1 stays configured but unplugged.** It keeps 10.10.99.10/24, which
overlaps nothing, so a laptop on 10.10.99.x plugged straight into that port is a
way back in when the data path is broken.

## Addressing

| Device | Address | Reached over |
| --- | --- | --- |
| FTD VLAN10 interface (FDM) | 10.10.10.1/24 | VLAN 10, in-band |
| FortiSwitch 108F | 10.10.10.12/24 | VLAN 10, in-band |
| Access point | 10.10.10.13/24 | VLAN 10, in-band |
| NetAuto host / admin PC | 10.10.10.20/24 | VLAN 10 |
| FTD Management1/1 | 10.10.99.10/24 | direct attach only, cable out |

DNS is `8.8.8.8` throughout — handed to clients by DHCP and used by the FTD
itself.

## Order of work

Switch first, firewall second. The switch has to be passing VLAN 10 before the
firewall can be managed on it.

## 1. FortiSwitch 108F

Console at 9600 8N1, or reach the factory address — commonly `192.168.1.99/24`,
user `admin`, no password.

Confirm standalone mode before anything else. A unit that was ever paired to a
FortiGate is in FortiLink mode and will ignore local configuration:

```
get system status
```

Then apply [fsw-config-template.cfg](fsw-config-template.cfg). Read the caveat
at the top of that file first — the syntax was written from documentation rather
than captured from a device, and two stanzas commonly differ between
FortiSwitchOS builds.

**Do the management-interface change from the console.** Moving the switch to
10.10.10.12 on VLAN 10 drops whatever session is applying it.

## 2. Cisco Firepower 1010

Console over the RJ-45 or mini-USB port, 9600 8N1. Default FTD credentials are
`admin` / `Admin123`. On a factory-fresh unit the setup wizard runs first and
asks for the management address directly.

Check what is actually there before changing anything, rather than trusting
documented defaults:

```
> show network
```

Then:

```
> configure network hostname ftd-edge-01
> configure network ipv4 manual 10.10.99.10 255.255.255.0 data-interfaces
> configure network dns servers 8.8.8.8
> show network
```

### On the `data-interfaces` gateway

Passing `data-interfaces` instead of an IP tells FTD to route
management-sourced traffic — smart licensing, database updates, DNS — over the
backplane and out through the data path. That is what lets Management1/1 sit
unplugged while licensing keeps working.

Verify the keyword is accepted on your software version. If it is not, leave the
gateway unset: the port stays reachable by direct attach, it just will not
license.

### Access lists

These apply to Management1/1 only, and are worth setting even though the cable
comes out, because the port is the recovery path:

```
> configure ssh-access-list 10.10.99.0/24
> configure https-access-list 10.10.99.0/24
```

Everything else — interfaces, VLANs, NAT, access rules, and the management-access
rule that puts FDM on 10.10.10.1 — is FDM work. See
[lab-data-plane.md](lab-data-plane.md) and
[ftd-config-template.yaml](ftd-config-template.yaml).

**Do not unplug Management1/1 until FDM answers on https://10.10.10.1 from the
NetAuto host.** That ordering is the difference between a clean cutover and a
console session.

## Verification

From the NetAuto host at `10.10.10.20`, once the data plane is up:

```bash
ping 10.10.10.1               # FTD VLAN10 interface
ping 10.10.10.12              # FortiSwitch
ssh admin@10.10.10.12         # switch CLI
curl -k https://10.10.10.1    # FDM
```

From any other VLAN 10 host, the same two management targets should refuse the
connection. If they answer, the trusted-host scoping did not take, and that is
the finding to chase before anything else.

## What netauto sees

The FortiSwitch is the only device in the lab with a plausible driver:
`fortinet_cli` over netmiko. It runs FortiSwitchOS rather than FortiOS, so
`fortinet_fortios` and its REST client do not apply and show-command output will
differ from a FortiGate.

The FTD has no driver at all — its CLI is not IOS, and there is no FTD or ASA
platform string.

```yaml
devices:
  - name: fsw-access-01
    platform: fortinet_cli
    host: 10.10.10.12
    credentials: LAB_FSW
    tags: [lab, access]
```

```bash
export LAB_FSW_USERNAME=admin
export LAB_FSW_PASSWORD='...'
```

Note that `net_discover_local` needs the NetAuto host directly attached to the
segment it sweeps, since `arp-scan` is only authoritative on a connected
segment. On VLAN 10 it will find the firewall, the switch, the AP and the wired
users — but nothing on VLAN 20 or 30. An empty sweep of those is the topology,
not a bug in the tool.
