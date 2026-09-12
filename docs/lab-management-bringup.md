# Lab management bring-up

Manual bring-up of the management plane on the three-device test lab, so that
netauto has something real to read.

netauto has no commit path, so nothing in this document is automated by it.
Every step here is done by hand, once, through a console cable or a web UI.
What netauto does afterwards is read the result.

## Topology

```
                Internet / ISP
                      |
              Eth1/1 outside (DHCP)
         Cisco Firepower 1010  ──── Mgmt1/1 ────┐
                      |                          |
              Eth1/2 inside (VLAN 1)             |
                      |                          |
      HPE Instant On 1930 ── Port 24 (VLAN 99) ──┤
                      |                          |
              access ports (VLAN 1)       FortiSwitch 108F
                      |                          |
                 test clients                 Port 8
                                                 |
                                           NetAuto host
```

Solid path is data, the Mgmt1/1 and Port 24 links are management.

**VLAN 99 exists only inside the Aruba.** All three management links are
untagged on the wire. The Firepower's Mgmt1/1 and the FortiSwitch's ports need
no VLAN configuration; the tag is applied and stripped at the Aruba's port 24.

## Address plan

Management segment `10.10.99.0/24`. Flat L2 — the NetAuto host is on the same
segment, so no gateway is needed to reach any device.

| Device | Interface | Address | Reachable over |
| --- | --- | --- | --- |
| Cisco Firepower 1010 | Management 1/1 (dedicated OOB) | 10.10.99.10/24 | HTTPS (FDM), SSH |
| HPE Instant On 1930 | VLAN 99 IP interface | 10.10.99.11/24 | HTTPS, SNMP |
| FortiSwitch 108F | `internal` | 10.10.99.12/24 | HTTPS, SSH |
| NetAuto host | eth0 | 10.10.99.20/24 | — |

| Range | Purpose |
| --- | --- |
| .1 | Reserved for a future L3 gateway, unused today |
| .2 – .9 | Spare infrastructure |
| .10 – .19 | Network devices |
| .20 – .29 | Automation hosts and jump boxes |
| .100 – .150 | Optional DHCP pool for bootstrap |
| .151 – .254 | Reserved |

Data plane, for context: VLAN 1, `10.10.10.0/24`, gateway `10.10.10.1` on the
Firepower inside interface. The outside interface takes DHCP from the ISP.

## Order of work

Management switch, then firewall, then access switch.

The Aruba goes last because it is the only device with no console port. If you
strand it, the only recovery is the reset button and a rebuild from scratch.

---

## 1. FortiSwitch 108F

Console at 9600 8N1, or reach the factory address — commonly `192.168.1.99/24`,
user `admin`, no password.

Confirm standalone mode first. A unit that was ever paired to a FortiGate is in
FortiLink mode and will ignore local configuration:

```
get system status

config system global
    set switch-mgmt-mode local
    set hostname fsw-mgmt-01
end
```

Management interface:

```
config system interface
    edit "internal"
        set mode static
        set ip 10.10.99.12 255.255.255.0
        set allowaccess ping https ssh snmp
    next
end

config system admin
    edit admin
        set password <password>
    next
end
```

No static route in phase 1. Add one only if you later put a gateway on `.1`.

Ports 1, 2 and 8 stay at their defaults — untagged, default VLAN. That is
already correct for this topology.

---

## 2. Cisco Firepower 1010

Console over the RJ-45 or mini-USB port, 9600 8N1. Default FTD credentials are
`admin` / `Admin123`.

On a factory-fresh unit the setup wizard runs first and asks for the management
address directly. Give it the values below and skip the `configure network`
commands.

Check what is actually there before changing anything, rather than trusting
documented defaults:

```
> show network
```

Then:

```
> configure network hostname ftd-edge-01
> configure network ipv4 manual 10.10.99.10 255.255.255.0 data-interfaces
> configure network dns servers 1.1.1.1,9.9.9.9
> show network
```

Once reachability from the NetAuto host is confirmed — and not before, since
these cut off everything outside the subnet:

```
> configure ssh-access-list 10.10.99.0/24
> configure https-access-list 10.10.99.0/24
```

### On the `data-interfaces` gateway

Passing the `data-interfaces` keyword instead of an IP tells FTD to route
management-sourced traffic — smart licensing, database updates, DNS — over the
backplane and out through the data path. That is what keeps a router off the
management segment.

Verify the keyword is accepted on your software version. If it is not, leave the
gateway unset: management stays reachable locally, it just will not license.

### Data side

Ethernet1/2 is already a switch port in VLAN1 on the 1010, and VLAN1 is the
inside interface, so the link to the Aruba comes up with no configuration.
Renumber the inside interface to `10.10.10.1/24` when you get to the data plane.

Keep the data path on VLAN 1 on both sides for now. Introducing a separate data
VLAN means creating a VLAN interface on the 1010 and reassigning the switch
port, which is data-plane work and not worth doing while management is still
coming up.

FDM is at `https://10.10.99.10`. First login requires completing the setup
wizard and accepting the EULA.

---

## 3. HPE Instant On 1930

The switch must be in **local management mode**, not Instant On cloud mode. In
cloud mode the local web UI is cut down and the switch expects to phone home.

Connect a laptop directly to any port. The switch takes DHCP by default and
falls back to a static address if no lease appears — check the quick-start card
for the fallback rather than guessing, or run a DHCP server on the laptop. Log
in as `admin` and set a password when prompted.

Menu names shift between firmware versions, so treat these as landmarks.

1. **Create the VLAN** — *Switching → VLAN*. Add VLAN 99, name it `MGMT`.
2. **Assign the port** — in the VLAN port membership table, set **Port 24**
   untagged in VLAN 99, set its PVID to 99, and remove it from VLAN 1.
3. **Move the management interface** — *Setup Network → Get Connected*. Switch
   from DHCP to static: `10.10.99.11`, mask `255.255.255.0`, gateway blank.
   Set the management VLAN to 99. Depending on firmware this selector is either
   on this page or under the VLAN interface configuration.

**Step 3 disconnects you.** The session dies the moment it is applied. Before
clicking apply, have a cable ready to move to port 24 and a static `10.10.99.x`
address on the laptop. Reconnect at `https://10.10.99.11`.

Leave Port 1 untagged in VLAN 1 — that is the uplink to the Firepower and needs
no change.

---

## Verification

From the NetAuto host at `10.10.99.20`:

```bash
for ip in 10.10.99.10 10.10.99.11 10.10.99.12; do ping -c2 "$ip"; done

ssh admin@10.10.99.10        # Firepower, FTD CLI
ssh admin@10.10.99.12        # FortiSwitch
curl -k https://10.10.99.11  # Aruba — web UI only, no SSH
```

The Aruba answers only the last one. For a repeatable check in a test harness,
SNMP read is more practical against that device than HTTP.

---

## Wiring it into netauto

### Driver coverage

This is the part to read before expecting much. Of the three devices, one has a
plausible driver path:

| Device | Nearest platform string | Status |
| --- | --- | --- |
| FortiSwitch 108F | `fortinet_cli` | Plausible. SSH over netmiko. Runs FortiSwitchOS, not FortiOS, so `fortinet_fortios` and its REST client do not apply. Show-command output will differ from a FortiGate. |
| Cisco Firepower 1010 | none | FTD's CLI is not IOS. The napalm `cisco_ios` driver will not parse it, and there is no FTD or ASA platform string. FDM's REST API is the real management interface and has no driver. |
| HPE Instant On 1930 | none | Instant On is a separate product line from AOS-CX, AOS-Switch and Central. No CLI, no local REST API. `aruba_osswitch` targets AOS-Switch/ProCurve and will not fit. |

So the lab exercises the Fortinet CLI path, and the discovery, port-scan and
ad-hoc paths against all three. It does not exercise the Cisco or Aruba drivers.
That is worth knowing before reading a clean run as broad validation.

If the goal is to shake out the Cisco and Aruba drivers specifically, this
hardware will not do it — an IOS/IOS-XE box and an AOS-CX or AOS-Switch unit
would, and both are available cheaply second-hand.

### Inventory entry

In `inventory/devices.yaml`:

```yaml
devices:
  - name: fsw-mgmt-01
    platform: fortinet_cli
    host: 10.10.99.12
    credentials: LAB_FSW
    tags: [lab, management]
```

Credentials come from the environment at connect time:

```bash
export LAB_FSW_USERNAME=admin
export LAB_FSW_PASSWORD='...'
```

The Firepower and the Aruba do not get inventory entries, because no driver
would read them.

### First run

`10.10.99.0/24` is RFC1918 and directly attached to the NetAuto host, so it
passes the ad-hoc target gate and `arp-scan` is authoritative on it.

```bash
# discovery — the one path already run against real equipment
net_discover_local(cidr="10.10.99.0/24", probe_ports="22,23,443")

# then the inventory device
net_device_facts(name="fsw-mgmt-01")
net_get_config(name="fsw-mgmt-01")
net_run_show(name="fsw-mgmt-01", command="get system status")
```

Expect to adjust response parsing. Per the README, no driver's real-gear path
beyond ARP discovery has been run yet, and FortiSwitchOS output differing from
FortiOS is exactly the kind of gap a first run surfaces.

All three devices should appear in the sweep with their MAC vendors, which is
itself a useful check — it confirms the addressing landed even on the two
devices no driver can reach.

