# Sanitized configuration backups

Running configurations of the lab devices, collected read-only by netauto and
**sanitized** before storage: password hashes, SNMP communities, private keys
and certificates, and serial numbers are redacted. These are safe to keep in a
public repository but are **not restorable backups** — the secrets are gone.

| File | Device | Source |
| --- | --- | --- |
| `fsw-access-01.conf` | FortiSwitch 108F | `show full-configuration` over SSH (fortinet_cli driver) |
| `ftd-edge-01.conf` | Cisco Firepower 1010 | `show running-config` (LINA) over SSH to the in-band mgmt IP |

A full, unredacted backup for restore purposes belongs somewhere private (a
private repo or an offline store), never here — see the repo `.gitignore`, which
keeps raw captured configs (`*.cfg`, `baselines/`) out for the same reason.
