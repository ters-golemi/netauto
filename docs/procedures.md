# Operational procedures

Two procedures netauto supports beyond its read-only inspection: upgrading
device firmware, and backing up device configuration. Both were added for the
lab and both respect netauto's stance — read-only by default, with a single,
deliberately gated write.

---

## Firmware upgrade

netauto's **Software Upgrade** workflow is the one operation that can write to a
device. It is off unless deliberately armed; run read-only it plans the upgrade
and produces a runbook, and touches nothing.

### What it does

`connect → snapshot → verify path → [install] → runbook`

1. **Snapshot** — records the running firmware version and takes a configuration
   backup, so there is a known-good point to compare against and roll back to.
2. **Verify** — compares the running version against the platform's recommended
   target and confirms the upgrade is needed and supported.
3. **Install** — the write. Happens **only when armed** (see gates below); the
   device reboots. Left unarmed, this step is skipped.
4. **Runbook** — a copy-pasteable runbook: the version delta, the backup, the
   exact transfer/verify/install commands, and the rollback plan.

### The three gates

The install fires only past all three, each off by default:

1. **`allow_writes: true`** in `config.yaml`. It gates firmware upgrade only —
   never a configuration commit, of which there is no path.
2. The driver declares the **`upgrade`** capability. Today only `fortinet_cli`
   (FortiOS / FortiSwitchOS) does.
3. The caller **confirms with the device name**. The workflow does this for you;
   there is no way to confirm by accident.

### Recommended target (FortiSwitch 108F)

**FortiSwitchOS 7.4.8** — the latest mature 7.4.x. FortiSwitchOS 7.2.x upgrades
directly to 7.4.x (no intermediate build) on the 108F. Read the 7.4.8 release
notes and confirm the path first.

### Procedure

1. **Download** the image from
   [support.fortinet.com](https://support.fortinet.com) → Download → Firmware
   Images → FortiSwitch → 7.4.8, into `firmware/fortiswitch/`.
2. **Serve it.** The switch pulls the image from a TFTP or FTP server it can
   reach. Run one on the NetAuto host, serving `firmware/fortiswitch/`.
3. **Plan it first (read-only).** In the GUI, *Workflows → Software Upgrade →
   Run* with the image and server left blank. Read the runbook it produces:
   current version, target, the exact steps, the rollback.
4. **Back up the config** — the snapshot step captures it, and the Backup
   procedure below stores a sanitized copy.
5. **Arm and run.** Set `allow_writes: true` in `config.yaml` and restart the
   service. Run the workflow again with the **image filename** and **server IP**
   filled in. The switch validates the image and reboots into it.
6. **Verify.** After the reboot, reconnect and run the **Configuration Check**
   workflow to confirm the new version and that the config survived.

### Rollback

Boot the previous image from the switch boot menu, or re-restore the prior
build. The configuration backup from the snapshot step is the known-good point.

### A note on timing

The install reboots the switch — several minutes of downtime. If the switch is
your management path, pick a window where that is acceptable.

---

## Configuration backup

netauto collects running configuration read-only and stores a **sanitized**
copy. These are snapshots and references, not restorable backups.

### What it does

- Collects the running configuration over the device's normal read path
  (`show full-configuration` on FortiOS/FortiSwitch; `show running-config` on
  the others).
- **Sanitizes before writing anything to disk**: password hashes, SNMP
  communities, private keys and embedded certificates, and serial numbers are
  redacted in memory. The result is verified to contain no plaintext password,
  no surviving hash, no key material and no serial before it is saved.
- Stores the sanitized config under `configs/` in the repository.

### Where backups belong

| Kind | Where | Why |
| --- | --- | --- |
| Sanitized snapshot | `configs/` (committed) | Safe to publish; useful for diffing and review |
| Full restorable backup | Private repo or offline store | Contains secrets — never the public repo |

The repository `.gitignore` keeps raw captured configs (`*.cfg`, `baselines/`)
out for this reason. A restorable backup with secrets intact must go somewhere
private.
