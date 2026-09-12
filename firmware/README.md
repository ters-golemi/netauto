# Firmware images

Firmware images for lab devices, stored here for the operator to upload to a
device (GUI) or serve over TFTP/FTP during an upgrade.

netauto never transfers or installs firmware — it is read-only by design. The
Software Upgrade workflow reads the device, verifies the upgrade path and
produces a runbook; the actual install is a human step. This folder is a
convenience for that step, not something netauto writes to or reads from.

Images are large binaries and are gitignored (see .gitignore). Do not commit
them.

## FortiSwitch 108F
Place the downloaded FortiSwitchOS image in `fortiswitch/`, e.g.
`fortiswitch/FSW_108F-v7.4.8-buildXXXX-FORTINET.out`.
Download from https://support.fortinet.com → Download → Firmware Images →
FortiSwitch → 7.4.8.
