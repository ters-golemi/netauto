"""What each workflow is, per platform.

Two workflows exist, and each supported platform gets its own instance of both
because the interesting part -- which show commands to run -- is per-platform
and cannot be generalised. The steps and the analysis are shared; only the
command set and the rule family change.

Every command here is checked against the read-only guard at import time by
the test suite, not merely by inspection. A workflow that could smuggle a
configuration change past `assert_read_only` would defeat the point of the
whole toolkit, so the command sets are data, reviewed like data, and the guard
remains the thing that decides.

Note the pipe: `assert_read_only` rejects `|` as command chaining, so nothing
here may pipe. That rules out the idioms one reaches for first -- Junos'
`| display set`, Cisco's `| section` -- and the commands below are written the
long way round instead.
"""

from __future__ import annotations

from dataclasses import dataclass

from netauto.drivers import supported_platforms
from netauto.drivers.base import platform_family

CONFIG_CHECK = "config-check"
DOCUMENTATION = "documentation"
SOFTWARE_UPGRADE = "software-upgrade"

KIND_NAMES = {
    CONFIG_CHECK: "Device Configuration Check",
    DOCUMENTATION: "Network Documentation Maker",
    SOFTWARE_UPGRADE: "Software Upgrade",
}

#: Recommended target firmware per platform, from vendor guidance. A platform
#: absent here has no upgrade target defined and the workflow says so rather
#: than guessing a version.
UPGRADE_TARGETS: dict[str, dict[str, str]] = {
    "fortinet_cli": {
        "version": "7.4.8",
        "note": "Latest mature FortiSwitchOS 7.4.x. FortiSwitchOS 7.2.x upgrades "
                "directly to 7.4.x — no intermediate build — except on 424E/M426 "
                "models. Read the 7.4.8 release notes and confirm the path first.",
    },
}


@dataclass(frozen=True)
class Step:
    """One stage of a workflow, as shown on the progress page."""

    key: str
    title: str
    detail: str = ""


# The pipelines. Documentation begins with the whole configuration check,
# because the document is meant to describe a network someone has just
# checked rather than one nobody has looked at.
CONFIG_CHECK_STEPS: tuple[Step, ...] = (
    Step("connect", "Connect to the device",
         "Opens one session using credentials resolved from the environment."),
    Step("config", "Pull the configuration",
         "Retrieves the running configuration as text."),
    Step("commands", "Run the show commands",
         "Runs this platform's read-only command set. Every command is "
         "checked against the allowlist before the session is opened."),
    Step("analyse", "Compare against configuration guides",
         "Evaluates the platform's ruleset, drawn from vendor hardening "
         "guides and configuration guidance, against what was collected."),
    Step("report", "Generate the report",
         "Ranks findings by severity and states the recommended improvement "
         "for each."),
)

DOCUMENTATION_STEPS: tuple[Step, ...] = CONFIG_CHECK_STEPS[:4] + (
    Step("topology", "Map the neighbours",
         "Reads LLDP/CDP to place this device among the ones it connects to."),
    Step("document", "Write the documentation",
         "Assembles inventory, interfaces, findings and a topology diagram "
         "into a document."),
    Step("export", "Generate the Word document",
         "Writes an editable .docx with the diagram embedded."),
)

SOFTWARE_UPGRADE_STEPS: tuple[Step, ...] = (
    Step("connect", "Connect to the device",
         "Opens one session using credentials resolved from the environment."),
    Step("snapshot", "Capture the pre-upgrade state",
         "Records the running firmware version and takes a configuration "
         "backup, so there is a known-good point to compare against and roll "
         "back to."),
    Step("verify", "Verify the target and upgrade path",
         "Compares the running version against the recommended target and "
         "confirms an upgrade is needed and supported."),
    Step("upgrade", "Transfer and install the image",
         "The one write netauto performs. Requires allow_writes, the driver's "
         "upgrade capability, and confirmation; the device reboots. Without "
         "those it is left as a manual step and the runbook says how."),
    Step("runbook", "Produce the upgrade runbook",
         "The version delta, the backup, the exact transfer/verify/install "
         "steps and the rollback plan."),
)

STEPS = {CONFIG_CHECK: CONFIG_CHECK_STEPS, DOCUMENTATION: DOCUMENTATION_STEPS,
         SOFTWARE_UPGRADE: SOFTWARE_UPGRADE_STEPS}


# Per-platform read-only command sets.
#
# Three platforms are deliberately empty. Meraki, Aruba Central and AOS-CX
# expose no CLI through their drivers -- their `capabilities` omit "command"
# -- so the workflow pulls state through get_config and reports the
# show-command step as not applicable rather than failing. An empty tuple here
# is a statement about the platform, not an omission.
COMMANDS: dict[str, tuple[str, ...]] = {
    "cisco_ios": (
        "show version",
        "show running-config",
        "show ip interface brief",
        "show interfaces status",
        "show vlan brief",
        "show spanning-tree summary",
        "show cdp neighbors detail",
        "show lldp neighbors detail",
        "show ip route summary",
        "show inventory",
    ),
    "cisco_xe": (
        "show version",
        "show running-config",
        "show ip interface brief",
        "show interfaces status",
        "show vlan brief",
        "show spanning-tree summary",
        "show cdp neighbors detail",
        "show lldp neighbors detail",
        "show ip route summary",
        "show inventory",
        "show license summary",
    ),
    "cisco_nxos": (
        "show version",
        "show running-config",
        "show interface brief",
        "show vlan brief",
        "show vpc",
        "show port-channel summary",
        "show cdp neighbors detail",
        "show lldp neighbors detail",
        "show ip route summary",
        "show inventory",
        "show feature",
    ),
    "cisco_xr": (
        "show version",
        "show running-config",
        "show ipv4 interface brief",
        "show interfaces brief",
        "show lldp neighbors detail",
        "show route summary",
        "show inventory",
        "show install active summary",
    ),
    "arista_eos": (
        "show version",
        "show running-config",
        "show ip interface brief",
        "show interfaces status",
        "show vlan",
        "show spanning-tree summary",
        "show lldp neighbors detail",
        "show ip route summary",
        "show inventory",
        "show mlag",
    ),
    "juniper_junos": (
        "show version",
        "show configuration",
        "show chassis hardware",
        "show interfaces terse",
        "show interfaces descriptions",
        "show lldp neighbors",
        "show route summary",
        "show system uptime",
        "show vlans",
    ),
    "aruba_osswitch": (
        "show system-information",
        "show running-config",
        "show interfaces brief",
        "show vlans",
        "show lldp info remote-device",
        "show ip route",
        "show modules",
    ),
    "fortinet_fortios": (
        "get system status",
        "get system interface",
        "get router info routing-table all",
        "show full-configuration",
        "get system ha status",
        "diagnose sys uptime",
    ),
    "fortinet_cli": (
        "get system status",
        "get system interface",
        "get router info routing-table all",
        "show full-configuration",
        "get system ha status",
        "diagnose sys uptime",
    ),
    # No CLI. See the note above.
    "aruba_aoscx": (),
    "aruba_central": (),
    "meraki": (),
}

#: Why a platform has no command set, shown in the report instead of a blank.
NO_CLI_REASON: dict[str, str] = {
    "aruba_aoscx": (
        "The AOS-CX driver speaks the REST API and declares no command "
        "capability, so configuration and state arrive through get_config "
        "rather than a CLI session."
    ),
    "aruba_central": (
        "Aruba Central is API-managed and has no device CLI. The workflow "
        "reads the Central device inventory instead."
    ),
    "meraki": (
        "Meraki devices have no CLI; everything is the Dashboard API. The "
        "workflow reads network and device state instead."
    ),
}


@dataclass(frozen=True)
class WorkflowSpec:
    """One workflow bound to one platform."""

    kind: str
    platform: str

    @property
    def id(self) -> str:
        return f"{self.kind}--{self.platform}"

    @property
    def name(self) -> str:
        return KIND_NAMES[self.kind]

    @property
    def family(self) -> str:
        return platform_family(self.platform)

    @property
    def commands(self) -> tuple[str, ...]:
        return COMMANDS.get(self.platform, ())

    @property
    def steps(self) -> tuple[Step, ...]:
        return STEPS[self.kind]

    @property
    def has_cli(self) -> bool:
        return bool(self.commands)

    @property
    def upgrade_target(self) -> dict[str, str]:
        """Recommended firmware for this platform, or {} if none is defined."""
        return UPGRADE_TARGETS.get(self.platform, {})

    @property
    def no_cli_reason(self) -> str:
        return NO_CLI_REASON.get(self.platform, "")


def _build_registry() -> dict[str, WorkflowSpec]:
    out: dict[str, WorkflowSpec] = {}
    for platform in supported_platforms():
        for kind in (CONFIG_CHECK, DOCUMENTATION, SOFTWARE_UPGRADE):
            spec = WorkflowSpec(kind=kind, platform=platform)
            out[spec.id] = spec
    return out


#: Every workflow, keyed by id: two per supported platform.
REGISTRY: dict[str, WorkflowSpec] = _build_registry()


def get(workflow_id: str) -> WorkflowSpec:
    try:
        return REGISTRY[workflow_id]
    except KeyError:
        raise KeyError(f"No workflow {workflow_id!r}.") from None


def for_platform(platform: str) -> list[WorkflowSpec]:
    return [s for s in REGISTRY.values() if s.platform == platform]
