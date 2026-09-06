"""Driver contract and the read-only command guard.

Every driver is a context manager yielding the same four read operations, so
callers never branch on vendor. The command guard is the safety-critical part
of this module: it decides what may be sent to a device at all.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any

from netauto.config import Settings
from netauto.errors import UnsafeCommand, UnsupportedOperation, WriteDisabled
from netauto.inventory import Device

# Commands permitted per platform family. A command must match one of these.
READ_ALLOW: dict[str, tuple[str, ...]] = {
    "cisco": (r"show\b", r"dir\b", r"ping\b", r"traceroute\b"),
    "juniper": (r"show\b", r"ping\b", r"traceroute\b", r"file\s+show\b"),
    "aruba": (r"show\b", r"display\b", r"ping\b", r"traceroute\b"),
    "fortinet": (r"get\b", r"show\b", r"diagnose\b", r"execute\s+ping\b",
                 r"execute\s+traceroute\b"),
    "generic": (r"show\b", r"display\b", r"get\b", r"ping\b", r"traceroute\b"),
}

# Rejected even if something above matched. Ordering never rescues these.
DENY = (
    r"\bconf(ig(ure)?)?\s+t(erm(inal)?)?\b",
    r"\bwrite\b", r"\bcopy\b", r"\bdelete\b", r"\berase\b", r"\bformat\b",
    r"\breload\b", r"\breboot\b", r"\brestart\b", r"\bshutdown\b",
    r"\bcommit\b", r"\brollback\b", r"\bload\b", r"\bset\b", r"\bunset\b",
    r"\bclear\b", r"\bno\s+\w", r"\brequest\s+system\b", r"\bexecute\s+(?!ping|traceroute)",
    r"\bdiagnose\s+\w+\s+(delete|flush|clear|set)\b",
)

# Shell/CLI chaining that could smuggle a second command past the allowlist.
CHAINING = re.compile(r"[;&|\n\r]|\$\(|`")

_DENY_RE = re.compile("|".join(DENY), re.IGNORECASE)


def platform_family(platform: str) -> str:
    """Map a platform string onto a command-guard family.

    Order matters. The Cisco test matches a bare "ios" substring, which also
    appears inside "fortinet_fortios" -- so the specific vendors are checked
    first and Cisco is the fallback among CLI platforms.
    """
    p = platform.lower()
    if "forti" in p:
        return "fortinet"
    if "junos" in p or p.startswith("juniper"):
        return "juniper"
    if "aruba" in p or "procurve" in p or "aoscx" in p:
        return "aruba"
    if p.startswith(("cisco", "arista")) or "nxos" in p or "ios" in p:
        return "cisco"
    return "generic"


def assert_read_only(command: str, platform: str) -> str:
    """Raise UnsafeCommand unless the command is unambiguously read-only.

    The guard is deliberately conservative: an unrecognised command is refused
    rather than forwarded. Widening it is a deliberate edit to READ_ALLOW, not
    something a caller can do at runtime.
    """
    cmd = command.strip()
    if not cmd:
        raise UnsafeCommand("Empty command.")
    if CHAINING.search(cmd):
        raise UnsafeCommand(
            f"Command chaining is not permitted: {command!r}. Send one command per call."
        )
    if _DENY_RE.search(cmd):
        raise UnsafeCommand(
            f"Command {command!r} matches a denied pattern. This toolkit is read-only; "
            f"configuration changes must be reviewed and applied by hand."
        )
    family = platform_family(platform)
    allowed = READ_ALLOW.get(family, READ_ALLOW["generic"])
    if not any(re.match(pattern, cmd, re.IGNORECASE) for pattern in allowed):
        raise UnsafeCommand(
            f"Command {command!r} is not on the read-only allowlist for {family!r} "
            f"platforms. Permitted prefixes: {', '.join(p.rstrip(chr(92)+'b') for p in allowed)}."
        )
    return cmd


class Driver(ABC):
    """Base class for all device drivers."""

    #: What this driver can actually do. Callers check before invoking.
    capabilities: frozenset[str] = frozenset({"facts", "config", "command"})

    def __init__(self, device: Device, settings: Settings) -> None:
        self.device = device
        self.settings = settings
        self._conn: Any = None

    # -- lifecycle ---------------------------------------------------------

    @abstractmethod
    def open(self) -> None:
        """Establish the connection."""

    @abstractmethod
    def close(self) -> None:
        """Tear the connection down. Must be safe to call twice."""

    def __enter__(self) -> "Driver":
        self.open()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- read operations ---------------------------------------------------

    @abstractmethod
    def facts(self) -> dict[str, Any]:
        """Vendor, model, OS version, serial, hostname, uptime where available."""

    @abstractmethod
    def get_config(self, kind: str = "running") -> str:
        """Return a configuration as text. kind is running, startup, or candidate."""

    @abstractmethod
    def run_read(self, command: str) -> str:
        """Run one allowlisted read-only command and return its output."""

    def neighbors(self) -> list[dict[str, Any]]:
        """LLDP/CDP neighbours as dicts, for topology discovery.

        Not abstract: a driver that cannot enumerate neighbours should say so
        rather than force every platform to grow a stub. Callers check the
        "neighbors" capability first and report the gap per device, so one
        cloud tenant does not sink a whole topology run.

        Each entry carries local_port, remote_host, remote_port and, where the
        platform offers them, remote_description and remote_chassis_id.
        """
        raise UnsupportedOperation(
            f"{type(self).__name__} cannot enumerate neighbours. "
            f"Topology discovery needs LLDP or CDP, which this platform does "
            f"not expose through netauto."
        )

    # -- write operations --------------------------------------------------

    def apply_config(self, config: str, *, confirm: str | None = None) -> str:
        """Refuse to commit. Present so callers get a clear error, not AttributeError.

        Diffing a candidate against the running configuration is supported via
        netauto.diffing and needs no write access.
        """
        raise WriteDisabled(
            f"Writes are disabled. {type(self).__name__} implements no commit path, "
            f"and allow_writes is {self.settings.allow_writes}. Use net_config_diff to "
            f"review the change, then apply it through your own change process."
        )
