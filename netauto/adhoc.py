"""Read-only sessions against hosts that are not in the inventory.

A sweep finds a switch nobody documented; the next thing anyone wants is to
look at it. Everything needed to do that already exists -- the drivers take a
Device, and a Device is a name, a platform, an address and a credentials
prefix -- so this builds one that lives for the length of a request and is
never written anywhere.

Two things make that safe enough to expose in a GUI.

The first is that nothing here widens what may be sent. The transient device
goes through the same drivers, the same read-only guard and the same audit
trail as an inventory entry; a discovered host is simply a device the
inventory has not heard of yet.

The second is that the target is gated. Handing an address to this module
makes the server offer its stored credentials to whatever answers, so a host
that answers SSH and logs what it is sent is all an attacker needs. Only
addresses this process has actually found on the wire, in a private range,
are connectable -- anything else is a deliberate inventory entry, made by
someone with access to the server's filesystem.
"""

from __future__ import annotations

import ipaddress
import os
import re
import time
from typing import Iterable

from netauto.drivers import supported_platforms
from netauto.errors import NetautoError
from netauto.inventory import Device
from netauto.scan import Host

#: Tenants, not boxes. Meraki and Central are reached by API key against a
#: cloud endpoint, so an IP address on a local segment says nothing about
#: them and an ad-hoc connection to one is meaningless.
CLOUD_PLATFORMS = frozenset({"meraki", "aruba_central"})

#: How long a swept address stays connectable. An address is only evidence
#: that something answered ARP at the moment of the sweep; a lease can move in
#: an afternoon, and a stale entry would point credentials at whatever holds
#: it now. Short enough to mean something, long enough to survive a coffee.
SEEN_TTL_SECONDS = 3600

#: Vendor tokens, in the order they are tested, mapped onto a platform to
#: pre-select. Read off the SSH banner first and the MAC vendor second. These
#: are a starting point for the operator, never a decision: an SSH banner is
#: whatever the far end chose to say, and a MAC prefix names who made the
#: chip, not what is running on it.
PLATFORM_HINTS: tuple[tuple[str, str], ...] = (
    ("juniper", "juniper_junos"),
    ("junos", "juniper_junos"),
    ("arista", "arista_eos"),
    ("fortigate", "fortinet_cli"),
    ("fortinet", "fortinet_cli"),
    ("procurve", "aruba_osswitch"),
    ("aruba", "aruba_aoscx"),
    ("hewlett", "aruba_aoscx"),
    ("hpe", "aruba_aoscx"),
    ("cisco", "cisco_ios"),
)

_PREFIX_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


class ConnectRefused(NetautoError):
    """An ad-hoc connection was not permitted to that target."""


def connectable_platforms() -> list[str]:
    """Platforms an address can be dialled on: everything but the tenants."""
    return [p for p in supported_platforms() if p not in CLOUD_PLATFORMS]


def guess_platform(banner: str = "", vendor: str = "") -> str:
    """Best guess at what a host is, or "" when nothing suggests one.

    SSH names its software before the client speaks, which is the better
    signal of the two: "SSH-2.0-Cisco-1.25" is a Cisco saying so itself,
    where a Cisco MAC prefix only says who built the board.
    """
    for text in (banner, vendor):
        haystack = text.lower()
        for token, platform in PLATFORM_HINTS:
            if token in haystack:
                return platform
    return ""


def guess_for(host: Host | None) -> str:
    """The guess for a swept host, read off its SSH banner and MAC vendor."""
    if host is None:
        return ""
    ssh = host.port(22)
    return guess_platform(banner=ssh.banner if ssh else "", vendor=host.vendor)


def credential_prefixes(env: dict[str, str] | None = None) -> list[str]:
    """Credential prefixes this server could actually authenticate with.

    Derived from the environment rather than configured: a prefix is usable
    exactly when the variables behind it are exported, so listing anything
    else would offer the operator choices that cannot work. Only the prefix
    names are read; no value is touched.
    """
    env = os.environ if env is None else env
    prefixes = set()
    for key in env:
        for suffix in ("_USERNAME", "_API_KEY", "_API_TOKEN"):
            if key.endswith(suffix) and len(key) > len(suffix):
                prefixes.add(key[: -len(suffix)])
    return sorted(prefixes)


class Discovered:
    """The addresses this process has found on the wire, and when.

    In memory and nowhere else, like workflow runs and the last topology.
    A restart forgets them, which costs a sweep and is the right trade: the
    alternative is a file of addresses that outlives the evidence for them.
    """

    def __init__(self, ttl: int = SEEN_TTL_SECONDS) -> None:
        self._ttl = ttl
        self._seen: dict[str, tuple[float, Host]] = {}

    def record(self, hosts: Iterable[Host]) -> None:
        now = time.time()
        for host in hosts:
            self._seen[host.ip] = (now, host)
        self._expire(now)

    def get(self, ip: str) -> Host | None:
        """The host as the sweep saw it, so a banner can inform the guess."""
        self._expire(time.time())
        found = self._seen.get(ip)
        return found[1] if found else None

    def __contains__(self, ip: str) -> bool:
        return self.get(ip) is not None

    def __len__(self) -> int:
        self._expire(time.time())
        return len(self._seen)

    def _expire(self, now: float) -> None:
        dead = [ip for ip, (at, _) in self._seen.items() if now - at > self._ttl]
        for ip in dead:
            del self._seen[ip]


def assert_connectable(ip: str, discovered: Discovered) -> str:
    """Refuse any target that is not a private address this process swept."""
    try:
        address = ipaddress.ip_address(ip.strip())
    except ValueError:
        raise ConnectRefused(f"Not an address: {ip!r}.") from None
    # is_global rather than is_private, which is a different question and the
    # wrong one twice over: it calls the documentation ranges private, and it
    # calls carrier-grade NAT space public, so a legitimate 100.64/10 lab host
    # would be refused while 203.0.113.0/24 sailed through.
    if address.is_global:
        raise ConnectRefused(
            f"{address} is routable on the internet. Ad-hoc connections are "
            f"limited to addresses that are not, because this points the "
            f"server's credentials at whatever answers. A device out there "
            f"belongs in the inventory, where adding it takes access to the "
            f"server itself."
        )
    if str(address) not in discovered:
        raise ConnectRefused(
            f"{address} was not found by a sweep on this server within the last "
            f"{SEEN_TTL_SECONDS // 60} minutes. Sweep its segment first, so the "
            f"address is one this server saw rather than one it was handed."
        )
    return str(address)


def likely_segment(ip: str) -> str:
    """The segment to offer sweeping, when an address has not been swept yet.

    A starting value for the Discover form rather than a claim: /24 is the
    overwhelmingly common case for a directly attached segment, and the
    operator edits the field if theirs is not. Empty for anything a sweep
    could not reach anyway -- a routable address, or IPv6, where a /24 means
    nothing.
    """
    try:
        address = ipaddress.ip_address(ip.strip())
    except ValueError:
        return ""
    if address.is_global or address.version != 4:
        return ""
    return str(ipaddress.ip_network(f"{address}/24", strict=False))


def build_device(ip: str, platform: str, credentials: str,
                 discovered: Discovered) -> Device:
    """A Device that exists for one request and is stored nowhere.

    Named for its address, because that is all that is known about it: an
    ad-hoc session never pretends to have an inventory identity.
    """
    address = assert_connectable(ip, discovered)
    if platform in CLOUD_PLATFORMS:
        raise ConnectRefused(
            f"{platform} is a cloud tenant reached by API, not a host on a "
            f"segment. There is nothing at {address} to dial for it."
        )
    if platform not in connectable_platforms():
        known = ", ".join(connectable_platforms())
        raise ConnectRefused(f"No driver for platform {platform!r}. Supported: {known}.")
    prefix = credentials.strip().upper()
    if not prefix:
        raise ConnectRefused(
            "Choose a credentials prefix. Secrets are read from the server's "
            "environment at connect time, never entered here or stored."
        )
    if not _PREFIX_RE.match(prefix):
        raise ConnectRefused(
            f"Not a credentials prefix: {credentials!r}. It names environment "
            f"variables, so it must look like CORE_SW."
        )
    return Device(name=address, platform=platform, host=address,
                  credentials=prefix, tags=("ad-hoc",))
