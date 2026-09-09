"""Finding hosts on a segment, and asking which management ports answer.

Two stages, kept separate because they answer different questions and have
different reach. An ARP sweep says which addresses are *live* on a directly
attached segment -- authoritative there, useless off it. A TCP connect probe
then says which management ports those hosts answer on, and works against any
address that routes.

The probe is an ordinary ``connect()`` and, at most, a read of whatever the
service volunteers first. No raw sockets, no half-open tricks: it needs no
privileges, and it learns nothing a client dialling the port would not. It
sends no bytes, so nothing on the far side is asked to do anything.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Iterable

from netauto.errors import NetautoError
from netauto.inventory import Inventory

#: What an operator is nearly always looking for: the two ways into a CLI.
DEFAULT_PORTS: tuple[int, ...] = (22, 23)

#: Labels for the ports worth naming. Anything else is shown as its number.
PORT_NAMES: dict[int, str] = {
    22: "ssh", 23: "telnet", 80: "http", 443: "https",
    830: "netconf", 4443: "https-alt", 8443: "https-alt",
}

#: Ports whose protocol carries credentials in clear text. An open one is a
#: finding, not just an inventory fact, so the GUI marks it differently.
CLEARTEXT_PORTS: frozenset[int] = frozenset({21, 23, 80})

#: Caps. A sweep is cheap per host but not free, and an unbounded port list
#: against an unbounded address range is a way to hang the GUI for an hour.
MAX_HOSTS = 1024          # a /22
MAX_PORTS = 16
MAX_PROBES = 4096         # hosts x ports actually attempted
MAX_WORKERS = 64

ARP_SCAN_TIMEOUT = 180
CONNECT_TIMEOUT = 1.0
BANNER_TIMEOUT = 0.6

_INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,30}$")


class ScanError(NetautoError):
    """A sweep or probe could not be run as asked."""


@dataclass(frozen=True)
class Port:
    """One port on one host, as the probe found it."""

    number: int
    is_open: bool
    banner: str = ""

    @property
    def name(self) -> str:
        return PORT_NAMES.get(self.number, str(self.number))

    @property
    def is_cleartext(self) -> bool:
        """Open on a protocol that carries credentials in the clear."""
        return self.is_open and self.number in CLEARTEXT_PORTS

    def as_dict(self) -> dict[str, object]:
        d: dict[str, object] = {"port": self.number, "name": self.name,
                                "open": self.is_open}
        if self.is_cleartext:
            d["cleartext"] = True
        if self.banner:
            d["banner"] = self.banner
        return d


@dataclass(frozen=True)
class Host:
    """One address that answered, with whatever else is known about it."""

    ip: str
    mac: str = ""
    vendor: str = ""
    ports: tuple[Port, ...] = ()
    #: Inventory device name, when this address is one netauto already manages.
    known_as: str = ""

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.is_open]

    def port(self, number: int) -> Port | None:
        for p in self.ports:
            if p.number == number:
                return p
        return None

    def as_dict(self) -> dict[str, object]:
        d: dict[str, object] = {"ip": self.ip, "mac": self.mac, "vendor": self.vendor}
        if self.known_as:
            d["known_as"] = self.known_as
        if self.ports:
            d["ports"] = [p.as_dict() for p in self.ports]
            d["open"] = [p.name for p in self.open_ports]
        return d


def parse_ports(text: str | Iterable[int] | None) -> tuple[int, ...]:
    """Read a port list from operator input. Empty means the defaults.

    Accepts ``"22,23"``, ``"22 23"``, or an iterable of ints. Rejects rather
    than silently dropping anything it cannot read: a typo'd port that
    quietly disappears reads as a closed port in the results.
    """
    if text is None or (isinstance(text, str) and not text.strip()):
        return DEFAULT_PORTS
    if isinstance(text, str):
        tokens = [t for t in re.split(r"[,\s]+", text.strip()) if t]
    else:
        tokens = [str(t) for t in text]
    ports: list[int] = []
    for token in tokens:
        try:
            number = int(token)
        except ValueError:
            raise ScanError(f"Not a port number: {token!r}.") from None
        if not 1 <= number <= 65535:
            raise ScanError(f"Port out of range: {number}.")
        if number not in ports:
            ports.append(number)
    if not ports:
        return DEFAULT_PORTS
    if len(ports) > MAX_PORTS:
        raise ScanError(f"At most {MAX_PORTS} ports per scan, got {len(ports)}.")
    return tuple(ports)


def parse_network(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Validate a target range and refuse one too large to sweep politely."""
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        raise ScanError(f"Not a network: {cidr!r} ({exc}).") from None
    if network.num_addresses > MAX_HOSTS:
        raise ScanError(
            f"{network} holds {network.num_addresses} addresses; this scans at "
            f"most {MAX_HOSTS} at a time. Sweep it in smaller prefixes."
        )
    return network


def arp_sweep(cidr: str, interface: str = "", *,
              timeout: int = ARP_SCAN_TIMEOUT) -> list[Host]:
    """Live hosts on a directly attached segment, by ARP.

    ARP is authoritative on the local segment: hosts answer it even when they
    drop ICMP, so this finds more than a ping sweep -- and nothing at all off
    the segment, where there is no ARP to answer.
    """
    parse_network(cidr)
    if interface and not _INTERFACE_RE.match(interface):
        raise ScanError(f"Not an interface name: {interface!r}.")
    binary = shutil.which("arp-scan")
    if not binary:
        raise ScanError("arp-scan is not installed on this host.")
    cmd = [binary, cidr, "--plain"]
    if interface:
        cmd += ["-I", interface]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise ScanError(f"arp-scan timed out sweeping {cidr}.") from None
    if proc.returncode != 0:
        raise ScanError(proc.stderr.strip() or f"arp-scan exited {proc.returncode}.")
    return parse_arp_scan(proc.stdout)


def parse_arp_scan(output: str) -> list[Host]:
    """Parse ``arp-scan --plain`` output: address, MAC, vendor, tab separated."""
    hosts: list[Host] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            hosts.append(Host(ip=parts[0].strip(), mac=parts[1].strip().lower(),
                              vendor=parts[2].strip() if len(parts) > 2 else ""))
    return hosts


def probe_port(host: str, number: int, *, timeout: float = CONNECT_TIMEOUT,
               banner_timeout: float = BANNER_TIMEOUT) -> Port:
    """Open a TCP connection and report whether it was accepted.

    A refused connection and an unreachable host are both reported as closed:
    from here they are the same answer -- there is no service to talk to.
    """
    try:
        with socket.create_connection((host, number), timeout=timeout) as sock:
            return Port(number, True, _read_banner(sock, banner_timeout))
    except OSError:
        return Port(number, False)


def _read_banner(sock: socket.socket, timeout: float) -> str:
    """Whatever the service says first, if it says anything quickly.

    SSH announces itself before the client speaks, which names the far end's
    software for free. Telnet opens with option negotiation, which is not
    text; that comes back empty rather than as mojibake.
    """
    sock.settimeout(timeout)
    try:
        raw = sock.recv(256)
    except OSError:
        return ""
    text = "".join(c for c in raw.decode("latin-1") if 32 <= ord(c) <= 126)
    return " ".join(text.split())[:120]


def probe_hosts(hosts: Iterable[Host | str], ports: Iterable[int] = DEFAULT_PORTS, *,
                timeout: float = CONNECT_TIMEOUT,
                workers: int = MAX_WORKERS) -> list[Host]:
    """Probe every port on every host, in parallel, returning them annotated."""
    targets = [Host(ip=h) if isinstance(h, str) else h for h in hosts]
    ports = tuple(ports)
    if not targets or not ports:
        return targets
    if len(targets) * len(ports) > MAX_PROBES:
        raise ScanError(
            f"{len(targets)} hosts x {len(ports)} ports is more than the "
            f"{MAX_PROBES}-probe limit. Narrow the range or the port list."
        )
    jobs = [(host, number) for host in targets for number in ports]
    with ThreadPoolExecutor(max_workers=min(workers, len(jobs))) as pool:
        results = list(pool.map(
            lambda job: probe_port(job[0].ip, job[1], timeout=timeout), jobs))
    by_ip: dict[str, list[Port]] = {}
    for (host, _), port in zip(jobs, results):
        by_ip.setdefault(host.ip, []).append(port)
    return [Host(ip=h.ip, mac=h.mac, vendor=h.vendor, known_as=h.known_as,
                 ports=tuple(by_ip.get(h.ip, ()))) for h in targets]


def annotate_known(hosts: Iterable[Host], inventory: Inventory | None) -> list[Host]:
    """Mark the addresses that are already managed devices.

    The point of a sweep is usually the opposite: what is on the wire that
    nobody put in the inventory. Naming the known ones is how that shows.
    """
    hosts = list(hosts)
    if inventory is None:
        return hosts
    by_ip = {d.host: d.name for d in inventory if d.host}
    return [Host(ip=h.ip, mac=h.mac, vendor=h.vendor, ports=h.ports,
                 known_as=by_ip.get(h.ip, "")) for h in hosts]
