"""Scanning: parsing operator input, and what a TCP probe actually reports.

The probe half runs against real sockets on the loopback -- a listener that
answers, a listener that says nothing, and a closed port -- because the thing
worth testing is what ``connect()`` reports back, and a mock of that only
tests the mock.
"""

import socket
import threading

import pytest

from netauto import scan
from netauto.inventory import Device, Inventory


@pytest.fixture
def listener():
    """A loopback listener. ``greeting`` is sent to whoever connects."""
    servers = []

    def start(greeting: bytes = b"") -> int:
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(5)
        servers.append(sock)

        def serve():
            while True:
                try:
                    conn, _ = sock.accept()
                except OSError:
                    return
                with conn:
                    if greeting:
                        try:
                            conn.sendall(greeting)
                        except OSError:
                            pass

        threading.Thread(target=serve, daemon=True).start()
        return sock.getsockname()[1]

    yield start
    for s in servers:
        s.close()


@pytest.fixture
def closed_port():
    """A port nothing is listening on: bound, read, then released."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


# --- operator input ---------------------------------------------------------

def test_empty_port_list_means_ssh_and_telnet():
    assert scan.parse_ports("") == (22, 23)
    assert scan.parse_ports(None) == (22, 23)


@pytest.mark.parametrize("text,expected", [
    ("22", (22,)),
    ("22,23", (22, 23)),
    ("22 23 443", (22, 23, 443)),
    ("443, 830", (443, 830)),
    ("22,22,23", (22, 23)),
])
def test_port_lists_are_parsed(text, expected):
    assert scan.parse_ports(text) == expected


@pytest.mark.parametrize("text", ["ssh", "22,ssh", "0", "65536", "-1"])
def test_bad_ports_are_refused_not_dropped(text):
    """A typo must not come back looking like a closed port."""
    with pytest.raises(scan.ScanError):
        scan.parse_ports(text)


def test_too_many_ports_refused():
    with pytest.raises(scan.ScanError, match="At most"):
        scan.parse_ports(",".join(str(p) for p in range(1000, 1000 + scan.MAX_PORTS + 1)))


def test_networks_are_validated():
    assert str(scan.parse_network("192.168.1.0/24")) == "192.168.1.0/24"
    assert str(scan.parse_network("192.168.1.7/24")) == "192.168.1.0/24"


@pytest.mark.parametrize("cidr", ["not-a-network", "192.168.1.0/99", ""])
def test_bad_networks_refused(cidr):
    with pytest.raises(scan.ScanError):
        scan.parse_network(cidr)


def test_oversized_range_refused():
    """An unbounded sweep is a way to hang the GUI for an hour."""
    with pytest.raises(scan.ScanError, match="smaller prefixes"):
        scan.parse_network("10.0.0.0/8")


def test_arp_scan_output_is_parsed():
    out = ("192.168.1.1\t00:11:22:AA:BB:CC\tCisco Systems\n"
           "192.168.1.9\t00:11:22:AA:BB:DD\n"
           "\n"
           "Interface: eth0, datalink type: EN10MB\n")
    hosts = scan.parse_arp_scan(out)
    assert [h.ip for h in hosts] == ["192.168.1.1", "192.168.1.9"]
    assert hosts[0].mac == "00:11:22:aa:bb:cc"
    assert hosts[0].vendor == "Cisco Systems"
    assert hosts[1].vendor == ""


def test_sweep_refuses_a_nonsense_interface():
    with pytest.raises(scan.ScanError, match="interface name"):
        scan.arp_sweep("192.168.1.0/30", "eth0; rm -rf /")


def test_sweep_reports_a_missing_arp_scan(monkeypatch):
    monkeypatch.setattr(scan.shutil, "which", lambda _: None)
    with pytest.raises(scan.ScanError, match="not installed"):
        scan.arp_sweep("192.168.1.0/30")


# --- probing ----------------------------------------------------------------

def test_open_port_is_reported_open(listener):
    port = listener()
    result = scan.probe_port("127.0.0.1", port, banner_timeout=0.05)
    assert result.is_open


def test_closed_port_is_reported_closed(closed_port):
    assert not scan.probe_port("127.0.0.1", closed_port, timeout=0.5).is_open


def test_unreachable_host_is_closed_not_an_error():
    """Refused and unreachable are the same answer: nothing to talk to."""
    result = scan.probe_port("127.0.0.1", 9, timeout=0.2, banner_timeout=0.05)
    assert not result.is_open and result.banner == ""


def test_banner_is_captured(listener):
    port = listener(b"SSH-2.0-Cisco-1.25\r\n")
    result = scan.probe_port("127.0.0.1", port, banner_timeout=0.5)
    assert result.banner == "SSH-2.0-Cisco-1.25"


def test_binary_negotiation_is_not_reported_as_a_banner(listener):
    """Telnet opens with option bytes, which are not text."""
    port = listener(b"\xff\xfd\x18\xff\xfd\x20")
    assert scan.probe_port("127.0.0.1", port, banner_timeout=0.5).banner == ""


def test_silent_service_gives_an_empty_banner(listener):
    port = listener()
    assert scan.probe_port("127.0.0.1", port, banner_timeout=0.05).banner == ""


def test_probe_hosts_fills_every_port(listener, closed_port):
    open_port = listener(b"SSH-2.0-OpenSSH_9.6\r\n")
    hosts = scan.probe_hosts(["127.0.0.1"], (open_port, closed_port),
                             timeout=0.5)
    assert len(hosts) == 1
    host = hosts[0]
    assert [p.number for p in host.ports] == [open_port, closed_port]
    assert host.port(open_port).is_open
    assert not host.port(closed_port).is_open
    assert [p.number for p in host.open_ports] == [open_port]


def test_probe_keeps_what_the_sweep_found(listener):
    port = listener()
    found = scan.Host(ip="127.0.0.1", mac="00:11:22:aa:bb:cc", vendor="Cisco")
    probed = scan.probe_hosts([found], (port,), timeout=0.5)[0]
    assert probed.mac == "00:11:22:aa:bb:cc" and probed.vendor == "Cisco"


def test_probe_budget_is_capped():
    hosts = [f"10.0.0.{n}" for n in range(1, 255)]
    with pytest.raises(scan.ScanError, match="probe limit"):
        scan.probe_hosts(hosts, tuple(range(1, 21)))


def test_no_ports_means_no_probing():
    """Sweeping without probing must not dial anything."""
    hosts = scan.probe_hosts([scan.Host(ip="10.0.0.1")], ())
    assert hosts[0].ports == ()


# --- reporting --------------------------------------------------------------

def test_telnet_open_is_flagged_as_cleartext():
    assert scan.Port(23, True).is_cleartext
    assert not scan.Port(22, True).is_cleartext
    assert not scan.Port(23, False).is_cleartext, "a closed port is not a finding"


def test_ports_are_named_where_it_helps():
    assert scan.Port(22, True).name == "ssh"
    assert scan.Port(9999, True).name == "9999"


def test_known_addresses_are_matched_to_the_inventory():
    inv = Inventory([Device(name="core-sw", platform="cisco_ios", host="192.168.1.1"),
                     Device(name="edge-fw", platform="fortinet_fortios", host="10.9.9.9")])
    hosts = scan.annotate_known(
        [scan.Host(ip="192.168.1.1"), scan.Host(ip="192.168.1.50")], inv)
    assert hosts[0].known_as == "core-sw"
    assert hosts[1].known_as == "", "an unmanaged host is the interesting one"


def test_annotation_survives_a_missing_inventory():
    hosts = scan.annotate_known([scan.Host(ip="192.168.1.1")], None)
    assert hosts[0].known_as == ""


def test_host_serialises_for_the_agent():
    host = scan.Host(ip="192.168.1.1", mac="00:11:22:aa:bb:cc", vendor="Cisco",
                     known_as="core-sw",
                     ports=(scan.Port(22, True, "SSH-2.0-Cisco-1.25"),
                            scan.Port(23, True), scan.Port(443, False)))
    d = host.as_dict()
    assert d["known_as"] == "core-sw"
    assert d["open"] == ["ssh", "telnet"]
    assert d["ports"][0]["banner"] == "SSH-2.0-Cisco-1.25"
    assert d["ports"][1]["cleartext"] is True
    assert "banner" not in d["ports"][2]
