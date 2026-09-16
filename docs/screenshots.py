#!/usr/bin/env python3
"""Regenerate the GUI screenshots the README embeds.

The screenshots used to be taken by hand, which is why they drifted: the ones
in git were a theme and two navigation tabs behind the app by the time anyone
noticed. This renders them from the real templates and the real stylesheet, so
re-running it is the whole update.

    .venv/bin/python docs/screenshots.py            # all of them
    .venv/bin/python docs/screenshots.py audit lab  # just these

Nothing here touches a device. The inventory is synthetic and every call that
would open a session is replaced with a canned result -- the same fiction the
README's captions already declare, written down instead of improvised. What is
real is everything that decides how a page *looks*: the templates, the
stylesheet, the rule IDs, the severities and the platform list.

Needs chromium on PATH. Output lands in docs/ at 2x for legibility on a
high-density display, which is what the committed PNGs have always been.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DOCS = ROOT / "docs"
WIDTH = 1180          # the app's own .shell max-width; the layout is built for it
SCALE = 2             # device pixel ratio
TALL = 5200           # capture window; the image is cropped back to the content

#: Pages with no natural end. Workflows lists three pipelines for each of the
#: twelve platforms, so the document is metres long and a full-height capture
#: is unreadable at README width. Cropping says the same thing the page's own
#: first screen says, which is what the caption describes.
MAX_CSS_HEIGHT: dict[str, int] = {"workflows": 1200, "lab-audit": 1580}
PW = "screenshot-only-not-a-real-password"

#: Everything dated renders from this instant, in UTC, rather than from the
#: clock. Three pages print a time -- the activity log, the topology's
#: "collected", the lab audit's "started" -- so without pinning it a re-run
#: always produces a diff and nobody can tell a real change from a new
#: timestamp. A generated artefact that cannot be diffed is not much better
#: than one taken by hand.
FIXED_EPOCH = 1773320400.0  # 2026-03-12 13:00:00 UTC

#: The synthetic fleet every inventory-driven page renders from. Seven devices
#: over four guard families and three tags, which is what the README's counts
#: and its note about arista_eos reporting family `cisco` both describe.
INVENTORY = """\
devices:
  - {name: core-sw-01,  platform: cisco_ios,        host: 10.20.0.1,  credentials: CORE_SW, tags: [core]}
  - {name: edge-rtr-01, platform: juniper_junos,    host: 10.20.0.2,  credentials: EDGE,    tags: [edge]}
  - {name: dc-spine-01, platform: arista_eos,       host: 10.20.0.5,  credentials: DC,      tags: [core]}
  - {name: dc-spine-02, platform: arista_eos,       host: 10.20.0.6,  credentials: DC,      tags: [core]}
  - {name: core-sw-02,  platform: cisco_ios,        host: 10.20.0.3,  credentials: CORE_SW, tags: [core]}
  - {name: acc-sw-11,   platform: aruba_aoscx,      host: 10.20.0.11, credentials: ACCESS,  tags: [access]}
  - {name: edge-fw-01,  platform: fortinet_fortios, host: 10.20.0.4,  credentials: EDGE_FW, tags: [edge]}
"""

#: Synthetic history for /activity, oldest first. Between them these produce
#: every badge colour the log can show, including the refusal -- which is the
#: row the README points at, and the reason the page exists.
HISTORY = [
    ("jordan", "login-failed",    "127.0.0.1",    ""),
    ("jordan", "login",           "127.0.0.1",    ""),
    ("jordan", "inspect-device",  "core-sw-01",   ""),
    ("jordan", "run-command",     "core-sw-01",   "show ip interface brief"),
    ("jordan", "inspect-device",  "edge-rtr-01",  ""),
    ("jordan", "command-refused", "core-sw-01",
     "reload \u2014 Command 'reload' matches a denied pattern. This toolkit is "
     "read-only; configuration changes must be reviewed and applied by hand."),
    ("jordan", "discover",        "10.20.0.0/24", "ports=22,23"),
    ("jordan", "connect",         "10.20.0.17",   "aruba_aoscx as LAB"),
    ("adis",   "login",           "127.0.0.1",    ""),
    ("adis",   "audit",           "tag:core",     "4 devices"),
]


# -- harness ---------------------------------------------------------------

def build_client(tmp: Path, *, admin: bool):
    """A logged-in TestClient over the real app, pointed at the fake fleet.

    `admin` is per screenshot rather than per run, because the committed
    images were taken that way and the README leans on it: only the Activity
    shot is an administrator's view, which is why only that one has the tab.
    A standard account genuinely cannot reach the page behind it.
    """
    inventory = tmp / "devices.yaml"
    inventory.write_text(INVENTORY)

    users = tmp / f"users-{'admin' if admin else 'standard'}.yaml"
    # Bare, not absolute: the Activity page prints this path, and the caller
    # runs from a scratch directory, so the image says "activity.log" the way a
    # real deployment does rather than naming someone's temp folder.
    log = Path("activity.log")
    os.environ["NETAUTO_USERS_FILE"] = str(users)
    os.environ["NETAUTO_ACTIVITY_LOG"] = str(log)
    os.environ["NETAUTO_SECRET_KEY"] = "screenshots-only"
    # The connect page offers whatever prefixes the environment carries; pin
    # them so the list in the image is the one the README describes.
    for prefix in ("LAB", "CORE_SW", "EDGE"):
        os.environ[f"{prefix}_USERNAME"] = "netauto"
        os.environ[f"{prefix}_PASSWORD"] = "unused-by-screenshots"

    from netauto.config import Settings

    real = Settings.load(root=ROOT)

    def pinned(cls=None, path=None, root=None):  # noqa: ARG001
        object.__setattr__(real, "inventory_path", inventory)
        return real

    Settings.load = classmethod(pinned)

    from fastapi.testclient import TestClient

    from netauto.web.app import create_app
    from netauto.web.users import UserStore

    store = UserStore(users)
    store.add("adis", PW, admin=admin)
    store.add("jordan", PW, admin=not admin)

    client = TestClient(create_app(store))
    token = client.get("/login").text.split('name="csrf_token" value="')[1].split('"')[0]
    client.post("/login", data={"username": "adis", "password_input": PW,
                                "csrf_token": token}, follow_redirects=False)

    # Seeded after the login so the harness's own session does not appear in
    # the log it is about to photograph.
    base = FIXED_EPOCH - 5400
    log.write_text("".join(
        json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(base + i * 331)),
            "user": user, "action": action, "target": target, "detail": detail,
        }) + "\n"
        for i, (user, action, target, detail) in enumerate(HISTORY)
    ))
    return client


def capture(html: str, out: Path, work: Path, limit: int | None = None) -> None:
    """Render one page to a cropped 2x PNG."""
    page = work / "page.html"
    page.write_text(html.replace('href="/static/style.css"', 'href="style.css"'))
    shutil.copy(ROOT / "netauto" / "web" / "static" / "style.css", work / "style.css")

    raw = work / "raw.png"
    with contextlib.suppress(FileNotFoundError):
        raw.unlink()
    subprocess.run(
        ["chromium", "--headless", "--disable-gpu", "--no-sandbox",
         "--hide-scrollbars", "--force-color-profile=srgb",
         f"--force-device-scale-factor={SCALE}",
         f"--window-size={WIDTH},{TALL}",
         f"--screenshot={raw}", f"--virtual-time-budget=4000",
         page.as_uri()],
        check=True, capture_output=True,
    )
    crop_to_content(raw, out, limit)


def crop_to_content(raw: Path, out: Path, limit: int | None = None) -> None:
    """Trim the empty page ground below the last thing drawn.

    The capture window is deliberately taller than any page, so every shot ends
    in a band of blank --ground. The last row that differs from it is the
    bottom of the content; everything past that is padding we choose, not
    padding the browser happened to leave.
    """
    from PIL import Image

    img = Image.open(raw).convert("RGB")
    w, h = img.size
    ground = img.getpixel((w - 4, h - 4))
    px = img.load()

    def row_is_ground(y: int) -> bool:
        # Sampling every 8th column: a full scan of 2360 columns x 4200 rows is
        # seconds of work to answer a question four samples already settle.
        return all(px[x, y] == ground for x in range(0, w, 8))

    last = h - 1
    while last > 0 and row_is_ground(last):
        last -= 1
    bottom = min(h, last + 1 + 28 * SCALE)
    if limit:
        bottom = min(bottom, limit * SCALE)
    img.crop((0, 0, w, bottom)).save(out, optimize=True)


# -- the fiction -----------------------------------------------------------

#: A cisco_ios running config with real problems in it. The audit screenshot is
#: the real ruleset's verdict on this text -- nothing about the findings is
#: written by hand, which is what lets the README call the rules real while the
#: switch is invented.
CISCO_CONFIG = """\
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
hostname core-sw-01
!
boot-start-marker
boot-end-marker
!
enable secret 5 $1$mERr$V1TkM0bqbGhCu3vGEVxJz.
!
no aaa new-model
!
ip domain-name lab.example.net
ip name-server 10.20.0.53
ip ssh version 2
!
service password-encryption
!
logging host 10.20.0.53
logging trap informational
!
service tcp-keepalives-in
service tcp-keepalives-out
!
interface GigabitEthernet0/1
 description uplink to edge-rtr-01
 no shutdown
!
interface GigabitEthernet0/24
 description access port
 switchport mode access
 spanning-tree portfast
!
ip http server
ip http secure-server
!
snmp-server community public RO
snmp-server community private RW
snmp-server location lab
!
ntp server 10.20.0.53
!
line con 0
 exec-timeout 0 0
line aux 0
line vty 0 4
 exec-timeout 0 0
 password cisco
 transport input telnet ssh
line vty 5 15
 exec-timeout 10 0
 transport input ssh
!
end
"""

#: A Junos config for the mixed-vendor lab's router. Same job as the Cisco one:
#: mostly right, with the faults that make the page worth a screenshot.
JUNOS_CONFIG = """\
set system host-name mixed-r1
set system root-authentication encrypted-password "$6$Xj2kQ9$8Nn1mB0pVqTf3aLcR7eWs2"
set system services ssh root-login deny
set system services ssh protocol-version v2
set system services telnet
set system services web-management http port 80
set system syslog host 192.168.121.2 any notice
set system syslog file messages any notice
set system ntp server 192.168.121.2
set system ntp server 192.168.121.3
set system login message "Authorised access only. Activity is logged."
set system login idle-timeout 10
set interfaces ge-0/0/0 unit 0 family inet address 192.168.121.11/24
set snmp community public authorization read-only
set protocols lldp interface all
"""

#: An Arista leaf that is in good order apart from one thing, so the lab audit
#: does not read as four copies of the same broken switch.
EOS_CONFIG = """\
! device: mixed-sw1 (DCS-7050SX3-48YC8, EOS-4.29.2F)
hostname mixed-sw1
!
service password-encryption
!
username admin privilege 15 secret sha512 $6$Kd9mQ2$rT8vY1pLc0wXn
enable secret sha512 $6$Pq3nRa$8jH2kD9sVbN4mZ
!
no ip http server
no ip http secure-server
management ssh
   idle-timeout 15
!
snmp-server community r34d-0nly-8f2a ro
snmp-server host 192.168.121.2 version 2c r34d-0nly-8f2a
!
ntp server 192.168.121.2 prefer
ntp server 192.168.121.3
!
logging host 192.168.121.2
logging trap informational
!
interface Ethernet1
   description spine1
   no switchport
!
line vty 0 4
   exec-timeout 15 0
   transport input ssh
!
end
"""

#: An NX-OS leaf with the fault that platform actually tends to ship with.
NXOS_CONFIG = """\
!Command: show running-config
version 9.3(10)
hostname mixed-nx1
!
feature telnet
feature ssh
feature lldp
!
no password strength-check
username admin password 5 $5$Ht2nQ$9dKmR3vP role network-admin
!
ip http server
!
snmp-server community public group network-operator
snmp-server host 192.168.121.2 traps version 2c public
!
ntp server 192.168.121.2 use-vrf management
!
logging server 192.168.121.2 6 use-vrf management
logging timestamp milliseconds
!
line vty
  exec-timeout 10
  transport input telnet ssh
!
"""

#: Which config a fake driver hands back. Keyed by device first so the lab's
#: four nodes each tell a different story, then by guard family for everything
#: the inventory pages render.
DEVICE_CONFIGS = {"mixed-sw1": EOS_CONFIG, "mixed-nx1": NXOS_CONFIG}
CONFIGS = {"cisco": CISCO_CONFIG, "juniper": JUNOS_CONFIG}

FACTS = {
    "core-sw-01": {"hostname": "core-sw-01", "vendor": "Cisco", "model": "WS-C3850-24T",
                   "os_version": "15.2(4)E10", "serial_number": "FDO1732Q0AB",
                   "uptime": 8641230},
}

#: LLDP as each device reports it. Designed so the graph shows the four states
#: the topology page distinguishes: a link both ends confirm, a link only one
#: end reported, a neighbour with no inventory entry, and a device that has no
#: LLDP table to ask for at all.
NEIGHBOURS = {
    "core-sw-01": [
        {"local_port": "Gi0/1", "remote_host": "edge-rtr-01", "remote_port": "ge-0/0/0"},
        {"local_port": "Gi0/2", "remote_host": "core-sw-02", "remote_port": "Gi0/2"},
        {"local_port": "Gi0/3", "remote_host": "dc-spine-01", "remote_port": "Ethernet1"},
    ],
    "core-sw-02": [
        {"local_port": "Gi0/2", "remote_host": "core-sw-01", "remote_port": "Gi0/2"},
        {"local_port": "Gi0/5", "remote_host": "acc-sw-11", "remote_port": "1/1/1"},
    ],
    "dc-spine-01": [
        {"local_port": "Ethernet1", "remote_host": "core-sw-01", "remote_port": "Gi0/3"},
        {"local_port": "Ethernet2", "remote_host": "dc-spine-02", "remote_port": "Ethernet2"},
    ],
    "dc-spine-02": [
        {"local_port": "Ethernet2", "remote_host": "dc-spine-01", "remote_port": "Ethernet2"},
        {"local_port": "Ethernet7", "remote_host": "acc-sw-99",
         "remote_port": "Gi1/0/24", "remote_description": "Catalyst 2960X, not in inventory"},
    ],
    "edge-rtr-01": [
        {"local_port": "ge-0/0/0", "remote_host": "core-sw-01", "remote_port": "Gi0/1"},
    ],
}


def install_fake_drivers() -> None:
    """Replace every driver's I/O, keeping the real class behind it.

    Subclassing rather than substituting matters: `capabilities` decides which
    platforms the topology page may even ask for LLDP, and the guard family
    comes off the real class too. Canning those as well would make the
    screenshots agree with this file instead of with netauto.
    """
    from netauto import drivers

    real = drivers.get_driver_class
    cache: dict[str, type] = {}

    def fake_for(platform: str) -> type:
        if platform in cache:
            return cache[platform]
        base = real(platform)

        class Fake(base):  # type: ignore[misc,valid-type]
            def open(self) -> None:
                self._connected = True

            def close(self) -> None:
                self._connected = False

            def facts(self):
                name = self.device.name
                return FACTS.get(name, {
                    "hostname": name, "vendor": base.__name__.split("_")[0].title(),
                    "model": "synthetic", "os_version": "synthetic",
                    "serial_number": "SYNTHETIC", "uptime": 604800,
                })

            def get_config(self, kind: str = "running") -> str:
                from netauto.drivers.base import platform_family
                if self.device.name in DEVICE_CONFIGS:
                    return DEVICE_CONFIGS[self.device.name]
                return CONFIGS.get(platform_family(self.device.platform), CISCO_CONFIG)

            def run_read(self, command: str) -> str:
                return (
                    "Interface              IP-Address      OK? Method Status    Protocol\n"
                    "GigabitEthernet0/1     10.20.0.1       YES NVRAM  up        up\n"
                    "GigabitEthernet0/2     unassigned      YES unset  up        up\n"
                    "GigabitEthernet0/3     unassigned      YES unset  up        up\n"
                    "Vlan1                  unassigned      YES NVRAM  admin down down\n"
                )

            def neighbors(self):
                return NEIGHBOURS.get(self.device.name, [])

        Fake.__name__ = base.__name__
        cache[platform] = Fake
        return Fake

    drivers.get_driver_class = fake_for
    # Bound at import time by the modules that collect topology and audit.
    for mod in ("netauto.topology", "netauto.audit", "netauto.session"):
        with contextlib.suppress(Exception):
            m = __import__(mod, fromlist=["get_driver_class"])
            if hasattr(m, "get_driver_class"):
                m.get_driver_class = fake_for


def pin_the_clock() -> None:
    """Freeze the dates the pages print, and the zone they print them in."""
    from netauto import topology

    os.environ["TZ"] = "UTC"
    time.tzset()

    real_build = topology.build

    def build(*a, **kw):
        topo = real_build(*a, **kw)
        topo.collected_at = FIXED_EPOCH
        return topo

    topology.build = build


def install_fake_lab() -> None:
    """Pin the lab page's state instead of reading this machine's.

    Left alone the page reports whatever netlab happens to be doing here, so
    the image would depend on whether a lab was up when someone ran the script
    -- and it would publish the absolute path netlab was found at, home
    directory and all. Both are pinned to what the README describes: one
    topology down, one up with its four nodes mapped.
    """
    from types import SimpleNamespace

    from netauto.lab import runner as lab_runner
    from netauto.web import app as appmod

    lab_runner.netlab_path = lambda: "/usr/local/bin/netlab"
    lab_runner.is_available = lambda: True

    nodes = SimpleNamespace(
        devices=[
            SimpleNamespace(name="spine1", platform="arista_eos", host="192.168.121.101"),
            SimpleNamespace(name="spine2", platform="arista_eos", host="192.168.121.102"),
            SimpleNamespace(name="leaf1",  platform="arista_eos", host="192.168.121.103"),
            SimpleNamespace(name="leaf2",  platform="arista_eos", host="192.168.121.104"),
        ],
        skipped=[],
    )
    appmod.lab_nodes_for = lambda topology: (
        nodes if "spine-leaf" in str(topology) else None
    )


def install_fake_scan() -> None:
    """Five hosts on a swept segment, two of them already managed."""
    from netauto import scan

    hosts = [
        scan.Host(ip="10.20.0.1", mac="00:1b:0d:63:1a:40", vendor="Cisco Systems"),
        scan.Host(ip="10.20.0.3", mac="00:1b:0d:63:1a:7c", vendor="Cisco Systems"),
        scan.Host(ip="10.20.0.37", mac="00:1b:0d:9f:22:04", vendor="Cisco Systems"),
        scan.Host(ip="10.20.0.52", mac="94:b4:0f:c1:88:e2", vendor="Aruba, a HPE Company"),
        scan.Host(ip="10.20.0.99", mac="3c:61:04:0d:5b:11", vendor="Juniper Networks"),
    ]
    banners = {
        "10.20.0.1":  ("SSH-2.0-Cisco-1.25", True),
        "10.20.0.3":  ("SSH-2.0-Cisco-1.25", False),
        "10.20.0.37": ("SSH-2.0-Cisco-1.25", True),
        "10.20.0.52": ("SSH-2.0-OpenSSH_8.4 ArubaOS-CX", False),
        "10.20.0.99": ("SSH-2.0-OpenSSH_7.9 Junos", False),
    }

    def arp_sweep(cidr: str, interface: str = "") -> list:  # noqa: ARG001
        return list(hosts)

    def probe_hosts(found: list, ports) -> list:  # noqa: ARG001
        out = []
        for h in found:
            banner, telnet = banners[h.ip]
            out.append(scan.Host(
                ip=h.ip, mac=h.mac, vendor=h.vendor, known_as=h.known_as,
                ports=(scan.Port(22, True, banner),
                       scan.Port(23, telnet, "User Access Verification" if telnet else "")),
            ))
        return out

    scan.arp_sweep = arp_sweep
    scan.probe_hosts = probe_hosts


#: The mixed-vendor lab the audit screenshot reports on: four nodes, four
#: platforms, which is the whole point of that topology.
LAB_NODES = [
    ("mixed-r1",  "juniper_junos",  "192.168.121.11"),
    ("mixed-sw1", "arista_eos",     "192.168.121.12"),
    ("mixed-nx1", "cisco_nxos",     "192.168.121.13"),
    ("mixed-c1",  "cisco_ios",      "192.168.121.14"),
]


def seed_lab_audit(client) -> None:
    """Put a finished lab audit in the job store for the page to render.

    The job is assembled here, but the findings in it are not: each node goes
    through the same audit_device the Audit page calls, against the same
    ruleset, so the verdicts on this screenshot are netauto's own rather than a
    plausible-looking table typed into a fixture.
    """
    from netauto.audit import audit_device
    from netauto.config import Settings
    from netauto.inventory import Device
    from netauto.lab import service as lab_service_mod

    settings = Settings.load()
    results = [
        audit_device(Device(name=n, platform=p, host=h, credentials="LAB"), settings)
        for n, p, h in LAB_NODES
    ]
    summary = {"devices": len(results), "fail": 0, "pass": 0, "errors": 0}
    for r in results:
        if r.get("error"):
            summary["errors"] += 1
        summary["fail"] += r.get("summary", {}).get("fail", 0)
        summary["pass"] += r.get("summary", {}).get("pass", 0)

    job = lab_service_mod.LabJob(
        id=LAB_AUDIT_ID, action=lab_service_mod.AUDIT,
        topology="labs/mixed-vendor/topology.yml", user="adis",
        status=lab_service_mod.DONE,
        created_at=FIXED_EPOCH - 154, finished_at=FIXED_EPOCH - 12,
        results=results, summary=summary,
    )
    client.app.state.lab.store.add(job)


LAB_AUDIT_ID = "screenshot"


# -- pages -----------------------------------------------------------------

#: Output name -> the request that produces it. Order is the README's order.
PAGES: dict[str, str] = {
    "dashboard": "/",
    "devices":   "/devices",
    "activity":  "/activity",
    "workflows": "/workflows",
    "lab":       "/lab",
    "discover":  "/discover?cidr=10.20.0.0%2F24&interface=eth0&probe=1&ports=22%2C23",
    "connect":   "/connect?ip=10.20.0.37",
    "topology":  "/topology?run=1",
    "audit":     "/audit?device=core-sw-01",
    "lab-audit": f"/lab/audits/{LAB_AUDIT_ID}",
}

#: Pages needing server-side state that no GET of theirs would create.
SEEDS = {"lab-audit": seed_lab_audit}

#: Only the Activity page is an administrator's view. Everything else is what a
#: standard account sees, which is why no other screenshot has the tab.
ADMIN_PAGES = frozenset({"activity"})

#: The connect page only offers a host the server itself swept within the hour,
#: so the sweep has to have happened in this session before the page is asked
#: for. Same rule the running server enforces; nothing is being worked around.
PREREQS: dict[str, tuple[str, ...]] = {
    "connect": (PAGES["discover"],),
}


def main(argv: list[str]) -> int:
    wanted = argv or list(PAGES)
    unknown = [w for w in wanted if w not in PAGES]
    if unknown:
        print(f"unknown page(s): {', '.join(unknown)}", file=sys.stderr)
        print(f"known: {', '.join(PAGES)}", file=sys.stderr)
        return 2
    if not shutil.which("chromium"):
        print("chromium not found on PATH", file=sys.stderr)
        return 2

    install_fake_drivers()
    install_fake_scan()
    install_fake_lab()
    pin_the_clock()

    with tempfile.TemporaryDirectory() as td, contextlib.chdir(td):
        tmp = Path(td)
        work = tmp / "render"
        work.mkdir()

        # Grouped so the two account layouts each cost one app build, and so
        # the order within a group still follows PAGES.
        for admin in (False, True):
            group = [n for n in PAGES if n in wanted
                     and (n in ADMIN_PAGES) == admin]
            if not group:
                continue
            client = build_client(tmp, admin=admin)
            for name in group:
                for prereq in PREREQS.get(name, ()):
                    client.get(prereq)
                if name in SEEDS:
                    SEEDS[name](client)
                r = client.get(PAGES[name])
                if r.status_code != 200:
                    print(f"  {name}: HTTP {r.status_code}", file=sys.stderr)
                    return 1
                out = DOCS / f"{name}.png"
                capture(r.text, out, work, MAX_CSS_HEIGHT.get(name))
                print(f"  {name:10} {PAGES[name]:54} {out.stat().st_size // 1024:>4} KB")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
