"""Topology assembly.

The load-bearing behaviour is merging: every link is reported twice, by both
ends, and a graph that fails to collapse those draws every cable as two.
"""

import xml.etree.ElementTree as ET

import pytest

from netauto import drawio, topology
from netauto.config import Settings
from netauto.errors import NetautoError, UnsupportedOperation
from netauto.inventory import Device, Inventory
from netauto.topology import Node, Topology, normalise_host, tier_for


def _settings():
    return Settings(inventory_path="unused", max_concurrency=4)


def _inventory(*devices):
    return Inventory(list(devices))


def _dev(name, platform="cisco_ios", tags=()):
    return Device(name=name, platform=platform, host="10.0.0.1",
                  credentials="X", tags=tuple(tags))


@pytest.fixture
def fake_neighbors(monkeypatch):
    """Drive topology.build from a dict of device name -> neighbour rows."""
    tables: dict[str, object] = {}

    def collect(device, settings):
        entry = tables.get(device.name)
        if isinstance(entry, Exception):
            return device.name, [], str(entry)
        return device.name, entry or [], ""

    monkeypatch.setattr(topology, "_collect_one", collect)
    return tables


# -- merging -------------------------------------------------------------


def test_a_link_reported_from_both_ends_becomes_one(fake_neighbors):
    fake_neighbors["sw1"] = [{"local_port": "Gi1/0/1", "remote_host": "sw2",
                              "remote_port": "Gi0/1"}]
    fake_neighbors["sw2"] = [{"local_port": "Gi0/1", "remote_host": "sw1",
                              "remote_port": "Gi1/0/1"}]
    topo = topology.build(_inventory(_dev("sw1"), _dev("sw2")), _settings())
    assert len(topo.links) == 1
    link = topo.links[0]
    assert link.confirmed
    assert {link.a, link.b} == {"sw1", "sw2"}
    assert {link.a_port, link.b_port} == {"Gi1/0/1", "Gi0/1"}


def test_a_link_only_one_end_reports_is_kept_but_unconfirmed(fake_neighbors):
    fake_neighbors["sw1"] = [{"local_port": "Gi1/0/1", "remote_host": "sw2",
                              "remote_port": "Gi0/1"}]
    fake_neighbors["sw2"] = []
    topo = topology.build(_inventory(_dev("sw1"), _dev("sw2")), _settings())
    assert len(topo.links) == 1
    assert not topo.links[0].confirmed


def test_the_far_end_report_fills_in_a_missing_port(fake_neighbors):
    """One side may omit the remote port; the other side supplies it."""
    fake_neighbors["sw1"] = [{"local_port": "Gi1/0/1", "remote_host": "sw2",
                              "remote_port": ""}]
    fake_neighbors["sw2"] = [{"local_port": "Gi0/1", "remote_host": "sw1",
                              "remote_port": "Gi1/0/1"}]
    topo = topology.build(_inventory(_dev("sw1"), _dev("sw2")), _settings())
    link = topo.links[0]
    assert "" not in (link.a_port, link.b_port)


@pytest.mark.parametrize("reported", ["SW2", "sw2.example.com", "SW2.Example.COM"])
def test_hostname_case_and_domain_do_not_duplicate_a_device(fake_neighbors, reported):
    """LLDP may report an FQDN or shout the name; both are the same switch."""
    fake_neighbors["sw1"] = [{"local_port": "Gi1", "remote_host": reported,
                              "remote_port": "Gi0/1"}]
    fake_neighbors["sw2"] = []
    topo = topology.build(_inventory(_dev("sw1"), _dev("sw2")), _settings())
    assert len(topo.nodes) == 2, f"{reported} created a duplicate node"
    assert topo.discovered_nodes == []


def test_a_port_channel_stays_two_cables(fake_neighbors):
    """Two links between the same pair are two links, not one.

    Keying a cable on its endpoints alone silently drops every member of a
    port-channel but the first -- and redundancy between core switches is
    exactly what someone opens a topology diagram to check.
    """
    fake_neighbors["sw1"] = [
        {"local_port": "Gi1/0/1", "remote_host": "sw2", "remote_port": "Gi0/1"},
        {"local_port": "Gi1/0/2", "remote_host": "sw2", "remote_port": "Gi0/2"},
    ]
    fake_neighbors["sw2"] = [
        {"local_port": "Gi0/1", "remote_host": "sw1", "remote_port": "Gi1/0/1"},
        {"local_port": "Gi0/2", "remote_host": "sw1", "remote_port": "Gi1/0/2"},
    ]
    topo = topology.build(_inventory(_dev("sw1"), _dev("sw2")), _settings())
    assert len(topo.links) == 2
    assert all(link.confirmed for link in topo.links)
    assert {link.a_port for link in topo.links} == {"Gi1/0/1", "Gi1/0/2"}


def test_port_channel_members_pair_by_port_not_by_order(fake_neighbors):
    """Members must pair with their real partner, not whichever came first."""
    fake_neighbors["sw1"] = [
        {"local_port": "Gi1/0/1", "remote_host": "sw2", "remote_port": "Gi0/1"},
        {"local_port": "Gi1/0/2", "remote_host": "sw2", "remote_port": "Gi0/2"},
    ]
    # Reported in the opposite order by the far end.
    fake_neighbors["sw2"] = [
        {"local_port": "Gi0/2", "remote_host": "sw1", "remote_port": "Gi1/0/2"},
        {"local_port": "Gi0/1", "remote_host": "sw1", "remote_port": "Gi1/0/1"},
    ]
    topo = topology.build(_inventory(_dev("sw1"), _dev("sw2")), _settings())
    pairs = {(link.a_port, link.b_port) for link in topo.links}
    assert pairs == {("Gi1/0/1", "Gi0/1"), ("Gi1/0/2", "Gi0/2")}


def test_port_channel_member_the_far_end_missed_is_still_drawn(fake_neighbors):
    """One confirmed member, one the far end did not report -- both are cables."""
    fake_neighbors["sw1"] = [
        {"local_port": "Gi1/0/1", "remote_host": "sw2", "remote_port": "Gi0/1"},
        {"local_port": "Gi1/0/2", "remote_host": "sw2", "remote_port": "Gi0/2"},
    ]
    fake_neighbors["sw2"] = [
        {"local_port": "Gi0/1", "remote_host": "sw1", "remote_port": "Gi1/0/1"},
    ]
    topo = topology.build(_inventory(_dev("sw1"), _dev("sw2")), _settings())
    assert len(topo.links) == 2
    assert sorted(link.confirmed for link in topo.links) == [False, True]


def test_neighbour_absent_from_inventory_becomes_a_discovered_node(fake_neighbors):
    fake_neighbors["sw1"] = [{"local_port": "Gi12", "remote_host": "ap-lobby",
                              "remote_port": "eth0",
                              "remote_description": "Aruba AP-515"}]
    topo = topology.build(_inventory(_dev("sw1")), _settings())
    assert [n.name for n in topo.discovered_nodes] == ["ap-lobby"]
    assert topo.discovered_nodes[0].description == "Aruba AP-515"
    assert not topo.discovered_nodes[0].known


def test_neighbour_with_no_name_is_skipped(fake_neighbors):
    """A row with no usable identity cannot become a node."""
    fake_neighbors["sw1"] = [{"local_port": "Gi1", "remote_host": "", "remote_port": "x"}]
    topo = topology.build(_inventory(_dev("sw1")), _settings())
    assert topo.links == []
    assert len(topo.nodes) == 1


def test_unreachable_device_is_a_gap_but_still_a_node(fake_neighbors):
    """A device that failed still belongs on the diagram, without links."""
    fake_neighbors["sw1"] = NetautoError("connection refused")
    topo = topology.build(_inventory(_dev("sw1")), _settings())
    assert "sw1" in topo.gaps
    assert "connection refused" in topo.gaps["sw1"]
    assert "sw1" in topo.nodes


def test_one_bad_device_does_not_sink_the_run(fake_neighbors):
    fake_neighbors["sw1"] = [{"local_port": "Gi1", "remote_host": "sw2",
                              "remote_port": "Gi0/1"}]
    fake_neighbors["sw2"] = UnsupportedOperation("no LLDP here")
    topo = topology.build(_inventory(_dev("sw1"), _dev("sw2")), _settings())
    assert len(topo.links) == 1
    assert list(topo.gaps) == ["sw2"]


def test_empty_inventory_yields_an_empty_graph():
    topo = topology.build(_inventory(), _settings())
    assert topo.nodes == {} and topo.links == []


# -- tiers ---------------------------------------------------------------


@pytest.mark.parametrize("tags,expected", [
    (("core",), "core"), (("spine",), "core"), (("wan", "edge"), "edge"),
    (("access",), "access"), (("dist",), "distribution"), (("nothing",), "unknown"),
])
def test_tier_comes_from_inventory_tags(tags, expected):
    assert tier_for(_dev("x", tags=tags)) == expected


def test_untagged_devices_get_a_tier_from_how_connected_they_are(fake_neighbors):
    """With no operator labels, the busiest device is treated as the core."""
    fake_neighbors["hub"] = [
        {"local_port": f"Gi{i}", "remote_host": f"leaf{i}", "remote_port": "Gi0"}
        for i in range(1, 5)
    ]
    for i in range(1, 5):
        fake_neighbors[f"leaf{i}"] = []
    devices = [_dev("hub")] + [_dev(f"leaf{i}") for i in range(1, 5)]
    topo = topology.build(_inventory(*devices), _settings())
    assert topo.nodes["hub"].tier == "core"
    assert topo.nodes["leaf1"].tier == "access"


@pytest.mark.parametrize("raw,expected", [
    ("SW1.example.com", "sw1"), ("  sw1  ", "sw1"), ("", ""),
])
def test_normalise_host(raw, expected):
    assert normalise_host(raw) == expected


# -- draw.io output ------------------------------------------------------


def _sample():
    topo = Topology()
    topo.nodes["rtr"] = Node("rtr", known=True, platform="juniper_junos", tier="edge")
    topo.nodes["sw"] = Node("sw", known=True, platform="cisco_ios", tier="core")
    topo.nodes["fw"] = Node("fw", known=True, platform="fortinet_fortios", tier="edge")
    topo.nodes["ap"] = Node("ap", known=False, tier="discovered")
    topo.links = [
        topology.Link("rtr", "ge-0/0/0", "sw", "Te1/1/1", confirmed=True),
        topology.Link("sw", "Gi1/0/12", "ap", "eth0", confirmed=False),
    ]
    return topo


def test_drawio_output_is_well_formed_xml():
    ET.fromstring(drawio.render(_sample()))


def test_drawio_picks_a_stencil_per_platform():
    root = ET.fromstring(drawio.render(_sample()))
    shapes = {}
    for obj in root.iter("UserObject"):
        style = obj.find("mxCell").get("style")
        found = [s.split("=", 1)[1] for s in style.split(";") if s.startswith("shape=")]
        if found:
            shapes[obj.get("label").split("<")[0]] = found[0]
    assert shapes["rtr"] == drawio.SHAPE_ROUTER
    assert shapes["fw"] == drawio.SHAPE_FIREWALL
    assert shapes["sw"] == drawio.SHAPE_SWITCH
    # A discovered device gets no icon at all: it could be an AP, a phone or
    # a server, and asserting one would be a claim we cannot support.
    assert "ap" not in shapes


def _edge_anchors(xml):
    """Anchor styles per edge, in document order."""
    root = ET.fromstring(xml)
    out = []
    for c in root.iter("mxCell"):
        if c.get("edge") != "1":
            continue
        style = c.get("style")
        out.append(";".join(s for s in style.split(";")
                            if s.startswith(("exitX", "exitY", "entryX", "entryY"))))
    return out


def test_port_channel_members_do_not_stack_on_one_path():
    """Two edges with the same endpoints get identical geometry by default.

    Without distinct anchors a two-member port-channel renders as a single
    line, which would undo the link matching in the picture.
    """
    topo = Topology()
    topo.nodes["a"] = Node("a", known=True, platform="cisco_ios", tier="core")
    topo.nodes["b"] = Node("b", known=True, platform="cisco_ios", tier="core")
    topo.links = [topology.Link("a", "Te1/1/2", "b", "Te1/1/2", confirmed=True),
                  topology.Link("a", "Te1/1/3", "b", "Te1/1/3", confirmed=True)]
    anchors = _edge_anchors(drawio.render(topo))
    assert len(anchors) == 2
    assert all(anchors), "parallel edges must carry explicit anchors"
    assert anchors[0] != anchors[1], "parallel edges must not share a path"


def test_a_single_link_keeps_default_routing():
    """Only parallel edges need pinning; the rest should route freely."""
    topo = Topology()
    topo.nodes["a"] = Node("a", known=True, platform="cisco_ios", tier="core")
    topo.nodes["b"] = Node("b", known=True, platform="cisco_nxos", tier="distribution")
    topo.links = [topology.Link("a", "Gi1", "b", "Eth1", confirmed=True)]
    assert _edge_anchors(drawio.render(topo)) == [""]


def test_drawio_uses_orthogonal_connectors():
    """The right-angle routing is what makes it read as Visio, not a scatter plot."""
    xml = drawio.render(_sample())
    assert "edgeStyle=orthogonalEdgeStyle" in xml


def test_drawio_labels_both_ends_of_a_link():
    root = ET.fromstring(drawio.render(_sample()))
    labels = [c.get("value") for c in root.iter("mxCell")
              if c.get("connectable") == "0"]
    assert "ge-0/0/0" in labels and "Te1/1/1" in labels


def test_drawio_marks_discovered_nodes_as_dashed():
    root = ET.fromstring(drawio.render(_sample()))
    for obj in root.iter("UserObject"):
        style = obj.find("mxCell").get("style")
        if obj.get("label").startswith("ap"):
            assert "dashed=1" in style
        else:
            assert "dashed=0" in style


def test_drawio_line_break_survives_xml_escaping():
    """A literal &#10; would be double-escaped and shown as text."""
    root = ET.fromstring(drawio.render(_sample()))
    labels = [o.get("label") for o in root.iter("UserObject")]
    assert "ap<br>(discovered)" in labels
    assert not any("&#10;" in x for x in labels)


def test_drawio_escapes_a_hostile_device_name():
    """A device named with a quote must not break the XML."""
    topo = Topology()
    topo.nodes['sw"1'] = Node('sw"1', known=True, platform="cisco_ios", tier="core")
    root = ET.fromstring(drawio.render(topo))
    assert 'sw"1' in [o.get("label") for o in root.iter("UserObject")]


def test_empty_topology_still_renders_a_valid_file():
    ET.fromstring(drawio.render(Topology()))


def test_as_dict_summarises(fake_neighbors):
    fake_neighbors["sw1"] = [{"local_port": "Gi1", "remote_host": "ap",
                              "remote_port": "eth0"}]
    fake_neighbors["sw2"] = NetautoError("down")
    topo = topology.build(_inventory(_dev("sw1"), _dev("sw2")), _settings())
    data = topology.as_dict(topo)
    assert data["summary"] == {"devices": 2, "discovered": 1, "links": 1,
                               "unreachable": 1}
    assert data["gaps"]["sw2"] == "down"


# -- web routes ----------------------------------------------------------


@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from netauto.web import app as appmod
    from netauto.web.users import UserStore

    monkeypatch.setenv("NETAUTO_SECRET_KEY", "test-key-not-for-production")
    monkeypatch.setenv("NETAUTO_ACTIVITY_LOG", str(tmp_path / "activity.log"))
    monkeypatch.delenv("NETAUTO_METRICS_TOKEN", raising=False)
    store = UserStore(tmp_path / "users.yaml")
    store.add("alice", "correct-horse-battery-staple", admin=True)
    appmod._FAILURES.clear()
    c = TestClient(appmod.create_app(store))
    token = c.get("/login").text.split('name="csrf_token" value="')[1].split('"')[0]
    c.post("/login", data={"username": "alice",
                           "password_input": "correct-horse-battery-staple",
                           "csrf_token": token})
    return c


@pytest.mark.parametrize("path", ["/topology", "/topology.drawio", "/topology.json"])
def test_topology_routes_require_a_session(tmp_path, monkeypatch, path):
    from fastapi.testclient import TestClient

    from netauto.web.app import create_app
    from netauto.web.users import UserStore

    monkeypatch.setenv("NETAUTO_SECRET_KEY", "k")
    monkeypatch.setenv("NETAUTO_ACTIVITY_LOG", str(tmp_path / "a.log"))
    store = UserStore(tmp_path / "u.yaml")
    store.add("alice", "correct-horse-battery-staple", admin=True)
    r = TestClient(create_app(store)).get(path, follow_redirects=False)
    assert r.status_code == 303


def test_topology_page_does_not_collect_until_asked(client, monkeypatch):
    """Opening the tab must not silently open a session to every device."""
    def boom(*a, **kw):
        raise AssertionError("collection ran without being requested")

    monkeypatch.setattr(topology, "build", boom)
    assert client.get("/topology").status_code == 200


def test_drawio_download_has_a_filename(client, monkeypatch):
    monkeypatch.setattr(topology, "build", lambda *a, **kw: _sample())
    r = client.get("/topology.drawio")
    assert r.status_code == 200
    assert "network-topology.drawio" in r.headers["content-disposition"]
    ET.fromstring(r.text)


def test_json_export_matches_the_graph(client, monkeypatch):
    monkeypatch.setattr(topology, "build", lambda *a, **kw: _sample())
    body = client.get("/topology.json").json()
    assert body["summary"]["links"] == 2
    assert {n["name"] for n in body["nodes"]} == {"rtr", "sw", "fw", "ap"}


def test_topology_adds_no_write_route(client):
    posts = {r.path for r in client.app.routes
             if getattr(r, "methods", None) and "POST" in r.methods}
    assert posts == {"/login", "/logout"}
