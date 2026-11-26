"""The Netstat tab, the hosts database and the globe's filters and layers (0.7.0; the user, 2026-11-16: "the firewall
app should have a 'netstat' like interface for looking at active ports and what apps they are attached to, and the
hosts that they connect to across the lan or wan. the firewall app should also have a globe that can be zoomed and
rotated and geoip'd hosts are databased for the apps they talk to, the time they are connected to *this *computer";
"the globe-firewall should allow filtering, so i can view apps connected to hosts all across the globe, or ports
talking to all hosts. The globe should have the same kind of geography associated with the exchanges globe, but the
firewall globe should instead of exchanges, have all the backbones,ibones, major internet infrastructure, (as many as
possible) datacenter locations."): the library's Firewall base's (liminal-libs 1.65.0) with what this plugin names for
them (apis.py), asked through the plugin as the platform asks it.

The tab's page over a reading made in the shape the library's Windows reader gives; one reading shared by both tabs and
kept in the hosts database; the globe's hosts and filters through the plugin's hooks; every data set's dict a data set
the library reads, its size, licence and credit said first, its query what the library's readers read (the submarine
cables of every telecom category, the lines on land not on power poles, Wikidata's data centres of every kind, the
Topology Zoo's maps of backbone networks: the user, 2026-11-19, "major network 'bones' need to be displayed on the
map", "also underwater lines"), the same data sets as the Linux firewall plugin's, their digest pinned; a download on
the user's word from the plugin's own address with the plugin's name as its User-Agent, drawn on the globe and removed;
the cards' calls as the library makes them; the facts, asking nothing, their counts written as the tabs write them;
off Windows, no view made and every hook of the two tabs refused before it reads, keeps or removes anything (its
status, reads and changes there, on any library: test_plugin.py); and the suite's guard (tests/conftest.py,
B-critique B1), which keeps a plugin attached under a login that says always from reading this PC's socket table into
its hosts database.

Nothing real: the socket table is a stand-in's reading (the guard refuses the real one), the hosts database and the
layers' folder are the test's own (the same guard), no GeoIP file is there, a download's server is a stand-in whose
answers are made in each source's documented shape (no query may be sent from a test: the first real click is theirs),
no process is started and nothing reaches the network."""
from __future__ import annotations

import gzip
import hashlib
import inspect
import io
import json
import os
import re
import subprocess
import tarfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import quote

import importlib.util
import pytest

# the Netstat tab, the hosts database and the globe's layers are liminal-libs 1.65.0's: skipped with an older library
# (whose World Wide Web tab is 0.6.1's: test_world.py)
ROUTES_TABLE = ["Routes"] if importlib.util.find_spec("liminal_libs.machines.routes") else []  # 1.67.0: last
# liminal-libs 1.70.0: the legs waiting for a line are tabled after the routes
try:
    from liminal_libs.machines.routes import WAITING_TITLE as _WAITING
    try:  # liminal-libs 1.74.0: the routes hop by hop, between them
        from liminal_libs.machines.routes import HOPS_TITLE as _HOPS
        ROUTES_TABLE = ROUTES_TABLE + [_HOPS]
    except ImportError:
        pass
    ROUTES_TABLE = ROUTES_TABLE + [_WAITING]
except ImportError:
    pass
pytest.importorskip("liminal_libs.machines.netstat", reason="the library has no Netstat tab before liminal-libs 1.65.0")

from conftest import Reached  # noqa: E402 - after the skip, as each of these
from liminal_libs import capture, dns, geo, hostbook, netpath, resources, sockets  # noqa: E402
from liminal_libs.apps.authorization import EnvironmentLogin, Login, Unauthorized, pair_name  # noqa: E402
from liminal_libs.apps.tabs import Tab  # noqa: E402
from liminal_libs.machines import infrastructure, netstat, world  # noqa: E402
from liminal_libs.machines.firewall import Firewall  # noqa: E402
from liminal_libs.machines.infrastructure import DataSet, form, parse  # noqa: E402
from liminal_libs.machines.windows import PowerShell  # noqa: E402
from liminal_libs.machines.world import LicenceRefused, size_words  # noqa: E402
from liminal_libs.sources.apis import problems  # noqa: E402
from liminal_libs.sources.conformance import problems as contract_problems  # noqa: E402
from plugin_platform_firewall_windows import MACHINE, WindowsFirewallPlugin, netstat_in  # noqa: E402
from plugin_platform_firewall_windows import apis as cards  # noqa: E402
from test_plugin import FakeWindows, plugin  # noqa: E402
from test_world import NOW, Clock, Feed, Watched, wait_for  # noqa: E402

LAN, PRINTER = "192.168.1.20", "192.168.1.50"
WEB, WEB2 = "81.2.69.142", "81.2.69.160"  # public addresses: the internet's
EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
PY = "C:\\Python315\\python.exe"
NAMES = {WEB2: "cdn.example"}  # the system's own hosts file, stood in
THREADS = ("-hosts", "-layer-download", "traffic-watcher", "-public-address", "firewall-windows-read")
# the data sets' digest (sha256 of apis.INFRASTRUCTURE as canonical JSON: sorted keys, no spaces, UTF-8), the same the
# Linux firewall plugin's tests pin: the two plugins name the same data sets, and a data set changed changes both
INFRASTRUCTURE_SHA256 = "8e31ca180948d874e461d61aeb336d456f39224193f4786af35e800afeaa2549"


def sock(proto="tcp", local=LAN, local_port=51000, remote="", remote_port=0, *, at: float, state="established",
         pid=4321, program="msedge.exe", path=EDGE, service="", title="", ago=None, unread=None) -> dict:
    """One socket as the library's Windows reader gives it (sockets' row), made `ago` seconds before `at`."""
    started = None if ago is None else at - ago
    return {"proto": proto, "family": 6 if ":" in local else 4, "state": state, "local": local,
            "local_port": local_port, "remote": remote, "remote_port": remote_port, "pid": pid,
            "pids": [pid] if pid else [], "program": program, "path": path, "service": service,
            "service_title": title, "user": "", "started": started, "process_started": None, "count": 1, "inode": 0,
            "seen": started if started is not None else at, "unread": dict(unread or {})}


def windows_rows(at: float) -> list[dict]:
    """What Windows' four tables list here: Edge out to the internet; the System process's file sharing reached from
    the local network and listening on every address; the DNS client's UDP port; the platform's own page; and a
    connection whose owner has ended, only waiting to close."""
    system = {"service": sockets.SYSTEM, "path": sockets.SYSTEM_PATH}
    return [
        sock(remote=WEB, remote_port=443, at=at, ago=120),
        sock(local=LAN, local_port=445, remote=PRINTER, remote_port=50500, at=at, ago=30, pid=4, program="System",
             path="", unread=system),
        sock(local="0.0.0.0", local_port=445, state="listening", at=at, ago=3 * 86400, pid=4, program="System",
             path="", unread=system),
        sock("udp", "0.0.0.0", 5353, state="bound", at=at, ago=3 * 86400, pid=1200, program="svchost.exe", path="",
             service="Dnscache", title="DNS Client", unread={"path": sockets.REFUSED}),
        sock(local="127.0.0.1", local_port=8775, state="listening", at=at, ago=3600, pid=901, program="python.exe",
             path=PY),
        sock(local=LAN, local_port=51003, remote=WEB2, remote_port=443, at=at, state="time-wait", pid=0, program="",
             path="", unread={"program": sockets.GONE}),
    ]


class Table:
    """This PC's socket tables as a stand-in for sockets.read: a recorded reading taken now, each read counted."""

    def __init__(self):
        self.reads = 0

    def __call__(self, *args, **kwargs) -> dict:
        self.reads += 1
        at = time.time()
        return {"system": "windows", "at": at, "awake": 1000.0 + self.reads, "took": 0.004, "root": False,
                "starts": True, "read": sockets.TABLES, "cut": False, "rows": windows_rows(at),
                "notes": [sockets.UDP_NOTE]}


class Keeping(Login):
    """A login that keeps what it is given (the login app's way, so a setting lasts a restart), each save noted."""

    def __init__(self, **values):
        self.values = {pair_name(k): v for k, v in values.items()}
        self.saved: list[str] = []

    def user(self) -> dict:
        return {"name": "tester"}

    def vector(self, name: str) -> str:
        if name not in self.values:
            raise Unauthorized(f"no {name} here", 404)
        return self.values[name]

    def save(self, variable: str, value) -> str:
        self.saved.append(variable)
        self.values[pair_name(variable)] = value
        return "the test's login"


class Answers:
    """The data sets' servers as a stand-in for world.fetch_url: each address asked, with its wait, its User-Agent and
    what it is for, and what each answers (a recorded answer; any other address a 404)."""

    def __init__(self, answers):
        self.answers, self.asked = dict(answers), []

    def __call__(self, url, timeout=None, *, handlers=(), agent="", what=""):
        self.asked.append((url, timeout, agent, what))
        if url not in self.answers:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        return io.BytesIO(self.answers[url])


def ours(name: str) -> dict:
    """One of the plugin's data sets, by its id."""
    return next(d for d in cards.INFRASTRUCTURE if d["id"] == name)


def answer(doc) -> bytes:
    return json.dumps(doc).encode("utf-8")


# answers made in the shape each source documents for the plugin's queries, none of them recorded (no query is sent
# from here: Overpass, out tags center and out tags geom, as its manual and its source print them; the query service,
# its SPARQL results as JSON; EMODnet's WFS, GeoJSON longitude first, its CRS named as GeoServer names it)
SITES = {"version": 0.6, "generator": "Overpass API", "elements": [
    {"type": "node", "id": 1, "lat": 52.3702, "lon": 4.8952,
     "tags": {"telecom": "data_center", "name": "AMS-1", "operator": "Example Hosting"}},
    {"type": "way", "id": 2, "center": {"lat": 50.1109, "lon": 8.6821}, "tags": {"building": "data_center"}},
    {"type": "node", "id": 3, "lat": 51.5074, "lon": -0.1278,
     "tags": {"telecom": "internet_exchange", "name": "LON-IX"}},
]}
CABLES = {"version": 0.6, "generator": "Overpass API", "elements": [
    {"type": "way", "id": 10, "bounds": {"minlat": 50.0, "minlon": -5.0, "maxlat": 51.0, "maxlon": -1.0},
     "geometry": [{"lat": 50.0, "lon": -5.0}, {"lat": 50.5, "lon": -3.0}, {"lat": 51.0, "lon": -1.0}],
     "tags": {"communication": "line", "location": "underwater", "name": "Cable A"}},
    {"type": "way", "id": 11, "geometry": [{"lat": 43.0, "lon": 5.0}, {"lat": 42.0, "lon": 8.0}],
     "tags": {"seamark:type": "cable_submarine", "seamark:cable_submarine:category": "fibre_optic"}},
    {"type": "node", "id": 12, "lat": 50.1, "lon": -5.5, "tags": {"telecom": "cable_landing_station", "name": "Porth"}},
]}
LINES = {"version": 0.6, "generator": "Overpass API", "elements": [
    {"type": "way", "id": 20,
     "geometry": [{"lat": 48.0, "lon": 2.0}, {"lat": 48.5, "lon": 2.5}, {"lat": 49.0, "lon": 3.0}],
     "tags": {"communication": "line", "telecom:medium": "fibre"}},
]}
PLACES = {"head": {"vars": ["item", "itemLabel", "kind", "coord", "operatorLabel"]}, "results": {"bindings": [
    {"item": {"type": "uri", "value": "http://www.wikidata.org/entity/Q100"},
     "itemLabel": {"type": "literal", "value": "An exchange point"},
     "kind": {"type": "uri", "value": "http://www.wikidata.org/entity/Q1433061"},
     "coord": {"type": "literal", "value": "Point(4.9 52.37)"}},
    {"item": {"type": "uri", "value": "http://www.wikidata.org/entity/Q101"},
     "itemLabel": {"type": "literal", "value": "A teleport"},
     "kind": {"type": "uri", "value": "http://www.wikidata.org/entity/Q10379228"},
     "coord": {"type": "literal", "value": "Point(-3.7 40.4)"},
     "operatorLabel": {"type": "literal", "value": "An operator"}},
]}}
ROUTES = {"type": "FeatureCollection", "crs": {"type": "name", "properties": {"name": "urn:ogc:def:crs:EPSG::4326"}},
          "features": [
              {"type": "Feature", "properties": {"name_": "Cable B"},
               "geometry": {"type": "MultiLineString", "coordinates": [[[7.0, 54.0], [7.5, 54.5], [8.0, 55.0]]]}},
              {"type": "Feature", "properties": {"pipe_name": "Cable C", "operator": "An operator"},
               "geometry": {"type": "LineString", "coordinates": [[-1.0, 58.0], [0.0, 59.0]]}}]}
# the Topology Zoo's archive as its repository holds it (gml.tar.gz: a folder of GML maps, gzipped), here one map in
# the shape its toolset wrote them (a network's values, its points with their places, its links)
GEANT = """graph [
  Network "GEANT"
  DateYear "2010"
  node [
    id 0
    label "Frankfurt"
    Longitude 8.68333
    Internal 1
    Latitude 50.11667
  ]
  node [
    id 1
    label "Amsterdam"
    Longitude 4.88969
    Internal 1
    Latitude 52.37403
  ]
  edge [
    source 0
    target 1
  ]
]
"""


def zoo_archive(maps: dict) -> bytes:
    """Maps in a gzipped tar, as the Topology Zoo's gml.tar.gz holds them."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tar:
        for name, text in maps.items():
            data = text.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(out.getvalue(), mtime=0)


@pytest.fixture(autouse=True)
def _nothing_outside(monkeypatch, tmp_path):
    """Nothing real is reached: no Npcap loaded nor its option read from this PC's registry, no route asked, no name
    server, no download but through a test's own stand-in, no process started, not this PC's data folder (each reach
    noted, so one inside a thread is seen too); no thread of a tab or a download left after a test. The socket table is
    the suite's guard's (tests/conftest.py: refused, unless a test stands in for it with `table`)."""
    reached: list[str] = []

    def refusing(name):
        def refuse(*args, **kwargs):
            reached.append(name)
            raise AssertionError(f"a test reached the real {name}")
        return refuse
    for module, name in ((capture, "load_pcap"), (capture, "npcap_admin_only"), (netpath, "lan_address"),
                         (world, "route_address"), (dns, "query"), (world, "fetch_url"), (urllib.request, "urlopen"),
                         (subprocess, "Popen")):
        monkeypatch.setattr(module, name, refusing(name))
    monkeypatch.setattr(geo, "data_folder", lambda: tmp_path / "data" / "geoip")
    monkeypatch.setattr(sockets, "known_names", lambda *args, **kwargs: dict(NAMES))
    for variable in ("LIMINAL_CHARTS_PORT", "LIMINAL_PLATFORM_PORT", "LIMINAL_FETCHER_PORT", "LIMINAL_LOGIN_PORT"):
        monkeypatch.delenv(variable, raising=False)  # Liminal's own pages at their own ports
    yield
    assert wait_for(lambda: not [t for t in threading.enumerate() if t.name.endswith(THREADS)]), "a thread was left"
    assert reached == []


@pytest.fixture
def table(monkeypatch) -> Table:
    """This PC's socket tables as a recorded reading (a reader of the test's own, as the guard asks)."""
    found = Table()
    monkeypatch.setattr(sockets, "read", found)
    return found


# -- what the plugin is given and names ------------------------------------------------------------------------------
def test_the_netstat_tab_is_the_firewall_bases_after_the_world_wide_web_tab_with_the_plugins_data_sets():
    assert netstat_in() and MACHINE.TABS[:2] == Firewall.TABS == (Tab("world", "World Wide Web", "world", 2.0),
                                                              Tab("netstat", "Netstat", "netstat", 3.0))
    hooks = MACHINE.interface()["hooks"]
    assert hooks["netstat"].startswith("() ") and hooks["hosts_recording"].startswith("(mode) ")
    assert hooks["hosts_forget"].startswith("(accept_forget=False) ")
    assert hooks["world_layer_get"].startswith("(dataset, accept_licence=False, log=None) ")
    assert {"world_show", "world_direction", "world_within", "world_pick", "world_layer",
            "world_layer_remove"} <= set(hooks)
    # a data set's download is a job the page may cancel; a layer's geometry a read (no log line)
    # liminal-libs 1.75.0: the ASN file's install; 1.101.0 (0.9.0): a GeoIP source's file, which the page may cancel too
    assert MACHINE.JOB_HOOKS == ("world_geoip", "world_layer_get", "world_asn", "world_geoip_get")
    assert MACHINE.CANCEL_HOOKS == ("world_layer_get", "world_geoip_get")
    assert "world_layer" in MACHINE.READ_HOOKS
    from liminal_libs.machines import firewall as firewall_module  # liminal-libs 1.74.0: when the traffic is watched
    watching = ["LIMINAL_TRAFFIC_WATCHING"] if hasattr(firewall_module, "WATCH_KEY") else []
    assert [k.name for k in MACHINE.keys] == ["LIMINAL_HOME_PLACE", "LIMINAL_HOSTS_RECORDING", *watching]
    assert MACHINE.INFRASTRUCTURE == cards.INFRASTRUCTURE and MACHINE.apis == cards.APIS  # its data sets and cards
    assert set(cards.NETSTAT) <= set(MACHINE.apis) and "Netstat" in MACHINE.about
    assert contract_problems(MACHINE) == [] and problems(MACHINE.apis) == []


def test_every_data_set_is_one_the_library_reads_its_size_licence_and_credit_said_before_its_download(tmp_path):
    ids = [d["id"] for d in cards.INFRASTRUCTURE]
    assert ids == ["osm-datacentres", "osm-cables", "osm-lines", "wikidata", "emodnet-cables", "topology-zoo",
                   "ourairports", "geonames-cities"]
    assert len(set(ids)) == 8  # liminal-libs 1.73.0: the airports and the cities
    for said in cards.INFRASTRUCTURE:
        d = DataSet.of(said)  # https only, a licence and a credit, a size, a known format: else a ValueError
        assert d.address().startswith("https://") and d.host in {"overpass-api.de", "query.wikidata.org",
                                                                  "ows.emodnet-humanactivities.eu",
                                                                  "raw.githubusercontent.com",
                                                                  "davidmegginson.github.io", "download.geonames.org"}
        assert d.credit["text"] in d.licence or d.format == "sparql"  # the credit the licence asks for, in its words
        assert d.about == said["about"] and d.title == said["title"]  # said whole: none cut to fit
        f = form(d, tmp_path)
        words = f["confirm"]["words"]
        assert f["job"] is True and f["hook"] == "world_layer_get" and d.host in words and size_words(d.size) in words
        assert words.index(d.licence) < words.index("You are asked to accept it next")  # the licence first
        assert f["fields"][1] == {"name": "accept_licence", "type": "accept",
                                  "title": f"Accept its licence ({d.licence_name})?", "words": d.licence,
                                  "yes": "Accept it and download"}
        limit = re.match(r"\[out:json\]\[timeout:(\d+)\];", d.query)
        if d.format == "overpass":  # its own time limit waited for, and a margin
            assert limit and d.wait >= int(limit.group(1)) + 20
            assert d.query.count("out tags ") == d.query.count("out ")  # tags alone: no node ids, no metadata
        elif d.format == "sparql":
            assert d.wait > 60  # the query service stops a query at 60 s
    osm = [DataSet.of(d) for d in cards.INFRASTRUCTURE if d["format"] == "overpass"]
    assert {d.licence_name for d in osm} == {"ODbL 1.0"} and all(d.credit == cards.OSM_CREDIT for d in osm)
    assert "out tags center qt;" in ours("osm-datacentres")["query"]
    assert "out tags geom qt;" in ours("osm-lines")["query"]
    cables = ours("osm-cables")["query"]  # the tags of OpenStreetMap's Telecoms page
    for tags in ('["seamark:type"="cable_submarine"]["seamark:cable_submarine:category"~"^(fibre_optic|fiber_optic|'
                 'optical|telephone|telegraph|telefon|communication|telephone/fibre_optic)$"]',
                 '["communication"="line"]["location"="underwater"]', '["communication"="line"]["submarine"="yes"]',
                 'nwr["telecom"="cable_landing_station"];out tags center qt;'):
        assert tags in cables, tags
    # the lines on land most like backbones: none on power poles (power=minor_line: local distribution)
    land = ours("osm-lines")
    assert '["communication"="line"]["location"!="underwater"]["submarine"!="yes"][!"power"];' in land["query"]
    assert land["about"] == "about 13,000 ways, none on power poles; no country is complete"
    wfs = ours("emodnet-cables")["query"]  # longitude first, as GeoJSON, the six telecom layers and no power cable
    assert "srsName=EPSG:4326" in wfs and "outputFormat=application/json" in wfs and "pcables" not in wfs
    assert ("typeName=" + ",".join(cards.EMODNET_LAYERS)) in wfs and len(cards.EMODNET_LAYERS) == 6
    assert "no credit is required" in cards.CC0 and "Creative Commons Attribution 4.0" in cards.CC_BY
    assert "Open Database License 1.0" in cards.ODBL and "© OpenStreetMap contributors" in cards.ODBL
    sparql = ours("wikidata")["query"]  # the variables the library's reader reads, and the four kinds of place
    assert all(f"?{v}" in sparql for v in ("item", "itemLabel", "kind", "coord", "operatorLabel"))
    assert all(f"wd:{k}" in sparql for k in infrastructure.KINDS)
    # a data centre of every kind (colocation centres among them, through P279*); the other kinds as they are
    assert "{ VALUES ?kind { wd:Q671224 } ?item wdt:P31/wdt:P279* ?kind . }" in sparql
    assert "{ VALUES ?kind { wd:Q1433061 wd:Q1349167 wd:Q10379228 } ?item wdt:P31 ?kind . }" in sparql
    # the Topology Zoo's maps: its archive alone, its size as its host gave it, its licence and its credit
    zoo = DataSet.of(ours("topology-zoo"))
    assert (zoo.format, zoo.url, zoo.query, zoo.size, zoo.licence_name) == ("gml", cards.ZOO_GML, "", 348_613,
                                                                            "CC BY 4.0")
    assert zoo.address() == "https://raw.githubusercontent.com/mroughan/InternetTopologyZoo/main/gml.tar.gz"
    assert zoo.credit == cards.ZOO_CREDIT and zoo.credit["url"] == cards.ZOO_REPO and zoo.licence == cards.ZOO_LICENCE
    for words in ("Creative Commons Attribution 4.0", "logical links", "not the networks of today", "newest map"):
        assert words in cards.ZOO_LICENCE, words
    assert "about 2010-2011" in zoo.title and "logical links, not fibre" in zoo.about


def test_the_submarine_cables_are_asked_of_every_telecom_category_the_map_uses():
    """The user, 2026-11-19: "also underwater lines". A submarine cable's use is its seamark:cable_submarine:category:
    the OSM wiki names a fibre optic cable "optical", and the map spells it, and telephone's, other ways too (taginfo,
    2026-11-18: telephone 749, fibre_optic 366, fiber_optic 64, optical 5, telefon 2, telegraph, communication and
    telephone/fibre_optic 1 each: 1,189 in all, of which fibre_optic and telephone alone, as 0.7.0 first asked, are
    1,115). Every one of them is asked for, as a whole value, and no power, mooring or ferry cable, as the Linux
    firewall plugin asks them."""
    [categories] = re.findall(r'\["seamark:cable_submarine:category"~"([^"]+)"\]', ours("osm-cables")["query"])
    for value in ("optical", "fibre_optic", "fiber_optic", "telephone", "telefon", "telegraph", "communication",
                  "telephone/fibre_optic"):
        assert re.search(categories, value), value
    for value in ("power", "mooring", "ferry", "sensor", "disused", "optical_x", "non_optical", "transmission"):
        assert not re.search(categories, value), value  # whole values alone
    assert ours("osm-cables")["about"] == "about 1,200 cable ways and 60 landing stations"
    covered = {a.name: a for a in cards.OVERPASS_API.areas}["Tag queries"].covered
    assert "optical, fibre_optic and fiber_optic, telephone, telegraph" in covered  # the card says which
    assert "those on power poles (power=*) left out" in covered


def test_the_data_sets_are_pinned_as_the_linux_firewall_plugin_names_them():
    """The Linux firewall plugin names the same data sets, in the same order (its apis.INFRASTRUCTURE), and its tests
    pin the same digest. Kept alike by hand, the two drifted once (0.7.0 asked two of the eight telecom categories of a
    submarine cable, 0.9.0 all eight), so a change to them is made on purpose, to both plugins and to both pins."""
    said = json.dumps(cards.INFRASTRUCTURE, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    assert hashlib.sha256(said.encode("utf-8")).hexdigest() == INFRASTRUCTURE_SHA256


def test_what_each_source_answers_the_plugins_queries_is_read_into_the_layers_the_globe_draws():
    def layers(name, doc) -> dict:
        found = parse(ours(name), doc if isinstance(doc, bytes) else answer(doc))["layers"]
        return {layer: (len(v.get("points") or ()), len(v.get("lines") or ())) for layer, v in found.items()
                if v.get("points") or v.get("lines")}
    assert layers("osm-datacentres", SITES) == {"datacentres": (2, 0), "exchanges": (1, 0)}
    assert layers("osm-cables", CABLES) == {"cables": (0, 2), "landings": (1, 0)}
    assert layers("osm-lines", LINES) == {"lines": (0, 1)}
    assert layers("wikidata", PLACES) == {"exchanges": (1, 0), "stations": (1, 0)}
    assert layers("emodnet-cables", ROUTES) == {"cables": (0, 2)}
    assert layers("topology-zoo", zoo_archive({"gml/Geant2010.gml": GEANT})) == {"pops": (2, 0), "backbones": (0, 1)}
    [line] = parse(ours("topology-zoo"), zoo_archive({"gml/Geant2010.gml": GEANT}))["layers"]["backbones"]["lines"]
    assert line == ([(4.88969, 52.37403), (8.68333, 50.11667)], "GEANT, 2010: Amsterdam to Frankfurt")


# -- the tab as the platform asks it ---------------------------------------------------------------------------------
def test_the_tab_lists_the_listening_ports_and_the_connections_with_their_programs_over_a_windows_reading(table):
    fake = FakeWindows()
    fw = plugin(fake)
    page = fw.ask("netstat")  # as the platform asks it, every three seconds while the tab is shown
    try:
        assert table.reads == 1 and fake.scripts == []  # the socket tables, and no PowerShell
        assert page["title"] == "Netstat" and json.dumps(page, allow_nan=False)
        note = page["note"]
        assert note.startswith("This machine's socket table, read ") and "with no capture and no administrator" in note
        assert ("3 listening ports, 3 connections to 3 hosts (2 on the internet, 1 on the local network, 0 on this "
                "machine)") in note
        assert sockets.UDP_NOTE in note and netstat.INTERPRETER in note  # Windows' own words, and the interpreter's
        assert "Hosts are recorded only while this plugin's Netstat or World Wide Web tab is shown." in note
        flows = page["flows"]
        assert [c["key"] for c in flows["columns"]][:3] == ["program", "dir", "remote"]
        rows = {r["remote"]: r for r in flows["rows"]}
        assert list(rows) == [f"{WEB}:443", f"{PRINTER}:50500", f"{WEB2}:443"]  # the ones up first
        edge = rows[f"{WEB}:443"]
        assert (edge["program"], edge["dir"], edge["labels"], edge["state"]) == (
            "msedge.exe (pid 4321)", "out", [{"kind": "internet"}], "established")
        assert edge["local"] == f"{LAN}:51000" and edge["duration"] >= 120 and edge["since"]
        files = rows[f"{PRINTER}:50500"]  # file sharing, reached from the local network
        assert (files["program"], files["dir"], files["labels"]) == ("System (pid 4)", "in",
                                                                     [{"kind": "local network"}])
        assert sockets.SYSTEM in files["unread"]
        gone = rows[f"{WEB2}:443"]  # its owner has ended: said, and its name from the hosts file
        assert (gone["program"], gone["name"], gone["state"]) == (sockets.GONE, "cdn.example", "time-wait")
        listening, database, *_recorded = page["tables"]  # liminal-libs 1.68.0: Connections recorded last
        assert listening["title"] == "Listening ports" and [r[:3] for r in listening["rows"]] == [
            ["445", "tcp", "every address"], ["5353", "udp", "every address"],
            [{"text": "8775", "sub": "Liminal's platform page"}, "tcp", "this machine only"]]
        assert listening["rows"][1][3:5] == [{"text": "svchost.exe (pid 1200) · Dnscache (DNS Client)",
                                               "sub": sockets.REFUSED}, "Dnscache (DNS Client)"]
        assert database["title"] == "The hosts database"
        assert dict(r for r in database["rows"])["Kept in"] == str(hostbook.path())  # the test's own folder
        assert [f["id"] for f in page["forms"]] == ["hosts-recording", "hosts-forget"]
    finally:
        fw.detach()


def test_one_reading_is_shared_by_both_tabs_and_kept_in_the_hosts_database(table, tmp_path):
    fw = Watched(capture_factory=Feed, geo_folder=tmp_path / "geoip", clock=Clock(), wall=Clock(NOW))
    try:
        fw.ask("netstat")
        fw.ask("world")  # within the reading's 2.5 s: the same reading
        assert table.reads == 1
        facts = hostbook.book().describe()
        assert facts["path"] == str(hostbook.path()) and facts["rows"] >= 2 and facts["hosts"] >= 2
        assert hostbook.path().is_relative_to(tmp_path)  # this PC's data folder is never written by a test
    finally:
        fw.detach()


def test_the_globe_shows_the_hosts_recorded_filtered_by_program_port_direction_and_time(table, tmp_path):
    fw = Watched(capture_factory=Feed, geo_folder=tmp_path / "geoip", clock=Clock(), wall=Clock(NOW))
    try:
        fw.ask("netstat")  # a reading, kept in the hosts database
        assert fw.ask("world_show", "hosts") == {"said": "Hosts recorded · all of them", "ok": True}
        page = fw.ask("world")
        # liminal-libs 1.101.0 (its review): the hosts view keeps the GeoIP sources table, after the hosts
        assert [t["title"] for t in page["tables"]] == ["What the globe shows", "Programs", "Ports", "Hosts",
                                                        "GeoIP sources", "Internet infrastructure", *ROUTES_TABLE]
        first = page["tables"][0]
        assert [o["hook"] for o in first["options"]] == ["world_show", "world_direction", "world_within", "world_pick",
                                                         "world_pick"]
        assert page["globe"]["showing"] == "Hosts recorded · all of them" and "charts" not in page
        assert page["globe"]["kinds"] == ["allowed", "outbound"] and page["globe"]["local"]["hosts"] == 1
        said = fw.ask("world_pick", "program=msedge.exe")["said"]
        assert said == "Hosts recorded · msedge.exe"
        assert fw.ask("world_pick", "port=tcp/443")["said"] == "Hosts recorded · msedge.exe · port 443/tcp"
        assert fw.ask("world_direction", "out")["said"].endswith(" · out")
        assert fw.ask("world_within", "day")["said"].endswith(" · seen in the last 24 hours")
        hosts = fw.ask("world")["tables"][3]
        assert [r[:2] for r in hosts["rows"]] == [[WEB, "msedge.exe"]]
        for hook, value, words in (("world_show", "nothing", "the globe shows traffic or hosts"),
                                   ("world_pick", "everything", "a pick is program=<name>"),
                                   ("world_direction", "up", "a direction is in, out or neither"),
                                   ("world_within", "year", "seen within hour, day, week or month")):
            with pytest.raises(ValueError, match=re.escape(words)):
                fw.ask(hook, value)
        assert fw.ask("world_pick", "clear")["said"] == "Hosts recorded · all of them"
        assert fw.ask("world_show", "traffic")["said"] == "Traffic watched now"
    finally:
        fw.detach()


def test_a_data_set_is_downloaded_on_your_word_from_the_plugins_address_and_drawn_on_the_globe(table, tmp_path,
                                                                                                 monkeypatch):
    sites = DataSet.of(ours("osm-datacentres"))
    servers = Answers({sites.address(): answer(SITES)})
    monkeypatch.setattr(world, "fetch_url", servers)  # the data sets' servers: a stand-in
    fw = Watched(capture_factory=Feed, geo_folder=tmp_path / "geoip", clock=Clock(), wall=Clock(NOW))
    try:
        page = fw.ask("world")
        offered = {f["id"]: f for f in page["forms"]}
        assert {f"world-layer-{d['id']}" for d in cards.INFRASTRUCTURE} <= set(offered)
        lines: list[str] = []
        with pytest.raises(LicenceRefused) as refused:  # the licence first: the page's second confirmation
            fw.ask("world_layer_get", "osm-datacentres", False, log=lines.append)
        assert refused.value.accept == "accept_licence" and servers.asked == [] and lines == []
        with pytest.raises(ValueError, match="is not one of this plugin's data sets"):
            fw.ask("world_layer_get", "peeringdb", True, log=lines.append)
        out = fw.ask("world_layer_get", "osm-datacentres", True, log=lines.append)  # accepted, in so many words
        # one request, of the plugin's own address and query, waited for as the data set says, with the plugin's name
        # (and its version, where the platform's registry gives one) as its User-Agent: nothing of the user's
        assert servers.asked == [(f"{cards.OVERPASS}?data={quote(sites.query, safe='')}", sites.wait,
                                  "firewall-windows", "a data set")]
        assert out["ok"] is True and out["said"].startswith("installed Data centres: 3 features (")
        assert out["lines"][:3] == ["asked of overpass-api.de", f"kept in {infrastructure.folder()}, in place of any "
                                    "older copy", "credited on the globe as © OpenStreetMap contributors"]
        assert lines[0] == "asking overpass-api.de for Data centres"
        g = fw.ask("world")["globe"]
        drawn = {layer["id"]: layer for layer in g["layers"]}
        assert {k: v["count"] for k, v in drawn.items()} == {"exchanges": 1, "datacentres": 2}
        assert drawn["datacentres"]["credits"] == [cards.OSM_CREDIT] and g["layer_hook"] == "world_layer"
        part = fw.ask("world_layer", "datacentres")["parts"][0]
        assert (part["set"], part["credit"], part["points"]["n"]) == ("osm-datacentres", cards.OSM_CREDIT, 2)
        facts = fw.api_facts()[cards.OVERPASS_API.name]
        assert facts["Data centres"].startswith("3 features, fetched ") and len(facts) == 3
        assert facts["Submarine cables and landing stations"].startswith("not downloaded")
        assert fw.ask("world_layer_remove", "osm-datacentres")["said"] == "removed Data centres"
        assert fw.api_facts()[cards.OVERPASS_API.name]["Data centres"].startswith("not downloaded")
        assert len(servers.asked) == 1 and table.reads >= 1
    finally:
        fw.detach()


def test_the_backbones_are_downloaded_on_your_word_from_the_topology_zoos_file_and_drawn_on_the_globe(table, tmp_path,
                                                                                                        monkeypatch):
    """The user, 2026-11-19: "major network 'bones' need to be displayed on the map". The Topology Zoo's archive, asked
    once at its own address, its licence accepted first; drawn as the backbones (on at first) and their points of
    presence, credited to the Zoo; said under its card."""
    zoo = DataSet.of(ours("topology-zoo"))
    servers = Answers({cards.ZOO_GML: zoo_archive({"gml/Geant2010.gml": GEANT})})
    monkeypatch.setattr(world, "fetch_url", servers)  # GitHub's raw files: a stand-in
    fw = Watched(capture_factory=Feed, geo_folder=tmp_path / "geoip", clock=Clock(), wall=Clock(NOW))
    try:
        with pytest.raises(LicenceRefused):
            fw.ask("world_layer_get", "topology-zoo", False)
        assert servers.asked == []
        lines: list[str] = []
        out = fw.ask("world_layer_get", "topology-zoo", True, log=lines.append)
        assert servers.asked == [(cards.ZOO_GML, zoo.wait, "firewall-windows", "a data set")]  # the file, alone
        assert out["ok"] is True and out["said"].startswith("installed Backbone networks, about 2010-2011: 3 features")
        assert out["lines"][2] == f"credited on the globe as {cards.ZOO_CREDIT['text']}"
        assert lines[-1] == "1 map in the answer: 1 network drawn, each from its newest map"
        drawn = {layer["id"]: layer for layer in fw.ask("world")["globe"]["layers"]}
        assert {k: (v["count"], v["on"]) for k, v in drawn.items()} == {"pops": (2, False), "backbones": (1, True)}
        assert drawn["backbones"]["credits"] == [cards.ZOO_CREDIT]
        [part] = fw.ask("world_layer", "backbones")["parts"]
        assert part["set"] == "topology-zoo" and part["lines"]["names"] == ["GEANT, 2010: Amsterdam to Frankfurt"]
        facts = fw.api_facts()[cards.TOPOLOGY_ZOO.name]["Backbone networks, about 2010-2011"]
        assert facts.startswith("3 features, fetched ")
    finally:
        fw.detach()


# -- what the tab reaches, on the plugin's cards -----------------------------------------------------------------------
def test_the_socket_tables_card_names_every_call_the_librarys_windows_reading_makes():
    card = cards.SOCKETS
    assert {c.name for c in card.used} == set(sockets.WINDOWS_CALLS) and len(card.used) == len(sockets.WINDOWS_CALLS)
    reader = inspect.getsource(sockets) + inspect.getsource(resources.WindowsProbe)  # the snapshot is the probe's
    assert all(re.search(rf"\b{name}\b", reader) for name in sockets.WINDOWS_CALLS)
    assert set(sockets.OWNER_CALLS.values()) <= {c.name for c in card.used}
    assert not {c.name for c in card.calls if not c.used} & set(sockets.WINDOWS_CALLS)  # what it does not call
    assert all(c.docs.startswith("https://learn.microsoft.com/en-us/windows/win32/api/") for c in card.used)
    # the tables' own classes and the one access a process is opened with, as the library asks them
    assert (sockets.TCP_OWNER_MODULE_ALL, sockets.UDP_OWNER_MODULE, sockets.QUERY_LIMITED) == (8, 2, 0x1000)
    named = {c.name: c for c in card.calls}
    assert "TCP_TABLE_OWNER_MODULE_ALL" in named["GetExtendedTcpTable"].about
    assert "UDP_TABLE_OWNER_MODULE" in named["GetExtendedUdpTable"].about
    assert "PROCESS_QUERY_LIMITED_INFORMATION" in named["OpenProcess"].about
    assert named["SetPerTcpConnectionEStats"].writes and not named["SetPerTcpConnectionEStats"].used  # an admin's
    assert card.kind == "system" and "no administrator is asked" in card.about and "never asked for" in card.auth


def test_the_data_sets_cards_name_the_one_request_each_makes_of_its_source():
    for card, base, kind in ((cards.OVERPASS_API, cards.OVERPASS, "overpass"), (cards.WIKIDATA, cards.WDQS, "sparql"),
                             (cards.EMODNET, cards.EMODNET_WFS, "geojson"), (cards.TOPOLOGY_ZOO, cards.ZOO_GML, "gml")):
        sets = [DataSet.of(d) for d in cards.INFRASTRUCTURE if d["format"] == kind]
        assert sets and card.base == base and all(d.url == base for d in sets)
        assert card.kind == ("feed" if kind == "gml" else "query")  # a file of the repository's, or a query service
        [get] = card.used  # one GET a data set, on a click
        assert get.name.startswith(f"GET {base}") and "on the World Wide Web tab's Internet infrastructure" in get.used
        for d in sets:
            address = d.address()
            if kind == "overpass":
                assert get.name == f"GET {base}?data=<query>" and address == f"{base}?data={quote(d.query, safe='')}"
            elif kind == "sparql":
                assert get.name == f"GET {base}?format=json&query=<query>"
                assert address == f"{base}?format=json&query={quote(d.query, safe='')}"
            elif kind == "geojson":
                assert get.name == "GET " + address.replace(",".join(cards.EMODNET_LAYERS), "<the six layers>")
            else:  # the archive alone: no query
                assert get.name == f"GET {base}" == f"GET {address}" and "raw.githubusercontent.com alone" in get.used
        assert card.link("terms") and card.verified == (cards.VERIFIED_GLOBE if kind == "gml" else
                                                        cards.VERIFIED_NETSTAT)
    assert cards.TOPOLOGY_ZOO.link("terms") == cards.ZOO_RAW + "LICENSE"  # the repository's own licence, CC BY 4.0
    assert cards.VERIFIED_GLOBE == "2026-11-19"
    assert "contact" in cards.WIKIDATA.limits and "403" in cards.WIKIDATA.limits  # its User-Agent policy, said
    assert "10,000 queries and 1 GB a day" in cards.OVERPASS_API.limits  # the public server's usage policy


# -- what they know, on the cards, asking nothing ----------------------------------------------------------------------
def test_its_facts_say_the_last_reading_the_recording_the_hosts_database_and_each_data_set_asking_nothing(table):
    fw = plugin(FakeWindows())
    assert cards.SOCKETS.name not in fw.api_facts() and fw.netstat_view(make=False) is None  # no view made for it
    try:
        fw.ask("netstat")
        reads = table.reads
        facts = fw.api_facts()
        assert table.reads == reads  # asking for the facts read nothing
        sockets_facts = facts[cards.SOCKETS.name]
        assert re.fullmatch(r"\w{3} \d\d \d\d:\d\d:\d\d: 6 sockets in 4 ms", sockets_facts["Last reading"])
        assert sockets_facts["Recording"] == "only while this plugin's Netstat or World Wide Web tab is shown"
        assert re.match(r"\d+ rows \(\d+ hosts?, \d+ programs?\), ", sockets_facts["Hosts database"])
        assert str(hostbook.path()) in sockets_facts["Hosts database"]
        assert facts[cards.OVERPASS_API.name] == {d["title"]: (
            "not downloaded: the World Wide Web tab's Internet infrastructure table offers it, its size and licence "
            "said first") for d in cards.INFRASTRUCTURE if d["format"] == "overpass"}
        assert list(facts[cards.WIKIDATA.name]) == ["Exchange points, ground stations and teleports"]
        assert list(facts[cards.EMODNET.name]) == ["Telecom cable routes in European waters"]
        assert facts[cards.TOPOLOGY_ZOO.name] == {"Backbone networks, about 2010-2011": (
            "not downloaded: the World Wide Web tab's Internet infrastructure table offers it, its size and licence "
            "said first")}
    finally:
        fw.detach()
    assert cards.SOCKETS.name not in fw.api_facts()  # detached: the view is gone, and its facts with it


def test_recording_all_the_time_is_said_on_the_card_and_ends_when_the_plugin_is_detached(table):
    fw = plugin(FakeWindows())
    fw.attach(object(), Keeping(LIMINAL_HOSTS_RECORDING="always"))  # the user chose always, through the login
    try:
        view = fw.netstat_view(make=False)
        assert view is not None and wait_for(view.recording) and wait_for(lambda: table.reads >= 1)
        assert fw.api_facts()[cards.SOCKETS.name]["Recording"] == ("all the time the platform runs: recording now, a "
                                                                    "reading every 5 s")
    finally:
        fw.detach()
    assert not view.recording() and not [t for t in threading.enumerate() if t.name == "firewall-windows-hosts"]


def test_its_facts_write_counts_as_the_tabs_do_and_say_a_reading_not_taken_yet_as_the_recording_takes_one():
    """Thousands as the Netstat tab writes them (1,204 hosts, never 1204 beside 12,345 rows), and a first reading
    said as recording takes it: at the tabs' asks, or every 5 s all the time the platform runs."""
    now = time.time()
    said = {"reading": None, "mode": "always", "recording": True, "error": "",
            "book": {"path": "hosts.db", "rows": 12_345, "hosts": 1_204, "programs": 1_041, "since": now - 3 * 86400,
                     "bytes": 2_500_000, "elsewhere": "", "problem": ""},
            "sets": [{"id": "osm-datacentres", "title": "Data centres", "format": "overpass", "installed": True,
                      "features": 5_073, "fetched": "2026-11-18T10:00:00+00:00", "bytes": 1_500_000, "dropped": 1_200}]}

    class View:  # the base's NetstatView as describe() answers, asking nothing
        def describe(self) -> dict:
            return dict(said)

    class Described(WindowsFirewallPlugin):
        def netstat_view(self, make=True):
            return View()
    fw = Described(PowerShell(runner=FakeWindows(), env={}), elevated=lambda: True)

    def facts() -> tuple[dict, dict]:
        out = fw._netstat_facts()
        return out[cards.SOCKETS.name], out[cards.OVERPASS_API.name]
    mine, sites = facts()
    assert mine["Hosts database"].startswith("12,345 rows (1,204 hosts, 1,041 programs), ")
    assert sites["Data centres"].startswith("5,073 features, fetched 2026-11-18 (") and sites["Data centres"].endswith(
        "; 1,200 left out")
    assert mine["Last reading"] == "none yet: the socket tables are read every 5 s, all the time the platform runs"
    said["recording"] = False  # always, but not recording now (a one-shot app; a folder of another system's drive)
    assert facts()[0]["Last reading"] == ("none yet: the socket tables are read only while this plugin's Netstat or "
                                          "World Wide Web tab is shown")
    said.update(mode="shown", reading={"at": now, "rows": 1_234, "took": 0.0042, "system": "windows"})
    assert facts()[0]["Last reading"].endswith(": 1,234 sockets in 4 ms")


# -- not for any machine but Windows (B-critique S1) -------------------------------------------------------------------
# a plausible ask of every hook of the Netstat tab, the hosts database and the globe's filters and layers but the tab's
# own page, as the platform's page, a POST to /api/machines/firewall-windows/ask or another plugin through the platform
# (app.ask) could send it to a plugin that is not valid here
ASKS = {"hosts_recording": ("always",), "hosts_forget": (True,), "world_show": ("hosts",), "world_direction": ("out",),
        "world_within": ("day",), "world_pick": ("port=tcp/443",), "world_layer": ("datacentres",),
        "world_layer_get": ("osm-datacentres", True), "world_layer_remove": ("osm-datacentres",)}


@pytest.mark.parametrize("system, called", [("linux", "Linux"), ("darwin", "macOS")])
def test_off_windows_no_view_is_made_and_every_hook_of_its_tabs_reads_records_keeps_and_removes_nothing(
        system, called, table, no_real_hosts):
    """Off Windows the Netstat tab says so and every other hook of the two tabs is refused in words before it reads the
    socket table, keeps a setting through the login, starts the recording, forgets a host or removes a layer: the hosts
    database and the layers' folder there are this system's own firewall plugin's (firewall-linux's, under Linux), so
    none of theirs is touched. Its status, reads and changes off Windows, on any library: test_plugin.py."""
    mine = plugin(FakeWindows())  # what a firewall plugin of this machine left there: hosts recorded and a layer
    mine.ask("netstat")
    mine.detach()
    recorded = hostbook.book().hosts()
    layer = infrastructure.folder() / "osm-datacentres.json"
    layer.parent.mkdir(parents=True, exist_ok=True)
    layer.write_text("{}", encoding="utf-8")
    reads, login, fake = table.reads, Keeping(LIMINAL_HOSTS_RECORDING="always"), FakeWindows()
    fw = WindowsFirewallPlugin(PowerShell(runner=fake, env={}), elevated=lambda: True, system=system)
    why = f"Windows Defender Firewall is Windows' own, and this machine runs {called}"
    fw.attach(object(), login)  # recording all the time, were it for here
    try:
        assert fw.netstat_view(make=False) is None  # no view made, no recording started beside the Linux firewall's
        assert fw.ask("netstat") == {"title": "Netstat", "note": f"Not for this machine: {why}. Nothing is read here."}
        assert set(ASKS) == set(netstat.HOOKS) - {"netstat"}  # every one of the base's (a new one needs an ask here)
        for hook, args in ASKS.items():
            with pytest.raises(ValueError, match="not for this machine") as refused:  # a refusal (400), in words
                fw.ask(hook, *args)
            assert why in str(refused.value), hook
        assert fw.netstat_view(make=False) is None and fw.api_facts() == {}  # still none: nothing read or said
        assert login.saved == [] and login.values == {pair_name("LIMINAL_HOSTS_RECORDING"): "always"}  # nothing kept
        assert not [t for t in threading.enumerate() if t.name.endswith(THREADS)]  # no recording, no download
        assert table.reads == reads and recorded and hostbook.book().hosts() == recorded  # none read, none forgotten
        assert layer.read_text(encoding="utf-8") == "{}"  # the layer of this system's own plugin, not removed
        assert fake.scripts == [] and no_real_hosts == []
    finally:
        fw.detach()


# -- the suite's guard (B-critique B1) ---------------------------------------------------------------------------------
def test_a_plugin_attached_under_a_login_that_says_always_starts_nothing_real(no_real_hosts, tmp_path):
    """The platform's own login reads this user's saved variables under the process's: here they say
    LIMINAL_HOSTS_RECORDING=always (what the Recording form keeps on Windows). The guard's "shown" in the test's process
    wins, so nothing records; the socket table the plugin's own view reads is the guard's refusal, and the hosts
    database and the layers are in the test's own folder."""
    saved = {"LIMINAL_HOSTS_RECORDING": "always"}
    fw = plugin(FakeWindows())
    fw.attach(object(), EnvironmentLogin(saved=lambda: dict(saved)))
    try:
        view = fw.netstat_view(make=False)
        assert view is not None and view.mode() == "shown" and not view.recording()
        assert not [t for t in threading.enumerate() if t.name.endswith("-hosts")]
        assert os.environ[hostbook.VARIABLE] == "shown"
        assert hostbook.path().is_relative_to(tmp_path) and infrastructure.folder().is_relative_to(tmp_path)
        with pytest.raises(Reached, match="socket table for real"):
            fw.ask("netstat")  # the plugin's own view, with the library's reader: the guard's refusal
        assert no_real_hosts == ["sockets.read ()"]
        no_real_hosts.clear()  # (read on purpose: the guard's own check at the end stays quiet)
        assert not hostbook.path().exists()  # nothing was kept
    finally:
        fw.detach()
