"""The World Wide Web tab (0.6.0; the user, 2026-11-14: "so for the firewall's both are going to get a 'world wide web
view' that shows the globe and the routes incoming all traffic, as well as monitoring port traffic stats"): the library's
Firewall base's tab (liminal-libs 1.55.0, machines/world.py) with what this plugin names for it (apis.py), asked through
the plugin as the platform asks it. Watching starts with the tab's ask and stops by itself after the viewing timeout, and
on detach. The GeoIP file is DB-IP's IP to City Lite at its monthly address (last month's while this month's is not
out), downloaded only once its licence is accepted, its places then credited to DB-IP. Home is the place set through
the login, else this network's public address as the plugin's name servers give it, placed by the file. The tab's cards
name what it reaches, and its facts say what it knows, asking nothing.

Nothing is captured, nothing is downloaded, no name server is asked and no process is started: the capture, the
download and the lookup are stand-ins, the GeoIP file is a tiny one written here, and the real ones fail the test if
reached. Npcap installed for administrators only (review F1) is a stand-in registry's option, and Npcap a stand-in
that loads nothing: this PC's Npcap option is never read."""
from __future__ import annotations

import contextlib
import gzip
import inspect
import io
import ipaddress
import os
import re
import struct
import subprocess
import sys
import threading
import time
import types
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone

import pytest

from liminal_libs import capture, dns, geo, netpath
from liminal_libs.apps.authorization import EnvironmentLogin
from liminal_libs.apps.tabs import Tab
from liminal_libs.capture import ACK, PSH, SYN, CaptureError, Packet
from liminal_libs.machines import world
from liminal_libs.machines.firewall import Firewall
from liminal_libs.machines.windows import PowerShell
from liminal_libs.machines.world import READ_S, LicenceRefused, WorldView
from liminal_libs.sources.apis import problems
from liminal_libs.traffic import TrafficBook
from plugin_platform_firewall_windows import MACHINE, WindowsFirewallPlugin
from plugin_platform_firewall_windows import apis as cards
from test_plugin import FakeWindows

# CI installs maxminddb (liminal-libs[geo]): there the placing tests run, and fail rather than skip without it
needs_reader = pytest.mark.skipif(not geo.available()[0] and not os.environ.get("CI"), reason="maxminddb is not installed here")

LAN = "192.168.1.20"  # this PC's address on its way out, as the stand-in capture says it
OWN = capture.own_addresses([LAN])
LONDON, CHANGCHUN, ROUTER = "81.2.69.142", "175.16.199.5", "192.168.1.1"
PUBLIC = "8.8.8.8"  # this network's public address, as the stand-in name server gives it
NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc).timestamp()
NOVEMBER = "https://download.db-ip.com/free/dbip-city-lite-2026-11.mmdb.gz"  # as DB-IP's download page gives it
OCTOBER = "https://download.db-ip.com/free/dbip-city-lite-2026-10.mmdb.gz"
BUILT_NOVEMBER = int(datetime(2026, 11, 1, 7, 41, tzinfo=timezone.utc).timestamp())
BUILT_OCTOBER = int(datetime(2026, 10, 1, 7, 41, tzinfo=timezone.utc).timestamp())
NPCAP_ADMIN_ONLY = capture.npcap_admin_only  # the library's own: reached only through a stand-in registry (admin_only)


# -- a tiny GeoIP file in the MaxMind DB format (2.0), as liminal-libs tests/test_geo.py writes one -------------------------
def control(kind: int, size: int) -> bytes:
    """A value's control byte: its type in the top 3 bits (0 for an extended type, whose number - 7 is the next byte),
    its size in the low 5 (29, 30 and 31: the size is in one, two or three more bytes)."""
    first, extended = (kind << 5, b"") if kind <= 7 else (0, bytes([kind - 7]))
    if size < 29:
        return bytes([first | size]) + extended
    if size < 285:
        return bytes([first | 29]) + extended + bytes([size - 29])
    if size < 65821:
        return bytes([first | 30]) + extended + (size - 285).to_bytes(2, "big")
    return bytes([first | 31]) + extended + (size - 65821).to_bytes(3, "big")


def encode(value) -> bytes:
    """One value of the data section: a typed unsigned integer (kind, n), a map, an array, a string, a double, an
    unsigned integer or a boolean."""
    if isinstance(value, tuple):
        kind, n = value
        width = (n.bit_length() + 7) // 8
        return control(kind, width) + n.to_bytes(width, "big")
    if isinstance(value, bool):
        return control(14, int(value))
    if isinstance(value, int):
        return encode((6, value))
    if isinstance(value, float):
        return control(3, 8) + struct.pack(">d", value)
    if isinstance(value, str):
        data = value.encode("utf-8")
        return control(2, len(data)) + data
    if isinstance(value, dict):
        return control(7, len(value)) + b"".join(encode(str(k)) + encode(v) for k, v in value.items())
    if isinstance(value, list):
        return control(11, len(value)) + b"".join(encode(v) for v in value)
    raise TypeError(value)


def mmdb(networks, built: int = BUILT_NOVEMBER) -> bytes:
    """A MaxMind DB file of `networks` ([(an IPv4 network, its record)]) of DB-IP's kind: a binary tree over the
    addresses' bits with 24-bit records (IPv4 under ::/96 in an IPv6 tree), 16 zero bytes, the records, then the
    metadata after its marker."""
    data, offsets, root = b"", {}, [None, None]
    for cidr, record in networks:
        net = ipaddress.ip_network(cidr)
        value, length = int(net.network_address), net.prefixlen + 96
        blob = encode(record)
        if blob not in offsets:
            offsets[blob], data = len(data), data + blob
        node = root
        for i in range(length):
            bit = (value >> (127 - i)) & 1
            if i == length - 1:
                node[bit] = ("data", offsets[blob])
            else:
                if not isinstance(node[bit], list):
                    node[bit] = [node[bit], node[bit]]
                node = node[bit]
    nodes, queue, number = [], [root], {}
    while queue:  # numbered breadth first: the root is node 0
        node = queue.pop(0)
        number[id(node)] = len(nodes)
        nodes.append(node)
        queue += [child for child in node if isinstance(child, list)]
    count = len(nodes)

    def record(child) -> int:  # a node's number; node_count for nothing; past it, 16 + the record's place in the data
        if child is None:
            return count
        return number[id(child)] if isinstance(child, list) else count + 16 + child[1]

    tree = b"".join(record(left).to_bytes(3, "big") + record(right).to_bytes(3, "big") for left, right in nodes)
    metadata = {"binary_format_major_version": (5, 2), "binary_format_minor_version": (5, 0), "build_epoch": (9, built),
                "database_type": "DBIP-City-Lite", "description": {"en": "written by test_world.py"},
                "ip_version": (5, 6), "languages": ["en"], "node_count": (6, count), "record_size": (5, 24)}
    return tree + bytes(16) + data + b"\xab\xcd\xefMaxMind.com" + encode(metadata)


def city(iso: str, country: str, name: str, lat: float, lon: float) -> dict:
    """A record as DB-IP's IP to City Lite holds one (its MMDB format page's paths)."""
    return {"city": {"names": {"en": name}}, "continent": {"code": "EU", "geoname_id": 1, "names": {"en": "a continent"}},
            "country": {"geoname_id": 2, "is_in_european_union": False, "iso_code": iso, "names": {"en": country}},
            "location": {"latitude": lat, "longitude": lon}, "subdivisions": [{"names": {"en": "a province"}}]}


PLACES = [("81.2.69.0/24", city("GB", "United Kingdom", "London", 51.5142, -0.0931)),
          ("175.16.199.0/24", city("CN", "China", "Changchun", 43.88, 125.3228)),
          ("8.8.8.0/24", city("US", "United States", "Mountain View", 37.386, -122.0838))]


# -- stand-ins --------------------------------------------------------------------------------------------------------------
def pk(at, src, sport, dst, dport, flags=0, proto="tcp", length=60) -> Packet:
    """A packet as the capture hands it, its direction judged against this PC's address."""
    return Packet(at, src, sport, dst, dport, flags, 0, proto, length, capture.judge(src, dst, OWN))


def traffic() -> list[Packet]:
    """What the adapter saw: London reaching the platform's page port, answered, with data; Changchun trying 3389 twice,
    never answered; a question to the router and its answer (the local network's, never placed)."""
    return [pk(10.0, LONDON, 51000, LAN, 8775, SYN, length=74), pk(10.1, LAN, 8775, LONDON, 51000, SYN | ACK, length=74),
            pk(10.2, LONDON, 51000, LAN, 8775, PSH | ACK, length=566),
            pk(10.3, LAN, 8775, LONDON, 51000, PSH | ACK, length=1466),
            pk(11.0, CHANGCHUN, 40001, LAN, 3389, SYN), pk(11.5, CHANGCHUN, 40002, LAN, 3389, SYN),
            pk(15.0, LAN, 53000, ROUTER, 53, proto="udp", length=80), pk(15.05, ROUTER, 53, LAN, 53000, proto="udp", length=120)]


class Clock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


class Feed:
    """The capture as a stand-in, pulled as a Watcher pulls one: opened (or refusing to open, in Npcap's words), its
    packets handed, then nothing yet; closed."""

    def __init__(self, packets=(), address=LAN, fail_open=None):
        self.packets, self.address, self.fail_open = deque(packets), address, fail_open
        self.opened = self.closed = 0

    def open(self):
        if self.fail_open:
            raise CaptureError(self.fail_open)
        self.opened += 1

    def next(self):
        return self.packets.popleft() if self.packets else None

    def close(self):
        self.closed += 1


class Downloads:
    """DB-IP's downloads as a stand-in: each address asked for, and what it gives (bytes; any other address a 404)."""

    def __init__(self, answers):
        self.answers, self.asked = dict(answers), []

    def __call__(self, url, timeout):
        self.asked.append((url, timeout))
        if url not in self.answers:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        return io.BytesIO(self.answers[url])


class Watched(WindowsFirewallPlugin):
    """The plugin over a stand-in powershell.exe, its World Wide Web tab watching through the test's stand-ins (as the
    library has a plugin's tests do it: make_world_view); `made` counts the views it made."""

    def __init__(self, **stand_ins):
        super().__init__(PowerShell(runner=FakeWindows(), env={}), elevated=lambda: True, clock=lambda: 1_800_000_000.0)
        stand_ins.setdefault("resolve", lambda version, servers: (None, "no name server answers in a test"))
        self.stand_ins, self.made = stand_ins, 0

    def make_world_view(self) -> WorldView:
        self.made += 1
        return WorldView(self.name, **self.stand_ins)


def wait_for(condition, seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.005)
    return condition()


def watching() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name == "traffic-watcher"]


@pytest.fixture(autouse=True)
def _nothing_real(monkeypatch, tmp_path):
    """Nothing real is reached: no Npcap loaded, nor its option read from this PC's registry, no route asked, no name
    server, no download, no process started, not this PC's data folder (each reach is noted, so one inside a thread is
    seen too). Each WorldView a test makes is stopped after it, and no watching thread is left."""
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
    made: list[WorldView] = []
    init = WorldView.__init__

    def tracked(self, *args, **kwargs):
        init(self, *args, **kwargs)
        made.append(self)
    monkeypatch.setattr(WorldView, "__init__", tracked)
    yield made
    for view in made:
        view.stop()
    assert wait_for(lambda: watching() == []), "a watching thread was left"
    assert wait_for(lambda: not [t for t in threading.enumerate() if t.name.endswith("-public-address")])
    assert reached == []


@pytest.fixture
def geo_folder(tmp_path):
    """The data folder's geoip/ with this month's file in it, as the tab's install leaves it."""
    folder = tmp_path / "geoip"
    folder.mkdir()
    (folder / "dbip-city-lite-2026-11.mmdb").write_bytes(mmdb(PLACES))
    return folder


# -- what the plugin names for the tab -----------------------------------------------------------------------------------------
def test_the_tab_is_the_firewall_bases_with_db_ips_file_its_credit_and_the_name_servers():
    assert MACHINE.TABS == Firewall.TABS == (Tab("world", "World Wide Web", "world", 2.0),)  # asked every 2 s while shown
    hooks = MACHINE.interface()["hooks"]
    # the install is run by the platform as a job, its log the job's panel (the base's JOB_HOOKS, kept by the plugin)
    assert hooks["world"].startswith("() ") and hooks["world_geoip"].startswith("(accept_licence=False, log=None) ")
    assert MACHINE.JOB_HOOKS == Firewall.JOB_HOOKS == ("world_geoip",) and set(MACHINE.JOB_HOOKS) <= set(hooks)
    assert {"refresh", "set_profile", "set_network", "allow", "move_rules"} <= set(hooks)  # its own and the base's, as before
    # home on the globe, set on the plugin's page and kept through the login: the base's one setting
    assert MACHINE.keys == Firewall.keys and [(k.name, k.secret) for k in MACHINE.keys] == [("LIMINAL_HOME_PLACE", False)]
    assert MACHINE.WORLD_TIMEOUT == 20.0
    # DB-IP's IP to City Lite at its monthly address, the library filling in the month
    assert MACHINE.GEOIP_URL == cards.CITY_LITE and world.month_url(MACHINE.GEOIP_URL, 2026, 11) == NOVEMBER
    assert world.file_stem(NOVEMBER, 2026, 11) == "dbip-city-lite-2026-11"
    for words in ("Creative Commons Attribution 4.0", "(CC BY 4.0", "creativecommons.org/licenses/by/4.0",
                  "\"IP Geolocation by DB-IP\"", "no warranty", "about 60 MB", "each month"):
        assert words in MACHINE.GEOIP_LICENCE, words  # the licence in plain words, and the download's size
    assert MACHINE.ATTRIBUTION == {"text": "IP Geolocation by DB-IP", "url": "https://db-ip.com"}  # DB-IP's own link
    # the name servers for this network's public address: the hw-stats plugin's, OpenDNS's before Google's, by IP version,
    # each name sent absolute (a trailing dot: none of this PC's DNS search suffixes goes with it)
    assert world.servers_of(MACHINE.PUBLIC_DNS, 4) == (("myip.opendns.com.", "a", "208.67.222.222", "OpenDNS"),
                                                       ("o-o.myaddr.l.google.com.", "txt", "216.239.32.10", "Google"))
    assert world.servers_of(MACHINE.PUBLIC_DNS, 6) == (("myip.opendns.com.", "aaaa", "2620:119:35::35", "OpenDNS"),
                                                       ("o-o.myaddr.l.google.com.", "txt", "2001:4860:4802:32::a", "Google"))


# -- the tab as the platform asks it ------------------------------------------------------------------------------------------
def test_the_tab_watches_this_pcs_adapter_while_it_is_asked_and_stops_by_itself(tmp_path):
    clock, feeds = Clock(), []

    def factory():
        feeds.append(Feed(traffic()))
        return feeds[-1]
    fw = Watched(capture_factory=factory, geo_folder=tmp_path / "geoip", clock=clock, wall=Clock(NOW),
                 book=TrafficBook(clock=lambda: 50.0))
    assert feeds == [] and watching() == [] and fw.made == 0  # nothing watched before the tab is asked
    page = fw.ask("world")  # as the platform asks it, every two seconds while the tab is shown
    view = fw.world_view()
    assert view.running and len(feeds) == 1 and feeds[0].opened == 1 and len(watching()) == 1 and fw.made == 1
    assert page["title"] == "World Wide Web"
    assert "Watching every packet at this machine's network adapter (192.168.1.20)" in page["note"]
    assert "no address is sent anywhere" in page["note"]
    assert wait_for(lambda: view.watcher.status()["packets"] == 8)
    page = fw.ask("world")
    g = page["globe"]
    by = {o["id"]: o for o in g["origins"]}
    assert list(by) == ["175.16.199.0/24", "81.2.69.0/24"]  # the most connections first; the router never placed
    assert (by["175.16.199.0/24"]["kind"], by["175.16.199.0/24"]["count"], by["175.16.199.0/24"]["ports"]) == (
        "unanswered", 2, [3389])
    assert (by["81.2.69.0/24"]["kind"], by["81.2.69.0/24"]["count"], by["81.2.69.0/24"]["ports"]) == ("allowed", 1, [8775])
    assert all(o["lat"] is None for o in g["origins"]) and g["local"]["places"] == 1  # no GeoIP file: nothing placed yet
    assert g["attribution"] is None  # nothing placed: nothing to credit yet
    assert [t["title"] for t in page["tables"]] == ["Busiest ports here", "Places", "Ports elsewhere"]
    assert page["tables"][0]["rows"][0][0] == "8775/tcp" and page["watching"]["address"] == LAN
    # nobody looks for longer than the timeout: watching stops by itself, and what was counted stays
    clock.t += 21
    assert wait_for(lambda: not view.running) and wait_for(lambda: watching() == []) and feeds[0].closed == 1
    assert view.page()["globe"]["origins"][0]["id"] == "175.16.199.0/24"
    fw.ask("world")  # looked at again: a capture of its own, on the same view
    assert view.running and len(feeds) == 2 and fw.made == 1
    fw.detach()
    assert not view.running and feeds[1].closed == 1 and watching() == []


@needs_reader
def test_without_a_geoip_file_db_ips_is_offered_its_licence_in_both_confirmations(tmp_path):
    folder = tmp_path / "geoip"
    fw = Watched(capture_factory=Feed, geo_folder=folder, clock=Clock(), wall=Clock(NOW))
    page = fw.ask("world")
    assert "No GeoIP file is installed" in page["globe"]["note"]
    # the form's own confirmation says what comes from where, with the licence first; the accept field's words are the
    # licence again, in the second confirmation the platform's page asks once the hook refuses
    [form] = page["forms"]
    assert (form["id"], form["hook"], form["title"]) == ("world-geoip", "world_geoip", "Install the GeoIP file")
    assert form["hook"] in fw.interface()["hooks"]
    [field] = form["fields"]
    assert (field["name"], field["type"], field["words"]) == ("accept_licence", "accept", MACHINE.GEOIP_LICENCE)
    words = form["confirm"]["words"]
    assert "downloaded from download.db-ip.com" in words and MACHINE.GEOIP_LICENCE in words and str(folder) in words
    assert words.index(MACHINE.GEOIP_LICENCE) < words.index("You are asked to accept it next")
    assert page["actions"] == [{"form": "world-geoip", "title": "Install the GeoIP file…",
                                "note": "Downloads it once you accept its licence"}]
    fw.detach()


def test_a_capture_that_cannot_run_says_why_and_how_never_asking_for_a_password(tmp_path):
    words = "Npcap is not installed (npcap.com; Wireshark installs it): packets cannot be watched"
    fw = Watched(capture_factory=lambda: Feed(fail_open=words), geo_folder=tmp_path, clock=Clock(), wall=Clock(NOW))
    note = fw.ask("world")["note"]
    assert note.startswith(f"Traffic cannot be watched here: {words}. {world.capture_help(words)}")
    assert "password" not in note.lower() and watching() == []
    assert fw.api_facts()[cards.NPCAP.name]["Watching"] == f"no: {words}"  # the card says it too


# -- Npcap installed for administrators only (review F1) ---------------------------------------------------------------------
STAND_IN_NPCAP = "Npcap is a stand-in here: nothing is loaded in a test"


class Registry:
    """winreg as a stand-in (as liminal-libs tests/test_capture_world.py has one): each key opened, with the access asked,
    and each value read, from `values` ({(key, name): value}); a missing one as winreg says it. Nothing of this PC's
    registry is read, and nothing is written."""

    HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY = 0x80000002, 0x20019, 0x0100
    KEY_SET_VALUE, KEY_CREATE_SUB_KEY = 0x0002, 0x0004

    def __init__(self, values):
        self.values, self.opened, self.read = dict(values), [], []

    def OpenKey(self, root, path, reserved=0, access=0x20019):  # noqa: N802 - winreg's own name
        self.opened.append((root, path, access))
        if not any(key == path for key, _ in self.values):
            raise FileNotFoundError(2, "The system cannot find the file specified")
        return contextlib.nullcontext(path)

    def QueryValueEx(self, key, name):  # noqa: N802
        self.read.append((key, name))
        if (key, name) not in self.values:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        return self.values[(key, name)], 4  # REG_DWORD


@pytest.fixture
def admin_only(monkeypatch):
    """Npcap installed for administrators only: its AdminOnly option ticked, in a stand-in registry, on a Windows the
    suite need not be running on; the platform no administrator, as its logon task runs it; this PC's way out at LAN.
    Npcap itself is a stand-in that notes each load, whether the platform was an administrator then, and loads nothing."""
    registry = Registry({(capture.NPCAP_OPTIONS, "AdminOnly"): 1})
    monkeypatch.setitem(sys.modules, "winreg", registry)
    monkeypatch.setattr(capture, "npcap_admin_only", NPCAP_ADMIN_ONLY)  # the library's own, reading the stand-in
    monkeypatch.setattr(capture, "_windows", lambda: True)
    monkeypatch.setattr(world, "route_address", lambda: LAN)
    state = types.SimpleNamespace(registry=registry, elevated=False, loads=[])
    monkeypatch.setattr(capture, "administrator", lambda: state.elevated)

    def load():
        state.loads.append(state.elevated)
        raise CaptureError(STAND_IN_NPCAP)
    monkeypatch.setattr(capture, "load_pcap", load)
    return state


def test_npcap_for_administrators_only_is_asked_nothing_when_the_tab_is_shown_and_the_tab_says_what_to_do(admin_only):
    """(Review F1) Npcap installed for administrators only ("Restrict Npcap driver's access to Administrators only") has
    its NpcapHelper ask for elevation, a UAC prompt, as soon as a process that is no administrator lists or opens an
    adapter: just showing the tab asked for it. Through the plugin's own view (the base's make_world_view and
    world.default_capture, as the platform has it), the option is read first, with read access alone, and Npcap is asked
    nothing: not loaded, no adapter listed or opened, no process started. The tab says why and what to do, asking for no
    administrator and no password, and the Npcap card's facts say it too (its words, which now say this:
    test_the_cards_name_what_the_tab_reaches_as_the_plugin_and_the_library_reach_it)."""
    assert WindowsFirewallPlugin.make_world_view is Firewall.make_world_view  # the base's view: its default capture
    fw = WindowsFirewallPlugin(PowerShell(runner=FakeWindows(), env={}), elevated=lambda: False)
    page = fw.ask("world")  # the tab shown, as the platform asks it
    view = fw.world_view(make=False)
    assert view is not None and not view.running and watching() == [] and admin_only.loads == []  # not even loaded
    registry = admin_only.registry
    assert registry.read == [(capture.NPCAP_OPTIONS, "AdminOnly")]
    [(root, path, access)] = registry.opened
    assert (root, path) == (Registry.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npcap\Parameters")
    assert access & Registry.KEY_READ == Registry.KEY_READ  # read access alone: nothing set, nothing made
    assert not access & (Registry.KEY_SET_VALUE | Registry.KEY_CREATE_SUB_KEY)
    note = page["note"]
    assert note.startswith(f"Traffic cannot be watched here: {capture.ADMIN_ONLY}. {world.capture_help(capture.ADMIN_ONLY)}")
    assert "\"Restrict Npcap driver's access to Administrators only\" unticked" in note  # Npcap installed again without it
    assert "or run the platform as an administrator" in note and "password" not in note.lower()
    assert fw.api_facts()[cards.NPCAP.name]["Watching"] == f"no: {capture.ADMIN_ONLY}"  # the card says it too
    fw.ask("world")  # asked again at once (the tab asks every 2 s): not tried again before RETRY_S, nothing read or asked
    assert len(registry.read) == 1 and admin_only.loads == [] and watching() == []
    fw.detach()


def test_npcap_for_administrators_only_is_tried_again_asking_it_nothing_and_opened_by_an_administrators_platform(
        admin_only, tmp_path):
    """(Review F1) Tried again RETRY_S later at the soonest, however often the tab asks: the option read again each time,
    Npcap asked nothing again. A platform run as an administrator has nothing to be prompted for, and goes on to Npcap."""
    clock = Clock()
    fw = Watched(geo_folder=tmp_path, clock=clock, wall=Clock(NOW))  # no capture of its own: world.default_capture
    fw.ask("world")
    registry = admin_only.registry
    assert len(registry.read) == 1 and admin_only.loads == []
    for _ in range(int(world.RETRY_S // 2)):  # asked every 2 s while shown: nothing tried before RETRY_S
        clock.t += 2
        fw.ask("world")
    assert len(registry.read) == 1 and admin_only.loads == []
    clock.t += world.RETRY_S
    assert "Traffic cannot be watched here: " + capture.ADMIN_ONLY in fw.ask("world")["note"]  # tried again: refused again
    assert len(registry.read) == 2 and admin_only.loads == [] and watching() == []
    admin_only.elevated = True  # the platform run as an administrator: opening Npcap prompts nobody
    clock.t += world.RETRY_S
    note = fw.ask("world")["note"]
    assert admin_only.loads == [True] and STAND_IN_NPCAP in note and capture.ADMIN_ONLY not in note
    fw.detach()


@needs_reader
def test_db_ips_file_is_downloaded_only_once_its_licence_is_accepted_and_its_places_credited(tmp_path):
    folder = tmp_path / "geoip"
    downloads = Downloads({NOVEMBER: gzip.compress(mmdb(PLACES))})
    fw = Watched(capture_factory=lambda: Feed(traffic()), geo_folder=folder, clock=Clock(), wall=Clock(NOW), fetch=downloads,
                 book=TrafficBook(clock=lambda: 50.0))
    form = fw.ask("world")["forms"][0]
    # run by the platform as a job (the form's `job`; its hook one of JOB_HOOKS), its lines followed in the plugin's panel
    assert form["job"] is True and form["hook"] in MACHINE.JOB_HOOKS
    assert "its progress shows in the panel below" in form["confirm"]["words"]
    # the platform's page asks the form's hook with its fields in order: the accept field false until the second
    # confirmation; its job route hands the job's output as the hook's log
    lines: list[str] = []
    with pytest.raises(LicenceRefused) as refused:
        fw.ask(form["hook"], False, log=lines.append)
    assert refused.value.accept == "accept_licence" == form["fields"][0]["name"]  # what the second confirmation sets
    for almost in (None, 1, "true", "yes"):
        with pytest.raises(LicenceRefused):
            fw.world_geoip(almost, log=lines.append)
    # nothing downloaded, nothing written, and nothing said: refused before the job's first line, which is how the
    # platform carries the refusal back to the page as the second confirmation
    assert downloads.asked == [] and not folder.exists() and lines == []
    out = fw.ask(form["hook"], True, log=lines.append)  # accepted, in so many words
    assert downloads.asked == [(NOVEMBER, READ_S)]  # DB-IP's address for this month, and nothing else
    assert lines[:2] == ["asking download.db-ip.com for dbip-city-lite-2026-11.mmdb.gz",
                         "downloading dbip-city-lite-2026-11.mmdb.gz from download.db-ip.com"]  # its progress, in the panel
    assert lines[-1].endswith(" downloaded: unpacking and checking it")
    assert out["ok"] is True and out["said"].startswith("installed dbip-city-lite-2026-11.mmdb (built 2026-11-01, ")
    assert out["lines"][0] == "downloaded from download.db-ip.com"
    assert [p.name for p in folder.iterdir()] == ["dbip-city-lite-2026-11.mmdb"]
    view = fw.world_view()
    assert wait_for(lambda: view.watcher.status()["packets"] == 8)
    page = fw.ask("world")
    assert "forms" not in page and "actions" not in page  # this month's file is in: nothing more is offered
    g = page["globe"]
    assert g["attribution"] == MACHINE.ATTRIBUTION  # credited wherever its places are: the globe ...
    assert "Places: IP Geolocation by DB-IP, https://db-ip.com." in page["tables"][1]["note"]  # ... and the Places table
    by = {o["id"]: o for o in g["origins"]}
    london = by["81.2.69.0/24"]
    assert (london["city"], london["country"], london["code"], london["lat"], london["lon"]) == (
        "London", "United Kingdom", "GB", 51.5142, -0.0931)
    assert by["175.16.199.0/24"]["label"] == "Changchun, China"
    assert fw.world_geoip(True)["said"].startswith("dbip-city-lite-2026-11.mmdb is installed already")
    assert len(downloads.asked) == 1  # not downloaded again
    fw.detach()


@needs_reader
def test_last_months_file_is_asked_of_db_ip_while_this_months_is_not_out(tmp_path):
    downloads = Downloads({OCTOBER: gzip.compress(mmdb(PLACES, built=BUILT_OCTOBER))})  # November's: a 404
    fw = Watched(capture_factory=Feed, geo_folder=tmp_path / "geoip", clock=Clock(), wall=Clock(NOW), fetch=downloads)
    out = fw.world_geoip(True)
    assert [u for u, _ in downloads.asked] == [NOVEMBER, OCTOBER]
    assert out["lines"][0] == "downloaded from download.db-ip.com: this month's file is not out yet, so last month's"
    assert fw.ask("world")["forms"][0]["title"] == "Update the GeoIP file"  # built before this month: its update offered
    fw.detach()
    january = Watched(capture_factory=Feed, geo_folder=tmp_path / "empty", clock=Clock(), fetch=Downloads({}),
                      wall=Clock(datetime(2027, 1, 3, tzinfo=timezone.utc).timestamp()))
    with pytest.raises(geo.GeoError, match="neither this month's nor last month's"):
        january.world_geoip(True)
    assert [u for u, _ in january.stand_ins["fetch"].asked] == [
        "https://download.db-ip.com/free/dbip-city-lite-2027-01.mmdb.gz",
        "https://download.db-ip.com/free/dbip-city-lite-2026-12.mmdb.gz"]


@needs_reader
def test_home_is_the_place_set_through_the_login_else_where_the_name_servers_say_this_network_is(geo_folder):
    asked = []

    def resolve(version, servers):
        asked.append((version, servers))
        return PUBLIC, servers[0][3]
    fw = Watched(capture_factory=Feed, geo_folder=geo_folder, clock=Clock(), wall=Clock(NOW), resolve=resolve)
    fw.attach(object(), EnvironmentLogin(env={"LIMINAL_HOME_PLACE": "48.86,2.35,Paris"}))
    g = fw.ask("world")["globe"]
    assert g["home"] == {"lat": 48.86, "lon": 2.35, "label": "Paris"} and "Home is the place you set." in g["note"]
    assert asked == []  # the user's place: no name server asked
    fw.detach()
    fw.attach(object(), EnvironmentLogin(env={}))  # attached again, no place set: this network's public address
    first = fw.ask("world")["globe"]
    assert first["home"] is None and "being asked for" in first["note"]  # asked on a thread of its own
    view = fw.world_view()
    assert wait_for(lambda: view.public_address(MACHINE.PUBLIC_DNS)[0] == PUBLIC)
    g = fw.ask("world")["globe"]
    assert g["home"] == {"lat": 37.386, "lon": -122.0838, "label": "Mountain View, United States"}
    assert "Home is where the GeoIP file puts this network's public address." in g["note"]
    fw.ask("world")
    # asked once, for the plugin's attachment: OpenDNS's and Google's IPv4 servers, their names absolute, nothing about
    # any peer
    assert asked == [(4, world.servers_of(MACHINE.PUBLIC_DNS, 4))]
    assert [s[2:] for s in asked[0][1]] == [s[2:] for s in cards.NAME_SERVERS[:2]]  # the plugin's own servers ...
    assert [s[0] for s in asked[0][1]] == [s[0] + "." for s in cards.NAME_SERVERS[:2]]  # ... asked for its names, absolute
    fw.detach()


def test_detach_ends_the_watching_and_forgets_the_tab(tmp_path):
    feed = Feed(traffic())
    fw = Watched(capture_factory=lambda: feed, geo_folder=tmp_path, clock=Clock(), wall=Clock(NOW))
    fw.attach(object(), EnvironmentLogin(env={}))
    fw.ask("world")
    view = fw.world_view()
    assert view.running and fw.api_facts()[cards.NPCAP.name]["Watching"].startswith("yes")
    fw.detach()
    assert not view.running and view.closed and feed.closed == 1 and watching() == []
    assert fw.world_view(make=False) is None and fw.app is None and fw.login is None  # detached as every plugin is
    facts = fw.api_facts()
    assert cards.NPCAP.name not in facts and cards.DBIP.name not in facts  # no facts of a tab not asked since
    # an ask still under way as it was detached, on the view it held: nothing starts again
    assert view.touch() is False and view.page() == {"title": "World Wide Web",
                                                      "note": "Nothing is watched now: the plugin was detached."}
    assert feed.opened == 1 and watching() == []


# -- what the tab reaches, on the plugin's API cards ------------------------------------------------------------------------
def test_the_cards_name_what_the_tab_reaches_as_the_plugin_and_the_library_reach_it():
    assert problems(MACHINE.apis) == [] and {cards.NPCAP, cards.DBIP, cards.OPENDNS, cards.GOOGLE} <= set(MACHINE.apis)
    # DB-IP's: the one download the tab makes, at the address the plugin names, and the file's credit and licence
    [download] = [c for c in cards.DBIP.used if c.name.startswith("GET ")]
    assert download.name == "GET " + MACHINE.GEOIP_URL.replace("{year}", "<year>").replace("{month}", "<month>")
    assert cards.DBIP.base.startswith(download.name[4:])
    assert cards.DBIP.link("terms") == "https://creativecommons.org/licenses/by/4.0/"
    assert cards.DBIP.docs == "https://db-ip.com/db/lite.php"  # its licence and attribution page
    assert {a.name for a in cards.DBIP.covered} == {"IP to City Lite", "The MMDB file", "The credit"}
    assert {c.name for c in cards.DBIP.used} == {download.name, "maxminddb.open_database(<file>, MODE_MMAP_EXT)",
                                                  "Reader.get(<address>)"}
    assert "maxminddb.open_database(str(path), maxminddb.MODE_MMAP_EXT)" in inspect.getsource(geo)  # how the library opens it
    assert "self._reader.get(address)" in inspect.getsource(geo.GeoIP)
    # the name servers': each question the tab may ask, as the library sends it (world.servers_of: the plugin's names made
    # absolute) and asks it (dns.query: nslookup, windowless, PUBLIC_WAIT_S for each answer and one retry)
    wait = f"-timeout={dns.PUBLIC_WAIT_S} -retry=1"
    assert cards.WAIT == wait and "wait=PUBLIC_WAIT_S" in inspect.getsource(dns.public_address)
    for version in (4, 6):
        for name, rtype, server, whose in world.servers_of(MACHINE.PUBLIC_DNS, version):
            card = cards.OPENDNS if whose == "OpenDNS" else cards.GOOGLE
            sent = f"nslookup -type={rtype} {wait} {name} {server}"
            assert name.endswith(".") and sent in {c.name for c in card.used}, (whose, rtype)
            assert version == 6 or card.base.startswith(sent), whose  # its base: the IPv4 question
    for card in (cards.OPENDNS, cards.GOOGLE):  # what goes out besides: the server asked for its own name, nothing else
        assert cards.SENT in card.about and "trailing dot" in cards.SENT and "PTR record of the server's own address" in cards.SENT
    assert {c.name.split()[-1] for c in (*cards.OPENDNS.used, *cards.GOOGLE.used)} == {s for _, _, s, _ in MACHINE.PUBLIC_DNS}
    asks = inspect.getsource(dns)  # the module's own words: its query is refused in these tests
    assert '["nslookup", f"-type={rtype}", *([f"-timeout={wait}", "-retry=1"]' in asks and "**_no_window()" in asks
    assert "0x08000000" in inspect.getsource(dns._no_window)  # CREATE_NO_WINDOW: no console pops up
    # Npcap's: every libpcap call the library's capture makes on Windows (the other two are Linux's alone), and the
    # capture the tab makes: every TCP and UDP packet, the headers alone, read within 150 ms
    made = set(re.findall(r"lib\.(pcap_\w+)\(", inspect.getsource(capture.PcapSource)))
    assert {c.name for c in cards.NPCAP.used if c.name.startswith("pcap_")} == made - {"pcap_setnonblock", "pcap_get_selectable_fd"}
    assert "capture.Capture(address, udp=True, payloads=False, host=False)" in inspect.getsource(world.default_capture)
    assert capture.bpf((), None, True) == "(tcp or udp)" and capture.SNAPLEN == 128 and capture.TIMEOUT_MS == 150
    assert capture.NPCAP.replace("\\", "/").endswith("/System32/Npcap") and r"%SystemRoot%\System32\Npcap" in cards.NPCAP.base
    # (review F1) and before any of them, Npcap's option for administrators only, read where Npcap keeps it, with
    # whether the platform is an administrator: an install for administrators only is asked nothing by one that is none
    [option] = [c for c in cards.NPCAP.used if not c.name.startswith("pcap_")]
    assert option.name == cards.NPCAP_ADMIN_ONLY == "HKLM\\" + capture.NPCAP_OPTIONS + "\\AdminOnly"
    assert option.area == "Administrators only" and "IsUserAnAdmin" in option.used and not option.writes
    assert 'winreg.QueryValueEx(key, "AdminOnly")' in inspect.getsource(NPCAP_ADMIN_ONLY)  # the library's own reader
    assert "IsUserAnAdmin" in inspect.getsource(capture.administrator)
    opening = inspect.getsource(capture.PcapSource.open)
    assert opening.index("_npcap_may_open()") < opening.index("load_pcap()")  # looked at before Npcap is even loaded
    assert "_npcap_may_open()" in inspect.getsource(capture.PcapSource._listed)  # and before each listing of its adapters
    auth = cards.NPCAP.auth  # as Npcap is installed on this PC (AdminOnly=0), and what an install for administrators gets
    assert "AdminOnly=0" in auth and "no UAC" in auth and "asks Npcap nothing, not even loading it" in auth
    assert "install Npcap again with the option unticked, or to run the platform as an administrator" in auth
    assert "never asks for an administrator or a password itself" in auth
    # its free license: five computers; only copies used with Nmap, Wireshark or Defender for Identity alone are not
    # counted, and this PC's, which Liminal uses directly, is
    assert "five computers" in cards.NPCAP.costs and "used only with Nmap, Wireshark or Microsoft Defender" in cards.NPCAP.costs
    assert "this PC's does" in cards.NPCAP.costs and "Npcap OEM" in cards.NPCAP.costs
    # DB-IP's: a month's file is never downloaded twice, and Update… fetches a newer month's in its place
    assert "never again" not in cards.DBIP.limits and "a month's file never twice" in cards.DBIP.limits


# -- what the tab knows, on the cards, asking nothing ---------------------------------------------------------------------------
@needs_reader
def test_the_tabs_facts_are_what_it_knows_and_asking_them_starts_nothing(tmp_path):
    feeds, clock = [], Clock()

    def factory():
        feeds.append(Feed(traffic()))
        return feeds[-1]
    fw = Watched(capture_factory=factory, geo_folder=tmp_path / "geoip", clock=clock, wall=Clock(NOW),
                 fetch=Downloads({NOVEMBER: gzip.compress(mmdb(PLACES))}))
    assert fw.api_facts() == {} and fw.made == 0  # the tab not asked: no facts, and no view made for them
    fw.ask("world")
    view = fw.world_view()
    assert wait_for(lambda: view.watcher.status()["packets"] == 8)
    facts = fw.api_facts()
    watched = facts[cards.NPCAP.name]["Watching"]
    assert watched.startswith("yes, at the adapter of 192.168.1.20 since ")
    assert watched.endswith(", while the World Wide Web tab is shown and for 20 s after")
    assert facts[cards.NPCAP.name]["Packets read"] == "8 in all: counted, none kept"
    assert facts[cards.DBIP.name]["GeoIP file"].startswith("none installed yet")
    fw.world_geoip(True)
    open_now = fw.api_facts()[cards.DBIP.name]["GeoIP file"]
    assert open_now.startswith("dbip-city-lite-2026-11.mmdb, built 2026-11-01, ") and open_now.endswith(": looked up on this PC")
    clock.t += 21
    assert wait_for(lambda: not view.running)
    assert fw.api_facts()[cards.NPCAP.name]["Watching"].startswith(
        "no: only while the World Wide Web tab is shown and for 20 s after (last until ")
    # nobody watches: the file is let go (still the one installed, said as such), and opened again at the next ask
    assert wait_for(lambda: view.describe()["geoip"]["open"] is False)
    assert fw.api_facts()[cards.DBIP.name]["GeoIP file"] == open_now + (
        " (let go while the tab is not watched; opened again at its next ask)")
    assert len(feeds) == 1 and fw.made == 1  # asking for the facts started nothing and made nothing
    fw.detach()
