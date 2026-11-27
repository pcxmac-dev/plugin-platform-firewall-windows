"""The Netstat tab and the hosts database (0.7.0; the user, 2026-11-16: "the firewall app should have a 'netstat' like
interface for looking at active ports and what apps they are attached to, and the hosts that they connect to across the
lan or wan"): the library's Firewall base's (liminal-libs 1.65.0) with what this plugin names for them (apis.py), asked
through the plugin as the platform asks it.

The tab's page over a reading made in the shape the library's Windows reader gives; one reading shared by the tab and
the World Wide Web plugin's ask of it (netstat_seen) and kept in the hosts database; the socket tables' card's calls as
the library makes them; the facts, asking nothing, their counts written as the tab writes them; off Windows, no view
made and every hook of the tab refused before it reads, keeps or removes anything (its status, reads and changes there,
on any library: test_plugin.py); and the suite's guard (tests/conftest.py, B-critique B1), which keeps a plugin
attached under a login that says always from reading this PC's socket table into its hosts database.

0.11.0 (the user, 2026-11-26, "Delete now"): the globe, its filters, its data sets and their tests are
plugin-platform-worldwideweb's (its tests/test_globe_sets.py pins the data sets' digest these tests pinned); none of it
is said or tested here.

Nothing real: the socket table is a stand-in's reading (the guard refuses the real one), the hosts database is the
test's own (the same guard), no process is started and nothing reaches the network."""
from __future__ import annotations

import inspect
import json
import os
import re
import subprocess
import threading
import time
import urllib.request

import pytest

from conftest import Reached
from liminal_libs import capture, dns, geo, hostbook, netpath, resources, sockets
from liminal_libs.apps.authorization import EnvironmentLogin, Login, Unauthorized, pair_name
from liminal_libs.machines import infrastructure, netstat, world
from liminal_libs.machines.windows import PowerShell
from liminal_libs.sources.apis import problems
from liminal_libs.sources.conformance import problems as contract_problems
from plugin_platform_firewall_windows import MACHINE, WindowsFirewallPlugin
from plugin_platform_firewall_windows import apis as cards
from test_plugin import FakeWindows, plugin

LAN, PRINTER = "192.168.1.20", "192.168.1.50"
WEB, WEB2 = "81.2.69.142", "81.2.69.160"  # public addresses: the internet's
EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
PY = "C:\\Python315\\python.exe"
NAMES = {WEB2: "cdn.example"}  # the system's own hosts file, stood in
THREADS = ("-hosts", "-layer-download", "traffic-watcher", "-public-address", "firewall-windows-read")


def wait_for(condition, seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.005)
    return condition()


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
def test_the_netstat_tab_is_the_firewall_bases_and_the_world_wide_web_tab_is_not_its_own():
    """0.10.0, liminal-libs 1.105.0: the Netstat tab, then the Networks tab; the World Wide Web tab, its hooks, its keys
    and its cards are plugin-platform-worldwideweb's (0.11.0: their words and code paths are gone from here). Its
    services to that plugin are the base's (test_services.py)."""
    assert [t.id for t in MACHINE.TABS] == ["netstat", "container_networks"]
    hooks = MACHINE.interface()["hooks"]
    assert hooks["netstat"].startswith("() ") and hooks["hosts_recording"].startswith("(mode) ")
    assert not {h for h in hooks if h.startswith("world")}
    assert {"netstat_seen", "hosts_found", "hosts_routes", "rules_covering"} <= set(hooks)
    assert [k.name for k in MACHINE.keys] == ["LIMINAL_HOSTS_RECORDING"]
    assert not set(cards.NETSTAT[1:]) & set(MACHINE.apis) and cards.SOCKETS in MACHINE.apis
    assert "Netstat" in MACHINE.about and "globe" not in MACHINE.about
    assert contract_problems(MACHINE) == [] and problems(MACHINE.apis) == []


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
    fw = plugin(FakeWindows())
    try:
        fw.ask("netstat")
        fw.netstat_seen()  # within the reading's 2.5 s: the same reading (the World Wide Web plugin's ask of it)
        assert table.reads == 1
        facts = hostbook.book().describe()
        assert facts["path"] == str(hostbook.path()) and facts["rows"] >= 2 and facts["hosts"] >= 2
        assert hostbook.path().is_relative_to(tmp_path)  # this PC's data folder is never written by a test
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


# -- what they know, on the cards, asking nothing ----------------------------------------------------------------------
def test_its_facts_say_the_last_reading_the_recording_and_the_hosts_database_asking_nothing(table):
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
        # 0.11.0: the globe's data sets and their facts are plugin-platform-worldwideweb's: none said here
        assert set(facts) <= {a.name for a in cards.APIS} and not {"Overpass API", "Wikidata Query Service"} & set(facts)
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
            # a data set a view of an older library might still describe: its words are the World Wide Web plugin's
            "sets": [{"id": "osm-datacentres", "title": "Data centres", "format": "overpass", "installed": True,
                      "features": 5_073, "fetched": "2026-11-18T10:00:00+00:00", "bytes": 1_500_000, "dropped": 1_200}]}

    class View:  # the base's NetstatView as describe() answers, asking nothing
        def describe(self) -> dict:
            return dict(said)

    class Described(WindowsFirewallPlugin):
        def netstat_view(self, make=True):
            return View()
    fw = Described(PowerShell(runner=FakeWindows(), env={}), elevated=lambda: True)

    def facts() -> tuple[dict]:
        out = fw._netstat_facts()
        assert list(out) == [cards.SOCKETS.name]  # 0.11.0: no data set's words
        return (out[cards.SOCKETS.name],)
    mine, = facts()
    assert mine["Hosts database"].startswith("12,345 rows (1,204 hosts, 1,041 programs), ")
    assert mine["Last reading"] == "none yet: the socket tables are read every 5 s, all the time the platform runs"
    said["recording"] = False  # always, but not recording now (a one-shot app; a folder of another system's drive)
    assert facts()[0]["Last reading"] == ("none yet: the socket tables are read only while this plugin's Netstat or "
                                          "World Wide Web tab is shown")
    said.update(mode="shown", reading={"at": now, "rows": 1_234, "took": 0.0042, "system": "windows"})
    assert facts()[0]["Last reading"].endswith(": 1,234 sockets in 4 ms")


# -- not for any machine but Windows (B-critique S1) -------------------------------------------------------------------
# a plausible ask of every hook of the Netstat tab and the hosts database but the tab's own page, as the platform's page,
# a POST to /api/machines/firewall-windows/ask or another plugin through the platform (app.ask) could send it to a
# plugin that is not valid here (0.11.0: the globe's hooks are plugin-platform-worldwideweb's, none here)
ASKS = {"hosts_recording": ("always",), "hosts_forget": (True,)}


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
        assert set(ASKS) == set(netstat.FIREWALL_HOOKS) - {"netstat"}  # every one of the base's (a new one: an ask)
        assert not set(netstat.GLOBE_HOOKS) & set(fw.HOOKS)  # 0.11.0: none of the globe's is a hook here
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


