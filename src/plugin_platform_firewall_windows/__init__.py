"""Windows Firewall for Liminal (the user, 2026-11-07: "i also need a windows and linux firewall plugin for the
platform"; 2026-11-08: "windows firewall, i need it to be able to read the configuration, and make changes";
"basically the firewall plugin is an interface for windows networking / defender / firewall, and will let me make
queries and alter the firewall configurations"): Windows Defender Firewall on this PC, read whole and changed on the
user's word, through PowerShell's NetSecurity cmdlets (the library's machines.windows.PowerShell).

- Read (no rights needed): one PowerShell call (read.ps1) gives the three profiles, the networks and their category,
  every rule with its ports, program and remote addresses, and Microsoft Defender's state; kept a minute, read on a
  thread when the plugin is attached and again after every change, so the platform's page asks it nothing slow.
- Queries: the rules filtered by a preset (inbound allowed, inbound blocked, outbound, Liminal's, turned off, all) or
  found by words, a port, a direction and an action.
- Groups (0.3.0; the user: "for both firewalls, i need to have groups, like system or application and then unassociated
  rules not tied to a specific application or system process can be in an other, i can create labels, like system or
  application, as well and move the rules in to that"): every rule sorted (sort_rule) into System (Windows' own: its
  services, the System process, its programs in Windows' folder, its own app packages and rule groups), Application (a
  program or a Microsoft Store app installed, Liminal's rules) or Other (no program, service or app: ports and addresses
  alone); the user's labels and moves kept through the platform's login (the library's rulegroups), never in Windows'
  firewall: no rule changes when it is moved.
- Names (0.4.0; the user: "lets group by application under apps or system, try best to organize under system and
  applications. Like system has 'core networking' or WSD or UPnP or RA Server or Remote Assistance or network discovery
  or ... applications has like starcraft or edge"; "try to group the system by 'services'"; "also rules that are turned
  off should be shown as well"): every System rule named by its service (Windows' own rule group, else its Windows
  service, its program; Windows' own app packages, known by their publisher, by the name their rules carry, an earlier
  version's left behind too), every Application rule by its application (its rule group, the group its program's
  other rules carry, its app package's name, its install folder, else the name its rules carry: one heading for an
  application's programs and versions), each name a heading of its own under its group (sort_rules); Windows' own rule
  groups the system's even for a program under Program Files (Windows Media Player); the rules turned off listed too,
  after those turned on.
- Changes, each asked by a form and confirmed: a rule turned on or off, removed (never one of Windows' own: those are
  turned off instead), or made (in the rule group "Liminal"); a profile's firewall turned on or off, its default for
  what comes in or goes out, its notifications; a network made private or public. Turning a profile off, or letting
  everything in by default, is asked a second time: this PC may be a router's DMZ host. A change needs an
  administrator: run as one, or Windows asks (UAC). Since 0.7.3 the changes are asked only from its page
  (PAGE_ONLY_HOOKS, the base's allow and remove among them): another plugin's ask is refused, and the platform asks
  its login whether you are at the page before it asks one over HTTP. The setup and the command line call the code
  directly, as before.
- The library's Firewall base keeps its setup (on, exposure, the services' rules) and Liminal's own rules' hooks.
- What it attaches to (0.5.0, plugin API 2.2; the user, 2026-11-11: "each plugin should reflect the the API its attached
  to, and present links that provide documentation"): Windows PowerShell and UAC, the NetSecurity, NetConnection and
  Defender cmdlets, Windows Firewall itself and its COM policy, and what names a rule (apis.py), drawn on the plugin's
  page; `api_facts` says what the last read found of them (when, how long, the rules, the profiles, the networks,
  Defender's state), asking nothing.
- The World Wide Web tab (0.6.0; the user, 2026-11-14: "so for the firewall's both are going to get a 'world wide web
  view' that shows the globe and the routes incoming all traffic, as well as monitoring port traffic stats"): the
  library's Firewall base draws it (liminal-libs 1.55.0, machines/world.py), and this plugin names what it reaches
  (apis.py). While the tab is shown, and for 20 s after, every TCP and UDP packet at this PC's adapter is read through
  Npcap and counted by port and by network; Npcap installed for administrators only is asked nothing by a platform that
  is none (it would ask for UAC), and the tab says how to put that right. Each public network is placed on the globe by
  DB-IP's IP to City Lite file on this PC, with its route to home: the place you set (LIMINAL_HOME_PLACE, kept through
  the login), else this network's public address as OpenDNS's or Google's name servers give it. The busiest ports are
  charted and tabled. The file is downloaded only on your word, its CC BY 4.0 licence shown and accepted first, as a job
  the platform follows in the plugin's panel (the base's JOB_HOOKS), and its places are credited "IP Geolocation by
  DB-IP". No peer's address leaves this PC, and none is looked up by name.
- The Netstat tab, the hosts database and the globe's filters and internet infrastructure (0.7.0; the user, 2026-11-16:
  "the firewall app should have a 'netstat' like interface for looking at active ports and what apps they are attached
  to, and the hosts that they connect to across the lan or wan. the firewall app should also have a globe that can be
  zoomed and rotated and geoip'd hosts are databased for the apps they talk to, the time they are connected to *this
  *computer"; "the globe-firewall should allow filtering, so i can view apps connected to hosts all across the globe,
  or ports talking to all hosts. The globe should have the same kind of geography associated with the exchanges globe,
  but the firewall globe should instead of exchanges, have all the backbones,ibones, major internet infrastructure, (as
  many as possible) datacenter locations."): the library's Firewall base draws them (liminal-libs 1.65.0: sockets.py,
  hostbook.py, machines/netstat.py, machines/infrastructure.py), and this plugin names what they reach (apis.py).
  Netstat lists this PC's listening ports and open connections from Windows' own socket tables, each with its
  program, pid and service, the remote host and port, whether that host is this PC's, the local network's or the
  internet's, its name or its GeoIP place, and how long it has been up: no capture, no administrator, no window. The
  hosts database (one small file in the data folder's hosts/, this PC's own) keeps each program's remote hosts, their
  ports, when they were first and last seen and how long they were connected; it records only while the Netstat or
  the World Wide Web tab is shown, unless you choose all the time the platform runs (LIMINAL_HOSTS_RECORDING, kept
  through the login). The globe shows the traffic watched or the hosts recorded, filtered by program, port, direction
  and when they were last seen, and draws the internet's infrastructure (data centres, exchange points, submarine
  cables and their landing stations, backbones and their points of presence, telecom lines on land, ground stations
  and teleports) from free-licensed data sets, each downloaded only on your word as a job, its size and licence said
  first, and credited where it is drawn (INFRASTRUCTURE: OpenStreetMap's through the Overpass API, Wikidata's,
  EMODnet's, the Internet Topology Zoo's; the user, 2026-11-19: "major network 'bones' need to be displayed on the
  map", "also underwater lines"). Off Windows the plugin is not for the machine at all (not_for_here): nothing is
  read, recorded, kept or removed there, and every hook of its two tabs is refused in words (make_netstat_view). On a
  library before 1.65.0 it loads as 0.6.1 did, its World Wide Web tab as it was, and names none of what those reach.
- run(), and who may ask a change (0.7.3; the independent review's finding PLT-H1, checked 2026-11-23, and the review
  of its fix, 2026-11-24): run() runs a PowerShell command line as this process runs it, never through Windows' prompt
  (UAC), and a command Windows denies is said, never asked again elevated. liminal-platform's POST
  /api/machines/{name}/run handed a plugin's run() any words a program on this PC sent: that route is gone (the user,
  2026-11-23: "Remove it"; liminal-platform 0.34.1), and only a command line asks run(), in its own process. The
  changes, which run at once when the platform is an administrator, are its PAGE_ONLY_HOOKS: before, any program on
  this PC asked them with two headers, the second confirmation being only an argument.
- Services' networks (0.8.0; liminal-libs 1.96.0's NetworkHost, network.py): the container plugins you let ask it for
  networks (its Networks tab) get each service's segment from Liminal's pool, a route into WSL through the VM's address
  in the active store (New-NetRoute -PolicyStore ActiveStore), the names in your domain forward and reverse (you set the
  domain: none is picked for you, and no service is placed until you do), the DHCP records of every container their
  segments hold, and, on Expose…, a port proxy per port on this PC's address on your network to the part's reserved
  address (decision 2 b, b1), with its rule from your local subnet on Private and Domain alone. Every change is a plan
  you approve on the page, carried out by one elevated script (UAC); Re-point… makes stale routes and proxies again.
  Making a network Private is asked a second time, naming each rule Private would then let in from beyond your subnet.
  Windows' excluded port ranges are read for the container plugins (excluded_ports).
- GeoIP sources (0.9.0; liminal-libs 1.101.0's machines/geosources.py, Monday list item 20; the user, 2026-11-19: "add a
  way to download different GEOIP sources"): the World Wide Web tab's GeoIP sources table, in place of its two install
  buttons, places and networks chosen apart, DB-IP's two files the default for both (the same addresses, folders and
  words as before). Their download, use and removal are the base's three page-only hooks, each refusing any ask but a
  person's signed in at the platform's page; each acceptance of a licence is kept in that person's own login store,
  never in a file. IPinfo Lite, for networks, is named and not offered (the user, 2026-11-25: each source offered only
  after their yes): its row waits for your word, with no button, no card and no key asked (apis.GEOIP_SOURCES).
- The globe's newer data sets (0.10.0, liminal-libs 1.104.0; the Monday list's items 24, 27, 28, 29 and 32):
  AfTerFibre's fibre on land in Africa (its map's tiles; CC BY 4.0), Natural Earth's 1:10m roads and railways as
  stand-ins for fibre where none is mapped (public domain), TopoHub's backbone model, RIPE Atlas's probes and its
  anchors' newest traceroutes (non-commercial), and CelesTrak's orbits of Starlink, OneWeb and HughesNet, placed with
  the sgp4 package pinned here (SGP4_PACKAGE), each footprint at 25 degrees of elevation. Each is downloaded only on
  your click, its size and licence said first, and kept in the plugin's own infrastructure.db (GLOBE2_SETS, their cards
  GLOBE2).

    python -m plugin_platform_firewall_windows status | rules [PRESET] | find WORDS [--port N] [--in|--out]
        [--allow|--block] | profiles | networks | set-rule ID on|off | remove-rule ID | add-rule NAME ... |
        set-profile NAME ... | set-network INDEX private|public | setup [STEP ...] | exposure | allow | remove | run
"""
from __future__ import annotations

import ntpath
import os
import re
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from liminal_libs import geo
from liminal_libs.machines.firewall import GROUP, NAME, Firewall, FirewallError, Rule
from liminal_libs.machines.plugin import CommandError
from liminal_libs.machines.rulegroups import Sorted, key_of
from liminal_libs.machines.windows import PowerShell, is_elevated, quote
from liminal_libs.machines.world import WorldView, size_words

from .apis import (APIS, CITY_LITE, CITY_LITE_LICENCE, DBIP, DBIP_CREDIT, DEFENDER_API, EMODNET, NAME_SERVERS,
                   NETCONNECTION, NETSECURITY, NETSTAT, NPCAP, OVERPASS_API, SOCKETS, TOPOLOGY_ZOO, WIKIDATA)
from .apis import GEONAMES_API, OURAIRPORTS_API
from .apis import AFTERFIBRE_API, CELESTRAK_API, NATURAL_EARTH_API, RIPE_ATLAS, SGP4_PACKAGE, TOPOHUB_API
from .apis import ASN_LITE, ASN_LITE_LICENCE
from .apis import GEOIP_SOURCES as SOURCES
from .apis import INFRASTRUCTURE as DATA_SETS
from .apis import RDAP_BOOTSTRAP as RDAP_FILES
from .network import EXCLUDED, WindowsNetwork
from liminal_libs.machines.segments import NetworkHost

__version__ = "0.10.0"
DIRECTIONS = {"in": "Inbound", "out": "Outbound"}
ACTIONS = {"allow": "Allow", "block": "Block"}
PROTOCOLS = {"tcp": "TCP", "udp": "UDP", "any": "Any"}
PROTOCOL_NUMBERS = {"6": "tcp", "17": "udp"}
PROFILE_NAMES = ("Domain", "Private", "Public")
READ_SCRIPT = Path(__file__).with_name("read.ps1")
READ_S = 60.0  # the configuration read again once it is this old
FIRST_WAIT_S = 8.0  # how long the first status waits for the first read
ROWS = 100  # rules listed at most under each service's or application's heading, and in each group for those with none
WINDIR = (os.environ.get("SystemRoot") or r"C:\Windows").rstrip("\\")  # Windows' folder: its programs are the system's
GROUP_NOTES = {
    "system": ("Windows' own, by service: its rule groups, its services, the System process, its programs in Windows' "
               "folder, its app packages"),
    "application": "by application: a program or a Microsoft Store app installed, Liminal's rules too",
    "other": "tied to no program, service or app: ports and addresses alone",
}
RULE_FIELDS = ("$pf = $_ | Get-NetFirewallPortFilter; $af = $_ | Get-NetFirewallAddressFilter; "
               "[pscustomobject]@{ Name = $_.DisplayName; Group = [string]$_.Group; Direction = $_.Direction.ToString(); "
               "Action = $_.Action.ToString(); Enabled = ($_.Enabled.ToString() -eq 'True'); Protocol = [string]$pf.Protocol; "
               "LocalPort = (@($pf.LocalPort) -join ','); RemoteAddress = (@($af.RemoteAddress) -join ','); "
               "Description = [string]$_.Description }")
PRESETS = {  # the rules shown: (title, which); those turned off too (0.4.0: "also rules that are turned off should be shown")
    "in-allow": ("Inbound allowed", lambda r: r.direction == "in" and r.action == "allow"),
    "in-block": ("Inbound blocked", lambda r: r.direction == "in" and r.action == "block"),
    "out": ("Outbound", lambda r: r.direction == "out"),
    "liminal": ("Liminal's", lambda r: r.group == GROUP),
    "off": ("Turned off", lambda r: not r.enabled),
    "all": ("All", lambda r: True),
}
DEFAULTS = {"inbound": "block", "outbound": "allow"}  # what Windows does where a profile's default is NotConfigured
UAC = "Windows asks for an administrator's permission first (UAC)."
SYSTEMS = {"linux": "Linux", "darwin": "macOS"}  # a system that is not Windows, by the name Python gives it, in words
DATA_SET_CARDS = {"overpass": OVERPASS_API.name, "sparql": WIKIDATA.name, "geojson": EMODNET.name,  # by a set's format
                  "gml": TOPOLOGY_ZOO.name, "ourairports": OURAIRPORTS_API.name, "geonames": GEONAMES_API.name,
                  # liminal-libs 1.104.0: the fibre, roads and railways, backbones, RIPE Atlas and the orbits
                  "shapefile": NATURAL_EARTH_API.name, "mvt": AFTERFIBRE_API.name, "topohub": TOPOHUB_API.name,
                  "atlas-probes": RIPE_ATLAS.name, "atlas-latest": RIPE_ATLAS.name, "omm-csv": CELESTRAK_API.name}


def _platform() -> str:
    """The system the platform runs on, as Python names it (sys.platform): win32 on Windows. A test stands in for it."""
    return sys.platform


def netstat_in(base=Firewall) -> bool:
    """Whether the library's Firewall base has the Netstat tab, the hosts database and the globe's layers (liminal-libs
    1.65.0: its netstat_view); an older one has the World Wide Web tab alone (0.7.0)."""
    return callable(getattr(base, "netstat_view", None))


def cards_for(base=Firewall) -> tuple:
    """The cards of what the plugin attaches to, with the library it runs with (0.7.0): every one of APIS where the
    Firewall base has the Netstat tab (netstat_in), else 0.6.1's, the socket tables' and the data sets' cards left out:
    the plugin reaches none of them there."""
    return APIS if netstat_in(base) else tuple(a for a in APIS if a not in NETSTAT)


def _ports(text) -> tuple[int, ...]:
    out = []
    for part in str(text or "").split(","):
        part = part.strip()
        if part.isdecimal() and 0 < int(part) < 65536:
            out.append(int(part))
    return tuple(out)


def rule_of(row: dict) -> Rule:
    """A Windows rule as the framework sees it: one of Liminal's when it is in the group under a name of its own."""
    display = str(row.get("Name") or "")
    prefix = f"{GROUP}: "
    short = display[len(prefix):] if display.startswith(prefix) else display
    owned = str(row.get("Group") or "") == GROUP and display.startswith(prefix) and bool(NAME.match(short))
    proto = str(row.get("Protocol") or "Any").strip()
    protocol = PROTOCOL_NUMBERS.get(proto) or (proto.lower() if proto.lower() in ("tcp", "udp") else "any")
    remote = str(row.get("RemoteAddress") or "Any")
    return Rule(short if owned else display, ports=_ports(row.get("LocalPort")) if protocol != "any" else (), protocol=protocol,
                direction="out" if str(row.get("Direction")) == "Outbound" else "in",
                action="block" if str(row.get("Action")) == "Block" else "allow",
                remote="any" if remote.lower() in ("any", "*") else remote, enabled=bool(row.get("Enabled", True)), owned=owned,
                detail=str(row.get("Description") or ""))


# -- the configuration as read --------------------------------------------------------------------------------

@dataclass(frozen=True)
class WinRule:
    """A rule as Windows holds it: `id` (its unique name: what a change names), its display name and group, whether it
    is one of Windows' own (`builtin`: its group a resource string; turned off rather than removed), and what it
    matches. A port filter or remote addresses Windows did not give a non-administrator are None (not read). What it is
    tied to (0.3.0): its program, its service (a Windows service's short name), its owner (an app container's: a
    Microsoft Store app's rule) and its app's package family, `package_system` when Windows signed that package as its
    own; `source` is its rule group as Windows keeps it (a resource string for Windows' own). What names them (0.4.0):
    its service's display name (`service_name`), and for a program on disk its product name, its description and its
    path as spelled there (`on_disk`: a rule may name it in lowercase); "" when not read (a read before 0.4.0, a
    program no longer there)."""
    id: str
    name: str
    group: str = ""
    builtin: bool = False
    enabled: bool = True
    direction: str = "in"
    action: str = "allow"
    profiles: str = "Any"
    program: str = "Any"
    protocol: str | None = "Any"
    local: str | None = "Any"
    remote_ports: str | None = "Any"
    remote: str | None = "Any"
    description: str = ""
    source: str = ""
    service: str = ""
    owner: str = ""
    package: str = ""
    package_system: bool = False
    service_name: str = ""
    product: str = ""
    file_description: str = ""
    on_disk: str = ""

    @property
    def owned(self) -> bool:
        return self.group == GROUP

    def covers(self, port: int) -> bool:
        """Whether its local ports include `port` (every port, a list, a range); a named set (RPC) or ports not read: no."""
        if self.local is None or (self.protocol or "").upper() not in ("TCP", "UDP", "ANY", "6", "17"):
            return False
        for part in self.local.split(","):
            part = part.strip()
            if part.lower() == "any" or part == str(port):
                return True
            m = re.fullmatch(r"(\d+)-(\d+)", part)
            if m and int(m.group(1)) <= port <= int(m.group(2)):
                return True
        return False

    def cover_rank(self, port: int) -> int:
        """How closely its local ports name `port`: 0 named, 1 in a range, 2 every port (or not covered)."""
        parts = [p.strip() for p in (self.local or "").split(",")]
        if str(port) in parts:
            return 0
        if any((m := re.fullmatch(r"(\d+)-(\d+)", p)) and int(m.group(1)) <= port <= int(m.group(2)) for p in parts):
            return 1
        return 2

    def said(self) -> dict:
        return {"id": self.id, "name": self.name, "group": self.group, "builtin": self.builtin, "enabled": self.enabled,
                "direction": self.direction, "action": self.action, "profiles": self.profiles, "program": self.program,
                "protocol": self.protocol, "local": self.local, "remotePorts": self.remote_ports, "remote": self.remote,
                "service": self.service, "package": self.package}


@dataclass(frozen=True)
class Snapshot:
    """The firewall's whole configuration as read at `at` (seconds since 1970), in `took` seconds."""
    at: float
    took: float
    profiles: tuple = ()  # {name, enabled, inbound, outbound, notify, allowInbound, logBlocked, logFile}
    networks: tuple = ()  # {index, interface, name, category, ipv4, ipv6}
    rules: tuple = ()  # WinRule
    defender: dict | None = None
    elevated: bool = False

    def profile(self, name: str) -> dict | None:
        return next((p for p in self.profiles if p["name"].lower() == str(name).lower()), None)

    @property
    def in_use(self) -> list[str]:
        """The profiles the networks this PC is on apply (Public, Private, Domain)."""
        names = {"public": "Public", "private": "Private", "domainauthenticated": "Domain"}
        return list(dict.fromkeys(names.get(n["category"].lower(), n["category"]) for n in self.networks))


def _text(v) -> str | None:
    return None if v is None else str(v)


def _mapping(value) -> dict:
    """A map the read gives (a service's or a program's, 0.4.0), by its key in lowercase: Windows' names are in any
    case; {} when the read has none (one made before 0.4.0)."""
    return {str(k).casefold(): v for k, v in value.items()} if isinstance(value, dict) else {}


def parse_snapshot(data: dict, at: float, took: float) -> Snapshot:
    """read.ps1's answer as a Snapshot (a read without the services' and programs' names, before 0.4.0, as well)."""
    rules = []
    services, programs = _mapping(data.get("Services")), _mapping(data.get("Programs"))
    for r in data.get("Rules") or []:
        group = str(r.get("Group") or "")
        source = str(r.get("GroupSource") or "")
        service, program = str(r.get("Service") or ""), str(r.get("Program") or "Any")
        info = programs.get(program.casefold())
        info = info if isinstance(info, dict) else {}
        rules.append(WinRule(
            id=str(r.get("Id") or ""), name=str(r.get("Name") or ""), group=group, builtin=source.startswith("@"),
            enabled=bool(r.get("Enabled")), direction="out" if str(r.get("Direction")) == "Outbound" else "in",
            action="block" if str(r.get("Action")) == "Block" else "allow", profiles=str(r.get("Profile") or "Any"),
            program=program, protocol=_text(r.get("Protocol")), local=_text(r.get("LocalPort")),
            remote_ports=_text(r.get("RemotePort")), remote=_text(r.get("Remote")), description=str(r.get("Description") or ""),
            source=source, service=service, owner=str(r.get("Owner") or ""), package=str(r.get("Package") or ""),
            package_system=bool(r.get("PackageSystem")),
            service_name=str((services.get(service.casefold()) if service else "") or "").strip(),
            product=str(info.get("Product") or "").strip(), file_description=str(info.get("Description") or "").strip(),
            on_disk=str(info.get("Path") or "").strip()))
    profiles = tuple({"name": str(p.get("Name")), "enabled": bool(p.get("Enabled")), "inbound": str(p.get("Inbound") or ""),
                      "outbound": str(p.get("Outbound") or ""), "notify": str(p.get("Notify") or ""),
                      "allowInbound": str(p.get("AllowInbound") or ""), "logBlocked": str(p.get("LogBlocked") or ""),
                      "logFile": str(p.get("LogFile") or "")} for p in data.get("Profiles") or [])
    networks = tuple({"index": int(n.get("Index") or 0), "interface": str(n.get("Interface") or ""), "name": str(n.get("Name") or ""),
                      "category": str(n.get("Category") or ""), "ipv4": str(n.get("IPv4") or ""), "ipv6": str(n.get("IPv6") or "")}
                     for n in data.get("Networks") or [])
    return Snapshot(at, took, profiles, networks, tuple(rules), data.get("Defender") or None, bool(data.get("Elevated")))


@dataclass(frozen=True)
class Query:
    """The rules shown: a preset, or words found (in the name, group, program, description or id), a port the rule's
    local ports cover, a direction and an action."""
    preset: str = "in-allow"
    words: str = ""
    port: int | None = None
    direction: str = ""
    action: str = ""

    @property
    def found(self) -> bool:
        return bool(self.words or self.port or self.direction or self.action)

    def matches(self, r: WinRule) -> bool:
        if not self.found:
            return PRESETS.get(self.preset, PRESETS["all"])[1](r)
        if self.direction and r.direction != self.direction:
            return False
        if self.action and r.action != self.action:
            return False
        if self.port and not r.covers(self.port):
            return False
        if self.words:
            hay = " ".join((r.name, r.group, r.program, r.description, r.id, r.service, r.package)).lower()
            return all(w in hay for w in self.words.lower().split())
        return True

    def words_said(self) -> str:
        bits = [f"“{self.words}”" if self.words else "", f"port {self.port}" if self.port else "",
                {"in": "inbound", "out": "outbound"}.get(self.direction, ""), {"allow": "allowing", "block": "blocking"}.get(self.action, "")]
        return ", ".join(b for b in bits if b) or PRESETS.get(self.preset, PRESETS["all"])[0].lower()


def when(seconds: float) -> str:
    """A time as this PC's local time (in UTC where Windows cannot localize it: a time near 1970 before Python 3.13)."""
    if not seconds:
        return "–"
    try:
        return datetime.fromtimestamp(seconds).astimezone().strftime("%b %d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return datetime.fromtimestamp(seconds, timezone.utc).strftime("%b %d %H:%M:%S UTC")


def default_of(value: str, which: str) -> str:
    """A profile's default for what comes in or goes out, in words (NotConfigured is Windows' own default)."""
    v = str(value or "").lower()
    if v in ("block", "allow"):
        return v
    return f"{DEFAULTS[which]} (Windows' default)"


def cell(text, sub=None):
    return {"text": text, "sub": sub} if sub else text


def on_off(value) -> bool | None:
    """on / off, yes / no, true / false (a form's or the command line's), None for neither."""
    v = str(value if value is not None else "").strip().lower()
    return True if v in ("on", "yes", "true", "1", "enable", "enabled") else False if v in ("off", "no", "false", "0", "disable", "disabled") else None


class RiskRefused(ValueError):
    """A change that may expose this PC, refused until the user accepts it in so many words (the page asks again)."""

    def __init__(self, message: str, accept: str = "accept_risk"):
        super().__init__(message)
        self.accept = accept


class WindowsFirewallPlugin(Firewall, WindowsNetwork):
    name = "firewall-windows"
    ICON = "wallglobe"  # a brick wall with the globe behind it (liminal-libs 1.34.0; the user's picture: "this one for windows firewall")
    SECTION = "os"  # drawn under the platform's OS plugins (liminal-platform 0.26.0)
    title = "Windows Firewall"
    about = ("Windows Defender Firewall, the networks and Microsoft Defender on this PC: every rule and profile read, "
             "queried and changed on your word (an administrator's, through UAC)"
             + ("; its Netstat, the hosts each program talks with, and the internet's infrastructure on its globe"
                if netstat_in() else ""))
    api = "2.2"
    # what it attaches to: PowerShell and UAC, NetSecurity, NetConnection, Defender, the COM policy, what names a rule,
    # the World Wide Web tab's (apis.py); and, with liminal-libs 1.65.0 (0.7.0), the socket tables and the data sets'
    # sources of the Netstat tab and the globe's layers (cards_for)
    apis = cards_for()
    order = 710
    # the base's hooks include world and world_geoip, the World Wide Web tab's page and its GeoIP file's install (0.6.0),
    # which the platform runs as a job (the base's JOB_HOOKS, kept: the plugin runs no job of its own)
    HOOKS = tuple(dict.fromkeys((*Firewall.HOOKS, "refresh", "find_rules", "show_rules", "set_rule", "remove_rule",
                                 "make_rule", "set_profile", "set_network",
                                 *NetworkHost.HOOKS, EXCLUDED)))  # 0.8.0: services' networks (network.py)
    TABS = (*Firewall.TABS, *NetworkHost.TABS)  # 0.8.0: the Networks tab after the World Wide Web and Netstat tabs
    ASKS = (*getattr(Firewall, "ASKS", ()), *NetworkHost.ASKS)
    # 0.8.0: Windows' excluded port ranges, read by anyone (the container plugins), beside both bases' reads
    READ_HOOKS = tuple(dict.fromkeys((*Firewall.READ_HOOKS, *NetworkHost.READ_HOOKS, EXCLUDED)))
    SERVICE_HOOKS = (*NetworkHost.SERVICE_HOOKS, EXCLUDED)
    # Its changes, asked only from its page (0.7.3, the review of PLT-H1's fix, 2026-11-24; liminal-libs 1.66.0's
    # apps/asking.py): another plugin's ask is refused (403), and liminal-platform 0.34.0 refuses one over HTTP (401)
    # unless its login shows that you are at the page. Before, any program on this PC could ask them with two headers:
    # on a platform run as an administrator the Public profile's firewall turned off, or a rule made letting everything
    # in, at once and with no prompt, the second confirmation (accept_risk) being only an argument. The base's allow and
    # remove among them (Liminal's own rules): the setup and the command line call their code directly, not through an
    # ask. Its reads and queries are asked by anyone, as before.
    PAGE_ONLY_HOOKS = (*NetworkHost.PAGE_ONLY_HOOKS,
                       "set_rule", "remove_rule", "make_rule", "set_profile", "set_network", "allow", "remove",
                       # 0.8.0 (service-containers-networking §8.1): the base's other changes too, its labels and moves,
                       # the hosts' recording and forgetting, the traffic's watching, the downloads; NetworkHost's own
                       # (approve_plan, the grants, the domain, Re-point…, Withdraw…) add up from its class
                       "move_rules", "new_label", "rename_label", "remove_label", "hosts_recording", "hosts_forget",
                       "world_watching", "world_geoip", "world_asn", "world_layer_get", "world_layer_remove",
                       # 0.10.0: the sgp4 package's download and removal, code the plugin then imports
                       "world_sky_get", "world_sky_remove")
    # -- the World Wide Web tab (0.6.0): its tab (TABS), its hooks and its setting (keys: LIMINAL_HOME_PLACE, home on the
    # globe) are the Firewall base's; what it reaches is named here (apis.py), since the library names no outside host
    GEOIP_URL = CITY_LITE  # DB-IP's IP to City Lite, this month's file (last month's while this month's is not out yet)
    RDAP_BOOTSTRAP = RDAP_FILES  # liminal-libs 1.72.1: the routers' networks are looked up from these
    GEOIP_LICENCE = CITY_LITE_LICENCE  # CC BY 4.0 in plain words, and the download's size: shown before it is accepted
    # liminal-libs 1.75.0: DB-IP's IP to ASN Lite beside it, each network's AS number and operator (an older library
    # offers neither)
    GEOIP_ASN_URL = ASN_LITE
    GEOIP_ASN_LICENCE = ASN_LITE_LICENCE
    ATTRIBUTION = DBIP_CREDIT  # "IP Geolocation by DB-IP", linked, wherever its places are
    # 0.9.0 (liminal-libs 1.101.0): the GeoIP sources (apis.py), places and networks chosen apart, DB-IP's the default
    # for both; their download, use and removal the base's three page-only hooks. IPinfo Lite is named, not offered.
    GEOIP_SOURCES = SOURCES
    PUBLIC_DNS = NAME_SERVERS  # OpenDNS's and Google's, asked for this network's public address: home, when you set none
    # -- the Netstat tab, the hosts database and the globe's filters and layers (0.7.0): the Firewall base's
    # (liminal-libs 1.65.0); what the layers are downloaded from is named here (apis.py's INFRASTRUCTURE:
    # OpenStreetMap's through the Overpass API, Wikidata's, EMODnet's, the Internet Topology Zoo's), each a data set the
    # user downloads on the World Wide Web tab
    INFRASTRUCTURE = DATA_SETS
    # 0.10.0 (liminal-libs 1.104.0): the sgp4 package the satellites are placed with, offered beside the data sets
    SKY_PACKAGE = SGP4_PACKAGE

    def __init__(self, powershell: PowerShell | None = None, elevated=None, clock=time.time, system: str | None = None,
                 book=None, platform: str = ""):
        self.ps = powershell if powershell is not None else PowerShell()
        self._elevated = elevated if elevated is not None else is_elevated  # a test's stand-in
        self._clock = clock
        self._system = system  # a test's (win32, linux, darwin); None: the system the platform runs on (_platform)
        self._rt = _Runtime()
        # 0.8.0: services' networks: the network database in the data folder (liminal-libs 1.96.0's netbook), opened
        # per call; a test's own book
        from liminal_libs.netbook import NetBook

        NetworkHost.__init__(self, wall=clock, book=book if book is not None else NetBook(), platform=platform)

    def app_stopping(self) -> None:
        """The platform stops: the base's (the hosts' recording ended), then its network works cancelled and joined
        and its plans forgotten (0.8.0)."""
        Firewall.app_stopping(self)
        self.network_stopping()

    def not_for_here(self) -> str:
        """Why this machine is not one the plugin is for, in words ("" when it is): Windows Defender Firewall is
        Windows' own, so off Windows (Linux, a WSL distribution among them, and macOS) the plugin is not for the
        machine at all (0.7.0; B-critique S1: never valid there, so its hosts' recording never starts beside the Linux
        firewall's, into the same hosts database). The library's Firewall base honours it: its setup, its tabs and its
        attach ask nothing and start nothing; this plugin's status, reads and changes too, and no Netstat view is made
        there (make_netstat_view), so every other hook of its two tabs is refused in words."""
        system = str(self._system if self._system is not None else _platform())
        if system.startswith(("win32", "cygwin")):
            return ""
        return f"Windows Defender Firewall is Windows' own, and this machine runs {SYSTEMS.get(system, system)}"

    def make_netstat_view(self):
        """The Firewall base's view of the Netstat tab, the hosts database and the globe's filters and layers
        (liminal-libs 1.65.0), made on Windows alone (0.7.0). Off Windows none is made, whatever asks for one: each of
        their hooks, which no page draws there but the platform still answers when asked (its ask, or another plugin's
        through the app), is refused in words (a ValueError, as the base's own refusals for a machine it is not for;
        the base refuses first where it guards a hook itself) before it reads the socket table, keeps the recording
        setting, starts recording, forgets a host or removes a layer: there the hosts database and the layers are that
        system's own firewall plugin's. Asked by the base alone (an older library has no such view)."""
        here = self.not_for_here()
        if here:
            raise ValueError(f"not for this machine: {here}")
        return super().make_netstat_view()

    # -- the read ------------------------------------------------------------------------------------------
    def read(self) -> Snapshot:
        """The whole configuration read now (one PowerShell call), kept; CommandError when it cannot be read, and off
        Windows, where nothing is run (not_for_here)."""
        here = self.not_for_here()
        if here:
            raise CommandError(f"not for this machine: {here}")
        began = time.monotonic()
        rows = self.ps.json(READ_SCRIPT.read_text(encoding="utf-8"), timeout=180)
        snap = parse_snapshot(rows[0] if rows else {}, self._clock(), time.monotonic() - began)
        with self._rt.lock:
            self._rt.snap, self._rt.error = snap, ""
        return snap

    def _read_quietly(self) -> None:
        try:
            self.read()
        except CommandError as e:
            with self._rt.lock:
                self._rt.error = str(e)
        finally:
            with self._rt.lock:
                self._rt.reader = None

    def snapshot(self, fresh: bool = False, wait: float = 0.0) -> Snapshot | None:
        """The configuration as last read; read again on a thread when it is older than READ_S (or `fresh`), waited
        for up to `wait` seconds. Off Windows nothing is read, and no thread is started for it (not_for_here)."""
        away = bool(self.not_for_here())
        with self._rt.lock:
            snap, reader = self._rt.snap, self._rt.reader
            stale = snap is None or fresh or self._clock() - snap.at > READ_S
            if stale and reader is None and not away:
                reader = self._rt.reader = threading.Thread(target=self._read_quietly, name="firewall-windows-read", daemon=True)
                reader.start()
        if reader is not None and wait > 0:
            reader.join(wait)
        with self._rt.lock:
            return self._rt.snap

    def attach(self, app, login=None) -> dict:
        interface = super().attach(app, login)
        if self.present():
            self.snapshot()  # read on a thread now, so the page's first look waits on nothing
        return interface

    def api_facts(self) -> dict:
        """What the last read found of its APIs, asking nothing (a read under way is not waited for): when it was and how
        long it took, the rules and profiles (NetSecurity), the networks (NetConnection), Defender's state; why the last
        read failed, if it did. And, once the World Wide Web tab was asked since the plugin was attached (0.6.0), whether
        it watches through Npcap and the GeoIP file it places with (_world_facts); once its Netstat view is made
        (0.7.0), the socket tables' last reading, the hosts' recording and database, and the globe's data sets
        (_netstat_facts)."""
        with self._rt.lock:
            snap, error = self._rt.snap, self._rt.error
        out: dict[str, dict[str, str]] = {}
        if snap is not None:
            on = sum(1 for r in snap.rules if r.enabled)
            out[NETSECURITY.name] = {
                "Last read": f"{when(snap.at)}, in {snap.took:.1f} s",
                "Rules": f"{len(snap.rules):,} ({on:,} on)",
                "Profiles": ", ".join(f"{p['name']} {'on' if p['enabled'] else 'off'}" for p in snap.profiles) or "none read",
                "Read as": "an administrator" if snap.elevated else "not an administrator: remote addresses from the COM policy"}
            out[NETCONNECTION.name] = {"Networks": ", ".join(f"{n['interface']} ({n['category'].lower()})" for n in snap.networks)
                                       or "none connected"}
            out[DEFENDER_API.name] = {"State": self._defender_words(snap)}
        if error:
            out.setdefault(NETSECURITY.name, {})["Last read failed"] = error
        out.update(self._world_facts())
        out.update(self._netstat_facts())
        return out

    def _world_facts(self) -> dict[str, dict[str, str]]:
        """What the World Wide Web tab knows of what it reaches (WorldView.describe), asking nothing and starting nothing:
        whether it watches through Npcap, at which adapter, or why it cannot; the packets it read; the GeoIP file it places
        with (DB-IP's), and whether it is open now (it is let go while nobody watches). Nothing before the tab was first
        asked since the plugin was attached: no view is made for this (the base's world_view(make=False))."""
        view = self.world_view(make=False)  # the Firewall base's view: made at the tab's first ask, forgotten on detach
        if not isinstance(view, WorldView):
            return {}
        d = view.describe()
        w = d.get("watching") or {}
        error = d.get("error") or w.get("error") or ""
        while_shown = f"while the World Wide Web tab is shown and for {view.timeout:g} s after"
        if w.get("running"):
            at = f", at the adapter of {d['address']}" if d.get("address") else ""
            since = f" since {when(w['started'])}" if w.get("started") else ""
            watching = f"yes{at}{since}, {while_shown}"
        elif error:
            watching = f"no: {error}"
        else:
            watching = f"no: only {while_shown}" + (f" (last until {when(w['stopped'])})" if w.get("stopped") else "")
        npcap = {"Watching": watching, "Packets read": f"{int(w.get('packets') or 0):,} in all: counted, none kept"}
        geoip = d.get("geoip")
        if geoip:
            built = ", ".join(x for x in ((f"built {geoip['date']}" if geoip.get("date") else ""),
                                          (size_words(geoip["size"]) if geoip.get("size") else "")) if x)
            file = str(geoip.get("file") or "") + (f", {built}" if built else "") + ": looked up on this PC" + (
                "" if geoip.get("open", True) else " (let go while the tab is not watched; opened again at its next ask)")
        else:
            readable, why = geo.available()
            # 0.6.1: a data folder on another system's drive (liminal-libs 1.58.0's WorldView.elsewhere: a share, a network
            # drive) holds that system's file, which the tab never reads, nor offers to install there
            elsewhere = getattr(view, "elsewhere", None)
            away = elsewhere() if callable(elsewhere) else ""
            file = (f"none read here: {away}" if away
                    else "none installed yet: the World Wide Web tab's Install the GeoIP file… downloads one once you accept "
                         "its licence" if readable else f"none can be read here: {why}")
        return {NPCAP.name: npcap, DBIP.name: {"GeoIP file": file}}

    def _netstat_facts(self) -> dict[str, dict[str, str]]:
        """What the Netstat tab, the hosts database and the globe's layers know of what they reach (0.7.0), asking
        nothing and starting nothing (the base's NetstatView.describe): the socket tables' last reading (when, how many
        sockets, how long it took), how the hosts are recorded and what the hosts database holds, under the socket
        tables' card; each data set of the globe, downloaded or not, under its source's card. Nothing with a library
        before 1.65.0 (it has no such view), nor before the plugin made its view (at its attach on this PC, or a tab's
        first ask): none is made for this (the base's netstat_view(make=False))."""
        made = getattr(self, "netstat_view", None)
        view = made(make=False) if callable(made) else None
        describe = getattr(view, "describe", None)
        if not callable(describe):
            return {}
        try:
            d = describe()
        except Exception:  # noqa: BLE001 - a view that cannot say: no facts (its tabs say why)
            return {}
        from liminal_libs import hostbook  # the library has them wherever there is a view (liminal-libs 1.65.0)
        from liminal_libs.machines import netstat

        mode = d.get("mode") if d.get("mode") in netstat.MODE_WORDS else "shown"
        recording = netstat.MODE_WORDS[mode]
        always = mode == "always" and bool(d.get("recording"))  # the recording thread reads: else the tabs' asks alone
        if mode == "always":
            recording += (f": recording now, a reading every {hostbook.ALWAYS_S:g} s" if always
                          else ", but not recording now")
        reading = d.get("reading") or None
        if reading:
            took = max(0.0, float(reading.get("took") or 0.0)) * 1000
            last = f"{when(reading.get('at') or 0)}: {int(reading.get('rows') or 0):,} sockets in {took:,.0f} ms"
        elif always:
            last = f"none yet: the socket tables are read every {hostbook.ALWAYS_S:g} s, {netstat.MODE_WORDS['always']}"
        else:
            last = f"none yet: the socket tables are read {netstat.MODE_WORDS['shown']}"
        book = d.get("book")
        if not isinstance(book, dict):
            kept = "not opened yet: it is read and written while one of the two tabs is shown, or as recording says"
        elif book.get("elsewhere"):
            kept = f"not kept from here: {book['elsewhere']}"
        else:
            kept = (f"{int(book.get('rows') or 0):,} rows ({plural(int(book.get('hosts') or 0), 'host')}, "
                    f"{plural(int(book.get('programs') or 0), 'program')}), {size_words(int(book.get('bytes') or 0))}, "
                    f"in {book.get('path') or 'the data folder'}"
                    + (f", recorded since {when(book['since'])}" if book.get("since") else ""))
            if book.get("problem"):
                kept += f"; {book['problem']}"
        sockets_facts = {"Last reading": last, "Recording": recording, "Hosts database": kept}
        if d.get("error"):
            sockets_facts["Problem"] = str(d["error"])
        out: dict[str, dict[str, str]] = {SOCKETS.name: sockets_facts}
        for s in d.get("sets") or ():
            card = DATA_SET_CARDS.get(str(s.get("format") or ""))
            if card is not None:
                out.setdefault(card, {})[str(s.get("title") or s.get("id") or "a data set")] = _data_set_words(s)
        return out

    def refresh(self) -> dict:
        """The configuration read again now (the page's Refresh)."""
        snap = self.read()
        return {"said": f"read {len(snap.rules)} rules, {len(snap.profiles)} profiles and {len(snap.networks)} network(s) in {snap.took:.1f} s",
                "ok": True}

    # -- the base's backend ---------------------------------------------------------------------------------
    def present(self) -> bool:
        """Whether Windows Defender Firewall is here to read: Windows PowerShell, on Windows alone (not_for_here)."""
        return not self.not_for_here() and self.ps.here

    def backend(self) -> str:
        return "Windows Defender Firewall"

    def _snap(self) -> Snapshot:
        snap = self.snapshot(wait=FIRST_WAIT_S * 4)
        if snap is None:
            here = self.not_for_here()
            raise CommandError(f"not for this machine: {here}" if here else
                               self._rt.error or "the configuration could not be read")
        return snap

    def state(self) -> dict:
        snap = self._snap()
        profiles = {p["name"]: p["enabled"] for p in snap.profiles}
        return {"enabled": bool(profiles) and all(profiles.values()), "profiles": profiles,
                "defaults": {p["name"]: {"inbound": p["inbound"], "outbound": p["outbound"]} for p in snap.profiles}}

    def list_rules(self, owned_only: bool = True) -> list[Rule]:
        snap = self._snap()
        out = []
        for r in snap.rules:
            if owned_only and not r.owned:
                continue
            try:
                out.append(rule_of({"Name": r.name, "Group": r.group, "Direction": "Outbound" if r.direction == "out" else "Inbound",
                                    "Action": "Block" if r.action == "block" else "Allow", "Enabled": r.enabled,
                                    "Protocol": r.protocol or "Any", "LocalPort": r.local or "Any", "RemoteAddress": r.remote or "Any",
                                    "Description": r.description}))
            except ValueError:  # one of Liminal's group under a name this framework would not give: read as another's
                continue
        return out

    def add_rule(self, rule: Rule) -> None:
        if not rule.owned:
            raise FirewallError("only Liminal's own rules are made here")
        parts = [f"New-NetFirewallRule -Group {quote(GROUP)} -DisplayName {quote(rule.label)}",
                 f"-Description {quote(rule.detail or 'made by the Liminal platform')}",
                 f"-Direction {DIRECTIONS[rule.direction]} -Action {ACTIONS[rule.action]} -Protocol {PROTOCOLS[rule.protocol]}",
                 f"-RemoteAddress {quote('Any' if rule.remote == 'any' else rule.remote)} -Profile Any",
                 f"-Enabled {'True' if rule.enabled else 'False'}"]
        if rule.ports:
            parts.append("-LocalPort " + ",".join(str(p) for p in rule.ports))
        self.ps.run_admin(" ".join(parts) + " | Out-Null")
        self.snapshot(fresh=True)

    def delete_rule(self, name: str) -> bool:
        out = self.ps.run_admin(f"$r = @(Get-NetFirewallRule -Group {quote(GROUP)} -ErrorAction SilentlyContinue | "
                                f"Where-Object {{ $_.DisplayName -eq {quote(GROUP + ': ' + name)} }}); "
                                "if ($r.Count) { $r | Remove-NetFirewallRule }; [Console]::Out.WriteLine($r.Count)")
        lines = [line.strip() for line in out.splitlines() if line.strip()]
        self.snapshot(fresh=True)
        return bool(lines) and lines[-1].isdecimal() and int(lines[-1]) > 0

    def enable(self) -> None:
        self.ps.run_admin("Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True")
        self.snapshot(fresh=True)

    def exposing(self, ports) -> list[tuple[int, str]]:
        """The enabled inbound allow rules reaching any of `ports` from another machine: by port, a range or every
        port; a rule for every port counted only when it is for any program or for Python (the apps run in it)."""
        wanted = ",".join(str(int(p)) for p in ports)
        script = (
            f"$ports = @({wanted}); "
            "Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | ForEach-Object { "
            "$rule = $_; "
            "$remote = @(($rule | Get-NetFirewallAddressFilter).RemoteAddress); "
            "if (@($remote | Where-Object { $_ -notin @('127.0.0.1', '::1') }).Count -eq 0) { return }; "
            "$pf = $rule | Get-NetFirewallPortFilter; $lp = @($pf.LocalPort); "
            "if ($lp -contains 'Any') { $program = [string](($rule | Get-NetFirewallApplicationFilter).Program); "
            "if ($program -ne 'Any' -and $program -notmatch 'python(w)?(3[0-9.]*)?\\.exe$') { return } }; "
            "foreach ($p in $ports) { "
            "$hit = ($lp -contains 'Any') -or ($lp -contains [string]$p) -or "
            "(@($lp | Where-Object { $_ -match '^(\\d+)-(\\d+)$' -and [int]$Matches[1] -le $p -and $p -le [int]$Matches[2] }).Count -gt 0); "
            "if ($hit) { [pscustomobject]@{ Port = $p; Rule = $rule.DisplayName } } } }"
        )
        return [(int(r["Port"]), str(r["Rule"])) for r in self.ps.json(script, timeout=600)]

    def run(self, *command: str, **options) -> str:
        """A PowerShell command line on this PC (Get-NetFirewallProfile; netsh advfirewall show allprofiles), its
        output, run as this process runs it and never through Windows' prompt (UAC): one Windows denies is a
        CommandError (denied), never asked again elevated, whatever LIMINAL_ELEVATE says. Only a command line asks it
        (0.7.3): no route of liminal-platform's asks it since its 0.34.1 (the review's PLT-H1)."""
        return self.ps.run(" ".join(command))

    # -- changes, each run as an administrator --------------------------------------------------------------
    def _admin(self, script: str) -> str:
        """A change run with an administrator's rights: as it is when this process has them, else through Windows' own
        prompt (UAC); the configuration read again after. Off Windows nothing is run (not_for_here)."""
        here = self.not_for_here()
        if here:
            raise CommandError(f"not for this machine: {here}")
        try:
            out = self.ps.run(script, timeout=120) if self._elevated() else self.ps.run_elevated(script)
        finally:
            try:
                self.read()  # at once: a read already under way may predate the change
            except CommandError as e:
                with self._rt.lock:
                    self._rt.error = str(e)
        return out

    def _rule(self, rid: str) -> WinRule:
        snap = self._snap()
        rule = next((r for r in snap.rules if r.id == str(rid)), None)
        if rule is None:
            raise ValueError(f"no rule with the id {rid!r} (read {when(snap.at)}; Refresh reads again)")
        return rule

    def set_rule(self, rule_id, enabled, label=None) -> dict:
        """A rule turned on or off (any rule, Windows' own too: turning it back is as easy)."""
        on = on_off(enabled)
        if on is None:
            raise ValueError(f"a rule is turned on or off, not {enabled!r}")
        rule = self._rule(rule_id)
        if rule.enabled == on:
            return {"said": f"“{rule.name}” is {'on' if on else 'off'} already", "ok": True}
        self._admin(f"Set-NetFirewallRule -Name {quote(rule.id)} -Enabled {'True' if on else 'False'}")
        now = self._rule(rule_id)
        return {"said": f"“{rule.name}” turned {'on' if now.enabled else 'off'}", "ok": now.enabled == on,
                "lines": [f"{rule.direction}bound {rule.action}, {ports_said(rule)}, {rule.program}"]}

    def remove_rule(self, rule_id, label=None) -> dict:
        """A rule removed: a rule made by a program or the user (Liminal's included), never one of Windows' own (turn
        that off instead: it comes back with Windows' updates or a reset anyway)."""
        rule = self._rule(rule_id)
        if rule.builtin:
            raise ValueError(f"“{rule.name}” is one of Windows' own rules: turn it off instead of removing it")
        self._admin(f"Remove-NetFirewallRule -Name {quote(rule.id)}")
        gone = all(r.id != rule.id for r in self._snap().rules)
        return {"said": f"“{rule.name}” removed" if gone else f"“{rule.name}” is still there", "ok": gone}

    def make_rule(self, name, direction="in", action="allow", protocol="tcp", ports=None, program=None, remote=None,
                      profiles="any") -> dict:
        """A rule made (in the rule group Liminal, so it is found as Liminal's): `ports` "80, 443" or "5000-5010" (TCP or
        UDP only), `program` a path or any, `remote` any, LocalSubnet or addresses, `profiles` any or Domain/Private/Public."""
        title = str(name or "").strip()
        if not title or len(title) > 120:
            raise ValueError("a rule needs a name (120 characters at most)")
        direction, action, protocol = str(direction or "in").lower(), str(action or "allow").lower(), str(protocol or "tcp").lower()
        if direction not in DIRECTIONS or action not in ACTIONS or protocol not in PROTOCOLS:
            raise ValueError("direction is in or out, action allow or block, protocol tcp, udp or any")
        local = str(ports or "").replace(" ", "")
        if local and protocol == "any":
            raise ValueError("ports need a protocol: tcp or udp")
        if local and not re.fullmatch(r"\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*", local):
            raise ValueError(f"ports are numbers or ranges, as 80,443 or 5000-5010, not {ports!r}")
        if local and any(not 0 < int(p) < 65536 for p in re.findall(r"\d+", local)):
            raise ValueError("a port is a number from 1 to 65535")
        chosen = [p.strip().capitalize() for p in str(profiles or "any").replace(";", ",").split(",") if p.strip()]
        if not chosen or any(p not in ("Any", *PROFILE_NAMES) for p in chosen):
            raise ValueError("profiles are any, or Domain, Private and Public")
        # Windows makes a second rule of a DisplayName already there, so "Make a rule" asked twice made two the same
        # (the review of 2026-11-21, item 26): one of Liminal's by that name is refused before anything runs, as the
        # Linux plugin and the library's Firewall.allow refuse it. Windows matches DisplayNames without case.
        if any(r.owned and r.name.casefold() == title.casefold() for r in self._snap().rules):
            raise ValueError(f"a Liminal rule named “{title}” is there already: remove it first")
        parts = [f"New-NetFirewallRule -Group {quote(GROUP)} -DisplayName {quote(title)} -Description {quote('made on the Liminal platform')}",
                 f"-Direction {DIRECTIONS[direction]} -Action {ACTIONS[action]} -Protocol {PROTOCOLS[protocol]}",
                 f"-Profile {','.join(chosen)}"]
        if local:
            parts.append(f"-LocalPort {local}")
        if program and str(program).strip().lower() != "any":
            parts.append(f"-Program {quote(str(program).strip())}")
        if remote and str(remote).strip().lower() not in ("any", "*"):
            parts.append(f"-RemoteAddress {','.join(quote(a.strip()) for a in str(remote).split(',') if a.strip())}")
        self._admin(" ".join(parts) + " | Out-Null")
        made = [r for r in self._snap().rules if r.name == title and r.owned]
        return {"said": f"“{title}” made ({direction}bound {action}{', ' + protocol.upper() + ' ' + local if local else ''})" if made
                else f"“{title}” was not found after making it", "ok": bool(made)}

    def set_profile(self, profile, enabled=None, inbound=None, outbound=None, notify=None, accept_risk=False) -> dict:
        """A profile's firewall on or off, its default for what comes in and what goes out (block, allow, or Windows'
        default), its notifications (Windows' "allow this app?" prompt). Off, or everything in by default, is refused
        until accepted in so many words (accept_risk): this PC may be the router's DMZ host."""
        name = next((p for p in PROFILE_NAMES if p.lower() == str(profile or "").lower()), None)
        if name is None:
            raise ValueError(f"a profile is Domain, Private or Public, not {profile!r}")
        current = self._snap().profile(name) or {}
        sets = []
        on = on_off(enabled) if enabled not in (None, "") else None
        if on is not None and on != current.get("enabled"):
            sets.append(f"-Enabled {'True' if on else 'False'}")
        for key, value in (("inbound", inbound), ("outbound", outbound)):
            v = str(value or "").strip().lower()
            if not v:
                continue
            if v not in ("block", "allow", "default"):
                raise ValueError(f"the default for {key} traffic is block, allow or default, not {value!r}")
            want = {"block": "Block", "allow": "Allow", "default": "NotConfigured"}[v]
            if want != current.get(key):
                sets.append(f"-Default{key.capitalize()}Action {want}")
        n = on_off(notify) if notify not in (None, "") else None
        if n is not None and (("True" if n else "False") != current.get("notify")):
            sets.append(f"-NotifyOnListen {'True' if n else 'False'}")
        if not sets:
            return {"said": f"the {name} profile is as asked already", "ok": True}
        risky = [w for w, hit in (("turns its firewall off", on is False), ("lets everything in by default", str(inbound or "").lower() == "allow")) if hit]
        if risky and not accept_risk:
            used = name in self._snap().in_use
            raise RiskRefused(f"this {' and '.join(risky)} for the {name} profile" + (", the one this PC's network uses now" if used else "")
                              + ": every program listening here could then be reached by other machines, and from the internet"
                              " when this PC is a router's DMZ host")
        self._admin(f"Set-NetFirewallProfile -Name {name} " + " ".join(sets))
        after = self._snap().profile(name) or {}
        return {"said": f"the {name} profile changed", "ok": True, "lines": [
            f"firewall {'on' if after.get('enabled') else 'off'}; inbound {default_of(after.get('inbound'), 'inbound')}; "
            f"outbound {default_of(after.get('outbound'), 'outbound')}; notifications {'on' if after.get('notify') == 'True' else 'off'}"]}

    def set_network(self, index, category, label=None, accept_risk=False) -> dict:
        """A network made private (trusted: the Private profile applies) or public (the Public profile applies). From
        Public to Private only once accepted in so many words (0.8.0, `accept_risk`), naming each rule turned on that
        Private would then let in from beyond your local subnet: this PC may be a router's DMZ host."""
        want = str(category or "").strip().capitalize()
        if want not in ("Private", "Public"):
            raise ValueError(f"a network is made private or public, not {category!r}")
        snap = self._snap()
        net = next((n for n in snap.networks if str(n["index"]) == str(index)), None)
        if net is None:
            raise ValueError(f"no network on interface {index} (read {when(snap.at)})")
        if net["category"] == want:
            return {"said": f"{net['interface']} ({net['name']}) is {want.lower()} already", "ok": True}
        if want == "Private" and accept_risk is not True:
            wide = private_wider(snap)
            raise RiskRefused(f"making {net['interface']} ({net['name']}) private turns on every rule scoped to the "
                              "Private profile for it" + (": these let in from beyond your local subnet: "
                                                          + "; ".join(wide[:12]) + (f" and {len(wide) - 12} more"
                                                                                     if len(wide) > 12 else "")
                                                          if wide else "") + ". This PC may be a router's DMZ host.")
        self._admin(f"Set-NetConnectionProfile -InterfaceIndex {int(net['index'])} -NetworkCategory {want}")
        now = next((n for n in self._snap().networks if n["index"] == net["index"]), net)
        return {"said": f"{net['interface']} ({net['name']}) is {now['category'].lower()} now", "ok": now["category"] == want,
                "lines": [f"the {now['category']} profile's rules apply to it"]}

    # -- queries --------------------------------------------------------------------------------------------
    def find_rules(self, words=None, port=None, direction=None, action=None) -> dict:
        """The rules shown, found: words in a rule's name, group, program, description or id; a port its local ports
        cover; a direction (in, out); an action (allow, block). Nothing given: the preset again."""
        d, a = str(direction or "").strip().lower(), str(action or "").strip().lower()
        if d and d not in DIRECTIONS:
            raise ValueError("a direction is in or out")
        if a and a not in ACTIONS:
            raise ValueError("an action is allow or block")
        p = None
        if port not in (None, ""):
            p = int(port)
            if not 0 < p < 65536:
                raise ValueError("a port is a number from 1 to 65535")
        with self._rt.lock:
            self._rt.query = Query(self._rt.query.preset, str(words or "").strip(), p, d, a)
            q = self._rt.query
        found = [r for r in self._snap().rules if q.matches(r)]
        return {"said": f"{plural(len(found), 'rule')} found: {q.words_said()}", "ok": True}

    def show_rules(self, preset) -> dict:
        """The rules shown by a preset (the table's choices); a search found before is set aside."""
        if preset not in PRESETS and preset != "found":
            raise ValueError(f"the rules shown are {', '.join(PRESETS)}, not {preset!r}")
        with self._rt.lock:
            q = self._rt.query
            self._rt.query = q if preset == "found" else Query(preset)
        return {"said": f"showing {PRESETS.get(preset, ('found',))[0].lower()}", "ok": True}

    def sorted_rules(self) -> dict[str, Sorted]:
        """Every rule read, by its key (its id's), with its own group and name (sort_rules): what a move checks."""
        return {key_of(rid): s for rid, s in self._sorted(self._rt.snap).items()}

    def _sorted(self, snap: Snapshot | None) -> dict[str, Sorted]:
        """`snap`'s rules by their id, each with its own group and name (sort_rules): worked out once for each read."""
        if snap is None:
            return {}
        with self._rt.lock:
            done = self._rt.sorted
        if done is not None and done[0] is snap:
            return done[1]
        found = sort_rules(snap.rules)
        with self._rt.lock:
            if self._rt.snap is snap:
                self._rt.sorted = (snap, found)
        return found

    def rules_shown(self, snap: Snapshot | None = None) -> tuple[Query, list[WinRule]]:
        """The rules the table lists: those the query matches (those turned off too, 0.4.0), each turned on before those
        turned off; for a port, the rules naming it first, then ranges, then every port (a rule for every port covers it
        too, for its program)."""
        with self._rt.lock:
            q = self._rt.query
        snap = snap if snap is not None else self._rt.snap
        found = [r for r in (snap.rules if snap else ()) if q.matches(r)]
        found.sort(key=lambda r: (r.cover_rank(q.port) if q.port else 0, not r.enabled))
        return q, found

    # -- what the platform's page shows ---------------------------------------------------------------------
    def status(self) -> dict:
        here = self.not_for_here()
        if here:  # 0.7.0: off Windows, asked nothing and offered nothing, as the library's Firewall base says it
            return self.not_here_status(here, backend="", enabled=False)
        if not self.present():
            return {"present": False, "backend": "", "enabled": False, "summary": "not present", "valid": False,
                    "why": "not present: Windows Defender Firewall is Windows'"}
        snap = self.snapshot(wait=FIRST_WAIT_S)
        if snap is None:
            reading = self._rt.reader is not None
            why = self._rt.error or ("reading the configuration" if reading else "not read yet")
            return {"present": True, "backend": self.backend(), "enabled": False, "valid": reading and not self._rt.error,
                    "summary": f"cannot be read: {why}" if self._rt.error else "reading its configuration…",
                    **({"why": f"cannot be read: {why}"} if self._rt.error else {})}
        problems = []
        off = [p["name"] for p in snap.profiles if not p["enabled"]]
        if off:
            problems.append(f"the firewall is off for {', '.join(off)}" + (" (the profile in use)" if set(off) & set(snap.in_use) else "")
                            + ": its setup, or Change… on its profile, turns it on")
        open_in = [p["name"] for p in snap.profiles if p["inbound"].lower() == "allow"]
        if open_in:
            problems.append(f"everything is let in by default for {', '.join(open_in)}")
        try:
            wanted = self.wanted()
        except Exception:  # noqa: BLE001 - no login file to read: nothing the framework needs
            wanted = []
        have = {r.name for r in self.list_rules()}
        missing = [w.name for w in wanted if w.name not in have]
        if missing:
            problems.append(f"{len(missing)} of the framework's rules missing: its setup adds them")
        rules = snap.rules
        inbound_allowed = sum(1 for r in rules if r.direction == "in" and r.action == "allow" and r.enabled)
        remote_read = sum(1 for r in rules if r.remote is not None)
        on = [p["name"] for p in snap.profiles if p["enabled"]]
        out = {
            "present": True, "valid": True, "backend": self.backend(), "enabled": bool(snap.profiles) and not off,
            "summary": (f"{self.backend()}: {'on' if not off else 'off for ' + ', '.join(off)}; "
                        f"{', '.join(snap.in_use) or 'no'} network in use; {len(rules)} rules ({inbound_allowed} letting in)"),
            "firewall": ("on for " + ", ".join(on)) + (f"; off for {', '.join(off)}" if off else "") if on else "off for every profile",
            "networkInUse": "; ".join(f"{n['interface']}: {n['name']} ({n['category'].lower()})" for n in snap.networks) or "none",
            "inbound": "; ".join(f"{p['name']} {default_of(p['inbound'], 'inbound')}" for p in snap.profiles),
            "notifications": "; ".join(f"{p['name']} {'on' if p['notify'] == 'True' else 'off'}" for p in snap.profiles),
            "ruleCount": f"{len(rules)}: {inbound_allowed} letting in, {sum(1 for r in rules if r.owned)} Liminal's, "
                         f"{sum(1 for r in rules if not r.enabled)} turned off",
            "remoteAddresses": (f"read for every rule" if remote_read == len(rules) else
                                f"read for {remote_read} of {len(rules)} rules (an administrator reads them all)"),
            "defender": self._defender_words(snap),
            "administrator": "yes: changes are made at once" if snap.elevated or self._elevated() else "no: Windows asks for an administrator's permission (UAC) for each change",
            "readAt": f"{when(snap.at)} in {snap.took:.1f} s",
            "tables": [self._networks_table(snap), self._profiles_table(snap), self._rules_table()],
            "forms": self._forms(snap),
            "actions": [{"hook": "refresh", "args": [], "title": "Read again", "note": "reads the whole configuration now"}],
        }
        if problems:
            out["problem"] = "; ".join(problems)
        return out

    @staticmethod
    def _defender_words(snap: Snapshot) -> str:
        d = snap.defender
        if not d:
            return "not read (another antivirus may hold its place)"
        signatures = d.get("Signatures") or ""
        return (f"antivirus {'on' if d.get('Antivirus') else 'off'}, real-time protection {'on' if d.get('RealTime') else 'OFF'}"
                + (f", signatures of {signatures.replace('T', ' ')[:16]}" if signatures else ""))

    def _networks_table(self, snap: Snapshot) -> dict:
        rows = []
        for n in snap.networks:
            other = "Private" if n["category"] == "Public" else "Public"
            rows.append([n["interface"], n["name"], cell(n["category"].lower(), f"the {'Domain' if n['category'] == 'DomainAuthenticated' else n['category']} profile applies"),
                         f"IPv4 {n['ipv4']}, IPv6 {n['ipv6']}",
                         {"form": "network", "title": f"Make {other.lower()}", "values": {"index": n["index"], "category": other,
                          "label": f"{n['interface']}: {n['name']}"}, "label": f"Make {n['interface']} {other.lower()}"}
                         if n["category"] in ("Public", "Private") else "–"])
        return {"title": "Networks", "note": "the profile of each network's category applies to it: private for a trusted one, public otherwise",
                "columns": [{"title": "Interface"}, {"title": "Network"}, {"title": "Category"}, {"title": "Connectivity"}, {"title": ""}],
                "rows": rows, "empty": "No network is connected."}

    def _profiles_table(self, snap: Snapshot) -> dict:
        used = snap.in_use
        rows = [[p["name"], cell("on" if p["enabled"] else "OFF", None if p["enabled"] else "nothing is filtered"),
                 default_of(p["inbound"], "inbound"), default_of(p["outbound"], "outbound"),
                 "on" if p["notify"] == "True" else "off",
                 ", ".join(n["interface"] for n in snap.networks if (n["category"] == p["name"] or (n["category"] == "DomainAuthenticated" and p["name"] == "Domain"))) or "–",
                 {"form": "profile", "title": "Change…", "values": {
                     "profile": p["name"], "enabled": "on" if p["enabled"] else "off",
                     "inbound": p["inbound"].lower() if p["inbound"].lower() in ("block", "allow") else "default",
                     "outbound": p["outbound"].lower() if p["outbound"].lower() in ("block", "allow") else "default",
                     "notify": "on" if p["notify"] == "True" else "off"}, "label": f"Change the {p['name']} profile"}]
                for p in snap.profiles]
        return {"title": "Profiles", "note": f"in use: {', '.join(used) or 'none'}; inbound blocked by default lets in only what a rule allows",
                "columns": [{"title": "Profile"}, {"title": "Firewall"}, {"title": "Inbound"}, {"title": "Outbound"},
                            {"title": "Notifications"}, {"title": "Used by"}, {"title": ""}], "rows": rows}

    def _rules_table(self) -> dict:
        """The rules shown, in their groups (0.3.0): System, Application, Other and the user's labels; in System and
        Application a heading for each service and application (0.4.0), each listing its first ROWS; a rule's group and
        name found by sort_rules, or the group where the user moved it. A rule turned off is listed too, after those
        turned on, marked for the page to show it dimmed."""
        snap = self._rt.snap
        q, found = self.rules_shown(snap)
        own = self._sorted(snap)
        rows = []
        for r in found:
            label = f"{r.name} ({r.id})"
            tied = (f"service {r.service}" if r.service else f"app {r.package.split('_')[0]}" if r.package
                    else "an app's own rule" if r.owner and r.program in ("", "Any") else None)
            cells = [cell(r.name, r.group or None), r.direction, r.action, ports_said(r), cell(r.program, tied),
                     "not read" if r.remote is None else ("any" if r.remote in ("*", "Any") else r.remote), r.profiles,
                     "on" if r.enabled else "off",
                     {"form": "rule-state", "title": "Turn off" if r.enabled else "Turn on",
                      "values": {"rule_id": r.id, "enabled": "off" if r.enabled else "on", "label": label},
                      "label": f"Turn {'off' if r.enabled else 'on'} {r.name}"},
                     {"form": "rule-remove", "title": "Remove", "values": {"rule_id": r.id, "label": label}, "label": f"Remove {r.name}"}
                     if not r.builtin else "–"]
            s = own.get(r.id) or sort_rule(r)
            rows.append((key_of(r.id), s, cells) if r.enabled else (key_of(r.id), s, cells, {"off": True}))
        every = snap.rules if snap else ()
        choices = [{"value": k, "title": t, "note": counted([x for x in every if f(x)])} for k, (t, f) in PRESETS.items()]
        if q.found:
            choices.append({"value": "found", "title": "Found", "note": q.words_said()})
        off = sum(1 for r in found if not r.enabled)
        base = {"title": "Rules",
                "note": (f"{len(found)} shown{f' ({off} turned off)' if 0 < off < len(found) else ''}: {q.words_said()}; "
                         "moving a rule to another group changes nothing in the firewall"),
                "options": [{"title": "Rules shown", "hook": "show_rules", "value": "found" if q.found else q.preset, "choices": choices}],
                "columns": [{"title": "Rule"}, {"title": "Direction"}, {"title": "Action"}, {"title": "Protocol and ports"},
                            {"title": "Program"}, {"title": "Remote"}, {"title": "Profiles"}, {"title": "State"}, {"title": ""}, {"title": ""}],
                "empty": "No rule shown: another choice, or Find, lists more.",
                "actions": [{"form": "rule-add", "title": "Add a rule…"}, {"form": "find", "title": "Find…",
                             "values": {"words": q.words, "port": q.port, "direction": q.direction, "action": q.action}},
                            {"hook": "refresh", "args": [], "title": "Read again", "note": "reads the whole configuration now"}]}
        return self.groups.table(base, rows, per_group=ROWS, notes=GROUP_NOTES)

    def _forms(self, snap: Snapshot) -> list[dict]:
        uac = "" if snap.elevated or self._elevated() else " " + UAC
        yes_no = [{"value": "on", "title": "on"}, {"value": "off", "title": "off"}]
        defaults = [{"value": "block", "title": "block"}, {"value": "allow", "title": "allow"},
                    {"value": "default", "title": "Windows' default"}]
        return [*self.groups.forms(),
            {"id": "rule-state", "hook": "set_rule", "title": "Turn a rule on or off",
             "fields": [{"name": "rule_id", "label": "Id", "type": "fixed"}, {"name": "enabled", "label": "Turned", "type": "fixed"},
                        {"name": "label", "label": "Rule", "type": "fixed"}],
             "confirm": {"title": "Turn this rule {enabled}?", "words": "{label} is turned {enabled}." + uac, "yes": "Turn it"}},
            {"id": "rule-remove", "hook": "remove_rule", "title": "Remove a rule",
             "fields": [{"name": "rule_id", "label": "Id", "type": "fixed"}, {"name": "label", "label": "Rule", "type": "fixed"}],
             "confirm": {"title": "Remove this rule?", "words": "{label} is removed for good (turning it off keeps it)." + uac,
                         "yes": "Remove it", "danger": True}},
            {"id": "rule-add", "hook": "make_rule", "title": "Add a rule",
             "note": "Made in the rule group Liminal, so it is found as Liminal's.",
             "fields": [{"name": "name", "label": "Name", "type": "text", "required": True, "placeholder": "Liminal path check 8795"},
                        {"name": "direction", "label": "Direction", "type": "choice", "value": "in",
                         "choices": [{"value": "in", "title": "inbound", "note": "what other machines send here"},
                                     {"value": "out", "title": "outbound", "note": "what this PC sends out"}]},
                        {"name": "action", "label": "Action", "type": "choice", "value": "allow",
                         "choices": [{"value": "allow", "title": "allow"}, {"value": "block", "title": "block"}]},
                        {"name": "protocol", "label": "Protocol", "type": "choice", "value": "tcp",
                         "choices": [{"value": "tcp", "title": "TCP"}, {"value": "udp", "title": "UDP"}, {"value": "any", "title": "any"}]},
                        {"name": "ports", "label": "Local ports", "type": "text", "placeholder": "8795, or 5000-5010", "empty": "every port",
                         "when": {"protocol": ["tcp", "udp"]}},
                        {"name": "program", "label": "Program", "type": "text", "placeholder": r"C:\Path\to\program.exe", "empty": "any program"},
                        {"name": "remote", "label": "From / to", "type": "text", "placeholder": "LocalSubnet, or 203.0.113.0/24", "empty": "anywhere"},
                        {"name": "profiles", "label": "Profiles", "type": "choice", "value": "any",
                         "choices": [{"value": "any", "title": "every profile"}, {"value": "Public", "title": "Public"},
                                     {"value": "Private", "title": "Private"}, {"value": "Domain", "title": "Domain"},
                                     {"value": "Private,Domain", "title": "Private and Domain"}]}],
             "submit": "Review",
             "confirm": {"title": "Make this rule?", "words": "“{name}”: {direction} {action}, {protocol} {ports}, {program}, from/to {remote}, "
                                                              "{profiles}." + uac, "yes": "Make it"}},
            {"id": "find", "hook": "find_rules", "title": "Find rules", "confirm": False,
             "note": "Words are looked for in a rule's name, group, program, description and id; a port in its local ports.",
             "fields": [{"name": "words", "label": "Words", "type": "text", "placeholder": "python, Remote Desktop, svchost"},
                        {"name": "port", "label": "Port", "type": "number", "min": 1, "max": 65535},
                        {"name": "direction", "label": "Direction", "type": "choice", "value": "",
                         "choices": [{"value": "", "title": "either"}, {"value": "in", "title": "inbound"}, {"value": "out", "title": "outbound"}]},
                        {"name": "action", "label": "Action", "type": "choice", "value": "",
                         "choices": [{"value": "", "title": "either"}, {"value": "allow", "title": "allow"}, {"value": "block", "title": "block"}]}],
             "submit": "Find"},
            {"id": "profile", "hook": "set_profile", "title": "Change a profile",
             "fields": [{"name": "profile", "label": "Profile", "type": "fixed"},
                        {"name": "enabled", "label": "Firewall", "type": "choice", "choices": yes_no},
                        {"name": "inbound", "label": "Inbound by default", "type": "choice", "choices": defaults,
                         "note": "block lets in only what a rule allows (Windows' default)"},
                        {"name": "outbound", "label": "Outbound by default", "type": "choice", "choices": defaults,
                         "note": "allow lets out all but what a rule blocks (Windows' default)"},
                        {"name": "notify", "label": "Notifications", "type": "choice", "choices": yes_no,
                         "note": "Windows asks whether a program it blocks may accept connections"},
                        {"name": "accept_risk", "type": "accept", "title": "Expose this PC?", "yes": "Change it anyway",
                         "words": ("With the firewall off, or everything let in by default, every program listening here can be reached by "
                                   "other machines on the network, and from the internet when this PC is a router's DMZ host.")}],
             "submit": "Review",
             "confirm": {"title": "Change the {profile} profile?", "words": "Firewall {enabled}; inbound {inbound}; outbound {outbound}; "
                                                                           "notifications {notify}." + uac, "yes": "Change it"}},
            {"id": "network", "hook": "set_network", "title": "Make a network private or public",
             "fields": [{"name": "index", "label": "Interface", "type": "fixed"}, {"name": "category", "label": "Made", "type": "fixed"},
                        {"name": "label", "label": "Network", "type": "fixed"},
                        {"name": "accept_risk", "type": "accept", "title": "Trust this network?", "yes": "Make it private",
                         "words": ("Every rule scoped to the Private profile then applies to it, those letting in from "
                                   "beyond your local subnet among them (named above).")}],
             "confirm": {"title": "Make this network {category}?",
                         "words": "{label} is made {category}: the {category} profile's rules apply to it." + uac, "yes": "Make it so"}},
        ]


def private_wider(snap: Snapshot) -> list[str]:
    """The rules turned on that let in, on the Private profile (or every profile), from beyond the local subnet: what
    making a network private turns on for it (0.8.0)."""
    out = []
    for r in snap.rules:
        if not (r.enabled and r.direction == "in" and r.action == "allow"):
            continue
        profiles = (r.profiles or "Any").lower()
        if "private" not in profiles and "any" not in profiles and "all" not in profiles:
            continue
        remote = (r.remote or "Any").strip().lower()
        if remote in ("localsubnet", "127.0.0.1", "::1") or remote is None:
            continue
        out.append(f"{r.name} ({ports_said(r)}, from {r.remote or 'anywhere'})")
    return out


def _expanded(program: str, windir: str = WINDIR) -> str:
    """A program's path as Windows runs it, in lowercase: its variables for Windows' folder expanded
    (%SystemRoot%\\system32\\svchost.exe -> c:\\windows\\system32\\svchost.exe)."""
    p = str(program or "").strip().strip('"')
    for var, value in (("%systemroot%", windir), ("%windir%", windir), ("%systemdrive%", windir[:2])):
        if p.lower().startswith(var):
            p = value + p[len(var):]
    return p.lower()


# -- each rule's group and name ------------------------------------------------------------------------------------

GUID = re.compile(r"\{?[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\}?", re.I)
PACKAGE_FOLDER = re.compile(r"([A-Za-z0-9.\-]+)_[^_]*_[^_]*_[^_]*_([a-z0-9]{13})", re.I)  # Name_Version_Arch_Resource_Publisher
FAMILY_FOLDER = re.compile(r"([A-Za-z0-9.\-]+)_([a-z0-9]{13})", re.I)  # Name_Publisher: Windows' own apps' (SystemApps\...)
WINDOWS_PUBLISHER = "cw5n1h2txyewy"  # the publisher id of Windows' own app packages (Microsoft Windows'), ending their family
FOLDERS = (  # a path's variables for the folders programs are installed in (the user's own: any user's)
    ("%programfiles(x86)%", r"C:\Program Files (x86)"), ("%programfiles%", r"C:\Program Files"),
    ("%programw6432%", r"C:\Program Files"), ("%programdata%", r"C:\ProgramData"), ("%allusersprofile%", r"C:\ProgramData"),
    ("%localappdata%", r"C:\Users\*\AppData\Local"), ("%appdata%", r"C:\Users\*\AppData\Roaming"), ("%userprofile%", r"C:\Users\*"))
VENDORS = frozenset({  # an install folder holding a vendor's several products: a program is named by the folder inside it
    "microsoft", "microsoft shared", "common files", "google", "jetbrains", "dassault systemes", "dell", "vmware",
    "nvidia corporation", "intel", "intel corporation", "amd", "adobe", "autodesk", "oracle", "apple", "hp", "lenovo",
    "asus", "logitech", "razer", "corsair", "realtek", "electronic arts", "ea games", "epic games", "origin games", "ubisoft",
    "blizzard entertainment", "modifiablewindowsapps"})
LIBRARIES = (  # a launcher's library of applications, each in a folder of its own inside it: that folder names it
    ("steamapps", "common"), ("gog galaxy", "games"), ("ubisoft game launcher", "games"), ("jetbrains", "toolbox", "apps"),
    ("xboxgames",))
WINDOWS_PROGRAM_FILES = frozenset({  # Windows' own components installed under Program Files: a resource in them is Windows'
    "windows media player", "windows defender", "windows defender advanced threat protection", "windows mail",
    "windows photo viewer", "windows nt", "windows portable devices", "windows sidebar", "windows security",
    "windows journal", "windows multimedia platform", "internet explorer", "windowspowershell"})


def readable(text) -> bool:
    """Whether a name Windows gave (a rule group, a rule's name) reads as words: not empty, not a resource it did not
    resolve (@FirewallAPI.dll,-28502; @{Package?ms-resource://...}; ms-resource:AppDisplayName), not a bare GUID
    ({00000000-1111-2222-3333-...})."""
    t = str(text or "").strip()
    return bool(t) and not t.startswith("@") and not t.casefold().startswith("ms-resource:") and not GUID.fullmatch(t)


def windows_package(family: str) -> bool:
    """Whether an app package family (Name_Publisher) is one of Windows' own: published by Microsoft Windows (its
    publisher id cw5n1h2txyewy), signed as the system's or not, installed or an earlier version's left behind."""
    return "_" in str(family or "") and str(family).rsplit("_", 1)[1].casefold() == WINDOWS_PUBLISHER


def _components(path: str, windir: str = WINDIR) -> list[str]:
    """A path's folders and file, its variables expanded (Windows' folder, the folders programs are installed in)."""
    p = str(path or "").strip().strip('"').replace("/", "\\")
    low = p.lower()
    for var, value in (("%systemroot%", windir), ("%windir%", windir), ("%systemdrive%", windir[:2]), *FOLDERS):
        if low.startswith(var):
            p = value + p[len(var):]
            break
    return [c for c in p.split("\\") if c]


def windows_resource(source: str, windir: str = WINDIR) -> bool:
    """Whether a rule group as Windows keeps it (WinRule.source) is a resource of Windows' own: "@<file>,-<number>" with
    the file a bare name (Windows looks it up in its own folder: @FirewallAPI.dll,-25000, @peerdistsh.dll,-1), a path in
    Windows' folder (@%SystemRoot%\\system32\\vmms.exe,-1), or a path in one of Windows' own components installed under
    Program Files or Program Files (x86) (@%ProgramFiles%\\Windows Media Player\\wmploc.dll,-1). Not a program's own
    resource anywhere else (@C:\\Program Files\\Vendor\\app.dll,-1), an app package's (@{...}), or a group's plain name."""
    s = str(source or "").strip()
    if not s.startswith("@") or s.startswith("@{"):
        return False
    m = re.fullmatch(r"@(.+?)(?:,\s*-?\d+)?", s)
    file = (m.group(1) if m else "").strip().strip('"')
    if not file:
        return False
    if not any(c in file for c in "\\/:"):
        return True
    parts = [c.casefold() for c in _components(file, windir)]
    home = [c.casefold() for c in _components(windir, windir)]
    if len(parts) > len(home) and parts[:len(home)] == home:
        return True
    return len(parts) > 3 and parts[1] in ("program files", "program files (x86)") and parts[2] in WINDOWS_PROGRAM_FILES


def package_of(program: str, windir: str = WINDIR) -> tuple[str, str]:
    """For a program in an app package's folder (...\\WindowsApps\\Name_Version_Arch_Resource_Publisher\\..., or one of
    Windows' own apps' ...\\SystemApps\\Name_Publisher\\...): its package family (Name_Publisher) and the family's own
    name part; ("", "") for any other program."""
    parts = _components(program, windir)
    for i in range(len(parts) - 2):
        if parts[i].casefold() in ("windowsapps", "systemapps"):
            m = PACKAGE_FOLDER.fullmatch(parts[i + 1]) or FAMILY_FOLDER.fullmatch(parts[i + 1])
            if m:
                return f"{m.group(1)}_{m.group(2)}", m.group(1)
    return "", ""


def _install_at(parts: list[str]) -> int | None:
    """Where in a path's folders the one a program is installed in is (install_folder); None for none."""
    low = [c.casefold() for c in parts]
    start = next((i + len(m) for i in range(len(low)) for m in LIBRARIES if tuple(low[i:i + len(m)]) == m), None)
    if start is None and len(low) > 2 and low[1] in ("program files", "program files (x86)", "programdata"):
        if low[1:3] == ["programdata", "package cache"]:  # installers kept for repairs: none is installed there
            return None
        start = 2
    if start is None and len(low) > 5 and low[1] == "users" and low[3] == "appdata" and low[4] in ("local", "roaming"):
        if low[4:6] == ["local", "temp"]:  # a temporary folder: no program is installed there
            return None
        start = 6 if low[4] == "local" and low[5] == "programs" else 5
    if start is None or start >= len(parts) - 1:
        return None
    while start + 1 < len(parts) - 1 and (low[start] in VENDORS or low[start + 1].startswith(low[start] + " ")):
        start += 1
    return None if low[start] == "windowsapps" else start  # an app's alias (...\Microsoft\WindowsApps\x.exe): no folder of its own


def install_folder(program: str, windir: str = WINDIR) -> str:
    """The folder a program is installed in, by its name as the path spells it: the one under Program Files, Program
    Files (x86), ProgramData, or a user's AppData\\Local\\Programs, AppData\\Local or AppData\\Roaming (C:\\Program Files
    (x86)\\Steam\\bin\\helper.exe: Steam), one deeper when that one is a vendor's holding several products (C:\\Program
    Files\\Google\\Chrome\\...: Chrome) or the one inside starts with its name (Contoso\\Contoso Paint\\...); an
    application's own in a launcher's library (LIBRARIES: ...\\steamapps\\common\\<game>\\..., ...\\GOG Galaxy\\Games\\
    <game>\\..., ...\\Ubisoft Game Launcher\\games\\<game>\\..., ...\\JetBrains\\Toolbox\\apps\\<IDE>\\..., the Xbox
    app's ...\\XboxGames\\<game>\\...). "" for a program in none of them, right in one, or in a temporary folder
    (AppData\\Local\\Temp) or the installers' cache (ProgramData\\Package Cache)."""
    parts = _components(program, windir)
    at = _install_at(parts)
    return "" if at is None else parts[at]


def _key(parts) -> str:
    """A path's folders as a key: in lowercase, a user's own folder as any user's (C:\\Users\\someone: c:\\users\\*)."""
    low = [c.casefold() for c in parts]
    if len(low) > 2 and low[1] == "users":
        low[2] = "*"
    return "\\".join(low)


def _home(program: str, windir: str = WINDIR) -> str:
    """Where a program lives, as a key (_key): the path of the folder it is installed in (install_folder), else of the
    folder holding it; "" for a bare file name."""
    parts = _components(program, windir)
    at = _install_at(parts)
    return _key(parts[:at + 1]) if at is not None else _key(parts[:-1]) if len(parts) > 1 else ""


def _stem(family: str) -> str:
    """An app package family without the numbers in its name, by which its versions are known: Windows' own parts get a
    new family with each update (MicrosoftWindows.10000001.Sample_cw5n1h2txyewy, then
    MicrosoftWindows.20000002.Sample_cw5n1h2txyewy: microsoftwindows.sample_cw5n1h2txyewy)."""
    name, _, publisher = str(family).casefold().rpartition("_")
    return ".".join(p for p in name.split(".") if not p.isdecimal()) + "_" + publisher


def families_of(rules, windir: str = WINDIR) -> dict[str, str]:
    """Each app package family's name as its own rules carry it (their rule group read as words, the one most of them
    carry), by the family in lowercase: what names an app's rules for its programs, whose own group is a GUID. A family
    whose rules carry none (an earlier version's left behind: Windows no longer reads its group, a resource of a
    package it no longer has) is named as the family of the same publisher and the same name but for its numbers
    (_stem) is, when one is."""
    seen: dict[str, Counter] = {}
    every: set[str] = set()
    for r in rules:
        family = (r.package or package_of(r.program, windir)[0]).casefold()
        if not family:
            continue
        every.add(family)
        if not r.owned and readable(r.group):
            seen.setdefault(family, Counter())[r.group] += 1
    named = {f: c.most_common(1)[0][0] for f, c in seen.items()}
    stems: dict[str, Counter] = {}
    for f, c in seen.items():
        stems.setdefault(_stem(f), Counter()).update(c)
    for f in sorted(every - set(named)):
        if _stem(f) in stems:
            named[f] = stems[_stem(f)].most_common(1)[0][0]
    return named


@dataclass(frozen=True)
class Names:
    """What the read taken whole knows that names a rule (sort_rules), each by a key in lowercase: an app package
    family's name as its rules carry it (`families`: families_of); the rule group the other rules for a program carry
    (`programs`, by its path: _key), and the one group the rules for the programs in a folder carry (`folders`, by the
    folder: _home); the name the rules of an app package (by its family) or of the programs in a folder outside the
    install folders (by the folder) carry (`units`: their own names, else their programs' product names). Empty for a
    rule sorted alone."""
    families: dict = field(default_factory=dict)
    programs: dict = field(default_factory=dict)
    folders: dict = field(default_factory=dict)
    units: dict = field(default_factory=dict)


def _unbracketed(name: str) -> str:
    """A rule's name without the part in brackets at its end (Contoso Photos (Inbound): Contoso Photos)."""
    return re.sub(r"\s*\([^()]*\)\s*$", "", name).strip() or name.strip()


def _own_name(r: WinRule) -> str:
    """A rule's own name as an application's, without the part in brackets at its end (Contoso Quest (TCP-In): Contoso
    Quest); "" for one that does not read as words (readable) or carries an identifier or a path (TCP Query
    User{...}C:\\...)."""
    name = _unbracketed(str(r.name or ""))
    return name if readable(name) and not GUID.search(name) and not re.search(r"[A-Za-z]:\\|\\\\", name) else ""


def _system_name(r: WinRule, program: str, windir: str, names: Names) -> str:
    """A System rule's service, as its heading shows it: Windows' rule group when it reads as words; for one of Windows'
    own app packages (an app's own rule, or a program in its folder), the name the family's rules carry (families_of),
    else Windows' own apps; its Windows service's display name (its short name in a read before 0.4.0); System process;
    its program's description, else its file name."""
    if readable(r.group):
        return r.group
    family = r.package or (package_of(program, windir)[0] if program.lower() not in ("", "any", "system") else "")
    if family:
        if names.families.get(family.casefold()):
            return names.families[family.casefold()]
        if (r.package and r.package_system) or windows_package(family):
            return "Windows' own apps"
    if r.service:
        return r.service_name or r.service
    low = program.lower()
    if low == "system":
        return "System process"
    if low not in ("", "any"):
        return r.file_description or ntpath.basename(r.on_disk or program)
    return ""


def _application_name(r: WinRule, program: str, windir: str, names: Names) -> str:
    """An Application rule's application, as its heading shows it: Liminal for Liminal's rules; its rule group when it
    reads as words; for a program, the group its other rules carry; in an app package's folder, the name its family's
    rules carry, else the one its rules carry (their own names, else their programs' product names: Names.units); in an
    install folder, the group its folder's other programs' rules carry, else the folder's name (install_folder);
    elsewhere, the group or the name its folder's rules carry; else its own name, its product name, its file name. For
    an app's own rule with no program: the name its family's rules carry, else its own name read as words without the
    part in brackets, else the family's own name part. Each fallback decided for the family or the folder in
    sort_rules, not for each program file: one name for an application's programs and versions."""
    if r.owned:
        return "Liminal"
    if readable(r.group):
        return r.group
    if program.lower() not in ("", "any", "system"):
        path = r.on_disk or program
        carried = names.programs.get(_key(_components(program, windir)))
        if carried:
            return carried
        family, part = package_of(path, windir)
        if family:
            f = family.casefold()
            return names.families.get(f) or names.units.get(f) or _own_name(r) or r.product or part
        home, folder = _home(path, windir), install_folder(path, windir)
        if folder:
            return names.folders.get(home) or folder
        return (names.folders.get(home) or names.units.get(home) or _own_name(r) or r.product
                or ntpath.basename(path))
    if r.package or r.owner:
        f = r.package.casefold()
        return (names.families.get(f) or names.units.get(f) if f else "") or _own_name(r) or r.package.split("_")[0]
    return ""


def sort_rule(r: WinRule, windir: str = WINDIR, names: Names | None = None) -> Sorted:
    """A Windows rule's own group, why, and its name in the group (the user: "groups, like system or application and then
    unassociated rules not tied to a specific application or system process can be in an other"; 0.4.0: "try best to
    organize under system and applications"; "try to group the system by 'services'"). Liminal's: an application's
    (Liminal's apps). An app container's (a Microsoft Store app's): an application's, Windows' own when its package is
    (signed as the system's, or published by Microsoft Windows: windows_package, an earlier version's left behind too).
    A Windows service's, the System process', a program's in Windows' folder or in the folder of one of Windows' own app
    packages, and Windows' own rule groups (a resource of Windows' own for their name: windows_resource), even for a
    program under Program Files (Windows Media Player's): the system's. Another program's: an application's. Tied to
    none of these: other. A System rule is named by its service (_system_name), an Application rule by its application
    (_application_name); `names` is what the read taken whole knows (sort_rules); an Other rule has no name."""
    program = (r.program or "").strip()
    low = program.lower()
    in_windows = _expanded(program, windir).startswith(windir.lower() + "\\")
    windows_group = windows_resource(r.source, windir)
    known = names if names is not None else Names()

    def system(why: str) -> Sorted:
        return Sorted("system", why, _system_name(r, program, windir, known))

    def application(why: str) -> Sorted:
        return Sorted("application", why, _application_name(r, program, windir, known))

    if r.owned:
        return application("Liminal's: made on the platform")
    if r.package:
        app = r.package.split("_")[0]
        return system(f"Windows' own app {app}") if r.package_system or windows_package(r.package) else application(f"the app {app}")
    if r.service:
        if low not in ("", "any", "system") and not in_windows and not windows_group:
            return application(f"the service {r.service}, run by {program}")
        return system(f"the Windows service {r.service}")
    if low == "system":
        return system("the System process: Windows' kernel")
    if low not in ("", "any"):
        if in_windows:
            return system(f"{ntpath.basename(program)}, in Windows' folder")
        if windows_group:  # Windows' own, its program under Program Files
            return system((f"Windows' own rule group {r.group}" if r.group else "one of Windows' own rules")
                          + f", for {ntpath.basename(program)}")
        family, part = package_of(program, windir)
        if windows_package(family):  # a program in the folder of one of Windows' own app packages, under Program Files
            return system(f"{ntpath.basename(program)}, of Windows' own app {part}")
        return application(f"the program {program}")
    if r.owner:
        return application("an app's own rule (a Microsoft Store app's)")
    if windows_group:
        return system(f"Windows' own rule group {r.group}" if r.group else "one of Windows' own rules")
    return Sorted("other", "no program, service or app: its ports and addresses alone")


def _spellings(names) -> dict[str, str]:
    """Each name's one spelling, by the name in lowercase: one with capitals over one all in lowercase, then the one
    most given, then the one given first."""
    given = Counter(names)
    best: dict[str, str] = {}
    for n in given:
        b = best.get(n.casefold())
        if b is None or (n != n.lower(), given[n]) > (b != b.lower(), given[b]):
            best[n.casefold()] = n
    return best


def _names_of(rules, first: dict, windir: str) -> Names:
    """What the read taken whole knows that names its Application rules (Names), from `first`, each rule's group."""
    carried: dict[str, Counter] = {}  # a program -> the groups its rules carry
    held: dict[str, Counter] = {}  # a folder -> the groups its programs' rules carry
    owns: dict[str, Counter] = {}  # an app package family or a folder outside the install folders -> its rules' own names
    products: dict[str, Counter] = {}  # -> its programs' product names
    for r in rules:
        program = (r.program or "").strip()
        if first[r.id].group != "application" or r.owned:
            continue
        has_program = program.lower() not in ("", "any", "system")
        path = r.on_disk or program
        family = package_of(path, windir)[0] if has_program else r.package
        home = _home(path, windir) if has_program and not family else ""
        if readable(r.group):
            if has_program:
                carried.setdefault(_key(_components(program, windir)), Counter())[r.group] += 1
            if home:
                held.setdefault(home, Counter())[r.group] += 1
            continue
        unit = family.casefold() or (home if not install_folder(path, windir) else "")
        if unit:
            if _own_name(r):
                owns.setdefault(unit, Counter())[_own_name(r)] += 1
            if r.product:
                products.setdefault(unit, Counter())[r.product] += 1
    units = {u: c.most_common(1)[0][0] for u, c in products.items()}
    units.update({u: c.most_common(1)[0][0] for u, c in owns.items()})  # their own names before their products'
    return Names(families_of(rules, windir), {k: c.most_common(1)[0][0] for k, c in carried.items()},
                 {k: next(iter(c)) for k, c in held.items() if len({g.casefold() for g in c}) == 1}, units)


def sort_rules(rules, windir: str = WINDIR) -> dict[str, Sorted]:
    """Every rule's own group, why and name (sort_rule), by its id, the read taken whole (_names_of): an app package's
    name as its family's own rules carry it, and as an earlier version's family's (families_of); a program's rules with
    no group of their own named by the group its other rules, or its folder's other programs' rules, carry; an app
    package's or an uninstalled program's name decided for the family or the folder, so its programs and versions are
    one heading; and each name spelled one way for all its rules (_spellings: a rule may write its program's path in
    lowercase, c:\\program files (x86)\\contoso quest\\quest.exe, where the program on disk, another rule's path, or the
    rules' own names, Contoso Quest (TCP-In), spell it Contoso Quest)."""
    rules = list(rules)
    first = {r.id: sort_rule(r, windir) for r in rules}  # the groups: they do not hang on the names
    names = _names_of(rules, first, windir)
    found = {r.id: sort_rule(r, windir, names) for r in rules}
    offered = [s.name for s in found.values() if s.name]
    for r in rules:  # a name all in lowercase (from a path a rule writes so), as the rules' own names spell it
        n, own = found[r.id].name, str(r.name or "").strip()
        if n and n == n.lower() and own[:len(n)].casefold() == n.casefold() and not own[len(n):len(n) + 1].isalnum():
            offered.append(own[:len(n)])  # starcraft ii: StarCraft II; contoso saga: Contoso Saga Retail's Contoso Saga
    spelled = _spellings(offered)
    return {rid: s if spelled.get(s.name.casefold(), s.name) == s.name else Sorted(s.group, s.why, spelled[s.name.casefold()])
            for rid, s in found.items()}


def counted(rules) -> str:
    """How many rules, and how many of them are turned off when some are and some are not: 12 rules, 3 turned off."""
    rules = list(rules)
    off = sum(1 for r in rules if not r.enabled)
    return plural(len(rules), "rule") + (f", {off} turned off" if 0 < off < len(rules) else "")


PROTOCOL_WORDS = {"1": "ICMPv4", "2": "IGMP", "6": "TCP", "17": "UDP", "41": "IPv6", "47": "GRE", "58": "ICMPv6", "256": "any"}


def ports_said(r: WinRule) -> str:
    """A rule's protocol and local ports in words (ports only for TCP and UDP)."""
    if r.protocol is None:
        return "not read"
    proto = PROTOCOL_WORDS.get(str(r.protocol), str(r.protocol))
    if proto.lower() == "any":
        return "any protocol"
    if proto.upper() not in ("TCP", "UDP"):
        return f"protocol {r.protocol}" + (f" ({proto})" if proto != str(r.protocol) else "")
    local = r.local if r.local not in (None, "", "Any") else "every port"
    return f"{proto} {local}"


def plural(n: int, word: str) -> str:
    """A count and its word, thousands written as the library's tabs write them (0.7.0): 1 rule, 1,204 hosts."""
    return f"{n:,} {word}{'' if n == 1 else 's'}"


def _data_set_words(s: dict) -> str:
    """A data set of the globe as its card's fact says it (Index.sets' entry, 0.7.0): being downloaded, its file that
    does not read, what is installed of it, or that it is not downloaded yet."""
    if s.get("downloading"):
        return "being downloaded now (its progress is in the plugin's panel)"
    if s.get("problem"):
        return str(s["problem"])
    if s.get("installed"):
        dropped = int(s.get("dropped") or 0)
        return (f"{plural(int(s.get('features') or 0), 'feature')}, fetched {str(s.get('fetched') or '')[:10]} "
                f"({size_words(int(s.get('bytes') or 0))})" + (f"; {dropped:,} left out" if dropped else ""))
    return ("not downloaded: the World Wide Web tab's Internet infrastructure table offers it, its size and licence "
            "said first")


@dataclass
class _Runtime:
    """What the plugin keeps while it lives, shared by its copies (the registry hands out a shallow one)."""
    lock: threading.Lock = field(default_factory=threading.Lock)
    snap: Snapshot | None = None
    error: str = ""
    reader: threading.Thread | None = None
    query: Query = field(default_factory=Query)
    sorted: tuple | None = None  # (the Snapshot, its rules' Sorted by id): sort_rules once for each read


MACHINE = WindowsFirewallPlugin()
