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
- Changes, each asked by a form and confirmed: a rule turned on or off, removed (never one of Windows' own: those are
  turned off instead), or made (in the rule group "Liminal"); a profile's firewall turned on or off, its default for
  what comes in or goes out, its notifications; a network made private or public. Turning a profile off, or letting
  everything in by default, is asked a second time: this PC may be a router's DMZ host. A change needs an
  administrator: run as one, or Windows asks (UAC).
- The library's Firewall base keeps its setup (on, exposure, the services' rules) and Liminal's own rules' hooks.

    python -m plugin_platform_firewall_windows status | rules [PRESET] | find WORDS [--port N] [--in|--out]
        [--allow|--block] | profiles | networks | set-rule ID on|off | remove-rule ID | add-rule NAME ... |
        set-profile NAME ... | set-network INDEX private|public | setup [STEP ...] | exposure | allow | remove | run
"""
from __future__ import annotations

import ntpath
import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from liminal_libs.machines.firewall import GROUP, NAME, Firewall, FirewallError, Rule
from liminal_libs.machines.plugin import CommandError
from liminal_libs.machines.rulegroups import Sorted, key_of
from liminal_libs.machines.windows import PowerShell, is_elevated, quote

__version__ = "0.3.0"
DIRECTIONS = {"in": "Inbound", "out": "Outbound"}
ACTIONS = {"allow": "Allow", "block": "Block"}
PROTOCOLS = {"tcp": "TCP", "udp": "UDP", "any": "Any"}
PROTOCOL_NUMBERS = {"6": "tcp", "17": "udp"}
PROFILE_NAMES = ("Domain", "Private", "Public")
READ_SCRIPT = Path(__file__).with_name("read.ps1")
READ_S = 60.0  # the configuration read again once it is this old
FIRST_WAIT_S = 8.0  # how long the first status waits for the first read
ROWS = 100  # rules listed at most in each group
WINDIR = (os.environ.get("SystemRoot") or r"C:\Windows").rstrip("\\")  # Windows' folder: its programs are the system's
GROUP_NOTES = {
    "system": "Windows' own: its services, the System process, its programs in Windows' folder, its app packages and rule groups",
    "application": "a program or a Microsoft Store app installed, Liminal's rules too",
    "other": "tied to no program, service or app: ports and addresses alone",
}
RULE_FIELDS = ("$pf = $_ | Get-NetFirewallPortFilter; $af = $_ | Get-NetFirewallAddressFilter; "
               "[pscustomobject]@{ Name = $_.DisplayName; Group = [string]$_.Group; Direction = $_.Direction.ToString(); "
               "Action = $_.Action.ToString(); Enabled = ($_.Enabled.ToString() -eq 'True'); Protocol = [string]$pf.Protocol; "
               "LocalPort = (@($pf.LocalPort) -join ','); RemoteAddress = (@($af.RemoteAddress) -join ','); "
               "Description = [string]$_.Description }")
PRESETS = {  # the rules shown: (title, which)
    "in-allow": ("Inbound allowed", lambda r: r.direction == "in" and r.action == "allow" and r.enabled),
    "in-block": ("Inbound blocked", lambda r: r.direction == "in" and r.action == "block" and r.enabled),
    "out": ("Outbound", lambda r: r.direction == "out" and r.enabled),
    "liminal": ("Liminal's", lambda r: r.group == GROUP),
    "off": ("Turned off", lambda r: not r.enabled),
    "all": ("All", lambda r: True),
}
DEFAULTS = {"inbound": "block", "outbound": "allow"}  # what Windows does where a profile's default is NotConfigured
UAC = "Windows asks for an administrator's permission first (UAC)."


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
    own; `source` is its rule group as Windows keeps it (a resource string for Windows' own)."""
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


def parse_snapshot(data: dict, at: float, took: float) -> Snapshot:
    """read.ps1's answer as a Snapshot."""
    rules = []
    for r in data.get("Rules") or []:
        group = str(r.get("Group") or "")
        source = str(r.get("GroupSource") or "")
        rules.append(WinRule(
            id=str(r.get("Id") or ""), name=str(r.get("Name") or ""), group=group, builtin=source.startswith("@"),
            enabled=bool(r.get("Enabled")), direction="out" if str(r.get("Direction")) == "Outbound" else "in",
            action="block" if str(r.get("Action")) == "Block" else "allow", profiles=str(r.get("Profile") or "Any"),
            program=str(r.get("Program") or "Any"), protocol=_text(r.get("Protocol")), local=_text(r.get("LocalPort")),
            remote_ports=_text(r.get("RemotePort")), remote=_text(r.get("Remote")), description=str(r.get("Description") or ""),
            source=source, service=str(r.get("Service") or ""), owner=str(r.get("Owner") or ""), package=str(r.get("Package") or ""),
            package_system=bool(r.get("PackageSystem"))))
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


class WindowsFirewallPlugin(Firewall):
    name = "firewall-windows"
    ICON = "wallglobe"  # a brick wall with the globe behind it (liminal-libs 1.34.0; the user's picture: "this one for windows firewall")
    title = "Windows Firewall"
    about = ("Windows Defender Firewall, the networks and Microsoft Defender on this PC: every rule and profile read, queried "
             "and changed on your word (an administrator's, through UAC)")
    api = "2.1"
    order = 710
    HOOKS = (*Firewall.HOOKS, "refresh", "find_rules", "show_rules", "set_rule", "remove_rule", "make_rule", "set_profile", "set_network")

    def __init__(self, powershell: PowerShell | None = None, elevated=None, clock=time.time):
        self.ps = powershell if powershell is not None else PowerShell()
        self._elevated = elevated if elevated is not None else is_elevated  # a test's stand-in
        self._clock = clock
        self._rt = _Runtime()

    # -- the read ------------------------------------------------------------------------------------------
    def read(self) -> Snapshot:
        """The whole configuration read now (one PowerShell call), kept; CommandError when it cannot be read."""
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
        for up to `wait` seconds."""
        with self._rt.lock:
            snap, reader = self._rt.snap, self._rt.reader
            stale = snap is None or fresh or self._clock() - snap.at > READ_S
            if stale and reader is None:
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

    def refresh(self) -> dict:
        """The configuration read again now (the page's Refresh)."""
        snap = self.read()
        return {"said": f"read {len(snap.rules)} rules, {len(snap.profiles)} profiles and {len(snap.networks)} network(s) in {snap.took:.1f} s",
                "ok": True}

    # -- the base's backend ---------------------------------------------------------------------------------
    def present(self) -> bool:
        return self.ps.here

    def backend(self) -> str:
        return "Windows Defender Firewall"

    def _snap(self) -> Snapshot:
        snap = self.snapshot(wait=FIRST_WAIT_S * 4)
        if snap is None:
            raise CommandError(self._rt.error or "the configuration could not be read")
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
        """A PowerShell command line on this PC (Get-NetFirewallProfile; netsh advfirewall show allprofiles), its output."""
        return self.ps.run(" ".join(command))

    # -- changes, each run as an administrator --------------------------------------------------------------
    def _admin(self, script: str) -> str:
        """A change run with an administrator's rights: as it is when this process has them, else through Windows' own
        prompt (UAC); the configuration read again after."""
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

    def set_network(self, index, category, label=None) -> dict:
        """A network made private (trusted: the Private profile applies) or public (the Public profile applies)."""
        want = str(category or "").strip().capitalize()
        if want not in ("Private", "Public"):
            raise ValueError(f"a network is made private or public, not {category!r}")
        snap = self._snap()
        net = next((n for n in snap.networks if str(n["index"]) == str(index)), None)
        if net is None:
            raise ValueError(f"no network on interface {index} (read {when(snap.at)})")
        if net["category"] == want:
            return {"said": f"{net['interface']} ({net['name']}) is {want.lower()} already", "ok": True}
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
        """Every rule read, by its key (its id's), with its own group (sort_rule): what a move checks."""
        snap = self._rt.snap
        return {key_of(r.id): sort_rule(r) for r in (snap.rules if snap else ())}

    def rules_shown(self) -> tuple[Query, list[WinRule]]:
        """The rules the table lists: those the query matches; for a port, the rules naming it first, then ranges, then
        every port (a rule for every port covers it too, for its program)."""
        with self._rt.lock:
            q = self._rt.query
        snap = self._rt.snap
        found = [r for r in (snap.rules if snap else ()) if q.matches(r)]
        if q.port:
            found.sort(key=lambda r: r.cover_rank(q.port))
        return q, found

    # -- what the platform's page shows ---------------------------------------------------------------------
    def status(self) -> dict:
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
        """The rules shown, in their groups (0.3.0): System, Application, Other and the user's labels, each listing its
        first ROWS; a rule's group found by sort_rule, or where the user moved it."""
        q, found = self.rules_shown()
        rows = []
        for r in found:
            label = f"{r.name} ({r.id})"
            tied = (f"service {r.service}" if r.service else f"app {r.package.split('_')[0]}" if r.package
                    else "an app's own rule" if r.owner and r.program in ("", "Any") else None)
            rows.append((key_of(r.id), sort_rule(r), [cell(r.name, r.group or None), r.direction, r.action, ports_said(r), cell(r.program, tied),
                         "not read" if r.remote is None else ("any" if r.remote in ("*", "Any") else r.remote), r.profiles,
                         "on" if r.enabled else "off",
                         {"form": "rule-state", "title": "Turn off" if r.enabled else "Turn on",
                          "values": {"rule_id": r.id, "enabled": "off" if r.enabled else "on", "label": label},
                          "label": f"Turn {'off' if r.enabled else 'on'} {r.name}"},
                         {"form": "rule-remove", "title": "Remove", "values": {"rule_id": r.id, "label": label}, "label": f"Remove {r.name}"}
                         if not r.builtin else "–"]))
        choices = [{"value": k, "title": t, "note": plural(sum(1 for x in (self._rt.snap.rules if self._rt.snap else ()) if f(x)), "rule")}
                   for k, (t, f) in PRESETS.items()]
        if q.found:
            choices.append({"value": "found", "title": "Found", "note": q.words_said()})
        base = {"title": "Rules",
                "note": f"{len(found)} shown: {q.words_said()}; moving a rule to another group changes nothing in the firewall",
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
                        {"name": "label", "label": "Network", "type": "fixed"}],
             "confirm": {"title": "Make this network {category}?",
                         "words": "{label} is made {category}: the {category} profile's rules apply to it." + uac, "yes": "Make it so"}},
        ]


def _expanded(program: str, windir: str = WINDIR) -> str:
    """A program's path as Windows runs it, in lowercase: its variables for Windows' folder expanded
    (%SystemRoot%\\system32\\svchost.exe -> c:\\windows\\system32\\svchost.exe)."""
    p = str(program or "").strip().strip('"')
    for var, value in (("%systemroot%", windir), ("%windir%", windir), ("%systemdrive%", windir[:2])):
        if p.lower().startswith(var):
            p = value + p[len(var):]
    return p.lower()


def sort_rule(r: WinRule, windir: str = WINDIR) -> Sorted:
    """A Windows rule's own group, and why (the user: "groups, like system or application and then unassociated rules
    not tied to a specific application or system process can be in an other"). Liminal's: an application's (Liminal's
    apps). An app container's (a Microsoft Store app's): an application's, Windows' own when Windows signed its package
    as the system's. A Windows service's, the System process', a program's in Windows' folder, and Windows' own rule
    groups (a resource of Windows' for their name): the system's. Another program's: an application's. Tied to none of
    these: other."""
    program = (r.program or "").strip()
    low = program.lower()
    in_windows = _expanded(program, windir).startswith(windir.lower() + "\\")
    if r.owned:
        return Sorted("application", "Liminal's: made on the platform")
    if r.package:
        app = r.package.split("_")[0]
        return Sorted("system", f"Windows' own app {app}") if r.package_system else Sorted("application", f"the app {app}")
    if r.service:
        if low not in ("", "any", "system") and not in_windows:
            return Sorted("application", f"the service {r.service}, run by {program}")
        return Sorted("system", f"the Windows service {r.service}")
    if low == "system":
        return Sorted("system", "the System process: Windows' kernel")
    if low not in ("", "any"):
        if in_windows:
            return Sorted("system", f"{ntpath.basename(program)}, in Windows' folder")
        return Sorted("application", f"the program {program}")
    if r.owner:
        return Sorted("application", "an app's own rule (a Microsoft Store app's)")
    if r.source.startswith("@") and not r.source.startswith("@{"):
        return Sorted("system", f"Windows' own rule group {r.group}" if r.group else "one of Windows' own rules")
    return Sorted("other", "no program, service or app: its ports and addresses alone")


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
    return f"{n} {word}{'' if n == 1 else 's'}"


@dataclass
class _Runtime:
    """What the plugin keeps while it lives, shared by its copies (the registry hands out a shallow one)."""
    lock: threading.Lock = field(default_factory=threading.Lock)
    snap: Snapshot | None = None
    error: str = ""
    reader: threading.Thread | None = None
    query: Query = field(default_factory=Query)


MACHINE = WindowsFirewallPlugin()
