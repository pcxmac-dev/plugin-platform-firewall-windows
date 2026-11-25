"""The plugin's network part (0.8.0; liminal-libs 1.96.0's NetworkHost; service-containers-networking-2026-11-23.md §5.1,
§6, §7 and §14, decision 2 as (b) with (b1)). The user, 2026-11-23: "all services/containers will use the firewall app
to create routing for the IP ranges of the containers"; "they do need to make sure that there is a route from the OS
firewall, to the virtual bridge (layer2) that connects each segment of containers"; "the firewall app will know it's
domain, and have name resolution to each container, reverse lookup for all containers, and contain DHCP records for
dynamically assigned addresses"; "all this is mediated between the firewall API and the containers (plugin to plugin)".

- Its stack is this PC's Windows, and it routes to WSL's one VM ("wsl"): a segment inside WSL is reached by one route
  per segment, `New-NetRoute -DestinationPrefix <its /24> -InterfaceIndex <the WSL adapter's> -NextHop <the VM's
  address> -PolicyStore ActiveStore`, always in the active store (a restart of Windows takes it away; the next Start's
  plan, or Re-point…, makes it again). The VM's address is the WSL plugin's `wsl_network` (read only while a Liminal
  distribution runs); the adapter is found by that address, never by its name, and a hop on none of this PC's
  adapters (no NAT: Consomme, mirrored) is refused in words.
- Your network reaches a service by a port proxy per port (decision 2 b, b1): `netsh interface portproxy add v4tov4`
  listening on this PC's address on your network alone (never 0.0.0.0), connecting to the part's reserved address
  through the route, with the rule `Liminal: svc-<owner>-<name>-<port>`: TCP in, from LocalSubnet, on the Private and
  Domain profiles, for the IP Helper service. TCP alone (the proxy's own limit).
- A Windows containers segment is this PC's own (its NAT network's gateway is a vEthernet here): no route, and an
  Expose is the rule alone (WinNAT publishes the port).
- Every change runs inside an approved plan's work (or as one of the page's own: Re-point…, Withdraw…, a leftover's
  Remove…), all its steps in one script from the fixed templates below, every value parsed first: one UAC prompt.
- What it reads for this, with no rights: this PC's IPv4 addresses and routes (Get-NetIPAddress, Get-NetRoute), the
  port proxies (netsh interface portproxy show v4tov4) and the excluded port ranges (netsh interface ipv4 show
  excludedportrange), which any plugin may ask (`excluded_ports`).
- Never written: New-NetNat, Remove-NetNat, Set-NetIPInterface -Forwarding, IPEnableRouter, portproxy reset (rule 14)."""
from __future__ import annotations

import ipaddress
import re
import threading
import time
from dataclasses import dataclass, field

from liminal_libs.instances import Refusal
from liminal_libs.machines.containers import rule_name
from liminal_libs.machines.firewall import GROUP
from liminal_libs.machines.plans import Cancelled
from liminal_libs.machines.segments import HALVES, POOL, WSL_NETWORK, NetworkHost, Step
from liminal_libs.machines.windows import quote

NET_S = 10.0  # the network read is kept this long
EXCLUDED = "excluded_ports"
NEVER = ("New-NetNat", "Remove-NetNat", "Set-NetIPInterface", "IPEnableRouter", "portproxy reset")
NET_SCRIPT = (
    "$a = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { "
    "[pscustomobject]@{ Index = [int]$_.InterfaceIndex; Alias = [string]$_.InterfaceAlias; Address = [string]$_.IPAddress; "
    "Length = [int]$_.PrefixLength } }); "
    "$r = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { "
    "[pscustomobject]@{ Prefix = [string]$_.DestinationPrefix; Index = [int]$_.InterfaceIndex; NextHop = [string]$_.NextHop; "
    "Metric = [int]$_.RouteMetric + [int]$_.InterfaceMetric; Store = [string]$_.Store } }); "
    "$p = @(netsh interface portproxy show v4tov4) -join \"`n\"; "
    "$x = @(netsh interface ipv4 show excludedportrange protocol=tcp) -join \"`n\"; "
    "[pscustomobject]@{ Addresses = $a; Routes = $r; Proxies = $p; Excluded = $x }")
VETHERNET = re.compile(r"^vEthernet", re.I)


@dataclass(frozen=True)
class NetFacts:
    """This PC's IPv4 networking as read with no rights, at `at`."""
    at: float
    addresses: tuple = ()  # {"index", "alias", "address", "length"}
    routes: tuple = ()  # {"prefix", "index", "next_hop", "metric", "store"}
    proxies: tuple = ()  # {"listen", "port", "connect", "connect_port"}
    excluded: tuple = ()  # (low, high)

    def adapter_of(self, address: str) -> dict | None:
        """The adapter whose subnet holds `address` (found by address, never by name)."""
        try:
            a = ipaddress.ip_address(address)
        except ValueError:
            return None
        for x in self.addresses:
            try:
                if a in ipaddress.ip_interface(f"{x['address']}/{x['length']}").network:
                    return x
            except ValueError:
                continue
        return None

    def lan(self) -> dict | None:
        """This PC's address on your network: the adapter of the default route with the lowest metric that is no
        virtual switch's (vEthernet), loopback or link-local."""
        best = None
        for r in sorted(self.routes, key=lambda r: r["metric"]):
            if r["prefix"] != "0.0.0.0/0":
                continue
            for x in self.addresses:
                if x["index"] != r["index"] or VETHERNET.match(x["alias"]):
                    continue
                ip = ipaddress.ip_address(x["address"])
                if ip.is_loopback or ip.is_link_local:
                    continue
                best = best or x
        return best


def parse_proxies(text: str) -> tuple:
    """netsh interface portproxy show v4tov4's table, as rows."""
    out = []
    for line in str(text or "").splitlines():
        m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+|\*)\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+|\S+)\s+(\d+)\s*$", line)
        if m:
            out.append({"listen": m.group(1), "port": int(m.group(2)), "connect": m.group(3),
                        "connect_port": int(m.group(4))})
    return tuple(out)


def parse_excluded(text: str) -> tuple:
    """netsh interface ipv4 show excludedportrange's ranges, as (low, high)."""
    out = []
    for line in str(text or "").splitlines():
        m = re.match(r"\s*(\d+)\s+(\d+)\s*\*?\s*$", line)
        if m and 0 < int(m.group(1)) <= int(m.group(2)) < 65536:
            out.append((int(m.group(1)), int(m.group(2))))
    return tuple(out)


def parse_net(data: dict, at: float) -> NetFacts:
    addresses = tuple({"index": int(a.get("Index") or 0), "alias": str(a.get("Alias") or ""),
                       "address": str(a.get("Address") or ""), "length": int(a.get("Length") or 0)}
                      for a in data.get("Addresses") or [] if a.get("Address"))
    routes = tuple({"prefix": str(r.get("Prefix") or ""), "index": int(r.get("Index") or 0),
                    "next_hop": str(r.get("NextHop") or ""), "metric": int(r.get("Metric") or 0),
                    "store": str(r.get("Store") or "")} for r in data.get("Routes") or [] if r.get("Prefix"))
    return NetFacts(at, addresses, routes, parse_proxies(data.get("Proxies") or ""),
                    parse_excluded(data.get("Excluded") or ""))


# -- the fixed templates, every value parsed first ---------------------------------------------------------------------
def _pool_prefix(value) -> str:
    net = ipaddress.ip_network(str(value), strict=True)
    if net.version != 4 or not net.subnet_of(ipaddress.ip_network(POOL)) or net.prefixlen < 16:
        raise Refusal(f"{value} is not a segment of Liminal's pool ({POOL}): no route is made to it from here")
    return str(net)


def _private(value, what: str) -> str:
    ip = ipaddress.ip_address(str(value))
    if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_link_local:
        raise Refusal(f"{what} {value} is not a private IPv4 address of a network of this PC's")
    return str(ip)


def _port(value) -> int:
    p = int(value)
    if not 0 < p < 65536:
        raise Refusal(f"{value} is not a port")
    return p


def _rule(value) -> str:
    v = str(value or "")
    if not re.fullmatch(r"svc-[a-z0-9-]{1,44}", v):
        raise Refusal(f"{v[:60]!r} is not a service's rule name")
    return v


def _drop_route(prefix: str) -> str:
    return (f"Get-NetRoute -DestinationPrefix {quote(prefix)} -PolicyStore ActiveStore -ErrorAction SilentlyContinue | "
            "Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue")


def _drop_rule(rule: str) -> str:
    return (f"Get-NetFirewallRule -Group {quote(GROUP)} -ErrorAction SilentlyContinue | Where-Object {{ $_.DisplayName -eq "
            f"{quote(GROUP + ': ' + rule)} }} | Remove-NetFirewallRule -ErrorAction SilentlyContinue")


def step_script(s: Step) -> str:
    """One step's lines, from its template: a route (in the active store alone), a route taken away, a port proxy on
    your network's address with its rule, a port proxy taken away with its rule, a rule alone."""
    d = dict(s.detail)
    if s.kind == "route":
        prefix, hop = _pool_prefix(d.get("prefix")), _private(d.get("next_hop"), "the next hop")
        index = int(d.get("interface") or 0)
        if index <= 0:
            raise Refusal("a route needs the WSL adapter's index")
        return (_drop_route(prefix) + "\n" +  # a stale route of that prefix: pointed again
                f"New-NetRoute -DestinationPrefix {quote(prefix)} -InterfaceIndex {index} -NextHop {quote(hop)} "
                "-PolicyStore ActiveStore -ErrorAction Stop | Out-Null")
    if s.kind == "unroute":
        return _drop_route(_pool_prefix(d.get("prefix") or d.get("prefix_")))
    if s.kind in ("proxy", "unproxy", "rule", "unrule"):
        rule = _rule(d.get("rule"))
        port = _port(d.get("host") or d.get("port"))
        if s.kind in ("rule", "unrule") or not d.get("proxy", True):
            if s.kind in ("unproxy", "unrule"):
                return _drop_rule(rule)
            return (_drop_rule(rule) + "\n" +
                    f"New-NetFirewallRule -Group {quote(GROUP)} -DisplayName {quote(GROUP + ': ' + rule)} "
                    f"-Description {quote('a Liminal service, from your local subnet')} -Direction Inbound -Action Allow "
                    f"-Protocol TCP -LocalPort {port} -RemoteAddress LocalSubnet -Profile Private,Domain | Out-Null")
        listen = _private(d.get("listen"), "the proxy's listen address")
        if s.kind == "unproxy":
            return (f"netsh interface portproxy delete v4tov4 listenaddress={listen} listenport={port} | Out-Null\n"
                    + _drop_rule(rule))
        connect, cport = _private(d.get("connect"), "the address it connects to"), _port(d.get("connect_port") or port)
        return (f"netsh interface portproxy add v4tov4 listenaddress={listen} listenport={port} connectaddress={connect} "
                f"connectport={cport} | Out-Null\n"
                f"if ($LASTEXITCODE) {{ throw 'netsh could not add the port proxy on {listen}:{port}' }}\n"
                + _drop_rule(rule) + "\n" +
                f"New-NetFirewallRule -Group {quote(GROUP)} -DisplayName {quote(GROUP + ': ' + rule)} "
                f"-Description {quote('a Liminal service: its port proxy, from your local subnet')} -Direction Inbound "
                f"-Action Allow -Protocol TCP -LocalPort {port} -LocalAddress {quote(listen)} -RemoteAddress LocalSubnet "
                "-Profile Private,Domain -Service iphlpsvc | Out-Null")
    raise Refusal(f"no template for a {s.kind!r} step")


def steps_script(steps) -> str:
    body = "\n".join(step_script(s) for s in steps)
    if any(word in body for word in NEVER):
        raise Refusal("a step would write what Liminal never writes")
    return "$ErrorActionPreference = 'Stop'\n" + body


@dataclass
class _NetRuntime:
    lock: threading.Lock = field(default_factory=threading.Lock)
    facts: NetFacts | None = None
    error: str = ""


class WindowsNetwork(NetworkHost):
    """The Windows firewall's network part: what NetworkHost asks of a subclass, for this PC."""

    DOMAIN_DEFAULT = None  # the user sets the domain: Liminal picks none (no install is placed until one is set)

    def _net_rt(self) -> _NetRuntime:
        rt = self.__dict__.get("_netrt")
        if rt is None:
            rt = self.__dict__.setdefault("_netrt", _NetRuntime())
        return rt

    def net_facts(self, fresh: bool = False) -> NetFacts:
        """This PC's IPv4 addresses, routes, port proxies and excluded port ranges, read with no rights (one
        PowerShell call), kept NET_S. Off Windows nothing runs."""
        here = self.not_for_here()
        if here:
            raise Refusal(f"not for this machine: {here}")
        rt = self._net_rt()
        with rt.lock:
            kept = rt.facts
        now = time.monotonic()
        if kept is not None and not fresh and now - kept.at < NET_S:
            return kept
        rows = self.ps.json(NET_SCRIPT, timeout=60)
        facts = parse_net(rows[0] if rows else {}, now)
        with rt.lock:
            rt.facts = facts
        return facts

    # -- what NetworkHost asks ---------------------------------------------------------------------------------------
    def stacks(self) -> dict:
        return {"own": "windows", "routes_to": ("wsl",)}

    def networks_here(self) -> list[str]:
        f = self.net_facts()
        out = []
        for x in f.addresses:
            try:
                out.append(str(ipaddress.ip_interface(f"{x['address']}/{x['length']}").network))
            except ValueError:
                continue
        for r in f.routes:
            try:
                net = ipaddress.ip_network(r["prefix"], strict=False)
            except ValueError:
                continue
            if net.prefixlen == 0 or net.is_multicast or str(net) == "255.255.255.255/32":
                continue
            out.append(str(net))
        return sorted(set(out))

    def wsl_networks(self) -> list[dict]:
        """The WSL plugins' wsl_network answers (each reads its own distribution only while it runs)."""
        return [a for _n, a, _e in self.net_ask_others(WSL_NETWORK) if isinstance(a, dict)]

    def next_hop(self, stack: str):
        if stack != "wsl":
            return "", 0, f"{self.title} routes to WSL's segments alone, not {stack}'s"
        answers = self.wsl_networks()
        if not answers:
            return "", 0, "no WSL plugin answers: turn one on (WSL Ubuntu, Fedora or Gentoo)"
        running = [a for a in answers if a.get("vm_address")]
        if not running:
            why = next((a.get("why") for a in answers if a.get("why")), "")
            return "", 0, ("no Liminal WSL distribution runs now: start it on its WSL plugin's page (a look never "
                           "starts one)" + (f"; {why}" if why else ""))
        a = running[0]
        if str(a.get("mode") or "nat") != "nat":
            return "", 0, f"WSL runs in {a.get('mode')} mode: there is no VM address to route to"
        vm = str(a["vm_address"])
        adapter = self.net_facts().adapter_of(vm)
        if adapter is None or not VETHERNET.match(adapter["alias"]):
            return "", 0, (f"the VM's address {vm} is on none of this PC's WSL adapters (WSL may have fallen back to "
                           "Consomme, which has no VM address to route to)")
        return vm, int(adapter["index"]), ""

    def lan_state(self, port: int, protocol: str) -> dict:
        snap = self.snapshot()
        if snap is None:
            return {"state": "unknown", "words": "the firewall is not read yet"}
        hits = [r for r in snap.rules if r.enabled and r.direction == "in" and r.action == "allow" and r.covers(port)
                and str(r.protocol or "Any").lower() in ("any", str(protocol).lower(), "6" if protocol == "tcp" else "17")]
        if not hits:
            return {"state": "closed", "words": f"no rule lets {protocol.upper()} {port} in"}
        wide = [r for r in hits if (r.remote or "Any").lower() in ("any", "*")]
        if wide:
            return {"state": "wider", "words": f"“{wide[0].name}” lets it in from anywhere, on {wide[0].profiles}"}
        return {"state": "lan", "words": f"“{hits[0].name}” lets it in from {hits[0].remote}, on {hits[0].profiles}"}

    def lan_detail(self, sid: str, port, address: str) -> dict:
        host = _port(port.get("host"))
        if str(port.get("protocol") or "tcp").lower() != "tcp":
            raise Refusal(f"netsh's port proxy carries TCP alone: UDP {host} cannot be opened to your network this way")
        rule = f"{rule_name(sid)}-{host}"
        if port.get("stack") == "windows":
            return {"proxy": False, "rule": rule, "words": f"its engine publishes it on this PC's addresses; the rule "
                    f"{GROUP}: {rule} lets your local subnet in, on the Private and Domain profiles"}
        lan = self.net_facts().lan()
        if lan is None:
            raise Refusal("this PC has no address on your network now: nothing can listen there")
        listen = lan["address"]
        target = str(port.get("here") or "").rsplit(":", 1)[0] or address
        if not target:
            raise Refusal(f"{sid} has no reserved address for its proxy to connect to")
        cport = int(port.get("container") or host) if not port.get("here") else int(str(port["here"]).rsplit(":", 1)[1])
        return {"proxy": True, "listen": listen, "listen_on": lan["alias"], "connect": target, "connect_port": cport,
                "rule": rule, "words": f"a port proxy on {listen}:{host} ({lan['alias']}) to {target}:{cport} through the "
                f"route, and the rule {GROUP}: {rule} from your local subnet on the Private and Domain profiles, for the "
                "IP Helper service"}

    def run_steps(self, steps, line, cancelled) -> None:
        """Every step of a plan in one script from the fixed templates: one elevation (UAC when the platform is not an
        administrator, on this PC's screen alone). An unanswered or declined prompt changes nothing, and says so."""
        script = steps_script(steps)
        if cancelled():
            raise Cancelled("cancelled before Windows was asked")
        for s in steps:
            line(f"{s.words}")
        line("Windows asks for an administrator's permission once, on this PC's screen (UAC)"
             if not self._elevated() else "run as an administrator: no prompt")
        try:
            self._admin(script)
        finally:
            try:
                self.net_facts(fresh=True)
            except Exception:  # noqa: BLE001 - read again at the next ask
                pass
        line(f"done: {len(steps)} step(s) made")

    def made_here(self) -> list[dict]:
        f = self.net_facts()
        out = []
        pool = ipaddress.ip_network(POOL)
        for r in f.routes:
            try:
                net = ipaddress.ip_network(r["prefix"], strict=False)
            except ValueError:
                continue
            if net.version == 4 and net.subnet_of(pool) and net.prefixlen >= 16:
                out.append({"id": f"route:{net}", "kind": "route", "key": ["route", str(net)],
                            "words": f"a route to {net} through {r['next_hop']} ({r['store'] or 'a store'})",
                            "detail": {"prefix": str(net)}})
        for p in f.proxies:
            try:
                ours = ipaddress.ip_address(p["connect"]) in pool  # a proxy of yours to anywhere else is never touched
            except ValueError:
                ours = False
            if not ours:
                continue
            out.append({"id": f"proxy:{p['listen']}:{p['port']}", "kind": "proxy", "key": ["proxy", p["listen"], p["port"]],
                        "words": f"a port proxy on {p['listen']}:{p['port']} to {p['connect']}:{p['connect_port']}",
                        "detail": {"listen": p["listen"], "host": p["port"], "rule": "svc-leftover"}})
        snap = self.snapshot()
        for r in (snap.rules if snap else ()):
            if r.owned and r.name.startswith(f"{GROUP}: svc-"):
                name = r.name[len(GROUP) + 2:]
                out.append({"id": f"rule:{name}", "kind": "rule", "key": ["rule", name], "words": f"the rule {r.name}",
                            "detail": {"rule": name, "host": int(next(iter(re.findall(r"\d+", r.local or "")), 0) or 1)}})
        return out

    def leftover_steps(self, item) -> list[Step]:
        kind = item.get("kind")
        d = dict(item.get("detail") or {})
        if kind == "route":
            return [Step("unroute", item["words"] + " taken away", d)]
        if kind == "proxy":
            return [Step("unproxy", item["words"] + " taken away", d)]
        if kind == "rule":
            return [Step("unrule", item["words"] + " removed", d)]
        raise Refusal(f"no leftover of the kind {kind!r}")

    def excluded_ports(self) -> dict:
        """The TCP port ranges Windows keeps for itself (Hyper-V, WSL, its own services), read with no rights: a
        container plugin never publishes in one."""
        return {"ranges": [list(r) for r in self.net_facts().excluded]}


__all__ = ["WindowsNetwork", "NetFacts", "parse_net", "parse_proxies", "parse_excluded", "step_script", "steps_script",
           "NET_SCRIPT", "NEVER", "EXCLUDED", "HALVES"]
