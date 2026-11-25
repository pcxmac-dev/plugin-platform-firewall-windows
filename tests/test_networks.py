"""Services' networks through this firewall (0.8.0; liminal-libs 1.96.0's NetworkHost; service-containers-networking
§5.1, §6 and §14, decision 2 as (b) with (b1)): the plugin itself, over a stand-in powershell.exe (netfake.FakeNet: this
PC's addresses and routes as recorded, the port proxies, Windows' excluded ports), attached to the library's own App
beside the library's stand-in container plugin (Docker inside Liminal-Ubuntu, a FakeDocker), a stand-in WSL plugin
(its wsl_network and hold) and a stand-in service plugin. The library's conformance sequence runs end to end with this
plugin routing and naming. No route, proxy or rule changes on this PC, nothing starts, no wsl, no netsh: the
stand-ins count what would have run and the elevations Windows would have asked for."""
from __future__ import annotations

import pytest

from liminal_libs.apps import App, asking
from liminal_libs.apps.asking import AskRefused
from liminal_libs.instances import Refusal
from liminal_libs.machines import segments as S
from liminal_libs.machines import standins
from liminal_libs.machines.plugin import MachinePlugin
from liminal_libs.machines.windows import PowerShell

import netfake
from plugin_platform_firewall_windows import RiskRefused, WindowsFirewallPlugin, private_wider
from plugin_platform_firewall_windows import network as N

DIG = "sha256:" + "a" * 64


class Frame(App):
    NAME = "frame"

    def __init__(self, login):
        super().__init__(log=lambda m: None, login=login)

    def disabled(self):
        return set()


class Wsl(MachinePlugin):
    """The WSL plugin offering Liminal-Ubuntu's engine: its wsl_network (as running, or stopped) and its holds."""

    name, title, about, api, order = "wsl-standin", "WSL Ubuntu", "a stand-in", "2.2", 992
    HOOKS = (*MachinePlugin.HOOKS, "hold", "let_go", "wsl_network")
    READ_HOOKS = ("wsl_network",)
    SERVICE_HOOKS = ("hold", "let_go", "wsl_network")
    PLUGIN_ONLY_HOOKS = ("hold", "let_go")

    def __init__(self):
        self.vm, self.mode, self.asked = "172.31.5.9", "nat", []

    def present(self):
        """Always there: a stand-in."""
        return True

    def status(self):
        """Valid: a stand-in."""
        return {"present": True, "valid": True, "summary": "", "why": ""}

    def wsl_network(self):
        """As the WSL base answers it."""
        return {"plugin": self.name, "distribution": "Liminal-Ubuntu", "mode": self.mode, "vm_address": self.vm,
                "running": ["Liminal-Ubuntu"] if self.vm else [], "engines": {"Liminal-Ubuntu": bool(self.vm)},
                "why": "" if self.vm else "Liminal-Ubuntu is stopped: its address is read only while it runs"}

    def hold(self, distribution):
        """Recorded."""
        self.asked.append(("hold", distribution))
        return {"ok": True}

    def let_go(self, distribution):
        """Recorded."""
        self.asked.append(("let_go", distribution))
        return {"ok": True}


def spec(lan=True):
    return {"owner": "jenkins", "name": "ci", "title": "Jenkins", "system": "linux", "parts": [{
        "name": "controller",
        "image": {"ref": "docker.io/jenkins/jenkins:2.528.2-lts-jdk21", "digest": DIG, "system": "linux",
                  "platforms": ["linux/amd64"], "size": 300_000_000, "licence": "MIT", "tar": True},
        "ports": [{"name": "web", "container": 8080, "host": 8080, "lan": lan, "about": "its pages"}],
        "volumes": [{"name": "home", "path": "/var/jenkins_home", "holds": "its jobs", "owner": 1000}],
        "memory": 2 << 30, "health": {"port": "web", "path": "/login", "ready_s": 30}}]}


class World:
    def __init__(self, tmp_path, domain="home.arpa", elevated=False, monkeypatch=None):
        self.fake = netfake.FakeNet()
        self.uac: list[str] = []
        world = self

        def run_elevated(ps, script, timeout=600.0):  # Windows' prompt: noted, then run as if you said yes
            world.uac.append(script)
            return ps.run(script, timeout)
        monkeypatch.setattr(PowerShell, "run_elevated", run_elevated)
        pairs = {S.DOMAIN_VAR: domain} if domain else {}
        self.app = Frame(standins.login(pairs))
        self.fw = WindowsFirewallPlugin(PowerShell(runner=self.fake, env={}), elevated=lambda: elevated,
                                        clock=lambda: 1_800_000_000.0, book=S.MemoryBook(), platform="windows::TEST")
        out = standins.Outside(sleep=lambda s: None, health=lambda h, p, path: True, platform="windows::TEST",
                               folder=tmp_path)
        self.docker = standins.FakeDocker()
        self.host = standins.StandInHost({"wsl-ubuntu": (standins.target(), self.docker)}, outside=out)
        self.wsl = Wsl()
        self.jenkins = standins.ServiceOwner("jenkins")
        for p in (self.fw, self.host, self.wsl, self.jenkins):
            self.app.attach(p)
        self.fw.snapshot(wait=5)

    def page(self, plugin, hook, *args):
        with asking.asking(asking.PAGE):
            return self.app.ask(plugin, hook, *args)

    def grant(self):
        self.page("standin-host", "grant_service", "jenkins", "wsl-ubuntu")
        self.page("firewall-windows", "grant_network", "standin-host")

    def wait(self, work):
        w = self.host._svc.works.get(work)
        w.thread.join(20)
        assert not w.thread.is_alive(), "the work never ended"
        return self.jenkins.call("service_work", work, 0)

    def plan(self, action="install", options=None):
        return self.jenkins.call("service_plan", action, "jenkins/ci", spec() if action == "install" else None,
                                 "wsl-ubuntu" if action == "install" else "", options or {})


@pytest.fixture
def world(tmp_path, monkeypatch):
    w = World(tmp_path, monkeypatch=monkeypatch)
    yield w
    for name in ("jenkins", "wsl-standin", "standin-host", "firewall-windows"):
        w.app.detach(name)


def test_the_conformance_sequence_runs_with_this_firewall_routing_and_naming(world):
    world.grant()
    done = standins.conformance(world.jenkins, world.page, spec(), "wsl-ubuntu", world.wait)
    assert done[-1] == "conformance"
    routes = [line for s in world.fake.changes for line in s.splitlines() if "New-NetRoute" in line]
    assert len(routes) == 2  # install, and install again (each its own plan)
    assert all("-PolicyStore ActiveStore" in s and "-InterfaceIndex 42" in s and "-NextHop '172.31.5.9'" in s
               and "-DestinationPrefix '10.77.1.0/24'" in s for s in routes)
    proxies = [line for s in world.fake.changes for line in s.splitlines() if "portproxy add" in line]
    assert proxies and all("listenaddress=192.168.50.228 " in p and "connectaddress=10.77.1.10 connectport=8080" in p
                           for p in proxies)
    assert not any(word in s for s in world.fake.changes for word in N.NEVER)
    assert not any("0.0.0.0" in line for s in world.fake.changes for line in s.splitlines() if "portproxy" in line)
    assert len(world.uac) == len(world.fake.changes)  # one elevation per plan's script, never more
    assert world.fake.routes[-1]["Prefix"] != "10.77.1.0/24" and world.fake.proxies == []  # all taken away again
    assert ("hold", "Liminal-Ubuntu") in world.wsl.asked


def test_a_services_names_are_answered_forward_and_reverse_in_the_domain_you_set(world):
    world.grant()
    plan = world.plan()
    standins_approve(world, plan)
    world.wait(world.jenkins.call("apply_plan", plan["plan"])["work"])
    assert world.fw.resolve_name("controller.jenkins-ci.home.arpa")["addresses"] == ["10.77.1.10"]
    assert world.fw.reverse_name("10.77.1.10")["name"] == "controller.jenkins-ci.home.arpa"
    leases = world.fw.leases()["leases"]
    assert any(x["address"] == "10.77.1.10" and x["assigned"] == "reserved" for x in leases)
    tab = world.fw.container_networks()
    assert [t["title"] for t in tab["tables"]][:3] == ["Segments by stack", "Waiting for your answer",
                                                      "Container plugins"]


def standins_approve(world, plan, **accepts):
    yes = {**standins.ACCEPTS_ALL, **accepts}
    for a in plan["approve"]:
        words = world.page(a["plugin"], "plan_words", a["plan"])
        needed = {x["name"] for x in words["accepts"]}
        world.page(a["plugin"], "approve_plan", a["plan"],
                   *[yes.get(k, False) if k in needed else False for k in words["approve_args"]])


def test_with_no_domain_set_no_service_is_placed(tmp_path, monkeypatch):
    w = World(tmp_path, domain="", monkeypatch=monkeypatch)
    w.grant()
    with pytest.raises(Refusal, match="Networks tab"):
        w.plan()
    assert w.fake.changes == [] and w.uac == []


def test_with_liminal_ubuntu_stopped_the_plan_is_refused_and_nothing_starts(world):
    world.grant()
    world.wsl.vm = ""
    with pytest.raises(Refusal, match="start it on its WSL plugin's page"):
        world.plan()
    assert world.fake.changes == [] and world.wsl.asked == []


def test_a_hop_on_none_of_this_pcs_wsl_adapters_is_refused(world):
    world.grant()
    world.wsl.vm = "192.168.50.77"  # on the Wi-Fi's subnet: not the WSL adapter's (Consomme, say)
    with pytest.raises(Refusal, match="none of this PC's WSL adapters"):
        world.plan()
    world.wsl.vm, world.wsl.mode = "172.31.5.9", "mirrored"
    with pytest.raises(Refusal, match="mirrored mode"):
        world.plan()


def test_a_container_plugin_not_let_is_refused_and_the_pages_changes_are_the_pages_alone(world):
    world.page("standin-host", "grant_service", "jenkins", "wsl-ubuntu")
    with pytest.raises(Refusal, match="let it on the firewall's Networks tab"):
        world.plan()
    for hook, args in (("grant_network", ("standin-host",)), ("set_domain", ("lan.example",)), ("repoint", ()),
                       ("withdraw", ("jenkins/ci",)), ("set_network", (11, "private", None, True)),
                       ("set_profile", ("Public", "off", None, None, None, True))):
        with pytest.raises(AskRefused):
            world.jenkins.call(hook, *args, plugin="firewall-windows")
    assert world.fake.changes == [] and world.uac == []


def test_reads_change_nothing_and_ask_windows_nothing(world):
    world.grant()
    for hook, args in (("network_host", ()), ("leases", ()), ("name_records", ()), ("excluded_ports", ()),
                       ("container_networks", ()), ("leftovers", ()), ("lan_open", ([8080],))):
        world.jenkins.call(hook, *args, plugin="firewall-windows")
    assert world.fake.changes == [] and world.uac == []
    assert world.fw.status()["valid"] is True
    assert world.fw.excluded_ports() == {"ranges": [[5357, 5357], [50000, 50059]]}


def test_a_stale_route_is_pointed_again_by_the_next_start_in_one_prompt(world):
    world.grant()
    plan = world.plan()
    standins_approve(world, plan)
    world.wait(world.jenkins.call("apply_plan", plan["plan"])["work"])
    world.wsl.vm = "172.31.7.7"  # WSL started again: a new address
    before = len(world.uac)
    start = world.plan("start")
    assert any(n.get("plan") for n in start["network"])
    standins_approve(world, start)
    world.wait(world.jenkins.call("apply_plan", start["plan"])["work"])
    assert len(world.uac) == before + 1
    assert world.fake.routes[-1] == {"Prefix": "10.77.1.0/24", "Index": 42, "NextHop": "172.31.7.7", "Metric": 256,
                                     "Store": "ActiveStore"}
    assert sum(r["Prefix"] == "10.77.1.0/24" for r in world.fake.routes) == 1  # the old one went first


def test_udp_cannot_cross_the_port_proxy_and_a_windows_segment_gets_its_rule_alone(world):
    with pytest.raises(Refusal, match="TCP alone"):
        world.fw.lan_detail("jenkins/ci", {"host": 9000, "protocol": "udp", "stack": "wsl"}, "10.77.1.10")
    d = world.fw.lan_detail("jenkins/ci", {"host": 8080, "protocol": "tcp", "stack": "windows"}, "")
    assert d["proxy"] is False and d["rule"] == "svc-jenkins-ci-8080"
    script = N.step_script(S.Step("proxy", "", {**d, "host": 8080}))
    assert "portproxy" not in script and "-RemoteAddress LocalSubnet -Profile Private,Domain" in script


def test_the_templates_take_only_what_they_parse(world):
    bad = [("route", {"prefix": "0.0.0.0/0", "next_hop": "172.31.5.9", "interface": 42}),
           ("route", {"prefix": "192.168.50.0/24", "next_hop": "172.31.5.9", "interface": 42}),
           ("route", {"prefix": "10.77.1.0/24", "next_hop": "8.8.8.8", "interface": 42}),
           ("route", {"prefix": "10.77.1.0/24'; Remove-NetRoute", "next_hop": "172.31.5.9", "interface": 42}),
           ("proxy", {"listen": "0.0.0.0", "host": 8080, "connect": "10.77.1.10", "rule": "svc-jenkins-ci-8080"}),
           ("proxy", {"listen": "127.0.0.1", "host": 8080, "connect": "10.77.1.10", "rule": "svc-jenkins-ci-8080"}),
           ("proxy", {"listen": "192.168.50.228", "host": 8080, "connect": "10.77.1.10", "rule": "x'; y"})]
    for kind, detail in bad:
        with pytest.raises((Refusal, ValueError)):
            N.step_script(S.Step(kind, "", detail))


def test_a_script_holding_what_liminal_never_writes_is_refused(monkeypatch):
    for word in N.NEVER:
        monkeypatch.setattr(N, "step_script", lambda s, w=word: f"{w} -Name x")
        with pytest.raises(Refusal, match="never writes"):
            N.steps_script([S.Step("rule", "", {})])


def test_making_a_network_private_is_asked_twice_naming_the_rules_it_turns_on(world):
    with pytest.raises(RiskRefused, match="Delivery Optimization") as e:
        world.fw.set_network(11, "private")
    assert e.value.accept == "accept_risk" and world.fake.changes == []
    assert "Set-NetConnectionProfile" not in " ".join(world.fake.scripts)
    assert world.fw.set_network(11, "private", accept_risk=True)["ok"]
    assert private_wider(world.fw.snapshot()) and world.fw.set_network(11, "public")["ok"]  # Public needs no second


def test_leftovers_are_routes_proxies_and_rules_no_service_accounts_for(world):
    world.fake.routes.append({"Prefix": "10.77.9.0/24", "Index": 42, "NextHop": "172.31.0.9", "Metric": 256,
                              "Store": "ActiveStore"})
    world.fake.proxies += [("192.168.50.228", 9090, "10.77.9.10", 9090), ("192.168.50.228", 3389, "192.168.50.5", 3389)]
    left = world.fw.leftovers()["leftovers"]
    assert {m["id"] for m in left} == {"route:10.77.9.0/24", "proxy:192.168.50.228:9090"}  # never your own proxy
    world.page("firewall-windows", "remove_leftover", "route:10.77.9.0/24")
    assert not any(r["Prefix"] == "10.77.9.0/24" for r in world.fake.routes) and len(world.uac) == 1


def test_off_windows_nothing_is_read_or_run(tmp_path, monkeypatch):
    fake = netfake.FakeNet()
    fw = WindowsFirewallPlugin(PowerShell(runner=fake, env={}), elevated=lambda: True, system="linux",
                               book=S.MemoryBook())
    with pytest.raises(Refusal, match="not for this machine"):
        fw.net_facts()
    assert fake.scripts == []
