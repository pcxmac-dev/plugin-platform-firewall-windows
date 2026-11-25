"""Who may ask the plugin's changes (0.7.3, the review of PLT-H1's fix, 2026-11-24). Its changes are asked only from its
page (PAGE_ONLY_HOOKS, as liminal-libs 1.66.0's apps/asking.py and liminal-platform 0.34.0 read them): a rule turned on
or off, removed or made, a profile changed, a network made private or public, and the base's allow and remove of
Liminal's own rules. Another plugin's ask is refused, and so is an ask that names no one; over HTTP the platform also
asks its login whether you are at the page. Before, any program on this PC asked them with two headers: on a platform
run as an administrator the review's body turned the Public profile's firewall off at once, with no prompt, its second
confirmation (accept_risk) being only an argument; on one that is not, Windows asked you (UAC) for a change nobody had
asked for. Its reads and queries are asked by anyone, as before. Asked through the library's own App (its ask names who
asks as the platform's does), over a stand-in powershell.exe and a stand-in for Windows' prompt: nothing runs, nothing
is elevated."""
from __future__ import annotations

import pytest

pytest.importorskip("liminal_libs.apps.asking", reason="no hook is asked only from its page before liminal-libs 1.66.0")

from liminal_libs import internal  # noqa: E402 - after the skip, as each of these
from liminal_libs.apps import App, asking  # noqa: E402
from liminal_libs.apps.authorization import EnvironmentLogin  # noqa: E402
from liminal_libs.machines.plugin import MachinePlugin  # noqa: E402
from liminal_libs.machines.windows import PowerShell, wrapped  # noqa: E402
from plugin_platform_firewall_windows import MACHINE  # noqa: E402
from test_plugin import FakeWindows, plugin  # noqa: E402

CHANGES = ("set_rule", "remove_rule", "make_rule", "set_profile", "set_network", "allow", "remove",
           # 0.8.0: the base's other changes, and NetworkHost's (liminal-libs 1.96.0)
           "move_rules", "new_label", "rename_label", "remove_label", "hosts_recording", "hosts_forget",
           "world_watching", "world_geoip", "world_asn", "world_layer_get", "world_layer_remove",
           "approve_plan", "grant_network", "revoke_network", "set_domain", "withdraw", "repoint",
           "remove_leftover", "forget_records")
READS = ("present", "status", "refresh", "find_rules", "show_rules", "wanted", "world", "netstat")
OFF = ("Public", "off", None, None, None, True)  # the review's body: the Public profile's firewall off, "accepted"
OPEN = ("x", "in", "allow", "any")  # and its second: a rule letting everything in, on every profile
OFF_SCRIPT = "Set-NetFirewallProfile -Name Public -Enabled False"


class Neighbour(MachinePlugin):
    """Another plugin of the platform, asking the firewall through its app as any plugin may (a container plugin, or
    the MCP plugin for a local agent)."""

    name, title = "neighbour", "Neighbour"

    def wants(self, hook, *args):
        """Not a hook: one of the firewall's asked through the app."""
        return self.app.ask("firewall-windows", hook, *args)


class Platform(App):
    """The library's App asking as the platform does: from its page's route, the page named in so many words, or from
    its own code, no one named."""

    NAME, TITLE, ICON = "platform", "Platform", "chip"

    def from_page(self, hook, *args):
        """As the page's route asks a hook."""
        with asking.asking(asking.PAGE):
            return self.ask("firewall-windows", hook, *args)

    def on_its_own(self, hook, *args):
        """As the app's own code asks a hook."""
        return self.ask("firewall-windows", hook, *args)


@pytest.fixture(params=[True, False], ids=["administrator", "not-administrator"])
def attached(request, monkeypatch):
    """The plugin on a platform run as an administrator, where a change runs at once and Windows asks nothing: the
    review's case; and on one that is not, where Windows asks (UAC). Windows' prompt a stand-in that notes each ask and
    runs it as if you said yes; the configuration read once; attached with another plugin to an app, let go after."""
    fake, asked, elevated = FakeWindows(), [], request.param

    def run_elevated(self, script, timeout=600.0):
        asked.append(script)
        return self.run(script, timeout)
    monkeypatch.setattr(PowerShell, "run_elevated", run_elevated)
    fw, neighbour = plugin(fake, elevated=elevated), Neighbour()
    app = Platform(log=lambda m: None, login=EnvironmentLogin(env={}))
    app.attach(fw)
    app.attach(neighbour)
    assert fw.snapshot(wait=5) is not None  # the read its attach began, done
    fake.scripts.clear()
    yield app, neighbour, fake, asked, elevated
    app.detach(neighbour.name)
    app.detach(fw.name)


def test_its_changes_are_said_to_be_asked_only_from_its_page_and_its_reads_by_anyone():
    assert set(internal.page_only(MACHINE)) == set(CHANGES)  # what the platform reads
    assert set(internal.plugin_only(MACHINE)) == {"network_plan", "apply_network", "network_work"}  # 0.8.0
    assert internal.problems(MACHINE) == []  # each a hook of its own, and someone may ask it
    for hook in CHANGES:
        assert asking.refusal(MACHINE, hook, asking.PAGE) == ""
        assert asking.refusal(MACHINE, hook, "neighbour") == (f"firewall-windows's {hook} is asked only from its page, "
                                                              "never by another plugin: neighbour asked it.")
        assert asking.refusal(MACHINE, hook, None).endswith("This ask names no asker: neither the page nor a plugin.")
    for hook in READS:
        assert {asking.refusal(MACHINE, hook, who) for who in (asking.PAGE, "neighbour", None)} == {""}


def test_another_plugin_or_no_one_asking_a_change_runs_nothing_and_its_page_does(attached):
    app, neighbour, fake, asked, elevated = attached
    for ask in (lambda: neighbour.wants("set_profile", *OFF),  # the review's body, its second confirmation said
                lambda: app.on_its_own("set_profile", *OFF),
                lambda: neighbour.wants("make_rule", *OPEN),
                lambda: app.on_its_own("make_rule", *OPEN),
                lambda: neighbour.wants("set_rule", "RemoteDesktop-UserMode-In-TCP", "on"),  # Remote Desktop let in
                lambda: neighbour.wants("remove_rule", "{A1}"),
                lambda: neighbour.wants("set_network", 11, "private"),
                lambda: neighbour.wants("allow", "x", [5432]),  # a port open to everyone, never confirmed
                lambda: neighbour.wants("remove", "x")):
        with pytest.raises(asking.AskRefused, match="is asked only from its page"):
            ask()
    assert fake.scripts == [] and asked == []  # nothing run nor read, and Windows not asked (UAC)
    assert fake.profiles["Public"]["Enabled"] is True
    assert neighbour.wants("present") is True and neighbour.wants("status")["valid"]  # its reads, as before
    assert neighbour.wants("find_rules", "remote desktop")["said"] == "1 rule found: “remote desktop”"
    assert app.from_page("set_profile", *OFF)["said"] == "the Public profile changed"  # its page's form, confirmed
    assert fake.profiles["Public"]["Enabled"] is False and fake.scripts[0] == wrapped(OFF_SCRIPT)
    assert asked == ([] if elevated else [OFF_SCRIPT])  # at once as an administrator, else through UAC
