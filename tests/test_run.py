"""run(): a PowerShell command line on this PC, run as this process runs it and never through Windows' own prompt
(UAC), whether or not the platform is an administrator. The review's PLT-H1 (2026-11-23): the platform's POST
/api/machines/{name}/run handed any words to a plugin's run(), and the Linux firewall's run() ran them as root (the
library's Shell.run defaults to root); that route is gone (liminal-platform 0.34.1), the command lines
(`liminal-platform machine firewall-windows run -- COMMAND`, this plugin's own `run -- COMMAND`) ask run() in their own
process, and the review asked the same of this plugin. Here run() has been the library's PowerShell.run all along, as
this user: only a change goes through an administrator, one of the plugin's own (_admin: at once when the platform is
one, else through UAC) or one of the base's own steps (its setup, Liminal's own rules: the library's run_admin, through
UAC when you set LIMINAL_ELEVATE=prompt). A form and its confirmation are the page's own and gate nothing: since 0.7.3
the changes are asked only from the page (PAGE_ONLY_HOOKS, tests/test_who_asks.py); before, any program on this PC
could ask one itself. These tests keep run() so: they fail if it ever asks for an administrator by default (through
_admin, run_admin or run_elevated), or when Windows denies a command and LIMINAL_ELEVATE=prompt is set wherever it can
be read. Over a stand-in powershell.exe and a stand-in prompt that notes each ask: nothing runs, nothing is elevated."""
from __future__ import annotations

import pytest

import plugin_platform_firewall_windows as plugin_module
import plugin_platform_firewall_windows.__main__ as cli
from liminal_libs.machines import windows
from liminal_libs.machines.plugin import CommandError
from liminal_libs.machines.windows import ELEVATE_VAR, PowerShell, wrapped
from test_plugin import FakeWindows, plugin

AS_ADMINISTRATOR = "made as an administrator\r\n"  # the stand-in prompt's answer, as if the user said yes to it
CHANGE = ("Set-NetFirewallRule", "-Name", "'RemoteDesktop-UserMode-In-TCP'", "-Enabled", "True")  # a change, as typed


@pytest.fixture
def uac(monkeypatch):
    """Windows' own prompt (UAC), whichever PowerShell asks it: each ask's script noted and answered as if the user
    said yes, with nothing run. The tests here assert that run() never asked it."""
    asked: list[str] = []

    def run_elevated(self, script, timeout=600.0):
        asked.append(script)
        return AS_ADMINISTRATOR
    monkeypatch.setattr(PowerShell, "run_elevated", run_elevated)
    return asked


def firewall(monkeypatch, fake, elevated, prompt=False):
    """The plugin over `fake`, the platform an administrator or not (`elevated`) whichever way the code asks: the
    plugin's own word for it and the library's is_elevated alike, not how the test itself runs. `prompt`:
    LIMINAL_ELEVATE=prompt wherever it can be read, set before the plugin is made: in this process's environment, where
    the plugin as shipped reads it (MACHINE's PowerShell has no env of its own: os.environ), and in the stand-in
    PowerShell's env, where the library's run_admin reads it here. So a run() that read it from either would ask
    through UAC on every machine, whatever that machine's own environment holds."""
    monkeypatch.setattr(plugin_module, "is_elevated", lambda: elevated)
    monkeypatch.setattr(windows, "is_elevated", lambda: elevated)
    if prompt:
        monkeypatch.setenv(ELEVATE_VAR, "prompt")
    return plugin(fake, env={ELEVATE_VAR: "prompt"} if prompt else None, elevated=elevated)


@pytest.mark.parametrize("elevated", [False, True])
def test_a_command_runs_as_this_process_runs_and_never_through_uac(monkeypatch, uac, elevated):
    fake = FakeWindows()
    fw = firewall(monkeypatch, fake, elevated)
    assert fw.run("Get-NetFirewallProfile") == "ran\r\n"
    assert fw.run("netsh", "advfirewall", "show", "allprofiles") == "ran\r\n"
    # each is the library's PowerShell.run of the words as they are, once: nothing put in front of them (no
    # Start-Process -Verb RunAs), and no read after them as after a change (_admin)
    assert fake.scripts == [wrapped("Get-NetFirewallProfile"), wrapped("netsh advfirewall show allprofiles")]
    assert uac == []
    # what goes through an administrator is one of the plugin's changes (since 0.7.3 asked only from its page:
    # test_who_asks.py): through this prompt when the platform is none, at once when it is one (so this stand-in is
    # where an elevated run() would have asked too)
    fw.set_rule("DeliveryOptimization-TCP-In", "off")
    assert uac == ([] if elevated else ["Set-NetFirewallRule -Name 'DeliveryOptimization-TCP-In' -Enabled False"])


@pytest.mark.parametrize("elevated", [False, True])
def test_a_command_windows_denies_is_said_and_never_asked_again_through_uac(monkeypatch, uac, elevated):
    # LIMINAL_ELEVATE=prompt, set wherever it can be read (firewall's `prompt`), lets the base's own steps (its setup,
    # Liminal's own rules: the library's run_admin) ask through UAC when Windows denies them; run() is none of them,
    # and a command Windows denies stays denied
    fake = FakeWindows(denied=True)
    fw = firewall(monkeypatch, fake, elevated, prompt=True)
    with pytest.raises(CommandError, match=r"^Access is denied\.$") as denied:
        fw.run(*CHANGE)
    assert denied.value.denied and fake.scripts == [wrapped(" ".join(CHANGE))] and uac == []


@pytest.mark.parametrize("elevated", [False, True])
def test_the_command_lines_run_is_the_same_run(monkeypatch, capsys, uac, elevated):
    fake = FakeWindows(denied=True)
    monkeypatch.setattr(cli, "MACHINE", firewall(monkeypatch, fake, elevated, prompt=True))
    assert cli.main(["run", "--", "Get-NetFirewallProfile", "-Name", "Public"]) == 0 and capsys.readouterr().out == "ran\r\n"
    assert cli.main(["run", "--", *CHANGE]) == 1 and capsys.readouterr().err == "Access is denied.\n"
    # the words after "--" as they are (the "--" itself not among them), each run once as this process runs it
    assert fake.scripts == [wrapped("Get-NetFirewallProfile -Name Public"), wrapped(" ".join(CHANGE))]
    assert uac == []
