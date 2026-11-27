"""What Windows Firewall attaches to (plugin API 2.2): its cards are sound; they name every cmdlet the plugin's scripts
send (the read and every change, through a stand-in powershell.exe), the COM and .NET calls of its read, and the
library's PowerShell calls it runs them with; its facts are what the last read found, asked without a script; and the
cards' pages answer (LIMINAL_VENDOR_PAGES=1 only, the one test that reaches the network). The Netstat tab's socket
tables (their calls and facts: test_netstat.py) and the services' networks (0.8.0) after them. 0.11.0: the World Wide
Web tab's cards (Npcap, DB-IP, the name servers, the globe's data sets' sources) are plugin-platform-worldwideweb's
alone, none here."""
from __future__ import annotations

import inspect
import os
import re

import pytest

import netfake

from liminal_libs.machines import windows
from liminal_libs.sources.apis import dead_links, problems
from plugin_platform_firewall_windows import MACHINE, READ_SCRIPT
from plugin_platform_firewall_windows import apis as cards
from test_plugin import FakeWindows, plugin

CMDLET = re.compile(r"\b(?:Get|Set|New|Remove|Enable|Disable|Copy|Show|Start|Add|Update|Invoke|ConvertTo)-[A-Z][A-Za-z]+")


def drive():
    """0.8.0: through netfake.FakeNet, the network read and steps too. The read and every change the plugin makes, through the stand-in, as an administrator: a rule turned on and
    off, one removed, one made, a profile set, a network's category, the setup's profiles on, the exposure check, and
    Liminal's own rule made and removed by name; the scripts it sent."""
    fake = netfake.FakeNet()
    fw = plugin(fake)
    fw.status()
    fw.set_rule("RemoteDesktop-UserMode-In-TCP", "on")
    fw.set_rule("RemoteDesktop-UserMode-In-TCP", "off")
    fw.remove_rule("{A1}")
    fw.make_rule("Liminal path check 8795", "in", "allow", "tcp", "8795", "", "LocalSubnet", "Public")
    fw.set_profile("Private", notify="off")
    fw.set_network(11, "private", accept_risk=True)
    fw.enable()
    fw.exposing((8765, 8775))
    fw.allow("web", (8443,), detail="a test")
    fw.snapshot(fresh=True, wait=5)
    fw.remove("web")
    netfake.drive_network(fw)  # 0.8.0: the network read, a route, a proxy, and both taken away
    return fw, fake


def used_cmdlets() -> set[str]:
    return {m for api in MACHINE.apis for c in api.used for m in CMDLET.findall(c.name)}


def test_the_cards_are_sound_and_each_says_where_its_documentation_is():
    assert problems(MACHINE.apis) == [] and MACHINE.apis == cards.APIS
    names = ["Windows PowerShell 5.1", "NetSecurity (PowerShell)", "NetConnection (PowerShell)",
             "Microsoft Defender Antivirus (Defender module)", "Windows Firewall (its policy over COM)",
             "Windows' names for a rule's service, app and program",
             "Windows' socket tables and their owners (IP Helper)",  # 0.7.0: the Netstat tab's
             "NetTCPIP (PowerShell)", "netsh (port proxy and excluded ports)"]  # 0.8.0: services' networks
    # 0.11.0 (the user, 2026-11-26, "Delete now"): the World Wide Web tab's cards are plugin-platform-worldwideweb's
    assert [a.name for a in MACHINE.apis] == names
    assert all(a.docs.startswith("https://learn.microsoft.com/") for a in MACHINE.apis)
    assert all(a.verified == "2026-11-11" for a in MACHINE.apis[:6])
    assert (cards.SOCKETS.docs, cards.SOCKETS.verified) == (
        "https://learn.microsoft.com/en-us/windows/win32/iphlp/ip-helper-start-page", "2026-11-18")
    assert not hasattr(cards, "INFRASTRUCTURE") and not hasattr(cards, "GLOBE2") and not hasattr(cards, "NPCAP")
    assert all(a.used and a.covered and len(a.areas) > len(a.covered) for a in MACHINE.apis)  # more of each API than it uses
    assert not any(c.costs for a in MACHINE.apis for c in a.calls)  # nothing here costs money
    assert {c.name for c in cards.NETSECURITY.calls if c.writes} >= {"Remove-NetFirewallRule", "Set-NetFirewallProfile"}


def test_the_cards_name_every_cmdlet_the_plugins_scripts_send(monkeypatch):
    fw, fake = drive()
    sent = {m for s in fake.scripts for m in CMDLET.findall(s)}
    named = used_cmdlets()
    assert sent <= named, sorted(sent - named)
    assert named - {"Start-Process"} <= sent, sorted(named - sent)  # Start-Process: the library's own elevation (below)
    assert all(c.name.split()[0] in " ".join(fake.scripts) for c in cards.NETSECURITY.used)


def test_the_cards_name_the_com_and_dotnet_calls_of_the_read():
    read = READ_SCRIPT.read_text(encoding="utf-8")
    assert "New-Object -ComObject HNetCfg.FwPolicy2" in read and "$policy.Rules" in read and "RemoteAddresses" in read
    assert "[Diagnostics.FileVersionInfo]::GetVersionInfo(" in read
    assert "IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)" in read
    for c in (*cards.NETSECURITY.used, *cards.NETCONNECTION.used, *cards.DEFENDER_API.used, *cards.NAMES.used):
        if c.name.startswith("Get-"):
            assert c.name.split()[0] in read, c.name


def test_the_powershell_card_names_how_the_library_runs_and_elevates_the_scripts():
    args = windows.PowerShell(runner=lambda a, t: (0, "", "")).args("Get-Date")
    assert " ".join(args[:6]) + " <script>" == cards.POWERSHELL.calls[0].name
    assert "ConvertTo-Json -Compress -Depth 5" in inspect.getsource(windows.PowerShell.json)
    assert "Start-Process -FilePath powershell.exe -Verb RunAs -Wait" in inspect.getsource(windows.PowerShell.run_elevated)
    assert "IsUserAnAdmin" in inspect.getsource(windows.is_elevated)


def test_its_facts_are_what_the_last_read_found_and_asking_them_sends_nothing():
    fake = FakeWindows()
    fresh = plugin(fake)
    assert fresh.api_facts() == {} and fake.scripts == []
    fw, fake = drive()
    before = len(fake.scripts)
    facts = fw.api_facts()
    assert len(fake.scripts) == before  # nothing asked
    net = facts["NetSecurity (PowerShell)"]
    assert net["Rules"].endswith(" on)") and net["Profiles"] == "Domain on, Private on, Public on" and net["Read as"].startswith("not")
    assert facts["NetConnection (PowerShell)"] == {"Networks": "Wi-Fi (private)"}
    assert facts["Microsoft Defender Antivirus (Defender module)"]["State"].startswith("antivirus on, real-time protection on")
    failed = plugin(FakeWindows(fail_read="The RPC server is unavailable."))
    failed.snapshot(wait=5)
    assert failed.api_facts() == {"NetSecurity (PowerShell)": {"Last read failed": "The RPC server is unavailable."}}


@pytest.mark.skipif(os.environ.get("LIMINAL_VENDOR_PAGES") != "1", reason="reaches the makers' pages: LIMINAL_VENDOR_PAGES=1")
def test_the_cards_pages_answer():
    assert dead_links(MACHINE.apis) == []
