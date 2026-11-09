"""The rules in groups (0.3.0; the user: "for both firewalls, i need to have groups, like system or application and then
unassociated rules not tied to a specific application or system process can be in an other, i can create labels, like
system or application, as well and move the rules in to that"): each rule sorted by what it is tied to, the read saying
it, and the user's labels and moves kept through the platform's login (a stand-in's variables here), never in Windows'
firewall: no script runs for a move."""
from __future__ import annotations

import json

from test_plugin import BUILTINS, FakeWindows, plugin, win_rule

from liminal_libs.apps.authorization import EnvironmentLogin
from liminal_libs.machines.rulegroups import key_of
from plugin_platform_firewall_windows import READ_SCRIPT, Query, WinRule, parse_snapshot, sort_rule


def group(**kw):
    s = sort_rule(WinRule("{x}", "a rule", **kw), windir=r"C:\Windows")
    return s.group, s.why


def test_each_rule_is_sorted_by_what_it_is_tied_to():
    assert group(service="Dnscache", program=r"%SystemRoot%\system32\svchost.exe") == ("system", "the Windows service Dnscache")
    assert group(service="VendorSvc", program=r"C:\Program Files\Vendor\svc.exe") == (
        "application", r"the service VendorSvc, run by C:\Program Files\Vendor\svc.exe")
    assert group(program="System") == ("system", "the System process: Windows' kernel")
    assert group(program=r"%windir%\system32\mfpmp.exe") == ("system", "mfpmp.exe, in Windows' folder")
    assert group(program=r"C:\WINDOWS\SystemApps\x\app.exe")[0] == "system"
    assert group(program=r"C:\Games\server.exe") == ("application", r"the program C:\Games\server.exe")
    assert group(package="Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy", package_system=True, owner="S-1-5-21-1") == (
        "system", "Windows' own app Microsoft.AAD.BrokerPlugin")
    assert group(package="OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0", owner="S-1-5-21-1") == ("application", "the app OpenAI.ChatGPT-Desktop")
    assert group(owner="S-1-5-21-1") == ("application", "an app's own rule (a Microsoft Store app's)")
    assert group(group="Core Networking", source="@FirewallAPI.dll,-25000") == ("system", "Windows' own rule group Core Networking")
    assert group(group="Xbox", source="@{Microsoft.GamingApp_1.0_x64__8wekyb3d8bbwe?ms-resource://x}")[0] == "other"  # no app said
    assert group(group="Liminal") == ("application", "Liminal's: made on the platform")
    assert group() == ("other", "no program, service or app: its ports and addresses alone")


def test_the_read_says_what_each_rule_is_tied_to():
    script = READ_SCRIPT.read_text(encoding="utf-8")
    assert "Get-NetFirewallServiceFilter -All" in script and "Get-AppxPackage" in script and "SignatureKind -eq 'System'" in script
    snap = parse_snapshot({"Rules": [
        dict(win_rule("{B1}", "Work or school account"), Owner="S-1-5-21-1", Package="Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy",
             PackageSystem=True),
        dict(win_rule("CoreNet-DHCP-In", "DHCP", "Core Networking", "@FirewallAPI.dll,-25301"), Service="Dhcp")]}, at=0, took=0)
    one, two = snap.rules
    assert (one.owner, one.package, one.package_system, one.service) == ("S-1-5-21-1", "Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy", True, "")
    assert (two.service, two.source, two.builtin) == ("Dhcp", "@FirewallAPI.dll,-25301", True)
    assert Query(words="dhcp").matches(two) and Query(words="brokerplugin").matches(one)
    assert sort_rule(one).group == "system" and sort_rule(two).why == "the Windows service Dhcp"


def test_rules_move_between_groups_and_labels_kept_through_the_login_alone():
    fake = FakeWindows()
    fw = plugin(fake)
    fw.show_rules("all")
    fw.status()
    login = EnvironmentLogin(env={})
    fw.login = login  # the platform lends its login; a stand-in's variables here
    scripts = len(fake.scripts)
    assert fw.new_label("Games")["ok"]
    game = key_of("{A1}")
    assert fw.move_rules([game], "Games")["said"] == "1 rule moved to Games"
    assert json.loads(login.env["FIREWALL_WINDOWS_GROUPS"]) == {"v": 1, "labels": ["Games"], "moved": {"Games": [game]}}
    rules = fw.status()["tables"][2]
    assert {g["id"]: g["count"] for g in rules["groups"]} == {"system": 4, "application": 0, "other": 1, "label:Games": 1}
    moved = next(r for r in rules["rows"] if r["key"] == game)
    assert moved["group"] == "label:Games" and moved["own"] == "application" and moved["moved"] is True
    assert moved["why"] == r"the program C:\Games\server.exe"
    assert [c["value"] for c in rules["move"]["choices"]] == ["system", "application", "other", "label:Games", "own"]
    assert len(fake.scripts) == scripts  # nothing asked of Windows for a label or a move
    assert {"label-new", "label-rename", "label-remove"} <= {f["id"] for f in fw.status()["forms"]}
    assert fw.remove_label("Games")["said"] == "the label Games removed: its 1 rule back in their own groups"
    assert "FIREWALL_WINDOWS_GROUPS" not in login.env
    assert set(fw.sorted_rules()) == {key_of(r["Id"]) for r in BUILTINS}
    assert {"move_rules", "new_label", "rename_label", "remove_label"} <= set(fw.interface()["hooks"])
