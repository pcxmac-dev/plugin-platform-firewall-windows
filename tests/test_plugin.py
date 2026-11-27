"""Windows Firewall, read whole and changed, all through a stand-in powershell.exe (nothing here changes this PC's
firewall: it is the user's own security setting): the configuration in one read and kept; the status valid whenever it
can be read, its facts and tables; the rules found and shown by a preset; each change's script, run at once by an
administrator or through UAC otherwise; the risky ones refused until accepted; the base's setup and Liminal's own
rules as before. Off Windows (0.7.0) not for the machine at all, on any library the plugin loads with: nothing read,
run or offered."""
from __future__ import annotations

import inspect
import json
import re

import pytest

import plugin_platform_firewall_windows.__main__ as cli
from liminal_libs.machines.firewall import Rule
from liminal_libs.machines.plugin import CommandError
from liminal_libs.machines.windows import ERROR_MARK, PowerShell, decoded
from plugin_platform_firewall_windows import MACHINE, Query, RiskRefused, WindowsFirewallPlugin, WinRule, rule_of


def win_rule(rid, name, group="", source="", enabled=True, direction="Inbound", action="Allow", profile="Any", program="Any",
             protocol="TCP", local="Any", remote="*"):
    return {"Id": rid, "Name": name, "Group": group, "GroupSource": source or group, "Enabled": enabled, "Direction": direction,
            "Action": action, "Profile": profile, "Program": program, "Protocol": protocol, "LocalPort": local, "RemotePort": "Any",
            "Remote": remote, "Description": "", "Store": "Local"}


BUILTINS = [
    win_rule("RemoteDesktop-UserMode-In-TCP", "Remote Desktop - User Mode (TCP-In)", "Remote Desktop", "@FirewallAPI.dll,-28752",
             enabled=False, local="3389"),
    win_rule("CoreNet-DNS-Out-UDP", "Core Networking - DNS (UDP-Out)", "Core Networking", "@FirewallAPI.dll,-25000",
             direction="Outbound", protocol="UDP", program=r"%SystemRoot%\system32\svchost.exe"),
    win_rule("DeliveryOptimization-TCP-In", "Delivery Optimization (TCP-In)", "Delivery Optimization", "@FirewallAPI.dll,-1",
             local="7680", program=r"%SystemRoot%\system32\svchost.exe"),
    win_rule("CoreNet-ICMP6-RA-In", "Core Networking - Router Advertisement (ICMPv6-In)", "Core Networking", "@FirewallAPI.dll,-2",
             protocol=None, local=None, remote=None),
    win_rule("{D00C34BC}", "codex_sandbox_offline_block_inbound", action="Block", protocol="Any"),
    win_rule("{A1}", "Game server", local="27015-27030", program=r"C:\Games\server.exe"),
]


class FakeWindows:
    """Answers powershell.exe: the whole configuration's read, the base's scripts, and every change, applied to its own
    state; records every script. `services` and `programs` are what 0.4.0's read adds (the services' display names, the
    programs on disk); without them it answers as a read before 0.4.0 did."""

    def __init__(self, profiles=None, rules=None, exposure=(), denied=False, networks=None, fail_read="", services=None, programs=None):
        self.profiles = {n: {"Name": n, "Enabled": True, "Inbound": "NotConfigured", "Outbound": "NotConfigured", "Notify": "True",
                             "AllowInbound": "NotConfigured", "LogBlocked": "False", "LogFile": ""} for n in ("Domain", "Private", "Public")}
        for name, on in (profiles or {}).items():
            self.profiles[name]["Enabled"] = on
        self.rules = [dict(r) for r in (BUILTINS if rules is None else rules)]
        self.networks = networks if networks is not None else [
            {"Index": 11, "Interface": "Wi-Fi", "Name": "Lakeside 4", "Category": "Public", "IPv4": "Internet", "IPv6": "NoTraffic"}]
        self.exposure, self.denied, self.fail_read = list(exposure), denied, fail_read
        self.named = {k: v for k, v in (("Services", services), ("Programs", programs)) if v is not None}
        self.scripts: list[str] = []
        self.reads = 0

    def __call__(self, args, timeout):
        s = decoded(args[6])
        self.scripts.append(s)
        changing = any(k in s for k in ("New-NetFirewallRule", "Remove-NetFirewallRule", "Set-NetFirewallProfile",
                                        "Set-NetFirewallRule", "Set-NetConnectionProfile"))
        if changing and self.denied:
            return 1, ERROR_MARK + "Access is denied.\r\n", ""
        if "HNetCfg.FwPolicy2" in s:  # read.ps1
            self.reads += 1
            if self.fail_read:
                return 1, ERROR_MARK + self.fail_read + "\r\n", ""
            return 0, json.dumps({"Profiles": list(self.profiles.values()), "Networks": self.networks, "Rules": self.rules,
                                  "Defender": {"Antivirus": True, "RealTime": True, "Signatures": "2026-11-07T22:38:16"}, "Elevated": False,
                                  **self.named}), ""
        if "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True" in s:
            for p in self.profiles.values():
                p["Enabled"] = True
            return 0, "", ""
        m = re.search(r"Set-NetFirewallProfile -Name (\w+) (.*)", s)
        if m:
            p = self.profiles[m.group(1)]
            for key, value in re.findall(r"-(\w+) (\w+)", m.group(2)):
                field_ = {"Enabled": "Enabled", "DefaultInboundAction": "Inbound", "DefaultOutboundAction": "Outbound", "NotifyOnListen": "Notify"}[key]
                p[field_] = (value == "True") if field_ == "Enabled" else value
            return 0, "", ""
        m = re.search(r"Set-NetFirewallRule -Name '([^']+)' -Enabled (\w+)", s)
        if m:
            for r in self.rules:
                if r["Id"] == m.group(1):
                    r["Enabled"] = m.group(2) == "True"
            return 0, "", ""
        m = re.search(r"Remove-NetFirewallRule -Name '([^']+)'", s)
        if m:
            self.rules = [r for r in self.rules if r["Id"] != m.group(1)]
            return 0, "", ""
        m = re.search(r"Set-NetConnectionProfile -InterfaceIndex (\d+) -NetworkCategory (\w+)", s)
        if m:
            for n in self.networks:
                if n["Index"] == int(m.group(1)):
                    n["Category"] = m.group(2)
            return 0, "", ""
        if "New-NetFirewallRule" in s:
            ports = re.search(r"-LocalPort ([0-9,-]+)", s)
            name = re.search(r"-DisplayName '([^']+)'", s).group(1)
            self.rules.append(win_rule(f"{{new-{len(self.rules)}}}", name, "Liminal",
                                       direction="Outbound" if "-Direction Outbound" in s else "Inbound",
                                       action="Block" if "-Action Block" in s else "Allow", protocol=re.search(r"-Protocol (\w+)", s).group(1),
                                       local=ports.group(1) if ports else "Any"))
            return 0, "", ""
        if "Remove-NetFirewallRule" in s or "$_.DisplayName -eq" in s:  # the base's delete of one of Liminal's by name
            display = re.search(r"\$_\.DisplayName -eq '([^']+)'", s).group(1)
            gone = [r for r in self.rules if r["Name"] == display and r["Group"] == "Liminal"]
            self.rules = [r for r in self.rules if r not in gone]
            return 0, f"{len(gone)}\r\n", ""
        if "Get-NetFirewallRule -Direction Inbound" in s:
            return 0, json.dumps([{"Port": p, "Rule": r} for p, r in self.exposure]), ""
        return 0, "ran\r\n", ""


def text(c):
    """A table cell's text (a cell is its text, or {text, sub})."""
    return c["text"] if isinstance(c, dict) else c


def plugin(fake, env=None, elevated=True, t=None):
    clock = (lambda: t[0]) if t is not None else (lambda: 1_800_000_000.0)
    return WindowsFirewallPlugin(PowerShell(runner=fake, env=env or {}), elevated=lambda: elevated, clock=clock)


def test_the_plugin_reads_windows_rules_as_the_framework_sees_them():
    assert MACHINE.name == "firewall-windows" and MACHINE.KIND == "machine" and MACHINE.SYSTEM == "platform" and MACHINE.STEPS == ("enable", "exposure", "rules")
    mine = rule_of({"Name": "Liminal: mail-example-test", "Group": "Liminal", "Direction": "Inbound", "Action": "Allow", "Enabled": True,
                    "Protocol": "TCP", "LocalPort": "25,587", "RemoteAddress": "Any", "Description": "mail"})
    assert (mine.name, mine.ports, mine.protocol, mine.owned, mine.remote, mine.detail) == ("mail-example-test", (25, 587), "tcp", True, "any", "mail")
    theirs = rule_of({"Name": "Core Networking - DNS (UDP-Out)", "Group": "@FirewallAPI.dll,-25000", "Direction": "Outbound", "Action": "Allow",
                      "Enabled": True, "Protocol": "17", "LocalPort": "Any", "RemoteAddress": "Any"})
    assert (theirs.owned, theirs.protocol, theirs.direction, theirs.ports) == (False, "udp", "out", ())
    posing = rule_of({"Name": "Liminal: mail", "Group": "Someone else", "Protocol": "Any", "LocalPort": "Any"})
    assert not posing.owned  # a rule naming itself Liminal's, outside the group, is not ours


def test_the_whole_configuration_is_read_once_kept_and_said():
    fake = FakeWindows()
    fw = plugin(fake, elevated=False)
    s = fw.status()
    assert s["valid"] and s["present"] and "problem" not in s and fake.reads == 1
    assert s["summary"] == "Windows Defender Firewall: on; Public network in use; 6 rules (3 letting in)"
    assert s["firewall"] == "on for Domain, Private, Public" and s["networkInUse"] == "Wi-Fi: Lakeside 4 (public)"
    assert s["inbound"] == "Domain block (Windows' default); Private block (Windows' default); Public block (Windows' default)"
    assert s["ruleCount"] == "6: 3 letting in, 0 Liminal's, 1 turned off"
    assert s["remoteAddresses"] == "read for 5 of 6 rules (an administrator reads them all)"
    assert s["defender"] == "antivirus on, real-time protection on, signatures of 2026-11-07 22:38"
    assert s["administrator"] == "no: Windows asks for an administrator's permission (UAC) for each change" and "rules" not in s
    fw.status()
    assert fake.reads == 1  # kept: the platform asks every plugin's status on each look
    networks, profiles, rules = s["tables"]
    assert networks["rows"][0][:4] == ["Wi-Fi", "Lakeside 4", {"text": "public", "sub": "the Public profile applies"}, "IPv4 Internet, IPv6 NoTraffic"]
    assert networks["rows"][0][4] == {"form": "network", "title": "Make private", "label": "Make Wi-Fi private",
                                      "values": {"index": 11, "category": "Private", "label": "Wi-Fi: Lakeside 4"}}
    assert [r[0] for r in profiles["rows"]] == ["Domain", "Private", "Public"] and profiles["rows"][2][5] == "Wi-Fi"
    assert profiles["rows"][2][6]["values"] == {"profile": "Public", "enabled": "on", "inbound": "default", "outbound": "default", "notify": "on"}
    assert [c["value"] for c in rules["options"][0]["choices"]] == ["in-allow", "in-block", "out", "liminal", "off", "all"]
    assert rules["options"][0]["value"] == "in-allow" and rules["options"][0]["hook"] == "show_rules"
    assert [c["note"] for c in rules["options"][0]["choices"]] == ["4 rules, 1 turned off", "1 rule", "1 rule", "0 rules", "1 rule",
                                                                   "6 rules, 1 turned off"]  # 0.4.0: the rules turned off counted in
    cells = [r["cells"] for r in rules["rows"]]  # 0.3.0: each row {cells, key, group, own, why}, in its group
    assert [text(c[0]) for c in cells] == ["Delivery Optimization (TCP-In)", "Core Networking - Router Advertisement (ICMPv6-In)", "Game server",
                                           "Remote Desktop - User Mode (TCP-In)"]  # 0.4.0: the one turned off too, after those on
    assert [r["group"] for r in rules["rows"]] == ["system", "system", "application", "system"]
    assert [r.get("off", False) for r in rules["rows"]] == [False, False, False, True] and cells[3][8]["title"] == "Turn on"
    assert rules["note"] == "4 shown (1 turned off): inbound allowed; moving a rule to another group changes nothing in the firewall"
    game = cells[2]
    assert game[3] == "TCP 27015-27030" and game[5] == "any" and game[9]["form"] == "rule-remove"  # not one of Windows' own
    assert cells[0][9] == "–" and cells[1][3] == "not read" and cells[1][5] == "not read"
    assert cells[0][8] == {"form": "rule-state", "title": "Turn off", "label": "Turn off Delivery Optimization (TCP-In)",
                           "values": {"rule_id": "DeliveryOptimization-TCP-In", "enabled": "off",
                                      "label": "Delivery Optimization (TCP-In) (DeliveryOptimization-TCP-In)"}}
    assert [a.get("form") or a.get("hook") for a in rules["actions"]] == ["rule-add", "find", "refresh", "label-new"]
    assert [(g["id"], g["count"]) for g in rules["groups"]] == [("system", 3), ("application", 1), ("other", 0)]
    by = {g["id"]: g for g in rules["groups"]}  # 0.4.0: a heading for each service and application
    assert [(c["title"], c["count"]) for c in by["system"]["children"]] == [("Core Networking", 1), ("Delivery Optimization", 1),
                                                                            ("Remote Desktop", 1)]
    assert [(c["title"], c["count"]) for c in by["application"]["children"]] == [("Game server", 1)]  # in no install folder: its rule's name


def test_rules_are_found_and_shown_by_a_preset():
    fw = plugin(FakeWindows())
    fw.status()
    assert fw.show_rules("off")["said"] == "showing turned off" and [r.name for r in fw.rules_shown()[1]] == ["Remote Desktop - User Mode (TCP-In)"]
    assert fw.find_rules("remote desktop")["said"] == "1 rule found: “remote desktop”"
    assert fw.find_rules(None, 27020)["said"] == "3 rules found: port 27020"  # the range, and two rules for every port
    assert [r.name for r in fw.rules_shown()[1]][0] == "Game server"  # the rule naming the port (here a range) first
    assert fw.find_rules("", 53, "out", "allow")["said"] == "1 rule found: port 53, outbound, allowing"
    t = fw.status()["tables"][2]
    assert t["options"][0]["value"] == "found" and t["options"][0]["choices"][-1] == {"value": "found", "title": "Found", "note": "port 53, outbound, allowing"}
    assert fw.show_rules("all")["said"] == "showing all" and len(fw.rules_shown()[1]) == 6
    for bad in (("", 70000), ("", None, "sideways"), ("", None, "", "maybe")):
        with pytest.raises(ValueError):
            fw.find_rules(*bad)
    with pytest.raises(ValueError):
        fw.show_rules("nonsense")
    assert WinRule("x", "x", local="RPC").covers(135) is False and WinRule("y", "y", local=None).covers(80) is False
    assert Query(words="dns core").matches(WinRule("z", "Core Networking - DNS (UDP-Out)"))


def test_each_change_runs_as_an_administrator_and_is_read_back():
    fake = FakeWindows()
    fw = plugin(fake)
    fw.status()
    a = fw.set_rule("RemoteDesktop-UserMode-In-TCP", "on")
    assert a["said"] == "“Remote Desktop - User Mode (TCP-In)” turned on" and a["ok"] and "Set-NetFirewallRule -Name 'RemoteDesktop-UserMode-In-TCP' -Enabled True" in fake.scripts[-2]
    assert fw.set_rule("RemoteDesktop-UserMode-In-TCP", "on")["said"].endswith("is on already")
    with pytest.raises(ValueError, match="one of Windows' own rules: turn it off instead"):
        fw.remove_rule("CoreNet-DNS-Out-UDP")
    assert fw.remove_rule("{A1}") == {"said": "“Game server” removed", "ok": True}
    made = fw.make_rule("Liminal path check 8795", "in", "allow", "tcp", "8795", "", "LocalSubnet, 203.0.113.0/24", "Public")
    assert made["ok"] and made["said"] == "“Liminal path check 8795” made (inbound allow, TCP 8795)"
    script = next(s for s in fake.scripts if "New-NetFirewallRule" in s)
    for piece in ("-Group 'Liminal'", "-DisplayName 'Liminal path check 8795'", "-Direction Inbound", "-Action Allow", "-Protocol TCP",
                  "-Profile Public", "-LocalPort 8795", "-RemoteAddress 'LocalSubnet','203.0.113.0/24'"):
        assert piece in script
    assert fw.status()["ruleCount"].endswith("1 Liminal's, 0 turned off")
    for bad, words in ((("", "in"), "needs a name"), (("x", "up"), "direction is in or out"), (("x", "in", "allow", "any", "80"), "need a protocol"),
                       (("x", "in", "allow", "tcp", "http"), "numbers or ranges"), (("x", "in", "allow", "tcp", "70000"), "1 to 65535"),
                       (("x", "in", "allow", "tcp", "", "", "", "Office"), "profiles are any")):
        with pytest.raises(ValueError, match=words):
            fw.make_rule(*bad)
    assert fw.set_network(11, "private", accept_risk=True)["said"] == "Wi-Fi (Lakeside 4) is private now"
    assert "Set-NetConnectionProfile -InterfaceIndex 11 -NetworkCategory Private" in "\n".join(fake.scripts)
    assert fw.status()["networkInUse"] == "Wi-Fi: Lakeside 4 (private)"
    with pytest.raises(ValueError, match="no rule with the id"):
        fw.set_rule("gone", "off")


def test_a_rule_made_twice_is_refused_before_anything_runs():
    # the review of 2026-11-21, item 26: "Make a rule" asked twice made two rules the same
    fake = FakeWindows(rules=[*BUILTINS, win_rule("{L1}", "web", "Liminal", local="80")])
    fw = plugin(fake)
    fw.status()
    for name in ("web", "WEB"):
        with pytest.raises(ValueError, match="a Liminal rule named “.+” is there already: remove it first"):
            fw.make_rule(name, "in", "allow", "tcp", "80")
    assert not any("New-NetFirewallRule" in s for s in fake.scripts)
    assert [r["Name"] for r in fake.rules].count("web") == 1
    # another's rule of that name (not in the group Liminal) is no bar
    fake = FakeWindows(rules=[*BUILTINS, win_rule("{O1}", "web", local="80")])
    assert plugin(fake).make_rule("web", "in", "allow", "tcp", "80")["ok"]


def test_a_profile_off_or_open_by_default_is_asked_again_and_said_after():
    fake = FakeWindows()
    fw = plugin(fake)
    fw.status()
    assert fw.set_profile("Public", "on", "default", "default", "on")["said"] == "the Public profile is as asked already"
    with pytest.raises(RiskRefused) as refused:
        fw.set_profile("Public", "off")
    assert refused.value.accept == "accept_risk" and "the one this PC's network uses now" in str(refused.value)
    assert "DMZ host" in str(refused.value) and not any("Set-NetFirewallProfile -Name" in s for s in fake.scripts)
    with pytest.raises(RiskRefused, match="lets everything in by default"):
        fw.set_profile("Private", None, "allow")
    done = fw.set_profile("Public", "off", None, None, "off", True)
    assert done["said"] == "the Public profile changed" and done["lines"] == [
        "firewall off; inbound block (Windows' default); outbound allow (Windows' default); notifications off"]
    assert "Set-NetFirewallProfile -Name Public -Enabled False -NotifyOnListen False" in "\n".join(fake.scripts)
    s = fw.status()
    assert s["valid"] and s["problem"].startswith("the firewall is off for Public (the profile in use)")
    fw.set_profile("Public", "on", "block")
    assert fake.profiles["Public"]["Inbound"] == "Block" and "problem" not in fw.status()
    with pytest.raises(ValueError, match="Domain, Private or Public"):
        fw.set_profile("Home", "on")


def test_without_elevation_a_change_goes_through_uac():
    fake = FakeWindows()
    fw = plugin(fake, elevated=False)
    fw.status()
    asked = []

    def elevated(script, timeout=600.0):
        asked.append(script)
        return fw.ps.run(script)  # as if the user said yes to Windows' prompt
    fw.ps.run_elevated = elevated
    fw.set_rule("DeliveryOptimization-TCP-In", "off")
    assert asked == ["Set-NetFirewallRule -Name 'DeliveryOptimization-TCP-In' -Enabled False"]
    assert "UAC" in [f for f in fw.status()["forms"] if f["id"] == "rule-state"][0]["confirm"]["words"]


def test_the_forms_ask_each_hook_with_its_arguments_in_order():
    fw = plugin(FakeWindows())
    forms = {f["id"]: f for f in fw.status()["forms"]}
    for form_id, hook in (("rule-state", fw.set_rule), ("rule-remove", fw.remove_rule), ("rule-add", fw.make_rule),
                          ("find", fw.find_rules), ("profile", fw.set_profile), ("network", fw.set_network)):
        f = forms[form_id]
        assert f["hook"] == hook.__name__ and [x["name"] for x in f["fields"]] == list(inspect.signature(hook).parameters), form_id
        assert f["hook"] in fw.HOOKS
    assert forms["find"]["confirm"] is False and forms["rule-remove"]["confirm"]["danger"]
    assert [x for x in forms["profile"]["fields"] if x["type"] == "accept"][0]["name"] == "accept_risk"


def test_a_configuration_that_cannot_be_read_is_said():
    fw = plugin(FakeWindows(fail_read="Access is denied."))
    s = fw.status()
    assert not s["valid"] and s["why"] == "cannot be read: Access is denied." and s["summary"] == "cannot be read: Access is denied."


def test_status_and_the_whole_setup_on_a_pc_with_a_profile_off():
    fake = FakeWindows(profiles={"Public": False}, exposure=[(8765, "Python")], rules=[])
    fw = plugin(fake)
    fw.wanted = lambda: [Rule("mail-example-test", ports=(25, 587), detail="the mail server container")]
    st = fw.status()
    assert st["present"] and not st["enabled"] and st["valid"]
    assert st["problem"] == ("the firewall is off for Public (the profile in use): its setup, or Change… on its profile, turns it on; "
                             "1 of the framework's rules missing: its setup adds them")
    done = fw.setup(log=lambda m: None)
    assert [(d["step"], d["ok"]) for d in done] == [("enable", True), ("exposure", False), ("rules", True)]
    assert "charts (8765) by Python" in done[1]["detail"]
    made = next(s for s in fake.scripts if "New-NetFirewallRule" in s)
    for piece in ("-Group 'Liminal'", "-DisplayName 'Liminal: mail-example-test'", "-Direction Inbound", "-Action Allow", "-Protocol TCP",
                  "-LocalPort 25,587", "-RemoteAddress 'Any'", "-Profile Any"):
        assert piece in made
    fw.snapshot(fresh=True, wait=5)
    assert "problem" not in fw.status() and [r.name for r in fw.list_rules()] == ["mail-example-test"]
    assert [(d["step"], d["ok"]) for d in fw.setup(log=lambda m: None)] == [("enable", None), ("exposure", False), ("rules", None)]
    script = next(s for s in fake.scripts if "Get-NetFirewallRule -Direction Inbound" in s)
    assert "$ports = @(8765,8775,8785,8795)" in script and "python(w)?(3[0-9.]*)?\\.exe$" in script


def test_liminals_rules_are_made_and_removed_and_no_other_is_touched():
    other = win_rule("{B2}", "Liminal: web", "Not Liminal", local="80")
    fake = FakeWindows(rules=[other])
    fw = plugin(fake)
    fw.allow("web", (8443,), detail="a test")
    fw.snapshot(fresh=True, wait=5)
    assert [r.name for r in fw.list_rules()] == ["web"]
    assert fw.remove("web") and fake.rules == [other]  # the other group's rule is left alone
    fw.snapshot(fresh=True, wait=5)
    assert not fw.remove("web")
    assert fw.run("Write-Output", "'hello'") == "ran\r\n" and fake.scripts[-1].endswith("} catch { [Console]::Out.WriteLine('LIMINAL-ERROR: ' + $_.Exception.Message); exit 1 }")


def test_without_an_administrator_the_setup_says_how_to_give_the_rights():
    fw = plugin(FakeWindows(denied=True, rules=[]))
    fw.wanted = lambda: [Rule("mail-example-test", ports=(25,))]
    done = fw.setup(log=lambda m: None, steps=("rules",))
    assert done[0]["ok"] is False and "needs an administrator" in done[0]["detail"] and "LIMINAL_ELEVATE=prompt" in done[0]["detail"]


def test_the_command_line_reads_finds_and_refuses_a_risk(monkeypatch, capsys):
    fw = plugin(FakeWindows())
    monkeypatch.setattr(cli, "MACHINE", fw)
    assert cli.main(["profiles"]) == 0 and capsys.readouterr().out.splitlines()[2].startswith("Public   firewall on;")
    assert cli.main(["networks"]) == 0 and "Wi-Fi: Lakeside 4 (Public)" in capsys.readouterr().out
    assert cli.main(["find", "game", "--in"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "1 rule found: “game”, inbound" and out[1].startswith("on   in   allow  TCP 27015-27030") and out[1].endswith("[{A1}]")
    assert cli.main(["rules", "off"]) == 0 and "Remote Desktop - User Mode (TCP-In)" in capsys.readouterr().out
    assert cli.main(["set-profile", "Public", "--off"]) == 1 and "--accept-risk changes it anyway" in capsys.readouterr().err
    assert cli.main(["set-rule", "{A1}", "off"]) == 0 and "“Game server” turned off" in capsys.readouterr().out
    assert cli.main(["add-rule", "Liminal 8795", "--ports", "8795", "--profiles", "Public"]) == 0
    assert cli.main(["remove-rule", "CoreNet-DNS-Out-UDP"]) == 1 and "turn it off instead" in capsys.readouterr().err
    with pytest.raises(SystemExit) as usage:
        cli.main(["nonsense"])
    assert usage.value.code == 2


@pytest.mark.parametrize("system, called", [("linux", "Linux"), ("darwin", "macOS")])
def test_off_windows_it_is_not_for_the_machine_and_reads_runs_and_offers_nothing(system, called):
    """Windows Defender Firewall is Windows' own (0.7.0; B-critique S1): off Windows (a Linux platform, the WSL suite's
    among them, or macOS) the plugin is not for the machine at all, with liminal-libs 1.63.0 as with 1.65.0. Its status
    says so and offers no setup; no read is run, nor a thread started for one; no change is run; it knows no facts.
    (Its Netstat tab's hooks, liminal-libs 1.65.0's: test_netstat.py; 0.11.0: it has no World Wide Web tab, which is
    plugin-platform-worldwideweb's.)"""
    fake = FakeWindows()
    fw = WindowsFirewallPlugin(PowerShell(runner=fake, env={}), elevated=lambda: True, system=system)
    why = f"Windows Defender Firewall is Windows' own, and this machine runs {called}"
    assert fw.not_for_here() == why and not fw.present()
    st = fw.status()
    assert (st["applies"], st["valid"], st["summary"], st["why"]) == (False, False, "not for this machine", why)
    assert fw.setup(log=lambda line: None) == [{"step": "enable", "ok": False, "detail": why}]
    assert "world" not in fw.HOOKS  # 0.11.0: the World Wide Web tab is plugin-platform-worldwideweb's
    assert fw.snapshot(fresh=True, wait=0.5) is None
    for change in (fw.refresh, lambda: fw.set_rule("RemoteDesktop-UserMode-In-TCP", "on"),
                   lambda: fw.make_rule("Liminal path check 8795", ports="8795")):
        with pytest.raises(CommandError, match="not for this machine"):
            change()
    assert fake.scripts == [] and fw.api_facts() == {}  # nothing run, nothing known
    assert fw._rt.reader is None and fw._rt.error == ""  # no read even tried: no thread started for one
    assert WindowsFirewallPlugin(PowerShell(runner=fake, env={}), system="win32").not_for_here() == ""
