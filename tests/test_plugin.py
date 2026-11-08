"""Windows Firewall: its status, its setup (on, exposure, the services' rules), Liminal's rules made and removed
and no other touched, the refusal when not an administrator, all through a stand-in powershell.exe (nothing
changes here)."""
from __future__ import annotations

import json
import re

from liminal_libs.machines.firewall import Rule
from liminal_libs.machines.windows import ERROR_MARK, PowerShell, decoded

from plugin_platform_firewall_windows import MACHINE, WindowsFirewallPlugin, rule_of


class FakeWindows:
    """Answers powershell.exe: the profiles, the rules, what the exposure check finds; records every script."""

    def __init__(self, profiles=None, rules=None, exposure=(), denied=False):
        self.profiles = dict(profiles or {"Domain": True, "Private": True, "Public": True})
        self.rules = list(rules or [])
        self.exposure = list(exposure)
        self.denied = denied
        self.scripts: list[str] = []

    def __call__(self, args, timeout):
        s = decoded(args[6])
        self.scripts.append(s)
        changing = any(k in s for k in ("New-NetFirewallRule", "Remove-NetFirewallRule", "Set-NetFirewallProfile"))
        if changing and self.denied:
            return 1, ERROR_MARK + "Access is denied.\r\n", ""
        if "Set-NetFirewallProfile" in s:
            self.profiles = {k: True for k in self.profiles}
            return 0, "", ""
        if "New-NetFirewallRule" in s:
            ports = re.search(r"-LocalPort ([0-9,]+)", s)
            self.rules.append({"Name": re.search(r"-DisplayName '([^']+)'", s).group(1), "Group": "Liminal", "Direction": "Inbound",
                               "Action": "Allow", "Enabled": True, "Protocol": re.search(r"-Protocol (\w+)", s).group(1),
                               "LocalPort": ports.group(1) if ports else "Any", "RemoteAddress": "Any",
                               "Description": re.search(r"-Description '([^']*)'", s).group(1)})
            return 0, "", ""
        if "Remove-NetFirewallRule" in s:
            display = re.search(r"\$_\.DisplayName -eq '([^']+)'", s).group(1)
            gone = [r for r in self.rules if r["Name"] == display and r["Group"] == "Liminal"]
            self.rules = [r for r in self.rules if r not in gone]
            return 0, f"{len(gone)}\r\n", ""
        if "Get-NetFirewallProfile" in s:
            return 0, json.dumps([{"Name": n, "Enabled": v, "Inbound": "Block", "Outbound": "Allow"} for n, v in self.profiles.items()]), ""
        if "Get-NetFirewallRule -Direction Inbound" in s:
            return 0, json.dumps([{"Port": p, "Rule": r} for p, r in self.exposure]), ""
        if "Get-NetFirewallRule -Group 'Liminal'" in s:
            mine = [r for r in self.rules if r["Group"] == "Liminal"]
            return 0, (json.dumps(mine[0] if len(mine) == 1 else mine) if mine else ""), ""
        return 0, "ran\r\n", ""


def plugin(fake, env=None):
    return WindowsFirewallPlugin(PowerShell(runner=fake, env=env or {}))


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


def test_status_and_the_whole_setup_on_a_pc_with_a_profile_off():
    fake = FakeWindows(profiles={"Domain": True, "Private": True, "Public": False}, exposure=[(8765, "Python")])
    fw = plugin(fake)
    fw.wanted = lambda: [Rule("mail-example-test", ports=(25, 587), detail="the mail server container")]
    st = fw.status()
    assert st["present"] and not st["enabled"] and st["profiles"] == {"Domain": True, "Private": True, "Public": False}
    assert st["summary"] == "Windows Defender Firewall: off (Domain, Private on; Public off); 0 Liminal rule(s)"
    done = fw.setup(log=lambda m: None)
    assert [(d["step"], d["ok"]) for d in done] == [("enable", True), ("exposure", False), ("rules", True)]
    assert "charts (8765) by Python" in done[1]["detail"]
    made = next(s for s in fake.scripts if "New-NetFirewallRule" in s)
    for piece in ("-Group 'Liminal'", "-DisplayName 'Liminal: mail-example-test'", "-Direction Inbound", "-Action Allow", "-Protocol TCP",
                  "-LocalPort 25,587", "-RemoteAddress 'Any'", "-Profile Any"):
        assert piece in made
    assert fw.status()["summary"] == "Windows Defender Firewall: on (Domain, Private, Public on); 1 Liminal rule(s)"
    assert [(d["step"], d["ok"]) for d in fw.setup(log=lambda m: None)] == [("enable", None), ("exposure", False), ("rules", None)]
    script = next(s for s in fake.scripts if "Get-NetFirewallRule -Direction Inbound" in s)
    assert "$ports = @(8765,8775,8785,8795,8796)" in script and "python(w)?(3[0-9.]*)?\\.exe$" in script


def test_liminals_rules_are_made_and_removed_and_no_other_is_touched():
    other = {"Name": "Liminal: web", "Group": "Not Liminal", "Direction": "Inbound", "Action": "Allow", "Enabled": True,
             "Protocol": "TCP", "LocalPort": "80", "RemoteAddress": "Any"}
    fake = FakeWindows(rules=[other])
    fw = plugin(fake)
    fw.allow("web", (8443,), detail="a test")
    assert [r.name for r in fw.list_rules()] == ["web"]
    assert fw.remove("web") and not fw.remove("web") and fake.rules == [other]  # the other group's rule is left alone
    assert fw.run("Write-Output", "'hello'") == "ran\r\n" and fake.scripts[-1].endswith("} catch { [Console]::Out.WriteLine('LIMINAL-ERROR: ' + $_.Exception.Message); exit 1 }")


def test_without_an_administrator_it_says_how_to_give_the_rights():
    fw = plugin(FakeWindows(denied=True))
    fw.wanted = lambda: [Rule("mail-example-test", ports=(25,))]
    done = fw.setup(log=lambda m: None, steps=("rules",))
    assert done[0]["ok"] is False and "needs an administrator" in done[0]["detail"] and "LIMINAL_ELEVATE=prompt" in done[0]["detail"]
