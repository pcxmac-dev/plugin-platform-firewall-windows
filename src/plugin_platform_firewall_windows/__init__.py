"""Windows Firewall for Liminal (the user, 2026-11-07: "i also need a windows and linux firewall plugin for the
platform"; the platform is "the interface for the software/hardware which facilitates the liminal
framework"): Windows Defender Firewall on this PC, driven through PowerShell's NetSecurity cmdlets (the
library's machines.windows.PowerShell): on for every profile; no rule letting another machine reach the
framework's pages; the ports the framework's services need (a domain login's mail server container) opened
as Liminal's own rules, in the rule group "Liminal", the only rules it ever changes. Changing the firewall
needs an administrator: run the platform as administrator, or set LIMINAL_ELEVATE=prompt to be asked (UAC)
when a step needs it. The library's Firewall base holds the rules, the status and the setup; this module
drives Windows'.

    python -m plugin_platform_firewall_windows status | setup [STEP ...] | rules | exposure
                                               | allow NAME PORT[,PORT ...] [tcp|udp] | remove NAME | run -- COMMAND
"""
from __future__ import annotations

from liminal_libs.machines.firewall import GROUP, NAME, Firewall, FirewallError, Rule
from liminal_libs.machines.windows import PowerShell, quote

__version__ = "0.1.0"
DIRECTIONS = {"in": "Inbound", "out": "Outbound"}
ACTIONS = {"allow": "Allow", "block": "Block"}
PROTOCOLS = {"tcp": "TCP", "udp": "UDP", "any": "Any"}
PROTOCOL_NUMBERS = {"6": "tcp", "17": "udp"}
RULE_FIELDS = ("$pf = $_ | Get-NetFirewallPortFilter; $af = $_ | Get-NetFirewallAddressFilter; "
               "[pscustomobject]@{ Name = $_.DisplayName; Group = [string]$_.Group; Direction = $_.Direction.ToString(); "
               "Action = $_.Action.ToString(); Enabled = ($_.Enabled.ToString() -eq 'True'); Protocol = [string]$pf.Protocol; "
               "LocalPort = (@($pf.LocalPort) -join ','); RemoteAddress = (@($af.RemoteAddress) -join ','); "
               "Description = [string]$_.Description }")


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
                remote="any" if remote.lower() == "any" else remote, enabled=bool(row.get("Enabled", True)), owned=owned,
                detail=str(row.get("Description") or ""))


class WindowsFirewallPlugin(Firewall):
    name = "firewall-windows"
    title = "Windows Firewall"
    about = ("Windows Defender Firewall on this PC: on for every profile, the framework's pages kept to this machine, the "
             "ports its services need opened as Liminal's own rules")
    api = "2.1"
    order = 710

    def __init__(self, powershell: PowerShell | None = None):
        self.ps = powershell if powershell is not None else PowerShell()

    def present(self) -> bool:
        return self.ps.here

    def backend(self) -> str:
        return "Windows Defender Firewall"

    def state(self) -> dict:
        rows = self.ps.json("Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ Name = $_.Name; "
                            "Enabled = ($_.Enabled.ToString() -eq 'True'); Inbound = $_.DefaultInboundAction.ToString(); "
                            "Outbound = $_.DefaultOutboundAction.ToString() } }")
        profiles = {str(r["Name"]): bool(r["Enabled"]) for r in rows}
        return {"enabled": bool(profiles) and all(profiles.values()), "profiles": profiles,
                "defaults": {str(r["Name"]): {"inbound": str(r.get("Inbound", "")), "outbound": str(r.get("Outbound", ""))} for r in rows}}

    def list_rules(self, owned_only: bool = True) -> list[Rule]:
        source = f"Get-NetFirewallRule -Group {quote(GROUP)} -ErrorAction SilentlyContinue" if owned_only else "Get-NetFirewallRule"
        return [rule_of(r) for r in self.ps.json(f"{source} | ForEach-Object {{ {RULE_FIELDS} }}", timeout=600)]

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

    def delete_rule(self, name: str) -> bool:
        out = self.ps.run_admin(f"$r = @(Get-NetFirewallRule -Group {quote(GROUP)} -ErrorAction SilentlyContinue | "
                                f"Where-Object {{ $_.DisplayName -eq {quote(GROUP + ': ' + name)} }}); "
                                "if ($r.Count) { $r | Remove-NetFirewallRule }; [Console]::Out.WriteLine($r.Count)")
        lines = [line.strip() for line in out.splitlines() if line.strip()]
        return bool(lines) and lines[-1].isdecimal() and int(lines[-1]) > 0

    def enable(self) -> None:
        self.ps.run_admin("Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True")

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


MACHINE = WindowsFirewallPlugin()
