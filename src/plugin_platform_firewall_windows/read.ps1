# The whole configuration in one read (the Windows Firewall plugin's): the firewall profiles, the networks and their
# category, every rule with its ports, program and remote addresses, and Microsoft Defender's state. Needs no rights:
# the rules come from the NetSecurity cmdlets (their unique Name is what a change names), their ports and programs from
# the filters read in bulk, their remote addresses from the firewall's COM policy (the address filters need an
# administrator), matched to each rule by its name, direction, action, program, protocol and local ports.
$protocols = @{ 'TCP' = 6; 'UDP' = 17; 'ANY' = 256; 'ICMPV4' = 1; 'ICMPV6' = 58 }
function ProtoNumber($p) {
    $s = ([string]$p).Trim().ToUpper()
    if ($s -match '^\d+$') { return [int]$s }
    if ($protocols.ContainsKey($s)) { return $protocols[$s] }
    return 256
}
function PortsKey($p) {
    # "RPC," (COM) and "RPC" (the cmdlets) alike; "*", "Any" and nothing are every port
    $parts = @((@($p) | ForEach-Object { ([string]$_) -split ',' }) | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    $s = $parts -join ','
    if ($s -eq '' -or $s -eq '*' -or $s -eq 'Any') { return '' }
    return $s
}
function ProgramKey($p) {
    # COM gives a program with its variables expanded (C:\WINDOWS\...), the cmdlets as written (%SystemRoot%\...)
    $s = [string]$p
    if ($s -eq '' -or $s -eq 'Any') { return '' }
    return [Environment]::ExpandEnvironmentVariables($s).ToLower()
}
function ProfileMask($p) {
    # COM's bit mask (Domain 1, Private 2, Public 4; every profile 0x7FFFFFFF) and the cmdlets' words alike
    if ($p -is [int]) { $m = [int]$p } else {
        $s = [string]$p; if ($s -match 'Any') { return 7 }
        $m = 0; if ($s -match 'Domain') { $m = $m -bor 1 }; if ($s -match 'Private') { $m = $m -bor 2 }; if ($s -match 'Public') { $m = $m -bor 4 }
    }
    return $m -band 7
}
$remote = @{}
$ambiguous = @{}  # a key two COM rules share with different addresses: not said rather than guessed
try {
    $policy = New-Object -ComObject HNetCfg.FwPolicy2
    foreach ($c in $policy.Rules) {
        $key = ([string]$c.Name) + '|' + [int]$c.Direction + '|' + [int]$c.Action + '|' + (ProgramKey $c.ApplicationName) + '|' + [int]$c.Protocol + '|' + (PortsKey $c.LocalPorts) + '|' + (ProfileMask ([int]$c.Profiles)) + '|' + [bool]$c.Enabled
        $ra = [string]$c.RemoteAddresses
        if (-not $remote.ContainsKey($key)) { $remote[$key] = $ra } elseif ($remote[$key] -ne $ra) { $ambiguous[$key] = $true }
    }
} catch { }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$ports = @{}
foreach ($f in @(Get-NetFirewallPortFilter -All -ErrorAction SilentlyContinue)) { $ports[[string]$f.InstanceID] = $f }
$apps = @{}
foreach ($f in @(Get-NetFirewallApplicationFilter -All -ErrorAction SilentlyContinue)) { $apps[[string]$f.InstanceID] = $f }
$addresses = @{}  # an administrator reads every rule's remote addresses as they are
if ($admin) { foreach ($f in @(Get-NetFirewallAddressFilter -All -ErrorAction SilentlyContinue)) { $addresses[[string]$f.InstanceID] = (@($f.RemoteAddress) | ForEach-Object { [string]$_ }) -join ',' } }
$rules = foreach ($r in @(Get-NetFirewallRule)) {
    $pf = $ports[[string]$r.Name]; $af = $apps[[string]$r.Name]
    $program = if ($af -and $af.Program) { [string]$af.Program } else { 'Any' }
    # a port filter Windows did not give (some built-in rules', to a non-administrator): its protocol and ports not read
    $protocol = if ($pf) { [string]$pf.Protocol } else { $null }
    $local = if ($pf) { (@($pf.LocalPort) | ForEach-Object { [string]$_ }) -join ',' } else { $null }
    $remotePort = if ($pf) { (@($pf.RemotePort) | ForEach-Object { [string]$_ }) -join ',' } else { $null }
    $dir = if ($r.Direction.ToString() -eq 'Inbound') { 1 } else { 2 }
    $act = if ($r.Action.ToString() -eq 'Allow') { 1 } else { 0 }
    $key = ([string]$r.DisplayName) + '|' + $dir + '|' + $act + '|' + (ProgramKey $program) + '|' + (ProtoNumber $protocol) + '|' + (PortsKey $local) + '|' + (ProfileMask $r.Profile.ToString()) + '|' + ($r.Enabled.ToString() -eq 'True')
    [pscustomobject]@{
        Id = [string]$r.Name; Name = [string]$r.DisplayName; Group = [string]$r.DisplayGroup; GroupSource = [string]$r.Group
        Enabled = ($r.Enabled.ToString() -eq 'True'); Direction = $r.Direction.ToString(); Action = $r.Action.ToString()
        Profile = $r.Profile.ToString(); Program = $program; Protocol = $protocol; LocalPort = $local; RemotePort = $remotePort
        Remote = if ($addresses.ContainsKey([string]$r.Name)) { $addresses[[string]$r.Name] } elseif ($pf -and $remote.ContainsKey($key) -and -not $ambiguous.ContainsKey($key)) { $remote[$key] } else { $null }
        Description = [string]$r.Description
        Store = $r.PolicyStoreSourceType.ToString()
    }
}
$profiles = foreach ($p in @(Get-NetFirewallProfile)) {
    [pscustomobject]@{ Name = [string]$p.Name; Enabled = ($p.Enabled.ToString() -eq 'True'); Inbound = $p.DefaultInboundAction.ToString()
        Outbound = $p.DefaultOutboundAction.ToString(); Notify = $p.NotifyOnListen.ToString(); AllowInbound = $p.AllowInboundRules.ToString()
        LogBlocked = $p.LogBlocked.ToString(); LogFile = [string]$p.LogFileName }
}
$networks = foreach ($n in @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)) {
    [pscustomobject]@{ Index = [int]$n.InterfaceIndex; Interface = [string]$n.InterfaceAlias; Name = [string]$n.Name
        Category = $n.NetworkCategory.ToString(); IPv4 = $n.IPv4Connectivity.ToString(); IPv6 = $n.IPv6Connectivity.ToString() }
}
$defender = $null
try {
    $m = Get-MpComputerStatus -ErrorAction Stop
    $defender = [pscustomobject]@{ Antivirus = [bool]$m.AntivirusEnabled; RealTime = [bool]$m.RealTimeProtectionEnabled
        Signatures = if ($m.AntivirusSignatureLastUpdated) { $m.AntivirusSignatureLastUpdated.ToString('s') } else { '' } }
} catch { }
[pscustomobject]@{ Profiles = @($profiles); Networks = @($networks); Rules = @($rules); Defender = $defender; Elevated = $admin }
