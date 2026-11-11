"""What Windows Firewall attaches to (plugin API 2.2, liminal_libs.sources.apis; the user, 2026-11-11: "each plugin
should reflect the the API its attached to, and present links that provide documentation ... it should also expose more
of what the API is about"): Windows PowerShell and its elevation (UAC), the NetSecurity cmdlets, the NetConnection
cmdlets, Microsoft Defender's, Windows Firewall itself (its documentation and its COM policy), and what names a rule's
service, app and program, each as Microsoft Learn describes it. Every address was read on 2026-11-11 (`VERIFIED`).
The facts (what the plugin kept of the last read) are said by the plugin's api_facts."""
from __future__ import annotations

from liminal_libs.sources.apis import Api, Area, Call, Link

VERIFIED = "2026-11-11"
PS51 = "?view=powershell-5.1"
WS = "?view=windowsserver2025-ps"
MODULE = "https://learn.microsoft.com/en-us/powershell/module/"
NETSEC = MODULE + "netsecurity/"
MANAGEMENT = MODULE + "microsoft.powershell.management/"
FIREWALL = "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/"
NETFW = "https://learn.microsoft.com/en-us/windows/win32/api/netfw/"
WIN32 = "https://learn.microsoft.com/en-us/windows/win32/"
DEFENDER = MODULE + "defender/"

POWERSHELL = Api(
    name="Windows PowerShell 5.1",
    maker="Microsoft",
    about=("The shell every Windows 11 has, its cmdlets returning objects. The plugin reads the whole firewall in one "
           "windowless powershell.exe (its read.ps1, given encoded, the objects back as JSON), and runs each change the "
           "same way: as it is when the platform runs as an administrator, else in a second PowerShell started elevated, "
           "which Windows asks you to allow (UAC)."),
    kind="powershell",
    base="powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand <script>",
    version="Windows PowerShell 5.1 (Windows' own; not PowerShell 7)",
    auth=("reading: no rights needed (the address filters are an administrator's: without them the remote addresses come "
          "from the firewall's COM policy); a change: an administrator, through UAC unless the platform runs as one"),
    limits="",
    costs="",
    links=(
        Link("What is Windows PowerShell?", "https://learn.microsoft.com/en-us/powershell/scripting/what-is-windows-powershell" + PS51,
             "docs"),
        Link("about_PowerShell_exe", MODULE + "microsoft.powershell.core/about/about_powershell_exe" + PS51, "reference"),
        Link("Start-Process", MANAGEMENT + "start-process" + PS51, "reference"),
        Link("ConvertTo-Json", MODULE + "microsoft.powershell.utility/convertto-json" + PS51, "reference"),
        Link("User Account Control", "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/",
             "guide"),
    ),
    areas=(
        Area("The command line", "powershell.exe's switches: no profile, no prompts, a script given encoded",
             MODULE + "microsoft.powershell.core/about/about_powershell_exe" + PS51,
             covered="the read and every change: windowless, its words back as one line when it fails"),
        Area("Objects as JSON", "a script's objects written out as JSON", MODULE + "microsoft.powershell.utility/convertto-json" + PS51,
             covered="the whole configuration in one answer"),
        Area("Elevation (UAC)", "an administrator's rights, asked of you by Windows",
             "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/",
             covered="each change runs elevated: as it is when the platform is, else Windows asks you"),
        Area("COM objects", "Windows' COM objects made from PowerShell", MODULE + "microsoft.powershell.utility/new-object" + PS51,
             covered="the firewall's own policy (HNetCfg.FwPolicy2: its own card)"),
        Area("Remoting", "commands run on other computers (WinRM, CIM sessions)", MODULE + "microsoft.powershell.core/about/about_remote" + PS51),
        Area("PowerShell 7", "the newer, cross-platform PowerShell (pwsh), installed beside 5.1",
             "https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-windows?view=powershell-7.6"),
    ),
    calls=(
        Call("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand <script>",
             "a script run windowless", "The command line", used="the read and every change",
             docs=MODULE + "microsoft.powershell.core/about/about_powershell_exe" + PS51),
        Call("ConvertTo-Json -Compress -Depth 5", "objects as JSON", "Objects as JSON", used="the read's answer",
             docs=MODULE + "microsoft.powershell.utility/convertto-json" + PS51),
        Call("Start-Process -FilePath powershell.exe -Verb RunAs -Wait", "a second PowerShell started elevated: Windows asks",
             "Elevation (UAC)", used="a change when the platform is not an administrator",
             docs=MANAGEMENT + "start-process" + PS51, writes=True),
        Call("IsUserAnAdmin (shell32)", "whether this process has an administrator's rights", "Elevation (UAC)",
             used="whether a change runs as it is", docs=WIN32 + "api/shlobj_core/nf-shlobj_core-isuseranadmin"),
        Call("WindowsPrincipal.IsInRole(Administrator)", "whether the read runs as an administrator", "Elevation (UAC)",
             used="the read: the address filters asked only then"),
        Call("New-Object -ComObject HNetCfg.FwPolicy2", "the firewall's COM policy", "COM objects",
             used="the read: each rule's remote addresses", docs=MODULE + "microsoft.powershell.utility/new-object" + PS51),
        Call("Invoke-Command -ComputerName <computer>", "a script run on another computer", "Remoting",
             docs=MODULE + "microsoft.powershell.core/invoke-command" + PS51),
    ),
    verified=VERIFIED,
)

NETSECURITY = Api(
    name="NetSecurity (PowerShell)",
    maker="Microsoft",
    about=("Windows Defender Firewall's cmdlets: every rule, with its conditions in separate filters (ports and protocol, "
           "program, service, addresses, interfaces, security), the per-profile settings, the global settings, IPsec and "
           "the Hyper-V firewall. The plugin reads the rules, their filters and the profiles in bulk, and turns a rule "
           "on or off, removes one, makes Liminal's, and sets a profile's firewall and defaults when you confirm it."),
    kind="powershell",
    base="the NetSecurity module (Windows PowerShell 5.1)",
    version="the NetSecurity module of Windows 11 and Windows Server 2025",
    auth=("reading the rules, the port, program and service filters and the profiles: no rights needed; the address "
          "filters and every change: an administrator (UAC)"),
    limits="",
    costs="",
    links=(
        Link("NetSecurity module", NETSEC + WS, "reference"),
        Link("Manage Windows Firewall with the command line", FIREWALL + "configure-with-command-line", "guide"),
        Link("Get-NetFirewallRule", NETSEC + "get-netfirewallrule" + WS, "reference"),
        Link("New-NetFirewallRule", NETSEC + "new-netfirewallrule" + WS, "reference"),
        Link("Windows Firewall", FIREWALL, "docs"),
    ),
    areas=(
        Area("Rules", "inbound and outbound rules: allow or block, on or off, their group and their store",
             NETSEC + "get-netfirewallrule" + WS,
             covered="every rule read; one turned on or off, removed (never one of Windows' own), or made in the group Liminal"),
        Area("Port filters", "a rule's protocol, local and remote ports", NETSEC + "get-netfirewallportfilter" + WS,
             covered="read in bulk for every rule"),
        Area("Application filters", "a rule's program or app package", NETSEC + "get-netfirewallapplicationfilter" + WS,
             covered="read in bulk: each rule's program"),
        Area("Service filters", "the Windows service a rule is for", NETSEC + "get-netfirewallservicefilter" + WS,
             covered="read in bulk: each rule's service, the System group's headings"),
        Area("Address filters", "a rule's local and remote addresses", NETSEC + "get-netfirewalladdressfilter" + WS,
             covered="read in bulk when the platform runs as an administrator (else through the COM policy)"),
        Area("Profiles", "Domain, Private, Public: the firewall on or off, the defaults in and out, notifications, logging",
             NETSEC + "get-netfirewallprofile" + WS,
             covered="read; one's firewall, defaults and notifications set (off, or everything in, asked twice)"),
        Area("Interface and security filters", "rules by interface type, by authentication and encryption",
             NETSEC + "get-netfirewallinterfacefilter" + WS),
        Area("Global settings", "the firewall's settings across the profiles", NETSEC + "get-netfirewallsetting" + WS),
        Area("The Hyper-V firewall", "rules for the virtual machines and WSL behind Hyper-V's switch",
             NETSEC + "get-netfirewallhypervrule" + WS),
        Area("Dynamic keywords", "addresses kept under a name a rule refers to", NETSEC + "get-netfirewalldynamickeywordaddress" + WS),
        Area("IPsec", "connection security rules, their authentication and cryptographic sets", NETSEC + "get-netipsecrule" + WS),
        Area("Group Policy", "rules kept in a Group Policy Object", NETSEC + "open-netgpo" + WS),
    ),
    calls=(
        Call("Get-NetFirewallRule", "every firewall rule", "Rules", used="the read; the exposure check",
             docs=NETSEC + "get-netfirewallrule" + WS),
        Call("Get-NetFirewallPortFilter -All", "every rule's protocol and ports", "Port filters", used="the read",
             docs=NETSEC + "get-netfirewallportfilter" + WS),
        Call("Get-NetFirewallApplicationFilter -All", "every rule's program", "Application filters", used="the read",
             docs=NETSEC + "get-netfirewallapplicationfilter" + WS),
        Call("Get-NetFirewallServiceFilter -All", "every rule's service", "Service filters", used="the read",
             docs=NETSEC + "get-netfirewallservicefilter" + WS),
        Call("Get-NetFirewallAddressFilter -All", "every rule's addresses", "Address filters",
             used="the read, as an administrator; the exposure check", docs=NETSEC + "get-netfirewalladdressfilter" + WS),
        Call("Get-NetFirewallProfile", "the three profiles' settings", "Profiles", used="the read",
             docs=NETSEC + "get-netfirewallprofile" + WS),
        Call("Set-NetFirewallRule -Name <id> -Enabled True|False", "a rule turned on or off", "Rules",
             used="Turn on… and Turn off…", docs=NETSEC + "set-netfirewallrule" + WS, writes=True),
        Call("Remove-NetFirewallRule", "a rule removed", "Rules", used="Remove… (never one of Windows' own); Liminal's by name",
             docs=NETSEC + "remove-netfirewallrule" + WS, writes=True),
        Call("New-NetFirewallRule -Group 'Liminal'", "a rule made, in the group Liminal", "Rules",
             used="Make…, and the framework's own rules", docs=NETSEC + "new-netfirewallrule" + WS, writes=True),
        Call("Set-NetFirewallProfile", "a profile's firewall, defaults or notifications set", "Profiles",
             used="a profile's form; the setup turns every profile on", docs=NETSEC + "set-netfirewallprofile" + WS, writes=True),
        Call("Enable-NetFirewallRule", "rules turned on by group or property", "Rules", docs=NETSEC + "enable-netfirewallrule" + WS,
             writes=True),
        Call("Disable-NetFirewallRule", "rules turned off by group or property", "Rules",
             docs=NETSEC + "disable-netfirewallrule" + WS, writes=True),
        Call("Copy-NetFirewallRule", "a rule copied to another store", "Rules", docs=NETSEC + "copy-netfirewallrule" + WS,
             writes=True),
        Call("Show-NetFirewallRule", "every rule with its filters, expanded", "Rules", docs=NETSEC + "show-netfirewallrule" + WS),
        Call("Get-NetFirewallSetting", "the global settings", "Global settings", docs=NETSEC + "get-netfirewallsetting" + WS),
        Call("Set-NetFirewallSetting", "the global settings changed", "Global settings",
             docs=NETSEC + "set-netfirewallsetting" + WS, writes=True),
        Call("Get-NetFirewallHyperVRule", "the Hyper-V firewall's rules", "The Hyper-V firewall",
             docs=NETSEC + "get-netfirewallhypervrule" + WS),
        Call("Get-NetFirewallHyperVVMSetting", "the Hyper-V firewall's settings for a VM creator (WSL's too)",
             "The Hyper-V firewall", docs=NETSEC + "get-netfirewallhypervvmsetting" + WS),
        Call("Get-NetIPsecRule", "the connection security rules", "IPsec", docs=NETSEC + "get-netipsecrule" + WS),
    ),
    verified=VERIFIED,
)

NETCONNECTION = Api(
    name="NetConnection (PowerShell)",
    maker="Microsoft",
    about=("A network connection's profile: the network each interface is on and its category, private or public (a "
           "domain network is Windows' own to set), which decides the firewall profile whose rules apply to it. The "
           "plugin shows the networks this PC is on and makes one private or public when you confirm it."),
    kind="powershell",
    base="the NetConnection module (Windows PowerShell 5.1)",
    version="the NetConnection module of Windows 11 and Windows Server 2025",
    auth="reading: no rights needed; a category changed: an administrator (UAC)",
    limits="",
    costs="",
    links=(
        Link("Get-NetConnectionProfile", MODULE + "netconnection/get-netconnectionprofile" + WS, "reference"),
        Link("Set-NetConnectionProfile", MODULE + "netconnection/set-netconnectionprofile" + WS, "reference"),
        Link("NetConnection module", MODULE + "netconnection/" + WS, "docs"),
        Link("Network Location Awareness", WIN32 + "winsock/network-location-awareness-service-provider-nla--2", "guide"),
    ),
    areas=(
        Area("Network profiles", "each connected interface's network, its category and its IPv4 and IPv6 connectivity",
             MODULE + "netconnection/get-netconnectionprofile" + WS,
             covered="the networks this PC is on, and the firewall profile each one uses"),
        Area("A network's category", "a network made private or public", MODULE + "netconnection/set-netconnectionprofile" + WS,
             covered="Private… and Public…, each confirmed"),
        Area("How Windows tells networks apart", "Network Location Awareness, which names the networks and finds a domain's",
             WIN32 + "winsock/network-location-awareness-service-provider-nla--2"),
        Area("Domain networks", "the domain profile, which Windows applies itself when a domain controller answers",
             FIREWALL),
    ),
    calls=(
        Call("Get-NetConnectionProfile", "the connected networks and their categories", "Network profiles", used="the read",
             docs=MODULE + "netconnection/get-netconnectionprofile" + WS),
        Call("Set-NetConnectionProfile -InterfaceIndex <n> -NetworkCategory Private|Public", "a network's category set",
             "A network's category", used="Private… and Public…", docs=MODULE + "netconnection/set-netconnectionprofile" + WS,
             writes=True),
    ),
    verified=VERIFIED,
)

DEFENDER_API = Api(
    name="Microsoft Defender Antivirus (Defender module)",
    maker="Microsoft",
    about=("Microsoft Defender Antivirus through PowerShell: its state and protections, its preferences and exclusions, "
           "its signatures' updates, scans and the threats it found. The plugin reads only its state beside the firewall: "
           "whether the antivirus and real-time protection are on, and when its signatures were last updated."),
    kind="powershell",
    base="the Defender module (Windows PowerShell 5.1)",
    version="the Defender module of Windows 11 and Windows Server 2025",
    auth="reading its state: no rights needed",
    limits="",
    costs="",
    links=(
        Link("Defender module", DEFENDER + WS, "reference"),
        Link("Get-MpComputerStatus", DEFENDER + "get-mpcomputerstatus" + WS, "reference"),
        Link("Microsoft Defender Antivirus in Windows", "https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows",
             "docs"),
        Link("Defender Antivirus's PowerShell cmdlets", "https://learn.microsoft.com/en-us/defender-endpoint/use-powershell-cmdlets-microsoft-defender-antivirus",
             "guide"),
        Link("Defender Antivirus's updates", "https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-updates",
             "changelog"),
    ),
    areas=(
        Area("Its state", "the antivirus and its protections on or off, its engine and signature versions",
             DEFENDER + "get-mpcomputerstatus" + WS,
             covered="antivirus on, real-time protection on, the signatures' last update, read with the firewall"),
        Area("Preferences", "how it scans and protects, its exclusions", DEFENDER + "get-mppreference" + WS),
        Area("Signatures", "its definitions brought up to date", DEFENDER + "update-mpsignature" + WS),
        Area("Scans", "a quick, full or custom scan", DEFENDER + "start-mpscan" + WS),
        Area("Threats", "what it detected, and its catalogue", DEFENDER + "get-mpthreatdetection" + WS),
    ),
    calls=(
        Call("Get-MpComputerStatus", "the antimalware state of this PC", "Its state",
             used="the read: AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated",
             docs=DEFENDER + "get-mpcomputerstatus" + WS),
        Call("Get-MpPreference", "its preferences", "Preferences", docs=DEFENDER + "get-mppreference" + WS),
        Call("Set-MpPreference", "its preferences changed", "Preferences", docs=DEFENDER + "set-mppreference" + WS, writes=True),
        Call("Add-MpPreference -ExclusionPath <path>", "a path it does not scan", "Preferences",
             docs=DEFENDER + "add-mppreference" + WS, writes=True),
        Call("Update-MpSignature", "its signatures updated", "Signatures", docs=DEFENDER + "update-mpsignature" + WS, writes=True),
        Call("Start-MpScan", "a scan started", "Scans", docs=DEFENDER + "start-mpscan" + WS),
        Call("Get-MpThreatDetection", "the threats it detected", "Threats", docs=DEFENDER + "get-mpthreatdetection" + WS),
    ),
    verified=VERIFIED,
)

WINDOWS_FIREWALL = Api(
    name="Windows Firewall (its policy over COM)",
    maker="Microsoft",
    about=("Windows Firewall itself: a host firewall on by default that blocks what comes in unless a rule allows it and "
           "lets out what goes out unless a rule blocks it, under three network profiles, beside IPsec and the Hyper-V "
           "firewall. Its COM policy (INetFwPolicy2) holds every rule with its remote addresses, which the plugin reads "
           "without an administrator's rights to show where each rule lets traffic in from."),
    kind="system",
    base="HNetCfg.FwPolicy2 (INetFwPolicy2, FirewallAPI.dll), made from PowerShell",
    version="Windows Firewall with Advanced Security (Windows Vista and later), as Windows 11's documentation gives it",
    auth="reading the COM policy: no rights needed",
    limits="",
    costs="",
    links=(
        Link("Windows Firewall overview", FIREWALL, "docs"),
        Link("INetFwPolicy2", NETFW + "nn-netfw-inetfwpolicy2", "reference"),
        Link("INetFwRule", NETFW + "nn-netfw-inetfwrule", "reference"),
        Link("Windows Firewall rules", FIREWALL + "rules", "guide"),
        Link("Windows Firewall tools", FIREWALL + "tools", "guide"),
        Link("netsh advfirewall", "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-advfirewall",
             "tool"),
    ),
    areas=(
        Area("Rules and profiles", "what a rule matches and does, and the Domain, Private and Public profiles", FIREWALL + "rules",
             covered="the plugin's groups, presets, Find and changes (the NetSecurity card's cmdlets)"),
        Area("The COM policy", "INetFwPolicy2: the rules, the profiles' settings, rule groups", NETFW + "nn-netfw-inetfwpolicy2",
             covered="its rules read: each one's remote addresses, matched to the cmdlets' rule"),
        Area("A rule over COM", "INetFwRule: its name, direction, action, program, protocol, ports, profiles, addresses",
             NETFW + "nn-netfw-inetfwrule", covered="what each rule is matched by, and its remote addresses"),
        Area("Configuring it", "the ways it is set up: Windows Security, the console, Group Policy, the command line",
             FIREWALL + "configure"),
        Area("Its log", "the dropped and allowed connections, written to a file", FIREWALL + "configure-logging"),
        Area("The Hyper-V firewall", "the firewall for Hyper-V's and WSL's virtual machines", FIREWALL + "hyper-v-firewall"),
        Area("Dynamic keywords", "addresses kept by name for rules to use", FIREWALL + "dynamic-keywords"),
        Area("netsh advfirewall", "the older command line for the same firewall",
             "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-advfirewall"),
        Area("The Windows Filtering Platform", "the kernel's filtering beneath the firewall", WIN32 + "fwp/windows-filtering-platform-start-page"),
    ),
    calls=(
        Call("INetFwPolicy2.Rules", "every rule in the firewall's policy", "The COM policy",
             used="the read: each rule's RemoteAddresses, by its name, direction, action, program, protocol, ports, profiles",
             docs=NETFW + "nf-netfw-inetfwpolicy2-get_rules"),
        Call("INetFwPolicy2.EnableRuleGroup", "a group of rules turned on or off", "The COM policy",
             docs=NETFW + "nn-netfw-inetfwpolicy2", writes=True),
        Call("INetFwPolicy2.RestoreLocalFirewallDefaults", "the firewall set back to Windows' defaults", "The COM policy",
             docs=NETFW + "nn-netfw-inetfwpolicy2", writes=True),
        Call("netsh advfirewall show allprofiles", "the profiles' settings, in netsh's words", "netsh advfirewall",
             docs="https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-advfirewall"),
    ),
    verified=VERIFIED,
)

NAMES = Api(
    name="Windows' names for a rule's service, app and program",
    maker="Microsoft",
    about=("What Windows says of the services, app packages and programs a rule names: a service's display name, whether "
           "an app package is signed as Windows' own, a program's product name and description. The plugin asks them in "
           "its read to file each rule under System or Application and name it by its service or application."),
    kind="powershell",
    base="Get-Service, Get-AppxPackage and .NET's FileVersionInfo, in the same read",
    version="Windows PowerShell 5.1 on .NET Framework 4.8",
    auth="no rights needed; a program is looked up on this PC's own fixed drives only, never one kept in the cloud only",
    limits="",
    costs="",
    links=(
        Link("Get-Service", MANAGEMENT + "get-service" + PS51, "reference"),
        Link("Get-AppxPackage", MODULE + "appx/get-appxpackage" + WS, "reference"),
        Link("FileVersionInfo.GetVersionInfo", "https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo.getversioninfo?view=netframework-4.8.1",
             "reference"),
        Link("Services", WIN32 + "services/services", "docs"),
    ),
    areas=(
        Area("Services", "each Windows service's name and display name", MANAGEMENT + "get-service" + PS51,
             covered="the display names of the services the rules name"),
        Area("App packages", "the Microsoft Store and Windows apps installed, their publisher and signature",
             MODULE + "appx/get-appxpackage" + WS, covered="which app packages are signed as Windows' own"),
        Area("A program's version information", "a file's product name, description, company, version",
             "https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo?view=net-11.0",
             covered="each rule's program on a fixed drive: its product name and description"),
        Area("A package's manifest", "an app package's declared identity and capabilities",
             MODULE + "appx/get-appxpackagemanifest" + WS),
    ),
    calls=(
        Call("Get-Service", "every Windows service", "Services", used="the services the rules name, by display name",
             docs=MANAGEMENT + "get-service" + PS51),
        Call("Get-AppxPackage", "the app packages installed", "App packages", used="Windows' own packages (SignatureKind System)",
             docs=MODULE + "appx/get-appxpackage" + WS),
        Call("[Diagnostics.FileVersionInfo]::GetVersionInfo(<path>)", "a program's version information",
             "A program's version information", used="each rule's program: its product name and description",
             docs="https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo.getversioninfo?view=netframework-4.8.1"),
        Call("Get-AppxPackageManifest", "an app package's manifest", "A package's manifest",
             docs=MODULE + "appx/get-appxpackagemanifest" + WS),
    ),
    verified=VERIFIED,
)

APIS = (POWERSHELL, NETSECURITY, NETCONNECTION, DEFENDER_API, WINDOWS_FIREWALL, NAMES)
