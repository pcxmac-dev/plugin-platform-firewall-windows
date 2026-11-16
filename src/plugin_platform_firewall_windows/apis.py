"""What Windows Firewall attaches to (plugin API 2.2, liminal_libs.sources.apis; the user, 2026-11-11: "each plugin
should reflect the the API its attached to, and present links that provide documentation ... it should also expose more
of what the API is about"): Windows PowerShell and its elevation (UAC), the NetSecurity cmdlets, the NetConnection
cmdlets, Microsoft Defender's, Windows Firewall itself (its documentation and its COM policy), and what names a rule's
service, app and program, each as Microsoft Learn describes it. Every address was read on 2026-11-11 (`VERIFIED`).
The facts (what the plugin kept of the last read) are said by the plugin's api_facts.

The World Wide Web tab (0.6.0) attaches to more, each as its makers' pages describe it: Npcap, through which the
library's capture reads the packets at this PC's adapter (its option for administrators only read from the registry
first: an install for administrators only is asked nothing by a platform that is none, since it would ask for UAC),
and DB-IP's IP to City Lite file, which places them on the globe (their pages read on 2026-11-15, `VERIFIED_WORLD`);
and OpenDNS's and Google's name servers, asked for this network's public address, which places home (the hw-stats
plugin's cards of them, read on 2026-11-11, `VERIFIED_DNS`).
What the tab is given of them lives here too, since the library names no outside host: the file's monthly address
(CITY_LITE), its licence in plain words (CITY_LITE_LICENCE), the credit its places carry (DBIP_CREDIT) and the name
servers (NAME_SERVERS)."""
from __future__ import annotations

from liminal_libs.sources.apis import Api, Area, Call, Link

VERIFIED = "2026-11-11"
VERIFIED_WORLD = "2026-11-15"  # the World Wide Web tab's Npcap and DB-IP cards: their makers' pages read then
# the name servers' cards: their pages as the hw-stats plugin read them (its OPENDNS and GOOGLE cards), OpenDNS's setup
# guide and Google Public DNS's questions read again on 2026-11-15
VERIFIED_DNS = "2026-11-11"
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

# -- the World Wide Web tab (0.6.0) --------------------------------------------------------------------------------------
# What the library's Firewall base is given (its GEOIP_URL, GEOIP_LICENCE, ATTRIBUTION and PUBLIC_DNS), and the cards of
# what the tab reaches with them.
DBIP_SITE = "https://db-ip.com/"
DBIP_DB = DBIP_SITE + "db/"
DBIP_FREE = "https://download.db-ip.com/free/"
# One month's IP to City Lite file, as DB-IP's download page gives it, the library filling in {year} and {month} (2026,
# 11): what Install the GeoIP file… downloads, this month's, or last month's while this month's is not out yet.
CITY_LITE = DBIP_FREE + "dbip-city-lite-{year}-{month}.mmdb.gz"
# Its licence in plain words, shown in both confirmations before the download (the second one accepts it).
CITY_LITE_LICENCE = (
    "DB-IP's IP to City Lite is free under the Creative Commons Attribution 4.0 International licence (CC BY 4.0, "
    "creativecommons.org/licenses/by/4.0): it may be used, shared and changed for any purpose, as long as DB-IP is "
    "credited. So wherever its places are shown, this page says \"IP Geolocation by DB-IP\" with a link to db-ip.com. "
    "It comes as it is, with no warranty, and its places are approximate. The download is about 60 MB (about 121 MB "
    "unpacked); DB-IP puts out a new one each month."
)
DBIP_CREDIT = {"text": "IP Geolocation by DB-IP", "url": "https://db-ip.com"}  # the link DB-IP's Lite licence asks for
# The name servers asked directly (no resolver between) for the asker's own address, which places home on the globe when
# you set no place: (the name, its type, the server, whose), the hw-stats plugin's own (its network.PUBLIC_SERVERS). The
# library asks one version's servers in turn, IPv4's first, IPv6's only when IPv4's gave no public address, each name
# made absolute (world.servers_of: myip.opendns.com., so no DNS search suffix of this PC's is sent with it).
NAME_SERVERS = (
    ("myip.opendns.com", "a", "208.67.222.222", "OpenDNS"),  # resolver1.opendns.com
    ("o-o.myaddr.l.google.com", "txt", "216.239.32.10", "Google"),  # ns1.google.com: its text record holds it
    ("myip.opendns.com", "aaaa", "2620:119:35::35", "OpenDNS"),
    ("o-o.myaddr.l.google.com", "txt", "2001:4860:4802:32::a", "Google"),
)
NPCAP_SITE = "https://npcap.com/"
NPCAP_GUIDE = NPCAP_SITE + "guide/"
# Npcap's install option "Restrict Npcap driver's access to Administrators only", where its developer's guide says the
# options are kept, as the library's capture reads it (capture.npcap_admin_only: read access alone) before asking Npcap
NPCAP_ADMIN_ONLY = r"HKLM\SYSTEM\CurrentControlSet\Services\npcap\Parameters\AdminOnly"
PCAP = "https://www.tcpdump.org/manpages/"
READER = "https://github.com/maxmind/MaxMind-DB-Reader-python"
OPENDNS_GUIDE = "https://www.opendns.com/setupguide/"
GOOGLE_DNS = "https://developers.google.com/speed/public-dns"
COMMANDS = "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/"

NPCAP = Api(
    name="Npcap (packet capture)",
    maker="Nmap Software",
    about=("A packet capture driver and library for Windows from the Nmap Project, with libpcap's API (wpcap.dll): an "
           "adapter opened, a filter compiled and set, each packet read as it arrives at the adapter, before Windows Firewall "
           "decides, so an attempt the firewall drops still shows. The library calls wpcap.dll by ctypes, no package "
           "between. While the World Wide Web tab is shown, and for 20 s after its last ask, the packets at the adapter "
           "of this PC's way out are read, their headers alone, and counted by port and by network: none is kept, and "
           "nothing is watched while the tab is not looked at."),
    kind="sdk",
    base=r"wpcap.dll in %SystemRoot%\System32\Npcap, through ctypes (liminal-libs capture.py)",
    version=("Npcap 1.88 on this PC, installed with Wireshark 4.6.9 (its wpcap.dll is libpcap 1.10.6); 1.90, of "
             "2026-10-21, is the newest"),
    auth=("any user: Npcap is installed here without \"Restrict Npcap driver's access to Administrators only\" (AdminOnly=0 "
          "in the npcap service's Parameters), so watching needs no administrator and no UAC. Installed for administrators "
          "only, Npcap has its NpcapHelper ask for elevation (a UAC prompt) as soon as a process that is no administrator "
          "lists or opens an adapter; so that option is read from the registry first (read access alone, nothing started), "
          "and then a platform that is no administrator asks Npcap nothing, not even loading it: the tab says to install "
          "Npcap again with the option unticked, or to run the platform as an administrator, and never asks for an "
          "administrator or a password itself. A platform run as an administrator watches as it is, with no prompt"),
    limits=("asked every 2 s while the tab is shown; watching ends 20 s after the last ask and when the plugin is "
            "detached; when it cannot start (Npcap missing, or installed for administrators only) it is tried again 15 s "
            "later at the soonest, the option read again; what is counted stays within the library's caps (256 ports here "
            "and as many elsewhere, 512 networks), no packet kept"),
    costs=("Npcap's free license covers five computers (virtual machines and containers count among them). Copies "
           "installed and used only with Nmap, Wireshark or Microsoft Defender for Identity do not count, but this PC's "
           "does: it came with Wireshark, and Liminal uses it directly, through wpcap.dll. More computers, or redistributing "
           "it, need a paid Npcap OEM license"),
    links=(
        Link("Npcap", NPCAP_SITE, "docs"),
        Link("The Npcap guide", NPCAP_GUIDE, "guide"),
        Link("Npcap Users' Guide (installing it; its options, administrators only among them)",
             NPCAP_GUIDE + "npcap-users-guide.html", "guide"),
        Link("Developing software with Npcap (where its install options are kept: AdminOnly among them)",
             NPCAP_GUIDE + "npcap-devguide.html", "reference"),
        Link("Npcap's API (pcap)", NPCAP_GUIDE + "wpcap/pcap.html", "reference"),
        Link("Npcap internals", NPCAP_GUIDE + "npcap-internals.html", "reference"),
        Link("pcap-filter(7)", PCAP + "pcap-filter.7.html", "reference"),
        Link("Npcap's changes", NPCAP_SITE + "changelog", "changelog"),
        Link("Npcap OEM", NPCAP_SITE + "oem/", "pricing"),
        Link("Npcap's license", "https://github.com/nmap/npcap/blob/master/LICENSE", "terms"),
    ),
    areas=(
        Area("Adapters", "the devices packets can be read from, and their addresses", PCAP + "pcap_findalldevs.3pcap.html",
             covered=("the adapter holding this PC's address on its way out (the default route's), and every adapter's "
                      "addresses, which tell what comes in from what goes out")),
        Area("Opening a capture", "an adapter opened, how much of each packet kept", PCAP + "pcap_open_live.3pcap.html",
             covered="the headers alone (128 bytes of each packet), not in promiscuous mode, a buffer timeout of 150 ms"),
        Area("Filters", "BPF filters compiled from words and set", PCAP + "pcap-filter.7.html",
             covered="(tcp or udp): every TCP and UDP packet, IPv4 and IPv6, to and from any of this PC's addresses"),
        Area("Reading packets", "each packet as it arrives, with its time", PCAP + "pcap_next_ex.3pcap.html",
             covered="each packet's addresses, ports, TCP flags and size on the wire, counted, never kept"),
        Area("Administrators only", ("an install option that keeps capture to administrators (AdminOnly): any other "
                                     "process that opens a capture has NpcapHelper ask for elevation (UAC)"),
             NPCAP_GUIDE + "npcap-users-guide.html",
             covered=("read first, from the registry: off on this PC, so watching runs as you; on, Npcap is opened only by "
                      "a platform run as an administrator, and asked nothing by one that is none, the tab saying to install "
                      "it again without the option or to run the platform as an administrator")),
        Area("Loopback capture", "this PC's traffic to itself, on the NPF_Loopback adapter", NPCAP_GUIDE + "npcap-devguide.html"),
        Area("Raw 802.11", "Wi-Fi frames in monitor mode, with their radiotap headers", NPCAP_SITE),
        Area("Writing a capture", "packets saved to a file Wireshark reads", PCAP + "pcap_dump_open.3pcap.html"),
        Area("The newer way to open", "pcap_create, then options, then pcap_activate", PCAP + "pcap_create.3pcap.html"),
    ),
    calls=(
        # read before any pcap_ call below (review F1): Npcap installed for administrators only asks for UAC otherwise
        Call(NPCAP_ADMIN_ONLY, "Npcap's option for administrators only, a REG_DWORD: 1 when it was ticked", "Administrators only",
             used=("read, with read access alone, before Npcap is asked for its adapters or to open one, with whether the "
                   "platform is an administrator (IsUserAnAdmin): when the option is on and it is none, Npcap is asked "
                   "nothing"),
             docs=NPCAP_GUIDE + "npcap-devguide.html"),
        Call("pcap_findalldevs", "every capture device and its addresses", "Adapters",
             used="the adapter to watch, and this PC's addresses (again every 30 s while it is watched)",
             docs=PCAP + "pcap_findalldevs.3pcap.html"),
        Call("pcap_freealldevs", "the device list freed", "Adapters", used="after each listing",
             docs=PCAP + "pcap_findalldevs.3pcap.html"),
        Call("pcap_open_live", "a device opened for capture", "Opening a capture",
             used="the tab's capture: 128 bytes of each packet, not promiscuous, packets handed on within 150 ms",
             docs=PCAP + "pcap_open_live.3pcap.html"),
        Call("pcap_compile", "a filter compiled", "Filters", used="(tcp or udp)", docs=PCAP + "pcap_compile.3pcap.html"),
        Call("pcap_setfilter", "the filter set", "Filters", used="the same", docs=PCAP + "pcap_setfilter.3pcap.html"),
        Call("pcap_freecode", "the compiled filter freed", "Filters", used="once it is set", docs=PCAP + "pcap_freecode.3pcap.html"),
        Call("pcap_datalink", "the link layer's type", "Reading packets", used="where each packet's IP header starts",
             docs=PCAP + "pcap_datalink.3pcap.html"),
        Call("pcap_next_ex", "the next packet", "Reading packets", used="each packet while the tab is watched",
             docs=PCAP + "pcap_next_ex.3pcap.html"),
        Call("pcap_geterr", "the last error in words", "Reading packets", used="why packets could not be watched, on the tab",
             docs=PCAP + "pcap_geterr.3pcap.html"),
        Call("pcap_close", "the capture closed", "Opening a capture",
             used="when watching ends: 20 s after the tab's last ask, or the plugin detached", docs=PCAP + "pcap_close.3pcap.html"),
        Call("pcap_loop", "packets handed to a callback", "Reading packets", docs=PCAP + "pcap_loop.3pcap.html"),
        Call("pcap_dump_open", "a capture file opened for writing", "Writing a capture", docs=PCAP + "pcap_dump_open.3pcap.html"),
        Call("pcap_create", "a capture handle made, not yet active", "The newer way to open", docs=PCAP + "pcap_create.3pcap.html"),
    ),
    verified=VERIFIED_WORLD,
)

DBIP = Api(
    name="DB-IP IP to City Lite",
    maker="DB-IP",
    about=("DB-IP's free database of where IP addresses are: every IPv4 and IPv6 range (7,777,816 of them in November "
           "2026's file) with its continent, country, region, city and approximate latitude and longitude, a new file "
           "at the start of each month, under CC BY 4.0. The World Wide Web tab places with it each public network "
           "traffic came from or went to, and this network's public address for home, looking them up in the file on "
           "this PC: no address is sent anywhere. The file is downloaded only when you ask, its licence shown and "
           "accepted first."),
    kind="feed",
    base="https://download.db-ip.com/free/dbip-city-lite-<year>-<month>.mmdb.gz, kept in the data folder's geoip/",
    version="IP to City Lite in the MMDB format (MaxMind DB 2.0), monthly: November 2026's built on 2026-11-01",
    auth="none: no account and no key; its licence, CC BY 4.0, accepted on the page before the download",
    limits=("a new file each month, about 60 MB to download (121 MB unpacked); downloaded only on your word, this "
            "month's or, while it is not out yet, last month's, and a month's file never twice: Update…, offered once the "
            "file installed is an earlier month's, fetches this month's in its place; one copy kept; an install stops by "
            "itself after 30 minutes, the download included"),
    costs="",
    links=(
        Link("DB-IP's free Lite databases", DBIP_DB + "lite.php", "docs"),
        Link("IP to City Lite", DBIP_DB + "download/ip-to-city-lite", "reference"),
        Link("IP to City Lite's MMDB format", DBIP_DB + "format/ip-to-city-lite/mmdb.html", "reference"),
        Link("The MaxMind DB format", "https://maxmind.github.io/MaxMind-DB/", "spec"),
        Link("maxminddb, the reader", READER, "sdk"),
        Link("CC BY 4.0", "https://creativecommons.org/licenses/by/4.0/", "terms"),
    ),
    areas=(
        Area("IP to City Lite", "each range's continent, country, region, city and approximate latitude and longitude",
             DBIP_DB + "download/ip-to-city-lite",
             covered="each public network on the globe placed by one of its addresses, and this network's public address for home"),
        Area("The MMDB file", "the MaxMind DB format, version 2.0, which free readers read",
             DBIP_DB + "format/ip-to-city-lite/mmdb.html",
             covered=("read on this PC from the data folder's geoip/, memory-mapped by maxminddb (never loaded whole) while "
                      "the tab is watched, its last 4,096 answers kept; let go once watching stops")),
        Area("The credit", "attribution to DB-IP.com, with a link back wherever its results are shown", DBIP_DB + "lite.php",
             covered="\"IP Geolocation by DB-IP\", linked to db-ip.com, on the globe and with the Places table while the file is open"),
        Area("IP to Country Lite", "each range's continent and country alone (8.1 MB)", DBIP_DB + "download/ip-to-country-lite"),
        Area("IP to ASN Lite", "each range's network: its AS number and organisation (9.2 MB)", DBIP_DB + "download/ip-to-asn-lite"),
        Area("The CSV files", "each Lite file as CSV, for a database to import (City Lite's is 660 MB)",
             DBIP_DB + "download/ip-to-city-lite"),
        Area("The full databases", "DB-IP's commercial databases, updated daily: IP to Country, Location, ISP, Location + ISP",
             DBIP_DB),
        Area("The lookup API", "an address looked up on DB-IP's servers, free in small numbers or with a paid key; never "
             "used here, since the address would leave this PC", DBIP_SITE + "api/doc.php"),
    ),
    calls=(
        Call("GET https://download.db-ip.com/free/dbip-city-lite-<year>-<month>.mmdb.gz", "one month's IP to City Lite, gzipped",
             "IP to City Lite",
             used=("Install the GeoIP file… and Update…, once you accept its licence, run by the platform as a job (its "
                   "progress in the plugin's panel): this month's, else last month's (a 404 while this month's is not out); "
                   "https on every hop, from download.db-ip.com alone; stopped after 30 minutes, and when the plugin is "
                   "detached"),
             docs=DBIP_DB + "download/ip-to-city-lite"),
        Call("maxminddb.open_database(<file>, MODE_MMAP_EXT)", "the file opened, memory-mapped by the reader's C extension",
             "The MMDB file",
             used=("the newest file in the data folder's geoip/, opened when the tab is asked, let go when watching stops "
                   "(opened again at the next ask)"), docs=READER),
        Call("Reader.get(<address>)", "the record of the range holding an address", "The MMDB file",
             used="each public network's place, and this network's public address's; never a local address's", docs=READER),
        Call("GET https://download.db-ip.com/free/dbip-country-lite-<year>-<month>.mmdb.gz", "one month's IP to Country Lite",
             "IP to Country Lite", docs=DBIP_DB + "download/ip-to-country-lite"),
        Call("GET https://download.db-ip.com/free/dbip-asn-lite-<year>-<month>.mmdb.gz", "one month's IP to ASN Lite",
             "IP to ASN Lite", docs=DBIP_DB + "download/ip-to-asn-lite"),
        Call("GET https://download.db-ip.com/free/dbip-city-lite-<year>-<month>.csv.gz", "one month's IP to City Lite as CSV",
             "The CSV files", docs=DBIP_DB + "download/ip-to-city-lite"),
    ),
    verified=VERIFIED_WORLD,
)

ASKED = ("once while the plugin is attached, the first time the World Wide Web tab is shown with a GeoIP file installed and "
         "no place of yours set (again 15 minutes later at the soonest when no address was given)")
# what goes out with each question, as the library sends it (dns.query through world.servers_of) and Windows' nslookup asks
SENT = ("The name goes absolute, with a trailing dot, so none of this PC's DNS search suffixes is sent with it; "
        "Windows' nslookup first asks the server for its own name (the PTR record of the server's own address: its "
        "\"Server:\" line), then the question. Nothing else goes out, never a peer's address.")
WAIT = "-timeout=3 -retry=1"  # nslookup's wait for each answer and its one retry (dns.PUBLIC_WAIT_S)

OPENDNS = Api(
    name="OpenDNS (myip.opendns.com)",
    maker="Cisco (OpenDNS)",
    about=("OpenDNS's resolvers answer the name myip.opendns.com, asked of them directly, with the asker's own public "
           "address: an A record over IPv4, an AAAA record over IPv6. The World Wide Web tab asks resolver1 "
           "(208.67.222.222, and 2620:119:35::35 over IPv6) for this network's public address, which the GeoIP file then "
           "places as home on the globe when you set no place of your own. " + SENT + " OpenDNS documents the "
           "resolvers, not this name."),
    kind="dns",
    base=f"nslookup -type=a {WAIT} myip.opendns.com. 208.67.222.222; -type=aaaa at 2620:119:35::35 (windowless)",
    version="OpenDNS's public resolvers (208.67.222.222, 208.67.220.220)",
    auth="none: a public DNS question",
    limits="none published; asked " + ASKED,
    costs="",
    links=(
        Link("OpenDNS's setup guide (its resolvers' addresses)", OPENDNS_GUIDE, "guide"),
        Link("OpenDNS", "https://www.opendns.com/", "docs"),
        Link("OpenDNS's support", "https://www.opendns.com/support/", "guide"),
        Link("Cisco Umbrella's status", "https://status.umbrella.cisco.com/", "status"),
        Link("OpenDNS's terms", "https://www.opendns.com/consumer-terms/", "terms"),
        Link("OpenDNS's privacy policy", "https://www.opendns.com/privacy-policy/", "terms"),
        Link("nslookup", COMMANDS + "nslookup", "tool"),
    ),
    areas=(
        Area("The asker's own address", "myip.opendns.com, answered with the address the question came from", OPENDNS_GUIDE,
             covered="this network's public IPv4 address, and its IPv6 one when there is no public IPv4 address"),
        Area("Its resolvers", "public resolvers anyone may use, with filtering for accounts", OPENDNS_GUIDE),
        Area("FamilyShield", "resolvers that block adult content (208.67.222.123, 208.67.220.123)", OPENDNS_GUIDE),
        Area("Accounts and filtering", "a network's own filtering, set up on its dashboard", "https://www.opendns.com/support/"),
    ),
    calls=(
        Call(f"nslookup -type=a {WAIT} myip.opendns.com. 208.67.222.222", "the asker's IPv4 address", "The asker's own address",
             used="this network's public IPv4 address, for home on the globe (asked first)", docs=OPENDNS_GUIDE),
        Call(f"nslookup -type=aaaa {WAIT} myip.opendns.com. 2620:119:35::35", "the asker's IPv6 address, asked over IPv6",
             "The asker's own address", used="this network's public IPv6 address, when neither server gives an IPv4 one"),
        Call("nslookup <name> 208.67.222.222", "any name resolved by OpenDNS", "Its resolvers", docs=OPENDNS_GUIDE),
    ),
    verified=VERIFIED_DNS,
)

GOOGLE = Api(
    name="Google's name servers (o-o.myaddr.l.google.com)",
    maker="Google",
    about=("Google's own name servers (ns1.google.com) answer the text record of o-o.myaddr.l.google.com with the address "
           "the question came from. The World Wide Web tab asks them for this network's public address, for home on the "
           "globe, when OpenDNS gives none. " + SENT + " Google documents no page for this name; its Public DNS pages, "
           "linked here, cover its DNS service and its terms."),
    kind="dns",
    base=(f"nslookup -type=txt {WAIT} o-o.myaddr.l.google.com. 216.239.32.10 (ns1.google.com; 2001:4860:4802:32::a over "
          "IPv6), windowless"),
    version="Google's authoritative servers for google.com",
    auth="none: a public DNS question",
    limits="none published; asked only when OpenDNS gives no public address, " + ASKED,
    costs="",
    links=(
        Link("Google Public DNS", GOOGLE_DNS, "docs"),
        Link("Google Public DNS: frequently asked questions", GOOGLE_DNS + "/faq", "guide"),
        Link("Google Public DNS: DNS over HTTPS (JSON)", GOOGLE_DNS + "/docs/doh/json", "reference"),
        Link("Google Public DNS's terms", GOOGLE_DNS + "/terms", "terms"),
        Link("Google Public DNS's privacy", GOOGLE_DNS + "/privacy", "terms"),
        Link("nslookup", COMMANDS + "nslookup", "tool"),
    ),
    areas=(
        Area("The asker's own address", "o-o.myaddr.l.google.com's text record, asked of ns1.google.com directly",
             covered="this network's public IPv4 or IPv6 address, when OpenDNS gives none"),
        Area("Google Public DNS", "the public resolvers (8.8.8.8, 8.8.4.4)", GOOGLE_DNS + "/docs/using"),
        Area("DNS over HTTPS", "names resolved over HTTPS, as JSON too", GOOGLE_DNS + "/docs/doh"),
    ),
    calls=(
        Call(f"nslookup -type=txt {WAIT} o-o.myaddr.l.google.com. 216.239.32.10", "the asker's address, in a text record",
             "The asker's own address", used="this network's public IPv4 address, when OpenDNS gives none"),
        Call(f"nslookup -type=txt {WAIT} o-o.myaddr.l.google.com. 2001:4860:4802:32::a", "the same, asked over IPv6",
             "The asker's own address", used="this network's public IPv6 address, when no IPv4 one was given and OpenDNS gives none"),
        Call("GET https://dns.google/resolve?name=<name>&type=<type>", "a name resolved over HTTPS, as JSON",
             "DNS over HTTPS", docs=GOOGLE_DNS + "/docs/doh/json"),
    ),
    verified=VERIFIED_DNS,
)

APIS = (POWERSHELL, NETSECURITY, NETCONNECTION, DEFENDER_API, WINDOWS_FIREWALL, NAMES, NPCAP, DBIP, OPENDNS, GOOGLE)
