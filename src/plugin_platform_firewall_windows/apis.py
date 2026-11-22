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
servers (NAME_SERVERS).

The Netstat tab, the hosts database and the globe's internet infrastructure (0.7.0) attach to five more (NETSTAT, the
fifth since 0.7.1), their pages read on 2026-11-18 (`VERIFIED_NETSTAT`) and the Topology Zoo's on 2026-11-19
(`VERIFIED_GLOBE`): Windows' own socket tables and their owners (IP Helper, the processes, the services), which the
library's sockets.read_windows asks with documented calls alone; and the four sources the globe's layers are downloaded
from, each only on your word: OpenStreetMap's features through the public Overpass server, Wikidata's places through its
query service, EMODnet's cable routes through its WFS, and the Internet Topology Zoo's maps of backbone networks from
its repository on GitHub (the user, 2026-11-19: "major network 'bones' need to be displayed on the map"). What the
layers are given of them lives here: each data set's address, query, size, licence in plain words and credit
(INFRASTRUCTURE, the library's Firewall base's), the licences' words (ODBL, CC0, CC_BY, ZOO_LICENCE) and the credits
(OSM_CREDIT, WIKIDATA_CREDIT, EMODNET_CREDIT, ZOO_CREDIT). The Linux firewall plugin names the same data sets, and both
plugins' tests pin their digest."""
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

# -- the Netstat tab, the hosts database and the globe's internet infrastructure (0.7.0) -------------------------------
# The Netstat tab reads Windows' own socket tables through the library's sockets.read_windows (every call documented:
# its WINDOWS_CALLS are the SOCKETS card's), and the hosts database is fed from the same readings, kept on this PC
# alone. The globe's layers are drawn from data sets downloaded only on your word, one request each, whose addresses,
# queries, licences and credits are named here, since the library names no outside host (its Firewall base's
# INFRASTRUCTURE): OpenStreetMap's features through the public Overpass server, Wikidata's places through its query
# service, EMODnet's cable routes through its WFS, whose capabilities offer GeoJSON (B-critique S11), and the Internet
# Topology Zoo's maps of backbone networks, one archive of GML files in its repository. Their pages were read on
# 2026-11-18 (`VERIFIED_NETSTAT`), EMODnet's capabilities on 2026-11-17, the Topology Zoo's repository, licence and
# records on 2026-11-19 (`VERIFIED_GLOBE`: progress/globe-research.md, nothing downloaded).
VERIFIED_NETSTAT = "2026-11-18"
VERIFIED_GLOBE = "2026-11-19"
API = WIN32 + "api/"
OVERPASS = "https://overpass-api.de/api/interpreter"  # the public Overpass server's (FOSSGIS runs it)
WDQS = "https://query.wikidata.org/sparql"  # the Wikidata Query Service's SPARQL endpoint
EMODNET_WFS = "https://ows.emodnet-humanactivities.eu/geoserver/emodnet/wfs"  # EMODnet Human Activities' WFS
ZOO_REPO = "https://github.com/mroughan/InternetTopologyZoo"  # the Internet Topology Zoo's repository (CC BY 4.0)
ZOO_RAW = "https://raw.githubusercontent.com/mroughan/InternetTopologyZoo/main/"  # its files, as they are
ZOO_GML = ZOO_RAW + "gml.tar.gz"  # every network's map in GML, one gzipped tar: 348,613 bytes (2026-11-19)
ZOO_RECORD = "https://researchdata.edu.au/internet-topology-zoo-data-set/4045587"  # Adelaide University's record
ZOO_DOI = "https://doi.org/10.25909/30153949.v1"  # the data set's DOI (figshare)
NETZSCHLEUDER = "https://networks.skewed.de/net/internet_top_pop"  # its points of presence, as Netzschleuder keeps them
OSM_WIKI = "https://wiki.openstreetmap.org/wiki/"
OVERPASS_DOC = "https://dev.overpass-api.de/overpass-doc/en/"
WDQS_MANUAL = "https://www.mediawiki.org/wiki/Wikidata_Query_Service/User_Manual"
WIKIDATA_WIKI = "https://www.wikidata.org/wiki/"
GEOSERVER_WFS = "https://docs.geoserver.org/latest/en/user/services/wfs/"
EMODNET_PORTAL = "https://emodnet.ec.europa.eu/en/"
EMODNET_RECORD = "https://emodnet.ec.europa.eu/geonetwork/srv/api/records/39ebe289-410b-4a5d-88a4-51bfcde538de"
# EMODnet's six telecommunication cable layers (its capabilities' "Telecommunication Cables - ..."; the power cables'
# pcables* are not telecom), one national source each: Germany's BSH, Spain's CICA, France's SHOM and SIGCables,
# Malta's IOI-MOC, the United Kingdom's OGA
EMODNET_LAYERS = ("emodnet:bshcontiscables", "emodnet:cicacables", "emodnet:shomcables", "emodnet:sigcables",
                  "emodnet:maltacables", "emodnet:ukfibrecables")

# Each data set's credit, drawn wherever its features are, as its licence asks; and its licence in plain words, shown in
# both confirmations before its download (the second one accepts it)
OSM_CREDIT = {"text": "© OpenStreetMap contributors", "url": "https://www.openstreetmap.org/copyright"}
WIKIDATA_CREDIT = {"text": "Wikidata", "url": WIKIDATA_WIKI + "Wikidata:Licensing"}
EMODNET_CREDIT = {"text": "EMODnet Human Activities; data originator Cogea Srl", "url": EMODNET_PORTAL}
ZOO_CREDIT = {"text": "Internet Topology Zoo (Knight, Nguyen, Falkner, Bowden, Roughan, IEEE JSAC 2011), Adelaide "
                      "University, CC BY 4.0", "url": ZOO_REPO}
ODBL = ("OpenStreetMap's data is free under the Open Database License 1.0 (opendatacommons.org/licenses/odbl/1-0): it "
        "may be copied, used and adapted as long as OpenStreetMap and its contributors are credited, and a changed "
        "copy passed on to others stays under the same licence. So wherever these features are drawn the page says "
        "\"© OpenStreetMap contributors\", linked to openstreetmap.org/copyright. It is what volunteers have mapped: "
        "incomplete in places, and it comes as it is.")
CC0 = ("Wikidata's structured data is in the public domain (Creative Commons Zero, "
       "creativecommons.org/publicdomain/zero/1.0): it may be used for anything and no credit is required; the page "
       "names Wikidata all the same. A place with no coordinates of its own is put where its seat or its town is, and "
       "it comes as it is.")
CC_BY = ("EMODnet's telecom cable routes are free under the Creative Commons Attribution 4.0 International licence "
         "(creativecommons.org/licenses/by/4.0): they may be copied, shared and adapted for any purpose, commercial "
         "uses included, as long as they are credited, the licence is linked and changes are said. Their record "
         "asks for these words: \"This data was downloaded from the EMODnet Portal (https://emodnet.ec.europa.eu/en/). "
         "The data originator is Cogea Srl.\" So wherever these routes are drawn the page says \"EMODnet Human "
         "Activities; data originator Cogea Srl\", linked to emodnet.ec.europa.eu, and the globe draws them thinned "
         "(no two vertices nearer than 0.02 degrees). They are the actual routes as six national sources gave them "
         "(Germany's BSH, Spain's CICA, France's SHOM and SIGCables, Malta's IOI-MOC, the United Kingdom's OGA); "
         "Dutch cables are withheld by their source for security, and the data comes as it is.")
ZOO_LICENCE = (
    "The Internet Topology Zoo's maps are free under the Creative Commons Attribution 4.0 International licence "
    "(creativecommons.org/licenses/by/4.0), as its repository's LICENSE and Adelaide University's record of it say: "
    "they may be copied, shared and adapted for any purpose, commercial uses included, as long as they are credited, "
    "the licence is linked and changes are said. So wherever its networks are drawn the page says \"Internet Topology "
    "Zoo (Knight, Nguyen, Falkner, Bowden, Roughan, IEEE JSAC 2011), Adelaide University, CC BY 4.0\", linked to its "
    "repository, and each network is named with the year of its map. What is changed: of each network only its newest "
    "map is drawn, from 2000 on, and of it only its own points of presence that have a place and the links between "
    "them, each drawn as the great circle between its two ends. These are logical links as the operators' public maps "
    "showed them about 2010 and 2011, placed at their cities: not the networks of today, nor the routes their fibre "
    "takes. The data comes as it is.")

# The data sets the globe may draw (the library's infrastructure.DataSet, as plain dicts its Firewall base reads), in
# the order its table lists them. `size` is an estimate where the maker gives none (B-research-infrastructure 4.1, 5.2,
# 5.3, 6.2, 7.3), said as one; `wait` is how long each socket operation of the download waits: the query's own time
# limit and a margin, for a server may be silent while a query runs (Overpass's [timeout:N]; the query service stops a
# query at 60 s). Overpass prints each site's centre and each line's route with its tags alone (out tags center, out
# tags geom: no node ids, nothing of who mapped it), sorted by place (qt). OpenStreetMap's tags as its Telecoms page
# gives them: a submarine cable is communication=line with location=underwater, submarine=yes, or seamark:type=
# cable_submarine of a telecom category (the eight below); a line on land is communication=line, telecom=line or
# telecom=cable, and one on power poles (power=minor_line, local distribution: 6,394 of communication=line's 15,775,
# taginfo 2026-11-18) is left out, which leaves the lines most like backbones. Wikidata's data centres are asked with
# their kinds (P279*: colocation centres among them, 211 items against 168, a count of 2026-11-19). EMODnet's WFS is
# asked for GeoJSON with its coordinates longitude first (srsName=EPSG:4326, which GeoServer reads as
# longitude/latitude). The Topology Zoo's archive is the file alone, its size as GitHub gave it (2026-11-19).
OSM = {"format": "overpass", "url": OVERPASS, "source": "OpenStreetMap, through the Overpass API",
       "licence_name": "ODbL 1.0", "licence": ODBL, "credit": OSM_CREDIT}
# liminal-libs 1.72.1: IANA's RDAP bootstrap files, IPv4 and IPv6: which registry holds an address, its routers'
# networks then looked up of that registry (the library's machines/lookups.py, within the registries' limits); named
# here, as every outside host is, never in the library
RDAP_BOOTSTRAP = ("https://data.iana.org/rdap/ipv4.json", "https://data.iana.org/rdap/ipv6.json")
# liminal-libs 1.73.0: what routers' names are read with (machines/names.py), drawn as layers too, each downloaded on
# the user's click with its size and its licence first
OURAIRPORTS_CSV = "https://davidmegginson.github.io/ourairports-data/airports.csv"  # 12.2 MB (2026-11-22)
OURAIRPORTS_LICENCE = ("OurAirports releases all of its data to the public domain: it may be used for any purpose, "
                       "with no permission needed, and comes with no guarantee of accuracy or fitness for use.")
OURAIRPORTS_CREDIT = {"text": "OurAirports", "url": "https://ourairports.com/data/"}
GEONAMES_CITIES = "https://download.geonames.org/export/dump/cities15000.zip"  # 3.2 MB (2026-11-22)
GEONAMES_LICENCE = ("GeoNames' data is free under the Creative Commons Attribution 4.0 licence: it may be used, "
                    "shared and adapted for any purpose, GeoNames credited as its source.")
GEONAMES_CREDIT = {"text": "GeoNames", "url": "https://www.geonames.org/"}

INFRASTRUCTURE = (
    {**OSM, "id": "osm-datacentres", "title": "Data centres", "size": 2_000_000, "wait": 210,
     "about": "about 5,000 sites, and its few exchange points",
     "query": ('[out:json][timeout:180];(nwr["telecom"="data_center"];nwr["building"="data_center"];'
               'nwr["telecom"="internet_exchange"];);out tags center qt;')},
    # a submarine cable's telecom categories: the OSM wiki's own word for fibre (optical), the spellings mapped beside
    # it (taginfo, 2026-11-18: telephone 749, fibre_optic 366, fiber_optic 64, optical 5, telefon 2, telegraph,
    # communication and telephone/fibre_optic 1 each), telephone's and telegraph's; power, mooring, ferry, sensor and
    # the like are left out
    {**OSM, "id": "osm-cables", "title": "Submarine cables and landing stations", "size": 3_000_000, "wait": 210,
     "about": "about 1,200 cable ways and 60 landing stations",
     "query": ('[out:json][timeout:180];(way["seamark:type"="cable_submarine"]'
               '["seamark:cable_submarine:category"~"^(fibre_optic|fiber_optic|optical|telephone|telegraph|telefon|'
               'communication|telephone/fibre_optic)$"];'
               'way["communication"="line"]["location"="underwater"];way["communication"="line"]["submarine"="yes"];);'
               'out tags geom qt;nwr["telecom"="cable_landing_station"];out tags center qt;')},
    {**OSM, "id": "osm-lines", "title": "Telecom lines on land (partial)", "size": 15_000_000, "wait": 330,
     "about": "about 13,000 ways, none on power poles; no country is complete",
     "query": ('[out:json][timeout:300];(way["communication"="line"]["location"!="underwater"]["submarine"!="yes"]'
               '[!"power"];way["telecom"="line"];way["telecom"="cable"];);out tags geom qt;')},
    {"id": "wikidata", "title": "Exchange points, ground stations and teleports", "format": "sparql", "url": WDQS,
     "source": "Wikidata", "licence_name": "CC0", "licence": CC0, "credit": WIKIDATA_CREDIT, "size": 200_000,
     "wait": 90, "about": "about 340 places, some data centres among them",
     "query": ('SELECT DISTINCT ?item ?itemLabel ?kind ?coord ?operatorLabel WHERE { { VALUES ?kind { wd:Q1433061 '
               'wd:Q1349167 wd:Q10379228 } ?item wdt:P31 ?kind . } UNION { VALUES ?kind { wd:Q671224 } ?item '
               'wdt:P31/wdt:P279* ?kind . } OPTIONAL { ?item wdt:P625 ?own } OPTIONAL { ?item wdt:P159/wdt:P625 ?seat '
               '} OPTIONAL { ?item wdt:P131/wdt:P625 ?place } BIND(COALESCE(?own, ?seat, ?place) AS ?coord) '
               'FILTER(BOUND(?coord)) OPTIONAL { ?item wdt:P137 ?operator } SERVICE wikibase:label { '
               'bd:serviceParam wikibase:language "en" } }')},
    {"id": "emodnet-cables", "title": "Telecom cable routes in European waters", "format": "geojson",
     "url": EMODNET_WFS, "source": "EMODnet Human Activities, through its WFS", "licence_name": "CC BY 4.0",
     "licence": CC_BY, "credit": EMODNET_CREDIT, "size": 4_000_000, "wait": 120,
     "about": "actual routes in European waters, and French cables beyond, from six national sources",
     "query": ("service=WFS&version=1.1.0&request=GetFeature&typeName=" + ",".join(EMODNET_LAYERS)
               + "&outputFormat=application/json&srsName=EPSG:4326")},
    {"id": "topology-zoo", "title": "Backbone networks, about 2010-2011", "format": "gml", "url": ZOO_GML,
     "source": "the Internet Topology Zoo (Adelaide University), through GitHub", "licence_name": "CC BY 4.0",
     "licence": ZOO_LICENCE, "credit": ZOO_CREDIT, "size": 348_613, "wait": 60,
     "about": ("261 maps of backbone networks (GÉANT, Internet2, ESnet, Sprint, NTT, Cogent and more), each network's "
               "newest drawn: logical links, not fibre")},
    # liminal-libs 1.73.0: the airports' codes and the cities routers' names are read with, drawn as layers too
    {"id": "ourairports", "title": "Airports and their codes", "format": "ourairports", "url": OURAIRPORTS_CSV,
     "source": "OurAirports, through its data's mirror on GitHub", "licence_name": "Public domain",
     "licence": OURAIRPORTS_LICENCE, "credit": OURAIRPORTS_CREDIT, "size": 12_800_000, "wait": 180,
     "about": "the world's large and medium airports with a three-letter code: routers' names are read with them"},
    {"id": "geonames-cities", "title": "Cities of the world", "format": "geonames", "url": GEONAMES_CITIES,
     "source": "GeoNames", "licence_name": "CC BY 4.0", "licence": GEONAMES_LICENCE, "credit": GEONAMES_CREDIT,
     "size": 3_400_000, "wait": 120,
     "about": "the cities of 15,000 people or more: named on the globe, and routers' names read with them"},
)

SOCKETS = Api(
    name="Windows' socket tables and their owners (IP Helper)",
    maker="Microsoft",
    about=("What Windows says of every socket on this PC, asked of the system itself: IP Helper's TCP and UDP tables "
           "in their OWNER_MODULE class, which give each socket its process, the time it was made and its service's "
           "tag, to any account; each owner's program from one snapshot of the processes, where it is on disk and when "
           "it started; the services behind a shared process. The library calls them by ctypes (its "
           "sockets.read_windows), no package between. The Netstat tab lists them, the hosts database is fed from "
           "them, and the globe's Hosts recorded is drawn from that database. No packet is captured, no administrator "
           "is asked, no process is started and nothing is sent anywhere."),
    kind="system",
    base="iphlpapi.dll, kernel32.dll, advapi32.dll and shell32.dll by ctypes (the library's sockets.read_windows)",
    version="Windows 10 and 11 (IP Helper's OWNER_MODULE tables and their owners' calls date from Windows XP SP2 "
            "and Vista)",
    auth=("any account: every socket, its process and when it was made, its service's tag; where a service's or "
          "Windows' own process is on disk is an administrator's to read, so it is said as not read, never asked for "
          "through UAC"),
    limits=("read while the Netstat tab (every 3 s) or the World Wide Web tab (every 2 s) is shown, one reading "
            "shared by both for 2.5 s, or every 5 s all the time the platform runs where you chose to record the hosts "
            "always; 20,000 sockets a reading at most; each owner asked once, the services listed once a reading; a "
            "connection shorter than the gap between two readings can be missed, and Windows lists no remote host for "
            "a UDP socket"),
    costs="",
    links=(
        Link("IP Helper", WIN32 + "iphlp/ip-helper-start-page", "docs"),
        Link("GetExtendedTcpTable", API + "iphlpapi/nf-iphlpapi-getextendedtcptable", "reference"),
        Link("MIB_TCPROW_OWNER_MODULE", API + "tcpmib/ns-tcpmib-mib_tcprow_owner_module", "reference"),
        Link("MIB_UDPROW_OWNER_MODULE", API + "udpmib/ns-udpmib-mib_udprow_owner_module", "reference"),
        Link("TCP_TABLE_CLASS", API + "iprtrmib/ne-iprtrmib-tcp_table_class", "reference"),
        Link("Process security and access rights", WIN32 + "procthread/process-security-and-access-rights", "guide"),
        Link("Services", WIN32 + "services/services", "guide"),
        Link("netstat", COMMANDS + "netstat", "tool"),
    ),
    areas=(
        Area("TCP connections and listeners", ("the TCP table, IPv4 and IPv6, each row with its state, both ends, its "
                                               "process, when it was made and its owner module's tag"),
             API + "iphlpapi/nf-iphlpapi-getextendedtcptable",
             covered="every connection and listener, in the OWNER_MODULE class (TCP_TABLE_OWNER_MODULE_ALL)"),
        Area("UDP endpoints", "the UDP table, IPv4 and IPv6, with the same facts of its owner",
             API + "iphlpapi/nf-iphlpapi-getextendedudptable",
             covered="every UDP socket bound here (UDP_TABLE_OWNER_MODULE), as ports only: no remote host is listed"),
        Area("A socket's owner module", "the program or the service behind one row of a table",
             API + "iprtrmib/ns-iprtrmib-tcpip_owner_module_basic_info",
             covered=("where a program is on disk, and the service behind a socket of a shared process (svchost.exe), "
                      "asked once for each owner")),
        Area("Processes", "every process in one snapshot; a process's program and times",
             WIN32 + "toolhelp/tool-help-library",
             covered=("each socket's program by its name; where it is on disk and when it started, asked with limited "
                      "information access alone (PROCESS_QUERY_LIMITED_INFORMATION)")),
        Area("Services", "the services this PC runs and the process of each", WIN32 + "services/services",
             covered="the services running in each process, by their short and display names"),
        Area("The awake clock", "time since the system started, its sleep and hibernation left out",
             API + "realtimeapiset/nf-realtimeapiset-queryunbiasedinterrupttime",
             covered="the hosts database's time connected: a night asleep is no time connected"),
        Area("Per-connection statistics", ("bytes, round trips and congestion of a TCP connection, once an "
                                           "administrator switched them on for it"),
             API + "iphlpapi/nf-iphlpapi-getpertcpconnectionestats"),
        Area("The tables without owners' modules", "TCP's table with each connection's offload state, the plain ones",
             API + "iphlpapi/nf-iphlpapi-gettcptable2"),
        Area("PowerShell's view", "the same tables as objects (the NetTCPIP cmdlets)",
             MODULE + "nettcpip/get-nettcpconnection" + WS),
    ),
    calls=(
        Call("GetExtendedTcpTable", ("the TCP table with each row's owner: its process, when it was made, its "
                                     "module's tag (TCP_TABLE_OWNER_MODULE_ALL), IPv4 and IPv6"),
             "TCP connections and listeners", used="each reading: every TCP connection and listener",
             docs=API + "iphlpapi/nf-iphlpapi-getextendedtcptable"),
        Call("GetExtendedUdpTable", "the UDP table with each row's owner (UDP_TABLE_OWNER_MODULE), IPv4 and IPv6",
             "UDP endpoints", used="each reading: every UDP socket bound here",
             docs=API + "iphlpapi/nf-iphlpapi-getextendedudptable"),
        Call("GetOwnerModuleFromTcpEntry", "an IPv4 TCP row's owner module: its name and its path",
             "A socket's owner module",
             used="once for each owner: its program's path, or the service a tagged row is for",
             docs=API + "iphlpapi/nf-iphlpapi-getownermodulefromtcpentry"),
        Call("GetOwnerModuleFromTcp6Entry", "an IPv6 TCP row's owner module", "A socket's owner module",
             used="the same, for IPv6", docs=API + "iphlpapi/nf-iphlpapi-getownermodulefromtcp6entry"),
        Call("GetOwnerModuleFromUdpEntry", "an IPv4 UDP row's owner module", "A socket's owner module",
             used="the same, for UDP", docs=API + "iphlpapi/nf-iphlpapi-getownermodulefromudpentry"),
        Call("GetOwnerModuleFromUdp6Entry", "an IPv6 UDP row's owner module", "A socket's owner module",
             used="the same, for UDP over IPv6", docs=API + "iphlpapi/nf-iphlpapi-getownermodulefromudp6entry"),
        Call("CreateToolhelp32Snapshot", "a snapshot of every process", "Processes",
             used="each reading: every process's program, once",
             docs=API + "tlhelp32/nf-tlhelp32-createtoolhelp32snapshot"),
        Call("Process32FirstW", "the snapshot's first process", "Processes", used="each reading's snapshot",
             docs=API + "tlhelp32/nf-tlhelp32-process32firstw"),
        Call("Process32NextW", "the snapshot's next process", "Processes", used="each reading's snapshot",
             docs=API + "tlhelp32/nf-tlhelp32-process32nextw"),
        Call("OpenProcess", "a process opened for limited information alone (PROCESS_QUERY_LIMITED_INFORMATION)",
             "Processes", used=("once for each owner (a service's and Windows' own refuse an ordinary account: said "
                                "as not read)"),
             docs=API + "processthreadsapi/nf-processthreadsapi-openprocess"),
        Call("QueryFullProcessImageNameW", "where a process's program is on disk", "Processes",
             used="each owner's program path", docs=API + "winbase/nf-winbase-queryfullprocessimagenamew"),
        Call("GetProcessTimes", "when a process started", "Processes",
             used="each owner's start: a process started again is a new owner, asked anew",
             docs=API + "processthreadsapi/nf-processthreadsapi-getprocesstimes"),
        Call("CloseHandle", "a handle closed", "Processes", used="after each owner is asked",
             docs=API + "handleapi/nf-handleapi-closehandle"),
        Call("QueryUnbiasedInterruptTime", "the time since the system started, its sleep left out", "The awake clock",
             used="each reading: the time connected the hosts database adds",
             docs=API + "realtimeapiset/nf-realtimeapiset-queryunbiasedinterrupttime"),
        Call("OpenSCManagerW", "the service manager opened, to connect and to list", "Services",
             used="each reading's services", docs=API + "winsvc/nf-winsvc-openscmanagerw"),
        Call("EnumServicesStatusExW", "the Win32 services running, each with its process", "Services",
             used="the services in each process: a socket of a shared one named by its service",
             docs=API + "winsvc/nf-winsvc-enumservicesstatusexw"),
        Call("CloseServiceHandle", "the service manager's handle closed", "Services",
             used="after the services are listed",
             docs=API + "winsvc/nf-winsvc-closeservicehandle"),
        Call("IsUserAnAdmin", "whether this process has an administrator's rights", "Processes",
             used="the reading's note: every socket is read either way",
             docs=API + "shlobj_core/nf-shlobj_core-isuseranadmin"),
        Call("GetPerTcpConnectionEStats", "a TCP connection's extended statistics (bytes, round trips, congestion)",
             "Per-connection statistics", docs=API + "iphlpapi/nf-iphlpapi-getpertcpconnectionestats"),
        Call("SetPerTcpConnectionEStats", "a connection's extended statistics switched on: an administrator's",
             "Per-connection statistics", docs=API + "iphlpapi/nf-iphlpapi-setpertcpconnectionestats", writes=True),
        Call("GetTcpTable2", "the TCP table with each connection's offload state", "The tables without owners' modules",
             docs=API + "iphlpapi/nf-iphlpapi-gettcptable2"),
        Call("Get-NetTCPConnection", "the TCP connections as objects, each with its owning process",
             "PowerShell's view", docs=MODULE + "nettcpip/get-nettcpconnection" + WS),
        Call("Get-NetUDPEndpoint", "the UDP endpoints as objects", "PowerShell's view",
             docs=MODULE + "nettcpip/get-netudpendpoint" + WS),
    ),
    verified=VERIFIED_NETSTAT,
)

OVERPASS_API = Api(
    name="Overpass API (OpenStreetMap)",
    maker="FOSSGIS (overpass-api.de), for OpenStreetMap",
    about=("A read-only API over OpenStreetMap's data, answering a query in Overpass QL with the map's elements that "
           "match it, by their tags. The globe's infrastructure is asked of its public server once a data set, on your "
           "click: the data centres and exchange points (each site's centre), the submarine cables of every telecom "
           "category with their routes and their landing stations, and the telecom lines on land (those on power poles "
           "left out), each with its tags alone (no node ids, no history, nothing of who mapped it). The answers are "
           "OpenStreetMap's contributors' work under the ODbL, credited on the globe, and are kept on this PC, so the "
           "globe asks nothing of anyone once they are in."),
    kind="query",
    base=OVERPASS,
    version="Overpass API 0.7.62, its public instance at overpass-api.de (two servers behind one name)",
    auth="none: no account and no key; the ODbL accepted on the page before a download",
    limits=("its usage policy: about 10,000 queries and 1 GB a day at most (a hundredth of that for regular use), no "
            "queries in parallel, an app naming itself in its User-Agent; HTTP 429 (too many) and 504 (no room now) "
            "when it is busy, which it often is; heavy and commercial use belong on servers of one's own. Asked once a "
            "data set on your click, the query's own time limit (180 or 300 s) waited for, once more a minute later "
            "when it is busy, ten minutes at most in all"),
    costs="",
    links=(
        Link("Overpass API", OSM_WIKI + "Overpass_API", "docs"),
        Link("Overpass QL", OSM_WIKI + "Overpass_API/Overpass_QL", "reference"),
        Link("The Overpass API user's manual", OVERPASS_DOC, "guide"),
        Link("The commons: the public instances' limits", OVERPASS_DOC + "preface/commons.html", "limits"),
        Link("Output formats", OVERPASS_DOC + "targets/formats.html", "reference"),
        Link("Telecoms in OpenStreetMap: their tags", OSM_WIKI + "Telecoms", "guide"),
        Link("OpenStreetMap's copyright and licence", "https://www.openstreetmap.org/copyright", "terms"),
        Link("The attribution guidelines", "https://osmfoundation.org/wiki/Licence/Attribution_Guidelines", "terms"),
        Link("The Open Database License 1.0", "https://opendatacommons.org/licenses/odbl/1-0/", "terms"),
    ),
    areas=(
        Area("Tag queries", "the elements that carry given tags, the whole planet or an area, as JSON",
             OSM_WIKI + "Overpass_API/Overpass_QL",
             covered=("three queries, one a data set: data centres and exchange points; submarine cables "
                      "(seamark:type=cable_submarine of the telecom categories: optical, fibre_optic and fiber_optic, "
                      "telephone, telegraph and their kin; communication=line under water) and landing stations; "
                      "telecom lines on land, those on power poles (power=*) left out")),
        Area("Places and routes", "an element's centre, its bounds or its whole geometry",
             OVERPASS_DOC + "targets/formats.html",
             covered="each site's centre (out tags center) and each line's route (out tags geom), their tags alone"),
        Area("Its usage policy", "the public instances' limits, and who should run a server of their own",
             OVERPASS_DOC + "preface/commons.html",
             covered=("one request a data set, on a click: no polling, no queries in parallel, the plugin's name and "
                      "version as its User-Agent")),
        Area("Other outputs", "XML, CSV, counts, and objects made by convert", OVERPASS_DOC + "targets/formats.html"),
        Area("History and changes", "the map as it was at a date, and what changed between two dates", OVERPASS_DOC),
        Area("A client's status", "its slots on the server and when they come free",
             OVERPASS_DOC + "preface/commons.html"),
    ),
    calls=(
        Call("GET https://overpass-api.de/api/interpreter?data=<query>", "a query's answer, as JSON", "Tag queries",
             used=("Download… and Update… on the World Wide Web tab's Internet infrastructure table, once you accept "
                   "the ODbL, run by the platform as a job (its progress in the plugin's panel; Cancel stops it): one "
                   "GET a data set, https on every hop, from overpass-api.de alone; stopped after 10 minutes, and when "
                   "the plugin is detached"),
             docs=OSM_WIKI + "Overpass_API/Overpass_QL"),
        Call("POST https://overpass-api.de/api/interpreter", "a query sent in the request's body", "Tag queries",
             docs=OSM_WIKI + "Overpass_API"),
        Call("GET https://overpass-api.de/api/status", "this client's slots, and the server's rate limit",
             "A client's status", docs=OVERPASS_DOC + "preface/commons.html"),
    ),
    verified=VERIFIED_NETSTAT,
)

WIKIDATA = Api(
    name="Wikidata Query Service",
    maker="the Wikimedia Foundation (Wikidata)",
    about=("The SPARQL endpoint over Wikidata, the free knowledge base: its items, their kinds and their statements, "
           "in the public domain (CC0). The globe asks it once, on your click, for the exchange points, data centres "
           "(of every kind: colocation centres among them), ground stations and teleports Wikidata knows with a place "
           "(each one's own coordinates, else its seat's or its town's), with their names and operators in English, "
           "and keeps the answer on this PC."),
    kind="query",
    base=WDQS,
    version="the Wikidata Query Service (SPARQL 1.1), as its user manual gives it",
    auth="none: no account and no key",
    limits=("a query runs 60 s at most; each client (its User-Agent and its address) has 60 s of processing a minute, "
            "30 failed queries a minute and 5 queries at once, and past them HTTP 429 with Retry-After (a client that "
            "goes on is banned for a while). Its User-Agent policy asks an automated client to name a contact: the "
            "plugin sends its name and version alone, so a refusal (HTTP 403) is said in words, and no contact is "
            "added. Asked once on your click, waited for 90 s"),
    costs="",
    links=(
        Link("The Wikidata Query Service user manual", WDQS_MANUAL, "docs"),
        Link("The SPARQL query service", WIKIDATA_WIKI + "Wikidata:SPARQL_query_service", "guide"),
        Link("Its query limits", WIKIDATA_WIKI + "Wikidata:SPARQL_query_service/query_limits", "limits"),
        Link("SPARQL 1.1 Query Language", "https://www.w3.org/TR/sparql11-query/", "spec"),
        Link("The User-Agent policy",
             "https://foundation.wikimedia.org/wiki/Policy:Wikimedia_Foundation_User-Agent_Policy", "terms"),
        Link("Wikidata's licensing", WIKIDATA_WIKI + "Wikidata:Licensing", "terms"),
        Link("CC0 1.0", "https://creativecommons.org/publicdomain/zero/1.0/", "terms"),
    ),
    areas=(
        Area("SPARQL queries", "items and their statements, matched by a query, as JSON", WDQS_MANUAL,
             covered=("one query: internet exchange points (Q1433061), data centres (Q671224, and its subclasses "
                      "through P279*), ground stations (Q1349167) and teleports (Q10379228), each with its place")),
        Area("The label service", "an item's name in a language asked for", WDQS_MANUAL,
             covered="each place's and its operator's name, in English"),
        Area("Its usage limits", "a query's time, a client's share, its User-Agent",
             WIKIDATA_WIKI + "Wikidata:SPARQL_query_service/query_limits",
             covered="one request, on a click, with the plugin's name and version"),
        Area("An item's own data", "an item's whole record as JSON (Special:EntityData)",
             WIKIDATA_WIKI + "Wikidata:Data_access"),
        Area("Federated queries", "a query that asks other SPARQL endpoints too", WDQS_MANUAL),
    ),
    calls=(
        Call("GET https://query.wikidata.org/sparql?format=json&query=<query>", "a query's results, as JSON",
             "SPARQL queries",
             used=("Download… and Update… on the World Wide Web tab's Internet infrastructure table, run by the "
                   "platform as a job: one GET, https on every hop, from query.wikidata.org alone"),
             docs=WDQS_MANUAL),
        Call("POST https://query.wikidata.org/sparql", "a query sent in the request's body (not cached)",
             "SPARQL queries", docs=WDQS_MANUAL),
        Call("GET https://www.wikidata.org/wiki/Special:EntityData/<item>.json", "an item's whole record",
             "An item's own data", docs=WIKIDATA_WIKI + "Wikidata:Data_access"),
    ),
    verified=VERIFIED_NETSTAT,
)

EMODNET = Api(
    name="EMODnet Human Activities (WFS)",
    maker="EMODnet (the European Commission's marine data network); data originator Cogea Srl",
    about=("The European Marine Observation and Data Network's Human Activities portal serves its layers through "
           "GeoServer as an OGC Web Feature Service. Its telecommunication cables' actual routes, as six national "
           "sources gave them (Germany's BSH, Spain's CICA, France's SHOM and SIGCables, Malta's IOI-MOC, the United "
           "Kingdom's OGA; Dutch cables withheld by their source), are asked once on your click, as GeoJSON with their "
           "coordinates longitude first, and drawn on the globe as submarine cables, credited as their record asks."),
    kind="query",
    base=EMODNET_WFS,
    version="WFS 1.1.0 (it offers 1.0.0, 1.1.0 and 2.0.0) on GeoServer, as its capabilities said on 2026-11-17",
    auth="none: no account and no key; CC BY 4.0 accepted on the page before a download",
    limits=("none named: its capabilities say Fees NONE and AccessConstraints NONE, and up to 1,000,000 features an "
            "answer; it is served behind Cloudflare. Asked once on your click, waited for 120 s"),
    costs="",
    links=(
        Link("EMODnet Human Activities", EMODNET_PORTAL + "human-activities", "docs"),
        Link("Cables, telecommunication, actual routes: the record", EMODNET_RECORD, "reference"),
        Link("The WFS's capabilities", EMODNET_WFS + "?service=WFS&request=GetCapabilities", "reference"),
        Link("GeoServer's WFS output formats", GEOSERVER_WFS + "outputformats/", "reference"),
        Link("GeoServer's axis ordering", GEOSERVER_WFS + "axis_order/", "guide"),
        Link("OGC Web Feature Service", "https://www.ogc.org/standards/wfs/", "spec"),
        Link("The EMODnet portal", EMODNET_PORTAL, "docs"),
        Link("CC BY 4.0", "https://creativecommons.org/licenses/by/4.0/", "terms"),
    ),
    areas=(
        Area("Telecom cable routes", "the actual routes of telecommunication cables in European waters", EMODNET_RECORD,
             covered=("the six telecom layers in one GetFeature, as GeoJSON, longitude first (srsName=EPSG:4326, "
                      "which GeoServer reads as longitude and latitude; urn:ogc:def:crs:EPSG::4326 is latitude "
                      "first)")),
        Area("Its capabilities", "what the service offers: its layers, formats and coordinate systems",
             EMODNET_WFS + "?service=WFS&request=GetCapabilities"),
        Area("Power cables", "the same sources' power cables (the pcables layers): not telecom", EMODNET_RECORD),
        Area("The map service (WMS)", "the same layers drawn as pictures", EMODNET_PORTAL + "human-activities"),
        Area("The record's download", "the routes as a shapefile and a geodatabase in one zip", EMODNET_RECORD),
    ),
    calls=(
        Call("GET https://ows.emodnet-humanactivities.eu/geoserver/emodnet/wfs?service=WFS&version=1.1.0"
             "&request=GetFeature&typeName=<the six layers>&outputFormat=application/json&srsName=EPSG:4326",
             "the six layers' features, as GeoJSON", "Telecom cable routes",
             used=("Download… and Update… on the World Wide Web tab's Internet infrastructure table, run by the "
                   "platform as a job: one GET, https on every hop, from ows.emodnet-humanactivities.eu alone"),
             docs=GEOSERVER_WFS + "outputformats/"),
        Call("GET https://ows.emodnet-humanactivities.eu/geoserver/emodnet/wfs?service=WFS&request=GetCapabilities",
             "what the service offers", "Its capabilities", docs=GEOSERVER_WFS + "outputformats/"),
        Call("GET https://ows.emodnet-humanactivities.eu/geoserver/emodnet/wfs?service=WFS&request=DescribeFeatureType",
             "a layer's properties", "Its capabilities", docs="https://www.ogc.org/standards/wfs/"),
    ),
    verified=VERIFIED_NETSTAT,
)

TOPOLOGY_ZOO = Api(
    name="Internet Topology Zoo (GitHub)",
    maker="Adelaide University (S. Knight, H. Nguyen, N. Falkner, R. Bowden, M. Roughan); its repository on GitHub",
    about=("261 maps of networks' backbones (some networks mapped in several years), transcribed from the operators' "
           "own public maps of about 2010 and 2011: "
           "research and education networks (GÉANT, Internet2, ESnet, RENATER, NORDUnet and more) and carriers "
           "(Sprint, UUNET, Cogent, NTT, Hurricane Electric and more), each with its points of presence, their places "
           "(at their cities) and the links between them. Its repository keeps them as a long-term store, not updated. "
           "The globe asks for its archive of GML maps once, on your click (0.35 MB), unpacks it in memory alone, and "
           "draws each network's newest map as backbones and their points of presence, credited as its licence asks: "
           "logical links between cities, not the routes of fibre, and not today's networks."),
    kind="feed",
    base=ZOO_GML,
    version=("its repository's main branch as read on 2026-11-19: gml.tar.gz, 348,613 bytes, one GML file a map "
             "(the maps' own dates: about 2010 and 2011, older ones of some networks beside them)"),
    auth="none: no account and no key; CC BY 4.0 accepted on the page before a download",
    limits="none named for one file; asked once on your click, waited for 60 s",
    costs="",
    links=(
        Link("The Internet Topology Zoo's repository", ZOO_REPO, "docs"),
        Link("Its licence (CC BY 4.0)", ZOO_RAW + "LICENSE", "terms"),
        Link("Adelaide University's record (Research Data Australia)", ZOO_RECORD, "reference"),
        Link("The data set's DOI", ZOO_DOI, "reference"),
        Link("Its points of presence, as Netzschleuder keeps them", NETZSCHLEUDER, "reference"),
        Link("CC BY 4.0", "https://creativecommons.org/licenses/by/4.0/", "terms"),
    ),
    areas=(
        Area("The networks' maps in GML", "every network's map in GML, one gzipped tar archive", ZOO_REPO,
             covered=("the archive, asked once on your click and unpacked in memory alone: of each network its newest "
                      "map, from 2000 on, its own points of presence with a place and the links between them")),
        Area("The same maps in GraphML", "the maps in GraphML (XML), in an archive of their own", ZOO_REPO),
        Area("Each network's own file", "one network's map, by its name, in GML or GraphML", ZOO_REPO),
        Area("The data set's records", "its record at Research Data Australia and its DOI at figshare", ZOO_RECORD),
    ),
    calls=(
        Call(f"GET {ZOO_GML}", "every network's map in GML, one gzipped tar archive", "The networks' maps in GML",
             used=("Download… and Update… on the World Wide Web tab's Internet infrastructure table, once you accept "
                   "CC BY 4.0, run by the platform as a job: one GET, https on every hop, from "
                   "raw.githubusercontent.com alone"),
             docs=ZOO_REPO),
        Call(f"GET {ZOO_RAW}graphml.tar.gz", "every network's map in GraphML, one gzipped tar archive",
             "The same maps in GraphML", docs=ZOO_REPO),
        Call(f"GET {ZOO_RAW}graphml/<network>.graphml", "one network's map in GraphML", "Each network's own file",
             docs=ZOO_REPO),
    ),
    verified=VERIFIED_GLOBE,
)

# liminal-libs 1.73.0: the sources of what routers' names are read with (the library's machines/names.py)
ROUTERS_VERIFIED = "2026-11-22"  # the two cards' pages, read on 2026-11-22
OURAIRPORTS_API = Api(
    name="OurAirports",
    maker="OurAirports (David Megginson and its contributors), its data mirrored on GitHub",
    about=("OurAirports keeps the world's airports, each with its codes, its place, its town and its country, and "
           "releases all of it to the public domain. The globe asks for its airports file once, on your click: each "
           "large or medium airport with a three-letter code is kept as a point of the airports layer, and routers' "
           "names are read with the codes (sea, fra) to place each router at its airport's town where the trace's "
           "time allows it. The request names the file alone and nothing about this machine."),
    kind="feed",
    base=OURAIRPORTS_CSV,
    version="airports.csv as its mirror served it on 2026-11-22: 12.2 MB, one row an airport, its codes among them",
    auth="none: no account and no key",
    limits="none named for one file; asked once on your click, waited for 180 s",
    costs="",
    links=(
        Link("OurAirports' data", "https://ourairports.com/data/", "docs"),
        Link("Its data's mirror on GitHub", "https://github.com/davidmegginson/ourairports-data", "reference"),
    ),
    areas=(
        Area("The airports", "every airport, heliport and seaplane base it knows, one CSV file",
             "https://ourairports.com/data/",
             covered="the file, asked once on your click: the large and medium airports with a three-letter code"),
        Area("The rest", "runways, frequencies, navigation aids, countries and regions, a file each",
             "https://ourairports.com/data/"),
    ),
    calls=(
        Call(f"GET {OURAIRPORTS_CSV}", "every airport it knows, one CSV file", "The airports",
             used=("Download… on the World Wide Web tab's Internet infrastructure table, once, on your word, as a job "
                   "the page may cancel; https on every hop, to this host alone"),
             docs="https://ourairports.com/data/"),
    ),
    verified=ROUTERS_VERIFIED,
)

GEONAMES_API = Api(
    name="GeoNames",
    maker="GeoNames (geonames.org)",
    about=("GeoNames keeps the world's places, free under CC BY 4.0, and offers them as files by kind and size. The "
           "globe asks for its file of the cities of 15,000 people or more once, on your click: each is kept as a "
           "point of the cities layer, the most people first (20,000 of them), named on the globe as it comes nearer, "
           "and routers' names are read with them (a city's name, or a city and its state as sttlwa). The request "
           "names the file alone and nothing about this machine."),
    kind="feed",
    base=GEONAMES_CITIES,
    version="cities15000.zip as served on 2026-11-22: 3.2 MB, one text file, one tab-separated row a city",
    auth="none: no account and no key (its web services need one; its files do not)",
    limits="none named for its files; asked once on your click, waited for 120 s",
    costs="",
    links=(
        Link("GeoNames' files", "https://download.geonames.org/export/dump/", "docs"),
        Link("Its licence: CC BY 4.0", "https://creativecommons.org/licenses/by/4.0/", "terms"),
    ),
    areas=(
        Area("The cities", "the cities of 15,000 people or more, one zipped text file",
             "https://download.geonames.org/export/dump/",
             covered="the file, asked once on your click: every city in it, the most people first"),
        Area("Its other files", "all its places, by country, and the smaller towns' files",
             "https://download.geonames.org/export/dump/"),
        Area("Its web services", "searches and lookups, with an account", "https://www.geonames.org/export/"),
    ),
    calls=(
        Call(f"GET {GEONAMES_CITIES}", "the cities of 15,000 people or more", "The cities",
             used=("Download… on the World Wide Web tab's Internet infrastructure table, once, on your word, as a job "
                   "the page may cancel; https on every hop, to this host alone"),
             docs="https://download.geonames.org/export/dump/"),
    ),
    verified=ROUTERS_VERIFIED,
)

# the Netstat tab's and the globe's layers' (0.7.0; the Topology Zoo's, 0.7.1)
NETSTAT = (SOCKETS, OVERPASS_API, WIKIDATA, EMODNET, TOPOLOGY_ZOO,
           OURAIRPORTS_API, GEONAMES_API)  # liminal-libs 1.73.0: what routers' names are read with

APIS = (POWERSHELL, NETSECURITY, NETCONNECTION, DEFENDER_API, WINDOWS_FIREWALL, NAMES, NPCAP, DBIP, OPENDNS, GOOGLE,
        *NETSTAT)
