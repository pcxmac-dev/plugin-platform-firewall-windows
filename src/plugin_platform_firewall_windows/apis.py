"""What Windows Firewall attaches to (plugin API 2.2, liminal_libs.sources.apis; the user, 2026-11-11: "each plugin
should reflect the the API its attached to, and present links that provide documentation ... it should also expose more
of what the API is about"): Windows PowerShell and its elevation (UAC), the NetSecurity cmdlets, the NetConnection
cmdlets, Microsoft Defender's, Windows Firewall itself (its documentation and its COM policy), and what names a rule's
service, app and program, each as Microsoft Learn describes it. Every address was read on 2026-11-11 (`VERIFIED`).
The facts (what the plugin kept of the last read) are said by the plugin's api_facts.

The Netstat tab and the hosts database (0.7.0) attach to Windows' own socket tables and their owners (IP Helper, the
processes, the services), which the library's sockets.read_windows asks with documented calls alone (SOCKETS; their
pages read on 2026-11-18, `VERIFIED_NETSTAT`); services' networks (0.8.0) to NetTCPIP and netsh.

0.11.0 (liminal-libs 1.105.0; the user, 2026-11-26: "Delete now"): the World Wide Web tab's cards and data (Npcap,
DB-IP and the GeoIP sources, OpenDNS's and Google's name servers, the globe's data sets and their sources, the sgp4
package, IANA's RDAP bootstrap files) are plugin-platform-worldwideweb's, moved there word for word with the tab; none
of them is named here any more."""
from __future__ import annotations

from liminal_libs.sources.apis import Api, Area, Call, Link

VERIFIED = "2026-11-11"
# the name servers' cards: their pages as the hw-stats plugin read them (its OPENDNS and GOOGLE cards), OpenDNS's setup
# guide and Google Public DNS's questions read again on 2026-11-15
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

# -- the Netstat tab and the hosts database (0.7.0) --------------------------------------------------------------------
# The Netstat tab reads Windows' own socket tables through the library's sockets.read_windows (every call documented:
# its WINDOWS_CALLS are the SOCKETS card's), and the hosts database is fed from the same readings, kept on this PC
# alone. Their pages were read on 2026-11-18 (`VERIFIED_NETSTAT`).
VERIFIED_NETSTAT = "2026-11-18"
API = WIN32 + "api/"
COMMANDS = "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/"
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

# 0.8.0: services' networks (network.py): the routes into WSL, the addresses and routes read, the port proxies
NETSH = "https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/"
NETTCPIP = Api(
    name="NetTCPIP (PowerShell)",
    maker="Microsoft",
    about=("This PC's IP addresses and routes. The plugin reads them with no rights (what a service's segment must not "
           "meet, the WSL adapter a route goes through, your network's address), and makes one route per service "
           "segment into WSL through the VM's address, always in the active store, so a restart of Windows takes it "
           "away; the next Start's plan, or Re-point…, makes it again."),
    kind="powershell",
    base="the NetTCPIP module (Windows PowerShell 5.1)",
    version="the NetTCPIP module of Windows 11 and Windows Server 2025",
    auth="reading: no rights needed; a route made or taken away: an administrator (UAC), inside a plan you approved",
    limits="routes in the active store alone: never the persistent store; never Set-NetIPInterface -Forwarding",
    costs="",
    links=(
        Link("Get-NetIPAddress", MODULE + "nettcpip/get-netipaddress" + WS, "reference"),
        Link("Get-NetRoute", MODULE + "nettcpip/get-netroute" + WS, "reference"),
        Link("New-NetRoute", MODULE + "nettcpip/new-netroute" + WS, "reference"),
        Link("Remove-NetRoute", MODULE + "nettcpip/remove-netroute" + WS, "reference"),
    ),
    areas=(
        Area("Addresses", "each interface's IPv4 addresses and prefix lengths", MODULE + "nettcpip/get-netipaddress" + WS,
             covered="what a segment must not meet; the WSL adapter, found by the VM's address; your network's address"),
        Area("Routes", "the route table, its stores", MODULE + "nettcpip/get-netroute" + WS,
             covered="read, and one route per service segment into WSL made and taken away"),
        Area("Forwarding", "an interface's forwarding (Set-NetIPInterface -Forwarding): never set here",
             MODULE + "nettcpip/set-netipinterface" + WS),
    ),
    calls=(
        Call("Get-NetIPAddress -AddressFamily IPv4", "this PC's IPv4 addresses", "Addresses", used="the network read",
             docs=MODULE + "nettcpip/get-netipaddress" + WS),
        Call("Get-NetRoute -AddressFamily IPv4", "the route table", "Routes", used="the network read, and before a route",
             docs=MODULE + "nettcpip/get-netroute" + WS),
        Call("New-NetRoute -DestinationPrefix <segment> -InterfaceIndex <n> -NextHop <the VM> -PolicyStore ActiveStore",
             "a route to a service's segment through WSL's VM", "Routes", used="an approved plan's work, Re-point…",
             docs=MODULE + "nettcpip/new-netroute" + WS, writes=True),
        Call("Remove-NetRoute -Confirm:$false", "a segment's route taken away (the active store's)", "Routes",
             used="Remove…, Withdraw…, a leftover's Remove…", docs=MODULE + "nettcpip/remove-netroute" + WS, writes=True),
    ),
    verified=VERIFIED,
)

NETSH_API = Api(
    name="netsh (port proxy and excluded ports)",
    maker="Microsoft",
    about=("netsh's interface portproxy: one TCP proxy per port a service opens to your network, listening on this PC's "
           "address there alone (never 0.0.0.0) and connecting to the part's reserved address through the route "
           "(decision 2 b, b1), carried by the IP Helper service; and the TCP port ranges Windows keeps for itself, "
           "which no service publishes in."),
    kind="cli",
    base="netsh.exe",
    version="Windows 11",
    auth="reading: no rights needed; a proxy added or deleted: an administrator (UAC), inside a plan you approved",
    limits="TCP alone; never portproxy reset (it removes every proxy, yours too)",
    costs="",
    links=(
        Link("netsh interface portproxy", NETSH + "netsh-interface-portproxy", "reference"),
        Link("netsh interface", NETSH + "netsh-interface", "reference"),
    ),
    areas=(
        Area("Port proxies", "v4tov4 proxies: listen address and port, connect address and port",
             NETSH + "netsh-interface-portproxy", covered="read; one per opened port added and deleted"),
        Area("Excluded port ranges", "the ports Windows and Hyper-V keep for themselves", NETSH + "netsh-interface",
             covered="read for the container plugins (excluded_ports)"),
        Area("Other proxies", "v4tov6, v6tov4 and v6tov6: never made here", NETSH + "netsh-interface-portproxy"),
    ),
    calls=(
        Call("netsh interface portproxy show v4tov4", "the port proxies", "Port proxies", used="the network read",
             docs=NETSH + "netsh-interface-portproxy"),
        Call("netsh interface portproxy add v4tov4 listenaddress=<your network's> listenport=<p> connectaddress=<part> "
             "connectport=<p>", "a port opened to your network", "Port proxies", used="Expose…",
             docs=NETSH + "netsh-interface-portproxy", writes=True),
        Call("netsh interface portproxy delete v4tov4 listenaddress=<a> listenport=<p>", "that port closed",
             "Port proxies", used="Conceal…, Remove…, Withdraw…", docs=NETSH + "netsh-interface-portproxy",
             writes=True),
        Call("netsh interface ipv4 show excludedportrange protocol=tcp", "the excluded port ranges",
             "Excluded port ranges", used="excluded_ports", docs=NETSH + "netsh-interface"),
    ),
    verified=VERIFIED,
)

NETSTAT = (SOCKETS,)  # 0.11.0: the Netstat tab's alone; the globe's sources are plugin-platform-worldwideweb's

APIS = (POWERSHELL, NETSECURITY, NETCONNECTION, DEFENDER_API, WINDOWS_FIREWALL, NAMES, *NETSTAT, NETTCPIP, NETSH_API)
