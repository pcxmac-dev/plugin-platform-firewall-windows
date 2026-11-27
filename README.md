# plugin-platform-firewall-windows

Windows Firewall for Liminal: Windows Defender Firewall, the networks and Microsoft Defender on this PC, every rule and
profile read, queried and changed on your word. Since 0.7.0 its Netstat tab lists the listening ports and the open
connections with the program behind each, and the hosts each program talks with are recorded on this PC; since 0.8.0
its Networks tab routes and names the container plugins' segments.

**0.11.0:** the World Wide Web tab (the globe, the traffic watched, the GeoIP files, the internet's infrastructure and
the satellites) is a plugin of its own, plugin-platform-worldwideweb (Monday list item 33), and nothing of it is left
here: its cards, data sets, hooks and tests went with it (the user, 2026-11-26: "Delete now"). That plugin asks this
one through the platform for what only a firewall knows (below). Floor: liminal-libs 1.105.0.

The user's words: "the platform is the interface for the software/hardware which facilitates the liminal framework";
"i also need a windows and linux firewall plugin for the platform" (2026-11-07); "windows firewall, i need it to be
able to read the configuration, and make changes"; "basically the firewall plugin is an interface for windows
networking / defender / firewall, and will let me make queries and alter the firewall configurations" (2026-11-08);
"for both firewalls, i need to have groups, like system or application and then unassociated rules not tied to a
specific application or system process can be in an other, i can create labels, like system or application, as well
and move the rules in to that" (2026-11-08); "lets group by application under apps or system, try best to organize
under system and applications. Like system has 'core networking' or WSD or UPnP or RA Server or Remote Assistance or
network discovery or ... applications has like starcraft or edge"; "try to group the system by 'services'"; "also
rules that are turned off should be shown as well" (2026-11-09); "so for the firewall's both are going to get a 'world
wide web view' that shows the globe and the routes incoming all traffic, as well as monitoring port traffic stats"
(2026-11-14); "the firewall app should have a 'netstat' like interface for looking at active ports and what apps they
are attached to, and the hosts that they connect to across the lan or wan. the firewall app should also have a globe
that can be zoomed and rotated and geoip'd hosts are databased for the apps they talk to, the time they are connected to
*this *computer"; "the globe-firewall should allow filtering, so i can view apps connected to hosts all across the
globe, or ports talking to all hosts. The globe should have the same kind of geography associated with the exchanges
globe, but the firewall globe should instead of exchanges, have all the backbones,ibones, major internet
infrastructure, (as many as possible) datacenter locations." (2026-11-16).

## What it does

A machine plugin of the platform (`liminal_libs.machines.firewall.Firewall`, plugin API 2.2) driving Windows Defender
Firewall through PowerShell (the library's `machines.windows.PowerShell`: a script given as `-EncodedCommand`,
windowless).

**Reading** needs no rights. One PowerShell call (`read.ps1`) reads:

- the three profiles (Domain, Private, Public): on or off, the default for inbound and outbound traffic,
  notifications;
- the networks this PC is on and their category (the profile that applies to each);
- every rule, with its ports and program (the NetSecurity cmdlets, their filters read in bulk) and its remote
  addresses. Those come from the firewall's COM policy, matched to each rule, because the address filters need an
  administrator: an administrator reads every rule's own, and a rule whose addresses could not be matched says "not
  read";
- what each rule is tied to: its service, its app's package, its owner;
- what names them: each Windows service's display name, and for each program the rules name that is on this PC's own
  fixed drives, its product name, its description and its path as spelled on disk (a rule may write it in lowercase).
  No program on a network drive or a removable one is looked up, nor a file kept in the cloud only (reading it would
  fetch it);
- Microsoft Defender's antivirus and real-time protection.

It takes about 4 to 6 s for some 650 rules, is kept for a minute, and is read on a thread when the plugin is attached
and again after each change, so the platform's page waits on nothing.

**The page** shows:

- facts: each profile, the network in use, the defaults, notifications, Defender, the rule counts;
- **Networks**, each made private or public;
- **Profiles**, each changed;
- **Rules**, chosen by a preset (inbound allowed, inbound blocked, outbound, Liminal's, turned off, all) or found by
  words, a port, a direction and an action. The rules turned off are listed too, after those turned on, dimmed; each
  preset says how many of its rules are turned off. For a port, the rules naming it come first. Each rule can be
  turned on or off, and removed when it is not one of Windows' own (those are turned off instead). Add a rule makes one
  in the group `Liminal`.

**The groups.** Every rule is in one of three groups, each opened with (+) and closed with (−):

- **System**, Windows' own, with a heading for each service: Windows' own rule group (Core Networking, Network
  Discovery, Remote Assistance, File and Printer Sharing, Remote Desktop, mDNS...), so "Network Discovery (WSD-In)" and
  "Network Discovery (UPnP-In)" are under Network Discovery; else its Windows service (DNS Client), its program's
  description or file name. Windows' own apps, known by their publisher (Microsoft Windows), are named as their rules
  name them, an earlier version's rules too (Windows Feature Experience Pack), else together as Windows' own apps. A
  rule group is Windows' own when its name comes from Windows' own files, even for a program under Program Files
  (Windows Media Player's rules).
- **Application**, with a heading for each application: Liminal's rules as Liminal; a rule's own group (Microsoft Edge,
  Google Chrome, Copilot, Microsoft Teams...), and a rule with no group by the group its program's other rules carry; a
  Microsoft Store app's programs by the name its app's rules carry; any other program by the folder it is installed in,
  one deeper in a vendor's folder holding several products (Microsoft, Google, JetBrains, Dell, VMware, Common
  Files...), an application's own folder in a launcher's library (Steam, GOG Galaxy, Ubisoft, JetBrains Toolbox, Xbox);
  a program in no install folder by the name its folder's rules carry. Each name is decided for the app or the folder,
  not for each program file, so a game's rules are one heading across its versions, and Microsoft Edge is apart from
  Microsoft Edge WebView2 Runtime. The Store app Media Player is a Microsoft Store app: it stays here, though its rules'
  group reads Windows Media Player as Windows' own player's does.
- **Other**: rules tied to no program, service or app (ports and addresses alone), one list.

You can make labels of your own (New label…, Rename…, Remove…) and move rules into them, or into another group (Move
to). Your labels and moves are kept through the platform's login, never in the firewall: moving a rule changes nothing
in it. Each heading lists up to 100 rules, and Find narrows a longer one.

**Changes** are each asked for in a form and confirmed. They run at once when the platform runs as an administrator;
otherwise Windows asks for an administrator's permission (UAC). Turning a profile off, or letting everything in by
default, is refused until you accept it a second time: this PC may be a router's DMZ host, and then every program
listening here could be reached from the internet. Since 0.7.3 they are asked only from the page: `set_rule`,
`remove_rule`, `make_rule`, `set_profile`, `set_network` and the base's `allow` and `remove` are its `PAGE_ONLY_HOOKS`,
so another plugin's ask of one is refused, and the platform asks its login whether you are at the page before it asks
one over HTTP. Before, any program on this PC could ask a change itself, its second confirmation included.

**The setup** works as before: `enable` (every profile on), `exposure` (no rule lets another machine reach the
framework's pages, 8765, 8775, 8785, 8795; a finding, never a change) and `rules` (the ports the framework's services
need, opened as `Liminal: <name>`). `allow`/`remove` make and remove Liminal's own rules.

## What the World Wide Web plugin asks of it

plugin-platform-worldwideweb draws the globe; this plugin answers it through the platform, with the library's Firewall
base's services (liminal-libs 1.105.0), only another plugin asking the changes:

- `netstat_seen`: the socket tables' last reading, the Netstat tab's own (one reading serves both for 2.5 s).
- `hosts_found` and `hosts_routes`: the hosts recorded in the hosts database, and the routes traced to them that it
  keeps; `hosts_keep_route` keeps a route traced, `hosts_keep_places` and `hosts_clear_places` the places looked up in
  that plugin's GeoIP file (the Netstat tab's place column; with that plugin not attached the note says why).
- `rules_covering`, in Windows' own terms: the rules of the last read covering a port (named, in a range holding it,
  or every port), of its protocol or of any, with each rule's id, program, service and group, those naming the port
  first; from the read kept, waiting on none.

Off Windows each refuses in words, reading nothing.

## The Netstat tab

The user's words (2026-11-16): "the firewall app should have a 'netstat' like interface for looking at active ports and
what apps they are attached to, and the hosts that they connect to across the lan or wan. the firewall app should also
have a globe that can be zoomed and rotated and geoip'd hosts are databased for the apps they talk to, the time they
are connected to *this *computer".

Since 0.7.0 the page has a **Netstat** tab: the library's Firewall base's (liminal-libs 1.65.0,
`sockets.py` and `machines/netstat.py`), asked every 3 s while it is shown.

- **Connections**: every open connection, with the program that holds it (its name, pid, and the service where one
  hosts it), the remote host and port, whether that host is this PC's, the local network's or the internet's, its name
  (from the system's own hosts file) or its place (from the GeoIP file on this PC), its state, since when, and how long
  it has been up (Windows says when each socket was made). Filtered on the page by direction, by where the host is, and
  by words (an address, a port, a program, a place).
- **Listening ports**: each protocol, port and program listening here (TCP listening, UDP bound), reached from every
  address, from this PC only, or from the addresses it is bound to, Liminal's own four pages named. A port that a
  program inside a WSL distribution listens on shows as WSL's relay, wslrelay.exe, listening on this PC's own address
  (Liminal's Linux apps' pages among them): which program holds it is for the Linux firewall plugin of the platform
  inside that distribution to say, since a platform on Windows never reaches into one.
- **How it is read**: from Windows' own socket tables (IP Helper's TCP and UDP tables in their OWNER_MODULE class, one
  snapshot of the processes, the list of services), documented calls alone: no packet captured, no administrator and
  no password asked, no process started, no window, no name looked up, nothing sent anywhere. What cannot be read is
  said in its row: where a service's or Windows' own process is on disk (an administrator's to read), which driver or
  service the System process (pid 4) holds a socket for (the table does not say), a connection whose program has ended
  (it is only waiting to close). Windows lists no remote host for a UDP socket, so UDP shows as ports; a connection
  shorter than the gap between two readings can be missed; and a program run by an interpreter shows as the
  interpreter (Liminal's own four apps show as python.exe, or as pythonw.exe where they were started at logon or at
  boot).
- One reading of the tables serves the tab and the World Wide Web plugin's asks for 2.5 s.

Off Windows the plugin is not for the machine at all: its status says so, its tabs say the same, and every other ask
of theirs (the recording, Forget…, and each service the World Wide Web plugin asks) is refused in words before it
reads, records, keeps or removes anything: the hosts database there is that system's own firewall plugin's.

## The hosts database

- **What it keeps**: for each program and remote host (with the protocol, the service's port and the direction): the
  program's path and service, whether the host is on the local network or the internet, its name where the system
  knows one, when it was first and last seen, how long it was connected to this PC (counted while Windows was awake: a
  night asleep is no time connected), how many connections, and the host's place once the GeoIP file on this PC gives
  one. This PC's own connections to itself are never kept, and a local host is never placed on the globe.
- **Where**: one small SQLite file on this PC's own disk, the data folder's `hosts/hosts.db`; at most 50,000 rows, the
  hosts longest unseen pruned first (about 13 MB with ordinary values). A data folder on another system's drive is that
  system's: nothing is kept there from here. Nothing in it is sent anywhere.
- **When it records**: only while this plugin's Netstat tab or the World Wide Web plugin's tab is shown (the default), or all the time
  the platform runs (a reading every 5 s), as you choose with **Recording…** or the plugin's setting **Recording
  hosts** (`LIMINAL_HOSTS_RECORDING`: `shown` or `always`), kept through the platform's login. **Forget…** removes every
  row, asked twice.

## From the command line

```
python -m plugin_platform_firewall_windows status
python -m plugin_platform_firewall_windows rules [in-allow|in-block|out|liminal|off|all]
python -m plugin_platform_firewall_windows find remote desktop --in
python -m plugin_platform_firewall_windows find --port 3389
python -m plugin_platform_firewall_windows profiles
python -m plugin_platform_firewall_windows networks
python -m plugin_platform_firewall_windows set-rule RemoteDesktop-UserMode-In-TCP off
python -m plugin_platform_firewall_windows remove-rule "{RULE-ID}"
python -m plugin_platform_firewall_windows add-rule "Liminal path check 8795" --ports 8795 --profiles Public
python -m plugin_platform_firewall_windows set-profile Public --on --inbound block --notify on
python -m plugin_platform_firewall_windows set-network 11 private
python -m plugin_platform_firewall_windows setup            # everything; or one step: setup exposure
python -m plugin_platform_firewall_windows exposure
python -m plugin_platform_firewall_windows run -- Get-NetFirewallProfile -Name Public   # as you: never through UAC
```

A rule's id (in brackets in `rules` and `find`) is what `set-rule` and `remove-rule` name. A change needs an
administrator: run as one, or Windows asks (UAC). `set-profile` refuses `--off` or `--inbound allow` without
`--accept-risk`. `run` runs a PowerShell command line as you, never through UAC: one Windows denies is said, not
asked again. It is the command line's alone (and `liminal-platform machine firewall-windows run -- COMMAND`'s): no
route of the platform's asks it since liminal-platform 0.34.1.

## Its API

The user's words (2026-11-11): "each plugin should reflect the the API its attached to, and present links that provide
documentation, the plugin interface should more or less contain what it already has, BUT, it should also expose more of
what the API is about". Since 0.5.0 (plugin API 2.2) the plugin declares what it attaches to (`apis.py`), and the
platform's page draws each card: what the API is, its links, every part of it (those the plugin uses first, the rest
under "more of the API": IPsec, the Hyper-V firewall, dynamic keywords, Group Policy...) and every call it makes, with
the API's other notable calls beside them.

- **Windows PowerShell 5.1** and its elevation: [about_PowerShell_exe](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1),
  [Start-Process](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process?view=powershell-5.1),
  [User Account Control](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/).
- **NetSecurity**: [the module](https://learn.microsoft.com/en-us/powershell/module/netsecurity/?view=windowsserver2025-ps),
  [Manage Windows Firewall with the command line](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-with-command-line).
- **NetConnection**: [Get-NetConnectionProfile](https://learn.microsoft.com/en-us/powershell/module/netconnection/get-netconnectionprofile?view=windowsserver2025-ps),
  [Set-NetConnectionProfile](https://learn.microsoft.com/en-us/powershell/module/netconnection/set-netconnectionprofile?view=windowsserver2025-ps).
- **Microsoft Defender Antivirus**: [Get-MpComputerStatus](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus?view=windowsserver2025-ps),
  [the Defender module](https://learn.microsoft.com/en-us/powershell/module/defender/?view=windowsserver2025-ps).
- **Windows Firewall** and its COM policy: [the overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/),
  [INetFwPolicy2](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2) (the remote addresses
  without an administrator), [netsh advfirewall](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-advfirewall).
- **Windows' names** for a rule's service, app and program: Get-Service, [Get-AppxPackage](https://learn.microsoft.com/en-us/powershell/module/appx/get-appxpackage?view=windowsserver2025-ps),
  [FileVersionInfo](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo.getversioninfo?view=netframework-4.8.1).

Since 0.7.0, one more for the Netstat tab, and since 0.8.0 two for the services' networks:

- **Windows' socket tables and their owners (IP Helper)**:
  [IP Helper](https://learn.microsoft.com/en-us/windows/win32/iphlp/ip-helper-start-page),
  [GetExtendedTcpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable),
  [its rows](https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_module).
  Its card names every call the library's Windows reading makes (its `sockets.WINDOWS_CALLS`), and what it leaves:
  the per-connection statistics an administrator must switch on, PowerShell's NetTCPIP cmdlets.
- **NetTCPIP** and **netsh** (port proxy and excluded ports): the routes and port proxies of the containers' segments.

0.11.0: the World Wide Web tab's cards (Npcap, DB-IP, OpenDNS, Google's name servers and the globe's data sets'
sources) are plugin-platform-worldwideweb's, word for word as they were here.

`api_facts()` says what the last read found, asking nothing: when it was and how long it took, the rules and the
profiles, whether it ran as an administrator, the networks and their categories, Defender's state, and why the last
read failed, if it did. Since 0.7.0, once its Netstat view is made, it also says the socket tables' last reading
(when, how many sockets, how long it took), how the hosts are recorded and what the hosts database holds.

The six Windows cards' addresses were read on 2026-11-11, the socket tables' on 2026-11-18. The test
`test_the_cards_pages_answer` asks each address again when `LIMINAL_VENDOR_PAGES=1` is set (it is skipped otherwise).
