# Changelog

## 0.6.0 (2026-11-16)

The World Wide Web tab (the user, 2026-11-14: "so for the firewall's both are going to get a 'world wide web view' that
shows the globe and the routes incoming all traffic, as well as monitoring port traffic stats"). The tab is liminal-libs
1.55.0's Firewall base's (`machines/world.py`): liminal-platform 0.27.0 draws it after Main and API and asks it every 2 s
while it is shown. The plugin names what it reaches (`apis.py`), since the library names no outside host:

- Watching: while the tab is shown, and for 20 s after its last ask, every TCP and UDP packet at the adapter of this
  PC's way out is read through Npcap, its headers alone, and counted by port and by network. Nothing is watched while
  nobody looks, watching ends when the plugin is detached, and no packet is kept. Npcap is installed here without
  "Restrict Npcap driver's access to Administrators only" (AdminOnly=0), so watching needs no administrator and no UAC.
  Installed for administrators only, Npcap has its NpcapHelper ask for elevation (a UAC prompt) as soon as a process
  that is no administrator lists or opens an adapter: the library reads that option first (read access alone) and a
  platform that is no administrator asks Npcap nothing, the tab saying to install Npcap again without the option or to
  run the platform as an administrator. Where watching cannot run, the tab says why and how to put it right, and never
  asks for an administrator or a password.
- Places: each public network is placed on the globe by DB-IP's IP to City Lite file, looked up on this PC, with its
  route to home; the local network's peers are summed apart, never placed. No peer's address is sent anywhere, and none
  is looked up by name.
- The file (`GEOIP_URL`): DB-IP's monthly address, https://download.db-ip.com/free/dbip-city-lite-{year}-{month}.mmdb.gz,
  last month's asked while this month's is not out yet. It is downloaded only from the tab's Install the GeoIP file…, on
  your word: the first confirmation says what comes from where and shows its licence (`GEOIP_LICENCE`: CC BY 4.0 in plain
  words, and the download's size, about 60 MB, 121 MB unpacked), and the second one accepts the licence. The platform
  runs the install as a job (the base's `JOB_HOOKS`, kept), its progress followed in the plugin's panel; it stops by
  itself after 30 minutes, the download included, and when the plugin is detached, and every hop is https from
  download.db-ip.com alone. A month's file is never downloaded twice: Update… is offered once the file installed is an
  earlier month's, and fetches this month's in its place. The file is open while the tab is watched and let go once
  watching stops. Its places are credited "IP Geolocation by DB-IP", linked to db-ip.com, on the globe and with the
  Places table (`ATTRIBUTION`). The second confirmation needs liminal-platform 0.28.0 or newer, which carries the licence's
  refusal back to the page (0.27.0 shows it in the job's panel instead).
- Home: the place you set in the plugin's settings, Home on the globe (LIMINAL_HOME_PLACE, "lat,lon[,label]", kept
  through the platform's login), else this network's public address placed by the file. That address is asked of
  OpenDNS's name servers, then Google's (`PUBLIC_DNS`: the hw-stats plugin's, asked with nslookup, windowless), once
  while the plugin is attached and only once a file is installed. Only that question goes out, its name absolute
  (`myip.opendns.com.`: none of this PC's DNS search suffixes goes with it); Windows' nslookup first asks the server
  for its own name (the PTR record of the server's own address).
- The busiest four ports here are charted (bytes a second in and out, the last ten minutes), and the busiest ports here,
  the places and the ports elsewhere are tabled.

Four more API cards (plugin API 2.2): Npcap (every libpcap call the library's capture makes on Windows, and before
them the AdminOnly option it reads; its install options; its licence: five computers, and this PC's copy counts though
it came with Wireshark, since Liminal uses it directly), DB-IP IP to City Lite (the download, the MMDB file and its
reader, the credit; the other Lite files, the full databases and the lookup API under "more of the API"), and OpenDNS's
and Google's name servers (each question as it is sent). `api_facts` says what the tab knows once it has been asked:
whether it watches and at which adapter, the packets read, why it cannot watch, and the GeoIP file it places with and
whether it is open now. Asking for the facts makes nothing and starts nothing: the tab's view is read through the
base's `world_view(make=False)`.

Tests (`tests/test_world.py`): the tab asked through the plugin as the platform asks it, with a stand-in capture,
download and name servers and a tiny GeoIP file written in the test; watching started by the ask and stopped by the
timeout and by the detach; the file downloaded only once its licence is accepted, asked as the platform's job route
asks it (refused before its first line, then its progress in its log), and last month's while this month's is not out;
Npcap installed for administrators only (a stand-in registry): asked nothing by a platform that is no administrator,
through the plugin's own view and the library's default capture, tried again 15 s later still asking it nothing, and
opened by a platform run as an administrator; home from the login, else from the name servers; the cards checked
against what the plugin and the library reach. The machine the tests run on never shows through (`tests/conftest.py`:
not inside WSL, no init known), so the suite reads alike on Windows and run inside a WSL distribution. Needs
liminal-libs>=1.55.0 with its geo extra (maxminddb).

## 0.5.2 (2026-11-15)

Drawn under the platform's OS plugins section, in the list on the left (the user: "then OS plugins" (the WSL distributions, the admin and the firewall plugins, as chosen)): `SECTION = "os"`, liminal-libs 1.51.0's machine-plugin attribute. liminal-platform 0.26.0 draws it; an older platform keeps the plugin under Machine plugins. Nothing else changes.

## 0.5.1 (2026-11-14)

Liminal's own ports are the four apps' alone (liminal-libs 1.52.0; the user, 2026-11-14: "i only want ports for liminal-login ; liminal-platform ; liminal-charts ; liminal-integrator"; "never provide ports for anything else"): the integrator's login at 8796 is gone, a login an app inherits being an object in that app, at its port. The exposure check asks about those four.

## 0.5.0 (2026-11-11)

Its API on its page, plugin API 2.2 (the user: "each plugin should reflect the the API its attached to, and present
links that provide documentation, the plugin interface should more or less contain what it already has, BUT, it should
also expose more of what the API is about"). Six cards (`apis.py`), each with Microsoft Learn's pages, every part of the
API said covered or not, and every call the plugin makes beside the API's other notable ones:
- Windows PowerShell 5.1: the command line it runs the read and every change with, JSON, elevation (Start-Process
  -Verb RunAs, UAC), IsUserAnAdmin, the read's own administrator check.
- NetSecurity: the rules and their port, program, service and address filters read in bulk, the profiles; Set-, New-
  and Remove-NetFirewallRule, Set-NetFirewallProfile; the module's other parts (global settings, the Hyper-V firewall,
  dynamic keywords, IPsec, Group Policy) under "more of the API".
- NetConnection: the networks and their categories.
- Microsoft Defender Antivirus: Get-MpComputerStatus, beside its preferences, signatures, scans and threats.
- Windows Firewall and its COM policy (INetFwPolicy2.Rules: the remote addresses without an administrator), netsh
  advfirewall, its log, the Hyper-V firewall, the Windows Filtering Platform.
- Windows' names for a rule: Get-Service, Get-AppxPackage, FileVersionInfo.

`api_facts()` says what the last read found, asking nothing: when and how long, the rules, the profiles, the rights it
read with, the networks, Defender's state, and why the last read failed. Tests: the cards name every cmdlet the plugin's
scripts send over the read and every change (a stand-in powershell.exe), the read's COM and .NET calls and the library's
PowerShell calls; a link check runs with LIMINAL_VENDOR_PAGES=1. Needs liminal-libs>=1.49.0.

## 0.4.0 (2026-11-09)

A heading for each service and each application (the user: "for the windows and linux firewall, lets have the same
system and application and other, but lets group by application under apps or system, try best to organize under system
and applications. Like system has 'core networking' or WSD or UPnP or RA Server or Remote Assistance or network
discovery or ... applications has like starcraft or edge"; "try to group the system by 'services'"; "also rules that are
turned off should be shown as well"):

- System is grouped again by service, the service being Windows' own rule group: Core Networking, Network Discovery,
  Remote Assistance, File and Printer Sharing, Remote Desktop, mDNS... WSD, UPnP and RA Server stay in each rule's name
  under its service, as in "Network Discovery (WSD-In)". A rule whose group is not words (empty, a name Windows could
  not read, a bare identifier) is named by its Windows service (DNS Client), else by its program's description or file
  name; the System process' rules with no group as "System process".
- Windows' own apps are known by their publisher, Microsoft Windows, and named as their rules name them, else together
  as "Windows' own apps". So the rules an earlier version of one of Windows' parts left behind (Windows can no longer
  read their names) are under System with the name of the part's current version, Windows Feature Experience Pack,
  instead of one heading each under Application; so are the programs in Windows' own apps' folders, where their file
  names were the headings before. Windows Web Experience Pack (the widgets), from the same publisher, is under System
  too.
- Application is grouped again by application: Liminal's rules as Liminal; a rule's own group when it is words
  (Microsoft Edge, Google Chrome, Copilot, Microsoft Teams...), and a rule with no group (as Windows' prompt makes them)
  by the group its program's other rules carry, or the other programs' in its folder; a Microsoft Store app's programs
  by the name its app's own rules carry, else the name its programs' rules carry, else the product name most of them
  carry; any other program by the folder it is installed in (under Program Files, Program Files (x86), ProgramData or
  your AppData), one folder deeper in a vendor's folder holding several products (Microsoft, Google, JetBrains, Dassault
  Systemes, Dell, VMware, Common Files and the like), an application's own folder in a launcher's library (Steam's, GOG
  Galaxy's, Ubisoft's, JetBrains Toolbox's, the Xbox app's). A program in no install folder, or in a temporary folder,
  is named by the group the rules for the programs in its folder carry, else by the rules' own names, else by its
  product name, else by its file name. Each name is decided for the app or the folder, not for each program file, so
  StarCraft II's rules are one heading across its versions, Steam's two programs one heading, and Microsoft Edge apart
  from Microsoft Edge WebView2 Runtime. Where a rule writes its program's path in lowercase, the name is spelled as the
  folder is on disk when the program is there, else as the rules' own names spell it (StarCraft II).
- Windows' own rule groups count as System even when the program is under Program Files: Windows Media Player's rules
  move from Application to System. A rule group is Windows' own when its name comes from Windows' own files: a file
  Windows finds in its own folder (FirewallAPI.dll), a file in Windows' folder, or one in Windows' own components under
  Program Files (Windows Media Player); never from a program's own install folder. The Store app Media Player, a
  Microsoft Store app whose rules' group also reads Windows Media Player, stays under Application: a Windows Media Player
  heading shows under both.
- Other and your labels stay single lists, and Move to is as it was. Each heading lists up to 100 rules (Find narrows a
  longer one), where a whole group listed only its first 100 before.
- The rules turned off are shown: Inbound allowed, Inbound blocked and Outbound list them too, after the rules turned on
  in each heading, and the page shows them dimmed. Each choice says how many of its rules are turned off; Turned off
  stays.
- The read also gets each Windows service's display name, and for each program on disk its product name, its description
  and its path as spelled there: about a tenth of a second more, no rights needed, nothing written. A program is looked
  up only on this PC's own fixed drives, never on a network drive or a removable one, and never a file kept in the cloud
  only (OneDrive's: reading it would fetch it). A read made before still works.

Needs liminal-libs>=1.41.0, and liminal-platform 0.16.0 to draw the headings and dim the rules turned off.

## 0.3.0 (2026-11-08)

The rules in groups (the user: "for both firewalls, i need to have groups, like system or application and then
unassociated rules not tied to a specific application or system process can be in an other, i can create labels, like
system or application, as well and move the rules in to that"; "just use basic expansion like a (+) to open and close
labels"). Every rule is sorted into System (Windows' own: a Windows service's, the System process', a program's in
Windows' folder, Windows' own app packages and rule groups), Application (another program's, a Microsoft Store app's,
Liminal's) or Other (tied to no program, service or app: ports and addresses alone), each saying why. The user's labels
(New label…, Rename…, Remove…) and the rules moved into them or into another group are the library's (liminal-libs
1.35.0 rulegroups), kept through the platform's login as FIREWALL_WINDOWS_GROUPS, never in the firewall: moving a rule
changes nothing in it. The read gets each rule's service, its owner and its app's package (signed as Windows' own or
not); Find looks in the service and the app too; the Rules table lists each group's first 100 rules. Needs
liminal-libs>=1.35.0 and liminal-platform 0.11.0 to draw the groups.

## 0.2.2 (2026-11-08)

Its icon is the one the user picked ("this one for windows firewall"): a brick wall in three dimensions with the globe
behind it, drawn in the library's line (liminal-libs 1.34.0's `wallglobe`). Needs liminal-libs>=1.34.0.

## 0.2.1 (2026-11-08)

Its icon is the four panes of Windows, each a wall of bricks, drawn in the library's line (liminal-libs 1.33.0's `windowsbricks`; the user: "for the firewalls, lets use an icon of TUX penguin or Windows and then convert it to a patchwork of bricks"). Needs liminal-libs>=1.33.0.

## 0.2.0 (2026-11-08)

Read whole, queried and changed (the user: "windows firewall, i need it to be able to read the configuration, and make
changes"; "basically the firewall plugin is an interface for windows networking / defender / firewall, and will let me
make queries and alter the firewall configurations"):

- The whole configuration in one PowerShell read (read.ps1): the three profiles, the networks and their category, every
  rule with its ports and program (the NetSecurity cmdlets, their filters read in bulk) and its remote addresses (the
  firewall's COM policy, matched by name, direction, action, program, protocol, ports, profiles and state; an
  administrator reads every rule's own), and Microsoft Defender's state. About 4 s for 645 rules, kept a minute, read on
  a thread when attached and again after each change, so the page's status asks it nothing slow.
- Valid whenever it can be read: what the base found wrong (a profile off, the framework's rules missing) is said as a
  problem; no Liminal rules is no fault.
- The page: facts (each profile, the network in use, the defaults, notifications, Defender, the counts), a Networks
  table (Make private / public), a Profiles table (Change…), a Rules table: presets (inbound allowed, inbound blocked,
  outbound, Liminal's, turned off, all), Find (words, a port, a direction, an action; the rules naming the port first),
  at most 100 listed, Turn on / off on each, Remove on those not Windows' own; Add a rule…, Read again.
- Changes (set_rule, remove_rule, make_rule, set_profile, set_network), each confirmed: run at once by an administrator,
  through UAC otherwise; a profile off or everything let in by default refused until accepted a second time (this PC
  may be a router's DMZ host); a rule of Windows' own turned off, never removed.
- The command line: status, rules, find, profiles, networks, set-rule, remove-rule, add-rule, set-profile,
  set-network, and the setup's commands as before.

## 0.1.0 (2026-11-07)

The first release: Windows Firewall for the platform, on the library's Firewall base
(liminal-libs 1.20.1).
