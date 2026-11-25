# plugin-platform-firewall-windows

Windows Firewall for Liminal: Windows Defender Firewall, the networks and Microsoft Defender on this PC, every rule and
profile read, queried and changed on your word; and, on its World Wide Web tab, the traffic coming in and going out on a
globe, with the ports' traffic. Since 0.7.0 its Netstat tab lists the listening ports and the open connections with the
program behind each, the hosts each program talks with are recorded on this PC, and the globe shows them, filtered,
over the internet's infrastructure.

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

## The World Wide Web tab

Since 0.6.0 the plugin's page has a tab after Main and its API tabs, **World Wide Web**: the library's Firewall base's
tab (liminal-libs 1.55.0, `machines/world.py`), which liminal-platform 0.27.0 asks every 2 s while it is shown. The
plugin names what it reaches (`apis.py`); the library names no outside host.

- **Watching runs only while you look.** While the tab is shown, and for 20 s after its last ask, every TCP and UDP
  packet at the adapter of this PC's way out is read through [Npcap](https://npcap.com/), its headers alone, and
  counted by port and by network. Watching stops by itself after that, and when the plugin is detached; no packet is
  kept, only counts, in memory. Npcap is installed on this PC without "Restrict Npcap driver's access to Administrators
  only" (AdminOnly=0), so watching needs no administrator and no UAC. Installed for administrators only, Npcap has its
  NpcapHelper ask for elevation (a UAC prompt) as soon as a process that is no administrator lists or opens an
  adapter, so the library reads that option from the registry first (read access alone) and a platform that is no
  administrator asks Npcap nothing: the tab says to install Npcap again with the option unticked, or to run the
  platform as an administrator. Where watching cannot run, the tab says why and how to put it right, tries again 15 s
  later at the soonest, and never asks for an administrator or a password.
- **The globe** places each public network (an IPv4 /24, an IPv6 /48) traffic came from or went to, by its kind:
  allowed in, unanswered in (nothing came back within 3 s: a scan, or a port the firewall drops) and out, with its route
  to home. The local network's peers are summed apart and never placed. At most 300 places are drawn, the rest summed.
- **Places come from a file on this PC**: DB-IP's [IP to City Lite](https://db-ip.com/db/download/ip-to-city-lite),
  under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). No peer's address is sent anywhere, and none is
  looked up by name. The file is downloaded only from the tab's **Install the GeoIP file…**: the first confirmation
  says what is downloaded, from where and to where, and shows the licence; the second one accepts it. It is about 60 MB
  (121 MB unpacked), this month's file, or last month's while this month's is not out yet, kept as one copy in the
  data folder's `geoip/`. The platform runs the install as a job (the library's `JOB_HOOKS`), its progress, the bytes
  so far and their percent, followed in the plugin's panel. It stops by itself after 30 minutes, the download
  included, and when the plugin is detached; every hop is https, from download.db-ip.com alone. A month's file is never
  downloaded twice: **Update…** is offered once the file installed is an earlier month's, and fetches this month's in
  its place. The file is open while the tab is watched, and let go once watching stops. Wherever its places are shown,
  the page says "IP Geolocation by DB-IP" with a link to db-ip.com, as the licence asks. The second confirmation comes
  from liminal-platform 0.28.0 or newer, which carries the licence's refusal back to the page; 0.27.0 shows the
  refusal in the job's panel instead.
- **Home** is the place you set in the plugin's settings, **Home on the globe** (`LIMINAL_HOME_PLACE`,
  `lat,lon[,label]`, as `48.86,2.35,Paris`; kept through the platform's login). Without one, home is where the file puts
  this network's public address, asked once of OpenDNS's name servers, then Google's (the hw-stats plugin's), with
  nslookup, windowless. Only that question goes out, its name absolute (`myip.opendns.com.`), so none of this PC's DNS
  search suffixes is sent with it; Windows' nslookup first asks the server for its own name (the PTR record of the
  server's own address).
- **The ports**: the four busiest ports here are charted (bytes a second in and out, over the last ten minutes), and
  tabled with the places and the ports elsewhere (the far end's ports of the connections this PC started).

## The Netstat tab

The user's words (2026-11-16): "the firewall app should have a 'netstat' like interface for looking at active ports and
what apps they are attached to, and the hosts that they connect to across the lan or wan. the firewall app should also
have a globe that can be zoomed and rotated and geoip'd hosts are databased for the apps they talk to, the time they
are connected to *this *computer".

Since 0.7.0 the page has a **Netstat** tab after World Wide Web: the library's Firewall base's (liminal-libs 1.65.0,
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
- One reading of the tables serves both tabs for 2.5 s.

Off Windows the plugin is not for the machine at all: its status says so, its tabs say the same, and every other ask
of theirs (a filter of the globe, the recording, Forget…, a layer, a data set's download or removal) is refused in
words before it reads, records, keeps or removes anything: the hosts database and the layers there are that system's
own firewall plugin's. On a library before 1.65.0 the plugin loads as 0.6.1 did, its World Wide Web tab as it was, and
names none of this.

## The hosts database

- **What it keeps**: for each program and remote host (with the protocol, the service's port and the direction): the
  program's path and service, whether the host is on the local network or the internet, its name where the system
  knows one, when it was first and last seen, how long it was connected to this PC (counted while Windows was awake: a
  night asleep is no time connected), how many connections, and the host's place once the GeoIP file on this PC gives
  one. This PC's own connections to itself are never kept, and a local host is never placed on the globe.
- **Where**: one small SQLite file on this PC's own disk, the data folder's `hosts/hosts.db`; at most 50,000 rows, the
  hosts longest unseen pruned first (about 13 MB with ordinary values). A data folder on another system's drive is that
  system's: nothing is kept there from here. Nothing in it is sent anywhere.
- **When it records**: only while this plugin's Netstat or World Wide Web tab is shown (the default), or all the time
  the platform runs (a reading every 5 s), as you choose with **Recording…** or the plugin's setting **Recording
  hosts** (`LIMINAL_HOSTS_RECORDING`: `shown` or `always`), kept through the platform's login. **Forget…** removes every
  row, asked twice.

## Internet infrastructure on the globe

The user's words (2026-11-16): "the globe-firewall should allow filtering, so i can view apps connected to hosts all
across the globe, or ports talking to all hosts. The globe should have the same kind of geography associated with the
exchanges globe, but the firewall globe should instead of exchanges, have all the backbones,ibones, major internet
infrastructure, (as many as possible) datacenter locations." And (2026-11-19): "also on the firewall theres no real
ibone or major hub s drawn on the map, data centers in the world (dataset) and major network 'bones' need to be
displayed on the map"; "also underwater lines".

- **What the globe shows**, the table right under it: the traffic watched now, or the hosts recorded; those filtered
  by program (its hosts across the globe), by port (every host on it), by direction (in or out) and by when they were
  last seen (within the last hour, day, 7 days or 30 days; their totals are all the time recorded). The eight programs
  and the eight ports with the most hosts are offered right under the globe, the rest in the Programs and Ports tables
  below it, beside a Hosts table.
- **The layers**: where the charts' exchanges globe draws exchanges, this globe draws the internet's infrastructure:
  data centres, internet exchange points, cable landing stations, ground stations and teleports, backbones and their
  points of presence, submarine cables, and telecom lines on land. "The same kind of geography" is read as the
  exchanges globe's marks, clusters and name boxes, on this globe's filled land, its equator stressed; day and night
  and the sun's mark are left out of this version. "ibones" is read as internet backbones: the Internet Topology Zoo's
  261 maps of networks (research networks such as GÉANT, Internet2 and ESnet, carriers such as Sprint, NTT and Cogent),
  each network's newest map drawn as links between its cities, about 2010-2011 and logical, not today's fibre routes
  (no free map of those exists: operators keep them private or sell them); OpenStreetMap's telecom lines on land
  (partial: no country is complete); and the submarine cables. Each layer is switched on and off in the globe's
  legend, remembered in this browser. The
  layers are drawn by liminal-platform 0.33.0 and later, whose page gives the globe its way to ask for them; an older
  platform's globe says that it cannot load them, and everything else works.
- **The data sets**, in the World Wide Web tab's **Internet infrastructure** table, each downloaded only on your word
  (**Download…**, **Update…**; **Remove…** takes it away), as a job (its progress in the plugin's panel; **Cancel**
  stops it; ten minutes at most), its size (an estimate where its maker gives none) and its licence said first and
  accepted in a second confirmation; then kept on this PC (the data folder's `infrastructure/`) and drawn from there,
  so the globe asks nothing of anyone. Each is credited on the globe as its licence asks.

| Data set | From | Licence | Size (an estimate) |
| --- | --- | --- | --- |
| Data centres, and the exchange points mapped | OpenStreetMap, through the public Overpass API | ODbL 1.0 | 2 MB |
| Submarine cables and landing stations | OpenStreetMap, through the public Overpass API | ODbL 1.0 | 3 MB |
| Telecom lines on land (partial) | OpenStreetMap, through the public Overpass API | ODbL 1.0 | 15 MB |
| Exchange points, ground stations and teleports | Wikidata, through its query service | CC0 | 0.2 MB |
| Telecom cable routes in European waters | EMODnet Human Activities, through its WFS | CC BY 4.0 | 4 MB |
| Backbone networks, about 2010-2011 | the Internet Topology Zoo, through GitHub | CC BY 4.0 | 0.35 MB (its own) |

- **One request a data set**: its query asks for the tags or the kinds of place it draws and nothing more, nothing about
  this PC or its traffic, with the plugin's name and version as its User-Agent and no contact (Wikidata's policy asks
  automated clients to name one: a refusal for want of it is said in words). The public Overpass server asks apps not
  to lean on it: it is asked once a data set, on your click, and once more a minute later when it is busy.
- **The submarine cables** are asked of every telecom category OpenStreetMap's mappers use (fibre_optic, fiber_optic,
  optical, telephone, telegraph, telefon, communication, telephone/fibre_optic: 1,189 ways, where fibre_optic and
  telephone alone were 1,115), as the Linux firewall plugin asks them; no power cable. The **lines on land** leave out
  those on power poles (power=minor_line: local distribution, 6,394 of 15,775), which leaves the lines most like
  backbones. **Wikidata's data centres** are asked with their kinds (colocation centres among them: 211 items, not 168).
- **EMODnet's cable routes** are a fifth data set because its WFS offers GeoJSON: the actual routes in European waters
  (and French cables beyond) as six national sources gave them, asked longitude first (`srsName=EPSG:4326`).
- **The Topology Zoo's maps** are a sixth: one archive of GML maps, unpacked in memory alone (32 MB at most, 2,000
  files, 4 MB a map), of each network its newest map from 2000 on, its own points of presence with a place and the
  links between them, each drawn as the great circle between its two ends. Its credit names its makers: "Internet
  Topology Zoo (Knight, Nguyen, Falkner, Bowden, Roughan, IEEE JSAC 2011), Adelaide University, CC BY 4.0".
- **Left out, and why**: PeeringDB and the IXP Database (for operational use alone), Packet Clearing House's
  directory and the ITU's map (non-commercial terms), TeleGeography (its data is sold), root server sites (no licence
  stated), cloud regions (no coordinates, and only one provider's page may be copied) and content networks' city lists
  (their sites' terms). Free, but not here yet: Wikipedia's list of exchange points (544 active, CC BY-SA 4.0, placed
  only at their cities, whose places take a second request) and NOAA's cables in US waters (CC0, two requests): a
  data set here is one request.

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

Since 0.6.0, four more for the World Wide Web tab:

- **Npcap**, the packet capture the library calls through wpcap.dll: [Npcap](https://npcap.com/),
  [its users' guide](https://npcap.com/guide/npcap-users-guide.html), [where its install options are kept, AdminOnly
  among them](https://npcap.com/guide/npcap-devguide.html), [its API](https://npcap.com/guide/wpcap/pcap.html),
  [pcap-filter(7)](https://www.tcpdump.org/manpages/pcap-filter.7.html). Its card names every libpcap call the
  library's capture makes, and the AdminOnly option it reads before them. Npcap's free license covers five computers.
  Copies installed and used only with Nmap, Wireshark or Microsoft Defender for Identity do not count, but this PC's
  does: it came with Wireshark, and Liminal uses it directly. More computers, or redistributing it, need Npcap OEM.
- **DB-IP IP to City Lite**, the GeoIP file: [the Lite databases and their licence](https://db-ip.com/db/lite.php),
  [IP to City Lite](https://db-ip.com/db/download/ip-to-city-lite), [its MMDB format](https://db-ip.com/db/format/ip-to-city-lite/mmdb.html),
  [the MaxMind DB format](https://maxmind.github.io/MaxMind-DB/) and [maxminddb](https://github.com/maxmind/MaxMind-DB-Reader-python),
  which reads it.
- **OpenDNS** (myip.opendns.com) and **Google's name servers** (o-o.myaddr.l.google.com), asked for this network's
  public address: [OpenDNS's setup guide](https://www.opendns.com/setupguide/), [Google Public DNS](https://developers.google.com/speed/public-dns).

Since 0.7.0, four more for the Netstat tab and the globe's layers, and since 0.7.1 a fifth (named only where the
library has the Netstat tab):

- **Windows' socket tables and their owners (IP Helper)**:
  [IP Helper](https://learn.microsoft.com/en-us/windows/win32/iphlp/ip-helper-start-page),
  [GetExtendedTcpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable),
  [its rows](https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_module).
  Its card names every call the library's Windows reading makes (its `sockets.WINDOWS_CALLS`), and what it leaves:
  the per-connection statistics an administrator must switch on, PowerShell's NetTCPIP cmdlets.
- **Overpass API**: [Overpass API](https://wiki.openstreetmap.org/wiki/Overpass_API),
  [Overpass QL](https://wiki.openstreetmap.org/wiki/Overpass_API/Overpass_QL),
  [the public instances' limits](https://dev.overpass-api.de/overpass-doc/en/preface/commons.html),
  [OpenStreetMap's copyright](https://www.openstreetmap.org/copyright),
  [the ODbL](https://opendatacommons.org/licenses/odbl/1-0/).
- **Wikidata Query Service**: [its user manual](https://www.mediawiki.org/wiki/Wikidata_Query_Service/User_Manual),
  [Wikidata's licensing](https://www.wikidata.org/wiki/Wikidata:Licensing).
- **EMODnet Human Activities (WFS)**: [the portal](https://emodnet.ec.europa.eu/en/human-activities),
  [the cables' record](https://emodnet.ec.europa.eu/geonetwork/srv/api/records/39ebe289-410b-4a5d-88a4-51bfcde538de),
  [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
- **Internet Topology Zoo (GitHub)**: [its repository](https://github.com/mroughan/InternetTopologyZoo),
  [its licence](https://raw.githubusercontent.com/mroughan/InternetTopologyZoo/main/LICENSE),
  [Adelaide University's record](https://researchdata.edu.au/internet-topology-zoo-data-set/4045587),
  [its DOI](https://doi.org/10.25909/30153949.v1).

`api_facts()` says what the last read found, asking nothing: when it was and how long it took, the rules and the
profiles, whether it ran as an administrator, the networks and their categories, Defender's state, and why the last
read failed, if it did. Since 0.6.0 it also says what the World Wide Web tab knows once it has been asked: whether it
watches and at which adapter, the packets read, why it cannot watch, and the GeoIP file it places with (and whether
that file is open now, or let go while nobody watches). Since 0.7.0, once its Netstat view is made, it also says the
socket tables' last reading (when, how many sockets, how long it took), how the hosts are recorded and what the hosts
database holds, and each data set of the globe, downloaded or not, under its source's card.

The six Windows cards' addresses were read on 2026-11-11, the Npcap and DB-IP cards' on 2026-11-15. The name servers'
cards are the hw-stats plugin's, read on 2026-11-11 (OpenDNS's setup guide and Google Public DNS's questions read again
on 2026-11-15). The four 0.7.0 cards' were read on 2026-11-18 (EMODnet's capabilities on 2026-11-17), and 0.7.1's,
the Topology Zoo's, on 2026-11-19. The test
`test_the_cards_pages_answer` asks each address again when `LIMINAL_VENDOR_PAGES=1` is set (it is skipped otherwise).
