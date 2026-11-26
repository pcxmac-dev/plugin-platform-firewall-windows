# Changelog

## 0.10.0 (2026-11-26, provisional)

The globe's newer data sets (the Monday list's items 24, 27, 28, 29 and 32; the user, 2026-11-26: "Build first, ask per
download"), on liminal-libs 1.104.0. Each is offered on the World Wide Web tab's Internet infrastructure table with its
size and its licence, exactly as the eight before them, and nothing is downloaded until you click. Floor: liminal-libs
1.104.0.
- **Fibre on land and its stand-ins** (item 24): AfTerFibre's map of Africa's terrestrial fibre (NSRC, CC BY 4.0 as its
  records say; its site states no licence now and offers no file, so its map's 56 tiles at zoom 5 are asked one after
  another on the one click; its contributors' names and e-mail addresses are never kept), and Natural Earth's 1:10m
  roads and railways (public domain, ferries left out), drawn dashed as stand-ins for fibre where none is mapped: a
  route found along them alone says so, and real fibre, cables or backbones are preferred wherever one is near.
- **In the plugin's own database** (item 27; the user, 2026-11-23: "Kept here, from my downloads"): what you download is
  kept in the data folder's `infrastructure/infrastructure.db` and read by area as the globe comes nearer; an older
  download's file is read into it once and left where it is.
- **Sources of the composite database** (items 28 and 29): TopoHub's model of the world's backbones (its repository's
  MIT label; no licence is stated for its data, and its words say so), RIPE Atlas's probes and anchors, and the newest
  traceroute of each anchor (measurement 5151, about 3 requests, offered once the probes are in; RIPE Atlas's terms 3.5:
  for non-commercial use on this PC, commercial use needs the RIPE NCC's permission).
- **The satellites** (item 32; the user chose CelesTrak and the sgp4 package): Starlink's, OneWeb's and HughesNet's
  orbits from CelesTrak (no licence stated; its usage policy kept: compressed, never asked twice on a busy answer,
  Update… held back 2 hours, HughesNet's three satellites by their numbers), each constellation its own colour, every
  footprint at 25 degrees of elevation drawn as one merged area, a geostationary satellite's the countries its beams
  reach (`HUGHESNET_BEAMS`). The sgp4 package is pinned (`SGP4_PACKAGE`: its Windows wheel (sgp4-2.27-cp311-abi3-win_amd64.whl, 148.9 kB, with its C extension), its size and sha256 from PyPI's
  file list) and offered beside the data sets as the base's `SKY_PACKAGE`; until it is downloaded the sky says it needs
  it and places nothing.
- Six cards for their sources (Natural Earth, AfTerFibre, TopoHub, RIPE Atlas, CelesTrak, sgp4), their pages read on
  2026-11-26 (`VERIFIED_GLOBE2`); each data set's facts under its card.
- Tests: the seventeen data sets' digest pinned (`INFRASTRUCTURE_SHA256`, the Linux plugin's too); each new set
  read by the library and offered with its licence first; HughesNet's beams named by the globe's own countries; the
  sgp4 pin, its offer and the sky's words without it; the cards; the sky's download among the jobs, and the sky's three hooks refused off Windows.

## 0.9.0 (2026-11-26)

More GeoIP sources for the World Wide Web tab, phase 1 (Monday list item 20; the design of 2026-11-24 with your answers
of 2026-11-25), on liminal-libs 1.101.0's machines/geosources.py. The user, 2026-11-19: "add a way to download different
GEOIP sources"; 2026-11-25: all three sources in phases, each offered only after your yes. Floor: liminal-libs 1.101.0.
- **GeoIP sources** (`apis.GEOIP_SOURCES`, the base's `GEOIP_SOURCES`): the tab's GeoIP sources table takes the place
  of Install the GeoIP file… and Install the ASN file…, a row a source's file (Source, Gives, Licence, Key, Here) with
  Use…, Download… (Update… once one is due) and Remove…. Places and networks are chosen apart; DB-IP's IP to City Lite
  and IP to ASN Lite are the default for both, at the same addresses, in the same folders and in the same words, each
  ending with the line that points to the full licence (CC BY 4.0).
- **Only you, at the page:** Download…, Use… and Remove… are the base's three page-only hooks (`world_geoip_get`, a job
  the page may cancel; `world_geoip_use`; `world_geoip_remove`, asked twice), and each refuses any ask but a person's
  signed in at the platform's page itself. Your acceptance of a licence is kept in your own login store
  (`licence-dbip-lite`, `licence-dbip-asn-lite`: the file and its month, the licence's version and page, your name),
  never in the licences file; a store that refuses it ends the download with nothing fetched. The old installs
  (`world_geoip`, `world_asn`) stay for programs: DB-IP's files as before, nothing recorded.
- **IPinfo Lite** for networks (CC BY-SA 4.0, "IP address data powered by IPinfo") is named and not offered: its row
  says "not offered: waiting for your word", with no button, no form, no card and no key asked (`IPINFO_TOKEN` is not
  declared), and its hooks refuse it before anything is read. It is offered once you say yes.
- The DB-IP card's words follow the new buttons and say where an acceptance is kept.
- Tests: the sources' digest pinned (`GEOIP_SOURCES_SHA256`, the Linux plugin's too); the table's rows and forms, IPinfo
  Lite's row without a button; a download for a person at the page, its record in a stand-in store and no licences
  file; the other askers refused before anything is read; the pins of the page-only, job and Cancel hooks restated.

## 0.8.0 (2026-11-25)

Services' networks through this firewall, on liminal-libs 1.96.0's NetworkHost (service-containers-networking-2026-11-23.md
§5.1, §6, §7 and §14; decision 2 as (b) with (b1), the user's choice). The user, 2026-11-23: "all services/containers will
use the firewall app to create routing for the IP ranges of the containers"; "the firewall app will know it's domain,
and have name resolution to each container, reverse lookup for all containers, and contain DHCP records"; "all this is
mediated between the firewall API and the containers (plugin to plugin)". Floor: liminal-libs 1.96.0. On 0.7.3 (the
review's PLT-H1 gates, not landed).
- **Routes into WSL:** a container plugin you let ask (the Networks tab's Let it…) gets each service's /24 from the
  Windows half of Liminal's pool (10.77.0.0/17), checked against this PC's addresses and routes (Get-NetIPAddress,
  Get-NetRoute, read with no rights), and one route per segment: `New-NetRoute -DestinationPrefix <it> -InterfaceIndex
  <the WSL adapter's> -NextHop <the VM's address> -PolicyStore ActiveStore`, a stale one of that prefix taken away
  first. The VM's address is the WSL plugin's `wsl_network` (read only while a Liminal distribution runs: a stopped one
  refuses the plan, naming its page, and nothing starts); the adapter is found by that address, never by its name; a
  hop on none of this PC's WSL adapters, or a mode other than NAT, is refused in words. A restart of Windows takes the
  route away: the next Start's plan points it again, in that Start's own approval, or Re-point… on the Networks tab.
- **Your network (decision 2 b, b1):** Expose… adds a port proxy per port (`netsh interface portproxy add v4tov4`)
  listening on this PC's address on your network alone (the default route's adapter that is no vEthernet: never
  0.0.0.0, loopback or a virtual switch), connecting to the part's reserved address and the container's own port
  through the route, with the rule `Liminal: svc-<owner>-<name>-<port>` (TCP in, from LocalSubnet, Private and Domain
  alone, for the IP Helper service). UDP is refused (the proxy carries TCP alone). A Windows containers segment is this
  PC's own: no route, and Expose… is its rule alone. Conceal…, Remove… and Withdraw… take exactly that away.
- **Names and DHCP records:** forward and reverse in the domain you set (`set_domain`, kept through the login: no
  default, so no service is placed until you set one); every container the granted plugins' segments hold recorded in
  the network database (network/network.db), found ones answered in reverse with their engine's own name.
- **One script, one prompt:** every plan's steps run as one PowerShell script from fixed templates (every prefix,
  address, port and rule name parsed first; a route's prefix must be in the pool, a hop and a listen address private),
  through `_admin`: UAC once on this PC's screen, or at once as an administrator. Never written: New-NetNat,
  Remove-NetNat, Set-NetIPInterface -Forwarding, IPEnableRouter, portproxy reset (refused if a script holds one).
- **The Networks tab** (the library's): segments by stack with each route current or stale, plans waiting for you,
  the container plugins you let, the domain, names, DHCP records, gone segments and leftovers (routes in the pool,
  proxies to it, svc- rules no service accounts for; your own proxies elsewhere are never listed), each with its
  Remove…; Re-point….
- **`excluded_ports`** (a read any plugin asks): Windows' excluded TCP port ranges (netsh interface ipv4 show
  excludedportrange), which the container plugins never publish in.
- **Asked twice:** making a network Private (`set_network`'s `accept_risk`), naming each rule turned on that Private
  would then let in from beyond your local subnet (N23).
- **Page-only:** the base's other changes too (labels and moves, the hosts' recording and forgetting, the traffic's
  watching, the downloads), beside NetworkHost's own (approve_plan, the grants, the domain, Re-point…, Withdraw…,
  leftovers, Forget…). network_plan, apply_network and network_work are a granted container plugin's alone.
- API cards: NetTCPIP (PowerShell) and netsh (port proxy and excluded ports).
- Tests: tests/test_networks.py (14) over tests/netfake.py, the library's conformance sequence among them with this
  plugin routing and naming; each of its 12 gates taken out once made a test fail.

## 0.7.3 (2026-11-24)

The changes are asked only from the page, and run() never asks for an administrator (the independent review's finding
PLT-H1, rated high, checked 2026-11-23). The user, 2026-11-23, of liminal-platform's route that handed a plugin's run()
any words: "Remove it" (gone since liminal-platform 0.34.1). And from the review of this release's first draft,
2026-11-24, each finding checked a second time: the changes are asked only from the page, and the tests set
`LIMINAL_ELEVATE=prompt` where the plugin reads it.

- **The changes are asked only from the page** (`PAGE_ONLY_HOOKS`, liminal-libs 1.66.0's word; the review's first
  finding, rated medium, there since 0.2.0): `set_rule`, `remove_rule`, `make_rule`, `set_profile` and `set_network`,
  and the base's `allow` and `remove` (Liminal's own rules). Another plugin's ask of one is refused (403), and
  liminal-platform 0.34.0 refuses one over HTTP (401) unless its login shows that you are at the page. Before, any
  program on this PC, of any account, asked them with the gates PLT-H1 named: the bind to 127.0.0.1, a Host header the
  client chooses and a constant header anyone can send. On a platform run as an administrator, `set_profile` with
  `["Public", "off", null, null, null, true]` turned the Public profile's firewall off at once, with no prompt (its
  "asked a second time" is `accept_risk`, an argument the asker sets), and `make_rule` with `["x", "in", "allow",
  "any"]` let everything in on every profile; on one that is not, Windows asked you (UAC) for a change nobody had
  asked for. A platform that holds no login asks them as before. The setup and the command line call the plugin's
  code directly, not through an ask, so they work as before; so do its reads and queries (`status`, `refresh`,
  `find_rules`, `show_rules`, its tabs). The 401 rests on the login's word that your browser is signed in, and a
  local login signs `default` in with no password: a proof that a program cannot make is the login's and the
  platform's to give.
- **run() never asks for an administrator**, whether or not the platform is one: a PowerShell command line runs as the
  platform runs, and one Windows denies is said ("Access is denied.") and never asked again through UAC, even with
  `LIMINAL_ELEVATE=prompt`. It has been the library's `PowerShell.run` since 0.1.0; only its docstring changes. No
  route of the platform's asks it any more (liminal-platform 0.34.1): this command line's `run -- COMMAND` and
  `liminal-platform machine firewall-windows run -- COMMAND` ask it in their own process.
- Tests: `tests/test_who_asks.py`, through the library's own App, on a platform run as an administrator and on one
  that is not: the changes refused to another plugin and to no one (the review's two bodies among them), nothing run
  nor read and Windows not asked; the page's ask run, at once or through UAC; the reads and queries asked by anyone.
  `tests/test_run.py`, over a stand-in powershell.exe and a stand-in prompt (nothing runs, nothing is elevated): a
  command runs once, as it is; one Windows denies is said and never asked again; the command line's `run -- COMMAND`
  is the same run. `LIMINAL_ELEVATE=prompt` is set in this process's environment too, where the plugin as shipped
  reads it, not only in the stand-in's (the review's second finding, rated low): a run() that read it there and asked
  through UAC passed wherever the suite ran without it.

## 0.7.2 (2026-11-24)

A rule made twice is refused (the review of 2026-11-21, item 26, finding 7).

- **"Make a rule" asked twice no longer makes two rules the same.** Windows makes a second rule of a DisplayName that
  is there already, and the check after New-NetFirewallRule only found what it had made. `make_rule` now looks first:
  one of Liminal's rules (the group Liminal) of that name, in any case, is refused in words ("is there already: remove
  it first") before anything runs, as the Linux plugin and the library's `Firewall.allow` refuse it. Another's rule of
  the same name is no bar. Test: `test_a_rule_made_twice_is_refused_before_anything_runs`.

## 0.7.1 (2026-11-19)

Backbone networks on the globe, cables of every telecom category, and a globe that zooms to 96x. The user,
2026-11-19: "i need to zoom in a few more times maybe 96x"; "also on the firewall theres no real ibone or major hub s
drawn on the map, data centers in the world (dataset) and major network 'bones' need to be displayed on the map";
"also underwater lines". And, 2026-11-16: "the firewall globe should instead of exchanges, have all the
backbones,ibones, major internet infrastructure, (as many as possible) datacenter locations." The globe is
liminal-libs 1.65.1's: it now zooms to 96x (was 12x), with Natural Earth's 1:10m map past 12x and GSHHG's coasts and
borders past 24x (LGPL-3.0, credited while drawn). This plugin names what the globe draws.

- **A sixth data set: backbone networks, about 2010-2011** (`apis.py`, `topology-zoo`). The Internet Topology Zoo's
  261 maps of networks (GÉANT, Internet2, ESnet, Sprint, NTT, Cogent and more): one archive of GML files on GitHub,
  348,613 bytes, under CC BY 4.0. Of each network, its newest map is drawn: its points of presence, and the links
  between them as great circles. They are logical links of about 2010-2011, placed at their cities, not today's fibre
  routes. Its licence's words are shown whole before the download. Its credit is drawn wherever its networks are:
  "Internet Topology Zoo (Knight, Nguyen, Falkner, Bowden, Roughan, IEEE JSAC 2011), Adelaide University, CC BY 4.0".
- **Submarine cables of every telecom category** (`osm-cables`, ODbL 1.0, about 3 MB). The query asks all eight
  categories OpenStreetMap's mappers use, as the Linux plugin does: 1,189 ways, where fibre_optic and telephone alone
  were 1,115. The two plugins now name the same six data sets in the same order, and both tests pin one digest.
- **Telecom lines on land, those on power poles left out** (`osm-lines`, ODbL 1.0): about 13,000 ways, about 15 MB
  (was 20 MB; both estimates). Lines on power poles are local distribution, not backbones.
- **Wikidata's data centres of every kind** (`wikidata`, CC0, about 0.2 MB): asked with their subclasses, so
  colocation centres come too (211 items, not 168), about 340 places in all.
- **A fifth card**, the Internet Topology Zoo (GitHub), its pages read on 2026-11-19. Its facts list the data set.
- `pyproject.toml`: liminal-libs[geo]>=1.65.1, the release that reads the Topology Zoo's maps. On 1.65.0 that one
  data set is left out, in words, and the others work.
- Not here yet: Wikipedia's list of exchange points (CC BY-SA 4.0, placed only at their cities) and NOAA's cables in
  US waters (CC0). Each needs more than one request, and a data set here is one.

Tests: test_netstat.py (all eight cable categories; the data sets' digest, the Linux plugin's; a stand-in Topology
Zoo archive read into the layers, downloaded through the plugin's hooks and drawn as backbones; the card's one GET;
the facts list the Zoo's set under its card); test_apis.py names the fifth card.

## 0.7.0 (2026-11-18)

The Netstat tab, the hosts database, and the globe's filters and internet infrastructure. The user, 2026-11-16: "the
firewall app should have a 'netstat' like interface for looking at active ports and what apps they are attached to,
and the hosts that they connect to across the lan or wan. the firewall app should also have a globe that can be
zoomed and rotated and geoip'd hosts are databased for the apps they talk to, the time they are connected to *this
*computer"; "the globe-firewall should allow filtering, so i can view apps connected to hosts all across the globe, or
ports talking to all hosts. The globe should have the same kind of geography associated with the exchanges globe, but
the firewall globe should instead of exchanges, have all the backbones,ibones, major internet infrastructure, (as many
as possible) datacenter locations." The tab, the database, the filters and the layers are liminal-libs 1.65.0's
Firewall base's (`sockets.py`, `hostbook.py`, `machines/netstat.py`, `machines/infrastructure.py`); the plugin names
what they reach (`apis.py`). liminal-platform 0.33.0 draws the layers.

- **Netstat**, a tab after World Wide Web, asked every 3 s while it is shown: this PC's listening ports and open
  connections from Windows' own socket tables, each with its program, pid and service, the remote host and port,
  whether that host is this PC's, the local network's or the internet's, its name or its GeoIP place, its state, since
  when and how long it has been up. No packet captured, no administrator, no process started, no window, no name
  looked up. What cannot be read is said in its row (where a service's process is on disk, which driver the System
  process holds a socket for, a connection whose program has ended). A program run by an interpreter shows as the
  interpreter (Liminal's own apps as python.exe, or pythonw.exe where they were started at logon or at boot), and a
  port a program inside a WSL distribution listens on as wslrelay.exe's: which program holds it is for the Linux
  firewall plugin inside that distribution to say.
- **The hosts database**, this PC's own (the data folder's `hosts/hosts.db`, at most 50,000 rows): each program's
  remote hosts, their ports, when they were first and last seen, how long they were connected while Windows was
  awake, how many connections, and their places. It records only while the Netstat or the World Wide Web tab is shown,
  unless you choose all the time the platform runs (**Recording…**, or the setting Recording hosts,
  `LIMINAL_HOSTS_RECORDING`, kept through the login); **Forget…** removes every row, asked twice.
- **The globe** shows the traffic watched or the hosts recorded, filtered by program, by port, by direction and by
  when they were last seen, the eight programs and the eight ports with the most hosts right under it. It draws the
  internet's infrastructure from five free-licensed data sets (`INFRASTRUCTURE`), each downloaded only on your word,
  as a job (its size and its licence said first and accepted in a second confirmation; Cancel stops it), kept on this
  PC and credited where it is drawn: data centres, submarine cables and their landing stations, and telecom lines on
  land (OpenStreetMap, through the public Overpass API, ODbL 1.0); exchange points, ground stations and teleports
  (Wikidata, CC0); telecom cable routes in European waters (EMODnet Human Activities' WFS, CC BY 4.0, asked longitude
  first). PeeringDB, root-server sites and cloud regions are left out: not free-licensed, or no licence stated.
- **Off Windows the plugin is not for the machine** (`not_for_here`): its status says so and nothing is read there,
  and no Netstat view is made (`make_netstat_view`), so every hook of its two tabs is refused in words before it reads,
  records, keeps, forgets or removes anything: there the hosts database and the layers are that system's own firewall
  plugin's.
- **Four more cards** (plugin API 2.2), their pages read on 2026-11-18: Windows' socket tables and their owners (IP
  Helper: every call the library's reading makes, `sockets.WINDOWS_CALLS`), the Overpass API, the Wikidata Query
  Service and EMODnet Human Activities (WFS). Their facts say the socket tables' last reading, how the hosts are
  recorded, what the database holds and each data set's state, asking nothing.
- Its floor is liminal-libs[geo]>=1.65.0. Given an older library all the same, it loads as 0.6.1 did: its World Wide
  Web tab as it was, and none of the four cards.

Tests: test_netstat.py (skipped before 1.65.0: the tab is the base's; each data set a DataSet with its forms' words;
answers in each source's documented shape read into the layers; the page over a stand-in Windows reading; a download
on the user's word; one reading shared and kept; off Windows nothing read, recorded or offered); test_world.py,
test_apis.py and test_plugin.py follow the library; tests/conftest.py's `no_real_hosts` guard, as the library's: no
test reads this PC's socket table or writes its hosts database.

## 0.6.1 (2026-11-16)

The GeoIP file's card tells the truth when the data folder is on another system's drive. With liminal-libs 1.58.0 the
World Wide Web tab neither reads nor offers to install the GeoIP file of a data folder on a share or a network drive
(`WorldView.elsewhere`): that system's platform installs its own. The card said "none installed yet: the World Wide Web
tab's Install the GeoIP file… downloads one", an action the tab no longer offers there. It now says "none read here:"
and why. With an older library it reads as before.

Tests: the card's words for such a folder, with the view's word stood in for.

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
