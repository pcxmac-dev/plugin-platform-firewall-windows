# Changelog

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
