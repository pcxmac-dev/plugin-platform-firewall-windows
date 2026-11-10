# plugin-platform-firewall-windows

Windows Firewall for Liminal: Windows Defender Firewall, the networks and Microsoft Defender on this PC, every rule and
profile read, queried and changed on your word.

The user's words: "the platform is the interface for the software/hardware which facilitates the liminal framework";
"i also need a windows and linux firewall plugin for the platform" (2026-11-07); "windows firewall, i need it to be
able to read the configuration, and make changes"; "basically the firewall plugin is an interface for windows
networking / defender / firewall, and will let me make queries and alter the firewall configurations" (2026-11-08);
"for both firewalls, i need to have groups, like system or application and then unassociated rules not tied to a
specific application or system process can be in an other, i can create labels, like system or application, as well
and move the rules in to that" (2026-11-08); "lets group by application under apps or system, try best to organize
under system and applications. Like system has 'core networking' or WSD or UPnP or RA Server or Remote Assistance or
network discovery or ... applications has like starcraft or edge"; "try to group the system by 'services'"; "also
rules that are turned off should be shown as well" (2026-11-09).

## What it does

A machine plugin of the platform (`liminal_libs.machines.firewall.Firewall`, plugin API 2.1) driving Windows Defender
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
listening here could be reached from the internet.

**The setup** works as before: `enable` (every profile on), `exposure` (no rule lets another machine reach the
framework's pages, 8765, 8775, 8785, 8795, 8796; a finding, never a change) and `rules` (the ports the framework's
services need, opened as `Liminal: <name>`). `allow`/`remove` make and remove Liminal's own rules.

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
```

A rule's id (in brackets in `rules` and `find`) is what `set-rule` and `remove-rule` name. A change needs an
administrator: run as one, or Windows asks (UAC). `set-profile` refuses `--off` or `--inbound allow` without
`--accept-risk`.
