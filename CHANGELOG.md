# Changelog

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
