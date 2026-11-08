# plugin-platform-firewall-windows

Windows Firewall for Liminal: Windows Defender Firewall on, the framework's pages kept to this machine, the ports its services need opened as Liminal's own rules.

The user's words (2026-11-07): "the platform is the interface for the software/hardware which facilitates the
liminal framework"; "i also need a windows and linux firewall plugin for the platform"; "and a windows and
linux admin plugin for platform".

## What it does

A machine plugin of the platform (`liminal_libs.machines.firewall.Firewall`, plugin API 2.1) driving Windows
Defender Firewall through PowerShell's NetSecurity cmdlets (the library's `machines.windows.PowerShell`: a script
given as `-EncodedCommand`, windowless). Every rule it makes is in the rule group `Liminal`, displayed as
`Liminal: <name>`; it changes no other rule.

- `status()`: each profile on or off, its default actions, Liminal's rules.
- `setup()`: `enable` (every profile on), `exposure` (no enabled inbound rule lets another machine reach the
  framework's pages, 8765, 8775, 8785, 8795, 8796: by port, a range, or every port for any program or for
  Python; a finding, never a change), `rules` (the ports the framework's services need, a domain login's mail
  server container published on every address, opened as `Liminal: mail-<domain>`).
- `allow(name, ports)`, `remove(name)`: Liminal's own rules, asked by the platform's page by name.

Changing the firewall needs an administrator: run the platform as administrator, or set `LIMINAL_ELEVATE=prompt`
and Windows asks (UAC) when a step needs it. Reading needs nothing.

## From the command line

```
python -m plugin_platform_firewall_windows status
python -m plugin_platform_firewall_windows setup            # everything; or one step: setup exposure
python -m plugin_platform_firewall_windows rules
python -m plugin_platform_firewall_windows exposure
python -m plugin_platform_firewall_windows allow web 8443
python -m plugin_platform_firewall_windows remove web
```

The platform app drives the same hooks from its page.
