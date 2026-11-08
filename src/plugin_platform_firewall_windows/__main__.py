"""The plugin from the command line (the platform app asks the same hooks from its page):

    python -m plugin_platform_firewall_windows status
    python -m plugin_platform_firewall_windows rules [in-allow|in-block|out|liminal|off|all]
    python -m plugin_platform_firewall_windows find [WORDS ...] [--port N] [--in|--out] [--allow|--block]
    python -m plugin_platform_firewall_windows profiles | networks
    python -m plugin_platform_firewall_windows set-rule ID on|off | remove-rule ID
    python -m plugin_platform_firewall_windows add-rule NAME [--out] [--block] [--protocol tcp|udp|any] [--ports 80,443]
                                                         [--program PATH] [--remote ADDRESSES] [--profiles any|Public,...]
    python -m plugin_platform_firewall_windows set-profile Domain|Private|Public [--on|--off] [--inbound block|allow|default]
                                                         [--outbound block|allow|default] [--notify on|off] [--accept-risk]
    python -m plugin_platform_firewall_windows set-network INDEX private|public
    python -m plugin_platform_firewall_windows setup [STEP ...] | exposure | allow NAME PORT[,PORT ...] [tcp|udp] | remove NAME
    python -m plugin_platform_firewall_windows run -- COMMAND

A change needs an administrator: run as one, or Windows asks (UAC)."""
from __future__ import annotations

import argparse
import json
import sys

from liminal_libs.machines.firewall import app_ports
from liminal_libs.machines.plugin import CommandError

from . import MACHINE, PRESETS, RiskRefused, ports_said


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m plugin_platform_firewall_windows", description="Windows Defender Firewall, read and changed")
    sub = p.add_subparsers(dest="what")
    sub.add_parser("status", help="the plugin's status as the platform's page reads it (JSON)")
    r = sub.add_parser("rules", help="the rules of a preset")
    r.add_argument("preset", nargs="?", default="in-allow", choices=list(PRESETS))
    f = sub.add_parser("find", help="rules found by words, a port, a direction and an action")
    f.add_argument("words", nargs="*")
    f.add_argument("--port", type=int)
    f.add_argument("--in", dest="direction", action="store_const", const="in")
    f.add_argument("--out", dest="direction", action="store_const", const="out")
    f.add_argument("--allow", dest="action", action="store_const", const="allow")
    f.add_argument("--block", dest="action", action="store_const", const="block")
    sub.add_parser("profiles", help="the three profiles")
    sub.add_parser("networks", help="the networks and their category")
    s = sub.add_parser("set-rule", help="a rule turned on or off")
    s.add_argument("id")
    s.add_argument("state", choices=["on", "off"])
    rm = sub.add_parser("remove-rule", help="a rule removed (never one of Windows' own)")
    rm.add_argument("id")
    a = sub.add_parser("add-rule", help="a rule made, in the group Liminal")
    a.add_argument("name")
    a.add_argument("--out", dest="direction", action="store_const", const="out", default="in")
    a.add_argument("--block", dest="action", action="store_const", const="block", default="allow")
    a.add_argument("--protocol", default="tcp", choices=["tcp", "udp", "any"])
    a.add_argument("--ports", default="")
    a.add_argument("--program", default="")
    a.add_argument("--remote", default="")
    a.add_argument("--profiles", default="any")
    pr = sub.add_parser("set-profile", help="a profile's firewall, defaults and notifications")
    pr.add_argument("profile")
    pr.add_argument("--on", dest="enabled", action="store_const", const="on")
    pr.add_argument("--off", dest="enabled", action="store_const", const="off")
    pr.add_argument("--inbound", choices=["block", "allow", "default"])
    pr.add_argument("--outbound", choices=["block", "allow", "default"])
    pr.add_argument("--notify", choices=["on", "off"])
    pr.add_argument("--accept-risk", action="store_true")
    n = sub.add_parser("set-network", help="a network made private or public")
    n.add_argument("index")
    n.add_argument("category", choices=["private", "public"])
    st = sub.add_parser("setup", help="the setup: enable, exposure, rules")
    st.add_argument("steps", nargs="*")
    sub.add_parser("exposure", help="rules letting other machines reach the framework's pages")
    al = sub.add_parser("allow", help="one of Liminal's own rules letting ports in")
    al.add_argument("name")
    al.add_argument("ports")
    al.add_argument("protocol", nargs="?", default="tcp", choices=["tcp", "udp"])
    re_ = sub.add_parser("remove", help="one of Liminal's own rules removed")
    re_.add_argument("name")
    ru = sub.add_parser("run", help="a PowerShell command line, its output")
    ru.add_argument("command", nargs=argparse.REMAINDER)
    return p


def rule_line(r) -> str:
    return f"{'on ' if r.enabled else 'off'}  {r.direction:3}  {r.action:5}  {ports_said(r):22}  {r.name}  [{r.id}]"


def said(answer: dict) -> int:
    print(answer.get("said", ""))
    for line in answer.get("lines") or []:
        print(f"  {line}")
    return 0 if answer.get("ok", True) else 1


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(list(sys.argv[1:] if argv is None else argv) or ["status"])
    m = MACHINE
    try:
        if args.what == "status":
            print(json.dumps(m.status(), indent=1))
            return 0 if m.present() else 1
        if args.what in ("rules", "find"):
            if args.what == "rules":
                m.show_rules(args.preset)
            else:
                print(m.find_rules(" ".join(args.words), args.port, args.direction, args.action)["said"])
            m._snap()
            _, found = m.rules_shown()
            for r in found:
                print(rule_line(r))
            return 0
        if args.what == "profiles":
            for p in m._snap().profiles:
                print(f"{p['name']:8} firewall {'on' if p['enabled'] else 'OFF'}; inbound {p['inbound']}; outbound {p['outbound']}; "
                      f"notifications {p['notify']}")
            return 0
        if args.what == "networks":
            for n in m._snap().networks:
                print(f"{n['index']:>3}  {n['interface']}: {n['name']} ({n['category']}); IPv4 {n['ipv4']}, IPv6 {n['ipv6']}")
            return 0
        if args.what == "set-rule":
            return said(m.set_rule(args.id, args.state))
        if args.what == "remove-rule":
            return said(m.remove_rule(args.id))
        if args.what == "add-rule":
            return said(m.make_rule(args.name, args.direction, args.action, args.protocol, args.ports, args.program, args.remote, args.profiles))
        if args.what == "set-profile":
            return said(m.set_profile(args.profile, args.enabled, args.inbound, args.outbound, args.notify, args.accept_risk))
        if args.what == "set-network":
            return said(m.set_network(args.index, args.category))
        if args.what == "setup":
            done = m.setup(log=print, steps=args.steps or None)
            return 0 if all(d["ok"] is not False for d in done) else 1
        if args.what == "exposure":
            hits = m.exposing(sorted(set(app_ports().values())))
            print("\n".join(f"{p}: {label}" for p, label in hits) or "no rule lets another machine reach the framework's pages")
            return 1 if hits else 0
        if args.what == "allow":
            rule = m.allow(args.name, [int(p) for p in args.ports.split(",")], protocol=args.protocol, detail="made from the command line")
            print(f"made: {rule.label}")
            return 0
        if args.what == "remove":
            print("removed" if m.remove(args.name) else f"no Liminal rule named {args.name}")
            return 0
        if args.what == "run":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            if command:
                print(m.run(*command), end="")
                return 0
    except RiskRefused as e:
        print(f"refused: {e} (--accept-risk changes it anyway)", file=sys.stderr)
        return 1
    except (CommandError, ValueError) as e:
        print(str(e), file=sys.stderr)
        return 1
    parser().print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
