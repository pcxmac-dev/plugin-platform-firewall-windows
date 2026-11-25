"""A stand-in for this PC's networking as the plugin's network part reads and changes it (0.8.0), on top of
test_plugin.FakeWindows: the IPv4 addresses and routes (as recorded on this PC: Wi-Fi 192.168.50.228/24, the Default
Switch 172.27.144.1/20, WSL's adapter 172.31.0.1/20), the port proxies and the excluded port ranges; every network
change script applied to its own state and recorded. Nothing reaches this PC."""
from __future__ import annotations

import json
import re

from liminal_libs.machines.segments import Step
from liminal_libs.machines.windows import decoded

from test_plugin import FakeWindows, win_rule

ADDRESSES = [
    {"Index": 1, "Alias": "Loopback Pseudo-Interface 1", "Address": "127.0.0.1", "Length": 8},
    {"Index": 11, "Alias": "Wi-Fi", "Address": "192.168.50.228", "Length": 24},
    {"Index": 30, "Alias": "vEthernet (Default Switch)", "Address": "172.27.144.1", "Length": 20},
    {"Index": 42, "Alias": "vEthernet (WSL (Hyper-V firewall))", "Address": "172.31.0.1", "Length": 20},
]
ROUTES = [
    {"Prefix": "0.0.0.0/0", "Index": 11, "NextHop": "192.168.50.1", "Metric": 35, "Store": "ActiveStore"},
    {"Prefix": "192.168.50.0/24", "Index": 11, "NextHop": "0.0.0.0", "Metric": 291, "Store": "ActiveStore"},
    {"Prefix": "172.27.144.0/20", "Index": 30, "NextHop": "0.0.0.0", "Metric": 5256, "Store": "ActiveStore"},
    {"Prefix": "172.31.0.0/20", "Index": 42, "NextHop": "0.0.0.0", "Metric": 5256, "Store": "ActiveStore"},
    {"Prefix": "224.0.0.0/4", "Index": 1, "NextHop": "0.0.0.0", "Metric": 331, "Store": "ActiveStore"},
]
EXCLUDED = ("\nProtocol tcp Port Exclusion Ranges\n\nStart Port    End Port\n----------    --------\n"
            "      5357        5357\n     50000       50059     *\n\n* - Administered port exclusions.\n")
PROXY_HEAD = "\nListen on ipv4:             Connect to ipv4:\n\nAddress         Port        Address         Port\n" \
             "--------------- ----------  --------------- ----------\n"


class FakeNet(FakeWindows):
    def __init__(self, *args, addresses=None, routes=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.addresses = [dict(a) for a in (addresses if addresses is not None else ADDRESSES)]
        self.routes = [dict(r) for r in (routes if routes is not None else ROUTES)]
        self.proxies: list[tuple] = []  # (listen, port, connect, connect_port)
        self.net_reads = 0
        self.changes: list[str] = []

    def __call__(self, args, timeout):
        s = decoded(args[6])
        if "Get-NetIPAddress -AddressFamily IPv4" in s and "portproxy show v4tov4" in s:
            self.scripts.append(s)
            self.net_reads += 1
            table = PROXY_HEAD + "".join(f"{a:<16}{p:<12}{c:<16}{cp}\n" for a, p, c, cp in self.proxies)
            return 0, json.dumps({"Addresses": self.addresses, "Routes": self.routes, "Proxies": table,
                                  "Excluded": EXCLUDED}), ""
        if any(k in s for k in ("New-NetRoute", "Remove-NetRoute", "portproxy add", "portproxy delete")) or (
                "svc-" in s and "NetFirewallRule" in s):
            self.scripts.append(s)
            self.changes.append(s)
            if self.denied:
                from liminal_libs.machines.windows import ERROR_MARK

                return 1, ERROR_MARK + "Access is denied.\r\n", ""
            for line in s.splitlines():
                m = re.search(r"Get-NetRoute -DestinationPrefix '([^']+)' -PolicyStore ActiveStore", line)
                if m:
                    self.routes = [r for r in self.routes if r["Prefix"] != m.group(1)]
                m = re.search(r"New-NetRoute -DestinationPrefix '([^']+)' -InterfaceIndex (\d+) -NextHop '([^']+)'", line)
                if m:
                    self.routes.append({"Prefix": m.group(1), "Index": int(m.group(2)), "NextHop": m.group(3),
                                        "Metric": 256, "Store": "ActiveStore"})
                m = re.search(r"portproxy add v4tov4 listenaddress=(\S+) listenport=(\d+) connectaddress=(\S+) "
                              r"connectport=(\d+)", line)
                if m:
                    self.proxies.append((m.group(1), int(m.group(2)), m.group(3), int(m.group(4))))
                m = re.search(r"portproxy delete v4tov4 listenaddress=(\S+) listenport=(\d+)", line)
                if m:
                    self.proxies = [p for p in self.proxies if (p[0], p[1]) != (m.group(1), int(m.group(2)))]
                m = re.search(r"\$_\.DisplayName -eq '([^']+)'", line)
                if m:
                    self.rules = [r for r in self.rules if not (r["Name"] == m.group(1) and r["Group"] == "Liminal")]
                m = re.search(r"New-NetFirewallRule .*-DisplayName '([^']+)'.*-LocalPort (\d+)", line)
                if m:
                    rule = win_rule(f"{{svc-{len(self.rules)}}}", m.group(1), "Liminal", protocol="TCP", local=m.group(2))
                    rule["Remote"] = "LocalSubnet"
                    rule["Profile"] = "Private, Domain"
                    self.rules.append(rule)
            return 0, "", ""
        return super().__call__(args, timeout)


def sample_steps() -> list[Step]:
    route = {"stack": "wsl", "prefix": "10.77.1.0/24", "next_hop": "172.31.5.9", "interface": 42,
             "segment": "docker/wsl-ubuntu/liminal-jenkins-ci", "made": 0.0}
    proxy = {"sid": "jenkins/ci", "stack": "wsl", "name": "web", "host": 8080, "protocol": "tcp", "container": 8080,
             "part": "controller", "proxy": True, "listen": "192.168.50.228", "connect": "10.77.1.10",
             "connect_port": 8080, "rule": "svc-jenkins-ci-8080"}
    return [Step("route", "a route", route), Step("proxy", "a proxy", proxy)], \
        [Step("unproxy", "the proxy away", proxy), Step("unroute", "the route away", route)]


def drive_network(fw) -> None:
    """The network read and one plan's steps each way, as the plugin's own work runs them."""
    fw.net_facts(fresh=True)
    fw.excluded_ports()
    make, take = sample_steps()
    fw.run_steps(make, lambda line: None, lambda: False)
    fw.run_steps(take, lambda line: None, lambda: False)
