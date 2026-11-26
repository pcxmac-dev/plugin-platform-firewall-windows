"""What the plugin answers plugin-platform-worldwideweb (0.10.0, liminal-libs 1.105.0): the World Wide Web tab left the
Firewall base for that plugin, which asks a firewall through the platform what only a firewall knows. The base's
services answer from this plugin's Netstat view (the socket table's reading, the hosts recorded, the routes kept), and
the rules covering a port are said in Windows' own terms: its rules' ids, programs, services and groups, those naming
the port first, then a range holding it, then every port. Off Windows each refuses in words. A library before 1.105.0
has none of them: the tests are skipped there."""
from __future__ import annotations

import pytest

from plugin_platform_firewall_windows import world_in

from test_plugin import BUILTINS, FakeWindows, plugin, win_rule

pytestmark = pytest.mark.skipif(world_in(), reason="a library before 1.105.0: the World Wide Web tab is still this "
                                                   "plugin's, and no other plugin asks these")
SERVICES = ("netstat_seen", "hosts_found", "hosts_routes", "rules_covering", "hosts_keep_route", "hosts_keep_places",
            "hosts_clear_places")


def test_the_services_are_its_hooks_and_the_changes_only_another_plugin_asks():
    fw = plugin(FakeWindows())
    from liminal_libs import internal

    assert set(SERVICES) <= set(fw.HOOKS) and set(SERVICES) <= set(internal.declared(fw, "SERVICE_HOOKS"))
    assert {"hosts_keep_route", "hosts_keep_places", "hosts_clear_places"} <= set(internal.plugin_only(fw))
    assert internal.problems(fw) == []


def test_the_rules_covering_a_port_in_windows_own_terms():
    rules = [*BUILTINS, win_rule("{W1}", "Web server", local="443", program=r"C:\web\server.exe"),
             win_rule("{W2}", "Anything TCP", local="Any")]
    fw = plugin(FakeWindows(rules=rules))
    fw.snapshot(fresh=True, wait=5)
    covering = fw.rules_covering(443)
    assert [r["label"] for r in covering][:1] == ["Web server"] and covering[0]["why"] == "port 443/tcp"
    assert covering[0]["program"] == r"C:\web\server.exe" and covering[0]["name"] == "{W1}"
    assert {r["why"] for r in covering[1:]} == {"every port"}
    game = fw.rules_covering(27020)
    assert [r["label"] for r in game][0] == "Game server" and game[0]["why"] == "a range holding 27020"
    assert [r["label"] for r in fw.rules_covering(3389)][0] == "Remote Desktop - User Mode (TCP-In)"
    assert fw.rules_covering(3389)[0]["enabled"] is False  # turned off, said so
    assert all(r["direction"] == "out" for r in fw.rules_covering(53, "udp") if r["label"].startswith("Core"))
    for bad in ((0,), ("443",), (True,), (443, "icmp")):
        with pytest.raises(ValueError):
            fw.rules_covering(*bad)
    fw.detach()


@pytest.mark.parametrize("system", ["linux", "darwin"])
def test_off_windows_every_service_refuses_in_words(system):
    from liminal_libs.machines.windows import PowerShell
    from plugin_platform_firewall_windows import WindowsFirewallPlugin

    fake = FakeWindows()
    fw = WindowsFirewallPlugin(PowerShell(runner=fake, env={}), elevated=lambda: True, system=system)
    for hook, args in (("netstat_seen", ()), ("hosts_found", ("describe",)), ("hosts_routes", ()),
                       ("rules_covering", (443,)), ("hosts_keep_places", ("2026-11-01", {}))):
        with pytest.raises(ValueError, match="not for this machine"):
            getattr(fw, hook)(*args)
    assert fake.scripts == [] and fw.netstat_view(make=False) is None
