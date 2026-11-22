"""What every test here shares: the machine the tests run on never shows through. Not inside WSL (the library's
world.under_wsl and, from liminal-libs 1.65.0, sockets.under_wsl, which a suite run inside a WSL distribution would
otherwise find), no init known (world._init), and Windows wherever the suite runs (the plugin's _platform: since 0.7.0
the plugin is Windows' alone, not_for_here), so the tabs' pages read alike on Windows, inside a WSL distribution and on
any Linux. A test that wants another says so itself (the plugin's `system`).

`no_real_hosts` (0.7.0; B-critique B1), every test's, asked for by none: from liminal-libs 1.65.0 a plugin a test
attaches reads its hosts' recording setting through its login, and a login with no variables of its own reads this
user's (the platform's EnvironmentLogin, the saved ones under the process's), so once the user chose "always" such a
test would start a thread reading this PC's socket table into this PC's own hosts database; and every ask of the
Netstat or the World Wide Web tab reads the socket table. So each test runs with LIMINAL_HOSTS_RECORDING set to "shown"
in its process (which wins over a saved one), the socket reader refused (`Reached`, a BaseException that no `except
Exception` in the code swallows, noted too and failed at the test's end: sockets.read, which the code looks up when it
reads), and the hosts database and the infrastructure layers' folder in the test's own folder (its tmp_path where it
has one, else one made the first time either is asked); each hosts database opened there is let go after it. A test
that reads a socket table gives the code a reader of its own (a stand-in for sockets.read), as the library's own suite
does. A library before 1.65.0 has neither: the variable alone is set, and its World Wide Web tab is 0.6.1's."""
from __future__ import annotations

import threading

import pytest

import plugin_platform_firewall_windows as plugin_module
from liminal_libs.machines import world

try:
    from liminal_libs import hostbook, sockets  # liminal-libs 1.65.0: the socket tables and the hosts database
    from liminal_libs.machines import infrastructure
except ImportError:  # a library before it: no tab of this plugin reads a socket or keeps a host
    hostbook = sockets = infrastructure = None
HOSTS_VARIABLE = "LIMINAL_HOSTS_RECORDING"  # liminal-libs 1.65.0's hostbook.VARIABLE, named here for older libraries


class Reached(BaseException):
    """The code under test reached this PC's real socket table: not an Exception, so the code cannot swallow it."""


@pytest.fixture(autouse=True)
def _not_this_machine(monkeypatch):
    monkeypatch.setattr(world, "under_wsl", lambda *args, **kwargs: None)
    monkeypatch.setattr(world, "_init", lambda: "")
    if sockets is not None:
        monkeypatch.setattr(sockets, "under_wsl", lambda *args, **kwargs: None)
    monkeypatch.setattr(plugin_module, "_platform", lambda: "win32")


@pytest.fixture(autouse=True)
def no_real_hosts(monkeypatch, request, tmp_path_factory):
    """Every test: no recording all the time by the user's own setting, no socket table read for real, and the hosts
    database and the infrastructure layers kept in the test's own folder (the module's docstring). Yields the reads
    refused, so the guard's own test can clear the one it makes on purpose."""
    monkeypatch.setenv(HOSTS_VARIABLE, "shown")
    if sockets is None:
        yield []
        return
    folder = request.getfixturevalue("tmp_path") if "tmp_path" in request.fixturenames else None
    lock = threading.Lock()

    def own():  # the test's own folder: made when first asked, from whichever thread asks
        nonlocal folder
        with lock:
            if folder is None:
                folder = tmp_path_factory.mktemp("no-real-hosts")
            return folder

    refused: list[str] = []

    def read(*args, **kwargs):
        refused.append(f"sockets.read {args[:1]!r}"[:300])
        raise Reached("the test read this PC's socket table for real: give the code a reader of its own")

    monkeypatch.setenv(hostbook.VARIABLE, "shown")  # the library's own name for it (HOSTS_VARIABLE today)
    monkeypatch.setattr(sockets, "read", read)
    monkeypatch.setattr(hostbook, "path", lambda: own() / "liminal-data" / hostbook.FOLDER / hostbook.FILE)
    monkeypatch.setattr(hostbook, "_BOOKS", {})
    monkeypatch.setattr(infrastructure, "folder", lambda: own() / "liminal-data" / infrastructure.FOLDER)
    yield refused
    for book in list(hostbook._BOOKS.values()):  # the hosts databases opened in the test: written and let go
        try:
            book.close()
        except Exception:  # noqa: BLE001 - one a test broke on purpose
            pass
    assert not refused, f"the test read this PC's socket table for real: {refused}"


@pytest.fixture(autouse=True)
def _no_real_trace(monkeypatch):
    """liminal-libs 1.67.0: the World Wide Web tab traces every connection's route while it is asked. In a test no route
    is traced for real (Windows' ICMP API and the tracers are refused: the test that reaches them fails) and the routes'
    thread never starts (a stand-in that starts nothing). A library before 1.67.0 traces nothing."""
    try:
        from liminal_libs import netpath
        from liminal_libs.machines import routes
    except ImportError:
        return

    def refused(*args, **kwargs):
        raise AssertionError("the test traced a route for real: give netpath.trace a probe and a run of its own")
    monkeypatch.setattr(netpath, "_icmp_probe", refused)
    monkeypatch.setattr(netpath, "_trace_run", refused, raising=False)
    monkeypatch.setattr(routes.Routes, "_thread", staticmethod(lambda work: None))
    # liminal-libs 1.72.0: nor is a router looked up for real (its name by reverse DNS, its network by RDAP and the
    # registries' bootstrap files), and the lookups' thread never starts. A library before 1.72.0 has no lookups.
    try:
        from liminal_libs.machines import lookups
    except ImportError:
        return

    def looked_up(*args, **kwargs):
        raise AssertionError("the test looked a router up for real: give the lookups stand-ins")
    monkeypatch.setattr(lookups, "_ptr", looked_up)
    monkeypatch.setattr(lookups, "_get", looked_up)
    monkeypatch.setattr(lookups.Lookups, "_thread", staticmethod(lambda work: None))
