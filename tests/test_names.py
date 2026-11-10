"""Each rule's name in its group (0.4.0; the user: "lets group by application under apps or system, try best to organize
under system and applications. Like system has 'core networking' or WSD or UPnP or RA Server or Remote Assistance or
network discovery or ... applications has like starcraft or edge"; "try to group the system by 'services'"; "also rules
that are turned off should be shown as well"): a System rule named by its service, an Application rule by its
application, Windows' own rule groups the system's even for a program under Program Files, the rules turned off shown
after those turned on, and the read naming the services and the programs. Windows' own names and invented ones only
(Contoso's); nothing here reads this PC."""
from __future__ import annotations

import re

from test_plugin import FakeWindows, plugin, text, win_rule

from liminal_libs.machines.rulegroups import key_of
from plugin_platform_firewall_windows import (PRESETS, READ_SCRIPT, ROWS, WINDOWS_PUBLISHER, WinRule, families_of, install_folder,
                                              package_of, parse_snapshot, readable, sort_rule, sort_rules, windows_package,
                                              windows_resource)

WINDIR = r"C:\Windows"
SVCHOST = r"%SystemRoot%\system32\svchost.exe"
APP = "S-1-5-21-1"  # an app container's owner: a Microsoft Store app's rule
PUBLISHER = "1a2b3c4d5e6f7"  # an app package's publisher, its 13 characters
GUID = "{0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9}"  # a rule group that is a bare GUID
UNREAD = "ms-resource:ProductPkgDisplayName"  # a rule's name Windows did not resolve


def named(name="a rule", **kw):
    s = sort_rule(WinRule("{x}", name, **kw), windir=WINDIR)
    return s.group, s.name


def folder(path, **kw):
    return named(program=path, **kw)[1]


def test_system_rules_are_named_by_their_service():
    # Windows' own rule group, when it reads as words
    assert named(group="Network Discovery", source="@FirewallAPI.dll,-32752", service="fdphost", program=SVCHOST) == (
        "system", "Network Discovery")
    assert named("Core Networking - DNS (UDP-Out)", group="Core Networking", source="@FirewallAPI.dll,-25000", program="System") == (
        "system", "Core Networking")
    assert named(group="mDNS", source=r"@%SystemRoot%\system32\firewallapi.dll,-37302", service="dnscache", program=SVCHOST) == (
        "system", "mDNS")
    # else its Windows service's display name, its short name in a read before 0.4.0
    unread = "@FirewallAPI.dll,-99999"  # a resource Windows did not resolve
    assert not readable(unread) and not readable(GUID) and not readable(" ") and readable("Remote Assistance")
    assert not readable("ms-resource:AppDisplayName") and not readable("MS-RESOURCE://Contoso.App/Resources/Name")  # unresolved too
    assert named(group=unread, source=unread, service="Dnscache", service_name="DNS Client", program=SVCHOST) == ("system", "DNS Client")
    assert named(group=GUID, source=GUID, service="Spooler", service_name="Print Spooler", program=SVCHOST) == ("system", "Print Spooler")
    assert named(service="Dnscache", program=SVCHOST) == ("system", "Dnscache")
    # else its program's description, else its file name
    assert named(group=GUID, source=GUID, program=rf"C:\WINDOWS\SystemApps\Contoso.Shell_{PUBLISHER}\ShellHost.exe",
                 file_description="Contoso Shell Host") == ("system", "Contoso Shell Host")
    assert named(program=r"%windir%\system32\mfpmp.exe") == ("system", "mfpmp.exe")
    # Windows' own app packages by their group, else together as Windows' own apps; the System process with no group
    start = f"@{{Contoso.Start_1.0.0.0_x64__{PUBLISHER}?ms-resource://Contoso.Start/Resources/Name}}"
    assert named(group="Start", source=start, package=f"Contoso.Start_{PUBLISHER}", package_system=True, owner=APP) == ("system", "Start")
    assert named(start, group=start, source=start, package=f"Contoso.Start_{PUBLISHER}", package_system=True, owner=APP) == (
        "system", "Windows' own apps")
    assert named(program="System") == ("system", "System process")


def test_application_rules_are_named_by_their_application():
    assert named(group="Liminal", program=r"C:\Python\python.exe") == ("application", "Liminal")
    # its own rule group, when it reads as words: Microsoft Edge apart from Microsoft Edge WebView2 Runtime
    assert named("Microsoft Edge (mDNS-In)", group="Microsoft Edge", source="Microsoft Edge",
                 program=r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe") == ("application", "Microsoft Edge")
    assert named(group="Microsoft Edge WebView2 Runtime", source="Microsoft Edge WebView2 Runtime",
                 program=r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\120.0.1.2\msedgewebview2.exe") == (
        "application", "Microsoft Edge WebView2 Runtime")
    # else its install folder: one name for its versions and its programs
    assert folder(r"C:\Program Files (x86)\Contoso Quest\Versions\Base11111\Quest_x64.exe") == "Contoso Quest"
    assert folder(r"C:\Program Files (x86)\Contoso Quest\Versions\Base22222\Quest_x64.exe") == "Contoso Quest"
    assert folder(r"C:\Program Files (x86)\Steam\steam.exe") == folder(r"C:\Program Files (x86)\Steam\bin\cef\webhelper.exe") == "Steam"
    assert folder(r"%ProgramFiles%\Contoso Notes\notes.exe") == "Contoso Notes"
    assert folder(r"C:\ProgramData\Contoso Agent\2.1\agent.exe") == "Contoso Agent"
    assert folder(r"C:\Users\someone\AppData\Local\Programs\Contoso Code\code.exe") == "Contoso Code"
    assert folder(r"C:\Users\someone\AppData\Local\Programs\Python\Python313\python.exe") == "Python"
    assert folder(r"%LOCALAPPDATA%\Contoso Chat\app-1.2.3\chat.exe") == "Contoso Chat"
    assert folder(r"C:\Users\someone\AppData\Roaming\Contoso Meet\bin\meet.exe") == "Contoso Meet"
    # one deeper in a vendor's folder holding several products, or where the one inside starts with its name
    assert folder(r"C:\Program Files\Google\Chrome\Application\chrome.exe") == "Chrome"
    assert folder(r"C:\Program Files\JetBrains\Contoso IDE 2030.1\bin\ide64.exe") == "Contoso IDE 2030.1"
    assert folder(r"C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeClickToRun.exe") == "ClickToRun"
    assert folder(r"C:\Program Files\Contoso\Contoso Paint\paint.exe") == "Contoso Paint"
    assert folder(r"C:\Program Files\Contoso\bin\tool.exe") == "Contoso" and folder(r"C:\Program Files\Dell\tool.exe") == "Dell"
    # a game's own folder in a Steam library, or the Xbox app's
    assert folder(r"C:\Program Files (x86)\Steam\steamapps\common\Contoso Racer\bin\racer.exe") == "Contoso Racer"
    assert folder(r"D:\SteamLibrary\steamapps\common\Contoso Racer\racer.exe") == "Contoso Racer"
    assert folder(r"C:\XboxGames\Contoso Flight\Content\flight.exe") == "Contoso Flight"
    # an application's own folder in a launcher's library
    assert folder(r"C:\Program Files (x86)\GOG Galaxy\Games\Contoso Saga\saga.exe") == "Contoso Saga"
    assert folder(r"C:\Program Files (x86)\GOG Galaxy\GalaxyClient.exe") == "GOG Galaxy"
    assert folder(r"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\games\Contoso Siege\bin\siege.exe") == "Contoso Siege"
    assert folder(r"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\upc.exe") == "Ubisoft Game Launcher"
    assert folder(r"C:\Users\someone\AppData\Local\JetBrains\Toolbox\apps\Contoso-IDE\ch-0\2030.1\bin\ide64.exe") == "Contoso-IDE"
    assert folder(r"C:\Program Files (x86)\Origin Games\Contoso Field\field.exe") == "Contoso Field"
    # in a temporary folder or the installers' cache it is in no install folder: elsewhere, it is named by its rules' own
    # name without the part in brackets, else by its product name, else by its file name
    for temp in (r"C:\Users\someone\AppData\Local\Temp\7zS01\setup.exe", r"%LOCALAPPDATA%\Temp\contoso\agent.exe",
                 rf"C:\ProgramData\Package Cache\{GUID}\setup.exe", r"C:\Games\server.exe", r"C:\Program Files\tool.exe"):
        assert install_folder(temp) == "", temp
    assert folder(r"C:\Users\someone\AppData\Local\Temp\7zS01\setup.exe") == "a rule"
    assert named("Contoso Server (TCP-In)", program=r"C:\Games\server.exe", product="Contoso Host") == ("application", "Contoso Server")
    assert named("ms-resource:AppDisplayName", program=r"C:\Games\server.exe", product="Contoso Host") == ("application", "Contoso Host")
    assert named(f"TCP Query User{GUID}c:\\games\\server.exe", program=r"C:\Games\server.exe") == ("application", "server.exe")
    assert install_folder(r"C:\Users\someone\AppData\Local\Microsoft\WindowsApps\contoso.exe") == ""  # an app's alias: no folder of its own
    # a program in an app package's folder: its family's name (sort_rules), else its rules' own name, its product name, the
    # family's name part
    packaged = rf"C:\Program Files\WindowsApps\Contoso.Notes_1.2.3.0_x64__{PUBLISHER}\app\notes.exe"
    assert package_of(packaged) == (f"Contoso.Notes_{PUBLISHER}", "Contoso.Notes") and package_of(r"C:\Games\server.exe") == ("", "")
    assert named("Contoso Notes", group=GUID, program=packaged, product="Notes Engine")[1] == "Contoso Notes"
    assert named(UNREAD, program=packaged, product="Contoso Notes")[1] == "Contoso Notes" and named(UNREAD, program=packaged)[1] == "Contoso.Notes"
    # an app's own rule with no program: its group, else its name without the part in brackets, else its family's name part
    family = f"Contoso.Photos_{PUBLISHER}"
    assert named(group="Contoso Photos", package=family, owner=APP) == ("application", "Contoso Photos")
    assert named("Contoso Photos (Inbound)", package=family, owner=APP) == ("application", "Contoso Photos")
    photos = f"@{{Contoso.Photos_1.0.0.0_x64__{PUBLISHER}?ms-resource://Contoso.Photos/Resources/Name}}"
    assert named(photos, group=photos, source=photos, package=family, owner=APP) == ("application", "Contoso.Photos")
    assert named() == ("other", "")  # Other has no name


def test_the_read_taken_whole_names_an_apps_programs_and_spells_each_name_one_way():
    family = f"Contoso.Notes_{PUBLISHER}"
    notes = rf"C:\Program Files\WindowsApps\Contoso.Notes_1.2.3.0_x64__{PUBLISHER}"
    rules = [WinRule("{n1}", "Notes by Contoso", group="Notes by Contoso", package=family, owner=APP),  # the app's own rule names it
             WinRule("{n2}", "notes.exe", group=GUID, source=GUID, program=notes + r"\app\notes.exe", product="Notes"),
             WinRule("{n3}", "helper", program=rf"c:\program files\windowsapps\contoso.notes_1.2.4.0_x64__{PUBLISHER}\helper.exe"),
             WinRule("{q1}", "quest", program=r"c:\program files (x86)\contoso quest\versions\base11111\quest_x64.exe"),  # gone from disk
             WinRule("{q2}", "quest", program=r"c:\program files (x86)\contoso quest\versions\base22222\quest_x64.exe",
                     on_disk=r"C:\Program Files (x86)\Contoso Quest\Versions\Base22222\Quest_x64.exe"),  # as spelled on disk
             WinRule("{q3}", "quest", program=r"c:\program files (x86)\contoso quest\versions\base33333\quest_x64.exe"),
             WinRule("{z1}", "Liminal: web", group="Liminal", program=notes + r"\x.exe")]
    assert families_of(rules, WINDIR) == {family.casefold(): "Notes by Contoso"}  # Liminal's own rules name no app
    assert {k: (s.group, s.name) for k, s in sort_rules(rules, windir=WINDIR).items()} == {
        "{n1}": ("application", "Notes by Contoso"), "{n2}": ("application", "Notes by Contoso"),
        "{n3}": ("application", "Notes by Contoso"), "{q1}": ("application", "Contoso Quest"),
        "{q2}": ("application", "Contoso Quest"), "{q3}": ("application", "Contoso Quest"), "{z1}": ("application", "Liminal")}
    assert sort_rule(rules[3], windir=WINDIR).name == "contoso quest"  # alone: as the rule spells it
    # no program on disk: the rules' own names spell a name all in lowercase (one that only starts so does not)
    gone = [WinRule("{r1}", "Contoso Racer", program=r"c:\program files (x86)\contoso racer\versions\base1\racer.exe"),
            WinRule("{r2}", "racer", program=r"c:\program files (x86)\contoso racer\versions\base2\racer.exe"),
            WinRule("{d1}", "Contoso Saga Retail", program=r"c:\program files (x86)\contoso saga\saga.exe"),
            WinRule("{t1}", "Contosoft Tool", program=r"c:\program files\contoso\tool.exe")]
    assert [s.name for s in sort_rules(gone, windir=WINDIR).values()] == ["Contoso Racer", "Contoso Racer", "Contoso Saga", "contoso"]


def test_windows_own_rule_groups_are_the_systems_even_for_a_program_under_program_files():
    for own in ("@FirewallAPI.dll,-31002", "@firewallapi.dll,-1", "@peerdistsh.dll,-9000", r"@%SystemRoot%\system32\vmms.exe,-1",
                r"@%windir%\system32\icsvc.dll,-2", r"@C:\WINDOWS\System32\wlansvc.dll,-3",
                r"@%ProgramFiles%\Windows Media Player\wmploc.dll,-4", r"@C:\Program Files (x86)\Windows Media Player\wmploc.dll,-5"):
        assert windows_resource(own, WINDIR), own
    for theirs in (r"@C:\Program Files\Contoso Sync\res.dll,-100", r"@%ProgramFiles%\Contoso\Contoso Sync\res.dll,-1",
                   r"@C:\Users\someone\AppData\Local\Contoso\res.dll,-1", r"@C:\Windows Tools\res.dll,-1", r"@D:\Windows\res.dll,-1",
                   f"@{{Contoso.App_1.0.0.0_x64__{PUBLISHER}?ms-resource://Contoso.App/Resources/Name}}", "Contoso Sync", "@", ""):
        assert not windows_resource(theirs, WINDIR), theirs
    player = sort_rule(WinRule("{p1}", "Windows Media Player (UDP-In)", group="Windows Media Player", source="@FirewallAPI.dll,-31002",
                               program=r"%ProgramFiles%\Windows Media Player\wmplayer.exe"), windir=WINDIR)
    assert (player.group, player.why, player.name) == ("system", "Windows' own rule group Windows Media Player, for wmplayer.exe",
                                                       "Windows Media Player")
    sharing = sort_rule(WinRule("{p2}", "Windows Media Player Network Sharing Service (TCP-In)", source="@FirewallAPI.dll,-31252",
                                group="Windows Media Player Network Sharing Service",
                                program=r"%PROGRAMFILES%\Windows Media Player\wmpnetwk.exe"), windir=WINDIR)
    assert (sharing.group, sharing.name) == ("system", "Windows Media Player Network Sharing Service")
    # a program's own resource is not Windows': its rule is the program's (Application), Other with no program
    sync = {"group": "Contoso Sync", "source": r"@C:\Program Files\Contoso Sync\res.dll,-100"}
    s = sort_rule(WinRule("{c1}", "Contoso Sync (TCP-In)", program=r"C:\Program Files\Contoso Sync\sync.exe", **sync), windir=WINDIR)
    assert (s.group, s.why, s.name) == ("application", r"the program C:\Program Files\Contoso Sync\sync.exe", "Contoso Sync")
    s = sort_rule(WinRule("{c2}", "Contoso Sync", service="ContosoSvc", program=r"C:\Program Files\Contoso Sync\svc.exe", **sync), windir=WINDIR)
    assert s.group == "application" and sort_rule(WinRule("{c3}", "Contoso Sync (UDP-In)", **sync), windir=WINDIR).group == "other"


def own_part(number, part, version="1000.1.0.0"):
    """One of Windows' own parts as an earlier version of it left its rule: its family, and its group, a resource
    Windows no longer reads (the package is gone)."""
    family = f"MicrosoftWindows.{number}.{part}_{WINDOWS_PUBLISHER}"
    return family, (f"@{{MicrosoftWindows.{number}.{part}_{version}_x64__{WINDOWS_PUBLISHER}"
                    f"?ms-resource://MicrosoftWindows.{number}.{part}/Resources/Name}}")


def test_windows_own_app_packages_are_the_systems_an_earlier_versions_left_behind_too():
    assert windows_package(f"Microsoft.Contoso_{WINDOWS_PUBLISHER}") and windows_package(f"x_{WINDOWS_PUBLISHER.upper()}")
    assert not windows_package(f"Contoso.App_{PUBLISHER}") and not windows_package("") and not windows_package(WINDOWS_PUBLISHER)
    old, old_group = own_part(10000001, "Sample")
    gone, gone_group = own_part(10000003, "Lonely")
    pack = "Windows Feature Experience Pack"
    rules = [  # an earlier version's: not signed as the system's in the read, its group no longer read; named as its current one
        WinRule("{o1}", old_group, group=old_group, source=old_group, package=old, owner=APP),
        WinRule("{o2}", pack, group=pack, package=own_part(20000002, "Sample")[0], package_system=True, owner=APP),
        WinRule("{o3}", gone_group, group=gone_group, source=gone_group, package=gone, owner=APP),  # no current one: together
        # published by Microsoft Windows but not signed as the system's (updated from the Store): Windows' own all the same
        WinRule("{w1}", "Contoso Widgets", group="Contoso Widgets", package=f"MicrosoftWindows.Client.Widgets_{WINDOWS_PUBLISHER}", owner=APP),
        WinRule("{w2}", "widgets", group=GUID,
                program=rf"C:\Program Files\WindowsApps\MicrosoftWindows.Client.Widgets_1.0.0.0_x64__{WINDOWS_PUBLISHER}\widgets.exe"),
        # Windows' own apps' programs in SystemApps: named as their family's rules are, not by their file names
        WinRule("{s1}", UNREAD, group=GUID, program=rf"C:\WINDOWS\SystemApps\MicrosoftWindows.Client.Sample_{WINDOWS_PUBLISHER}\Host.exe"),
        WinRule("{s2}", pack, group=pack, package=f"MicrosoftWindows.Client.Sample_{WINDOWS_PUBLISHER}", package_system=True, owner=APP),
        WinRule("{s3}", UNREAD, group=GUID, program=rf"C:\WINDOWS\SystemApps\MicrosoftWindows.Client.Other_{WINDOWS_PUBLISHER}\Other.exe"),
        # another publisher's: an application's, an earlier version named as its current one, never as another publisher's
        WinRule("{t1}", "Contoso Pack", group="Contoso Pack", package=f"Contoso.20000002.Pack_{PUBLISHER}", owner=APP),
        WinRule("{t2}", "@{x}", group="@{x}", package=f"Contoso.10000001.Pack_{PUBLISHER}", owner=APP),
        WinRule("{t3}", "@{x}", group="@{x}", package="Contoso.10000001.Pack_7g8h9i0j1k2l3", owner=APP)]
    got = sort_rules(rules, windir=WINDIR)
    assert {k: (s.group, s.name) for k, s in got.items()} == {
        "{o1}": ("system", pack), "{o2}": ("system", pack), "{o3}": ("system", "Windows' own apps"),
        "{w1}": ("system", "Contoso Widgets"), "{w2}": ("system", "Contoso Widgets"),
        "{s1}": ("system", pack), "{s2}": ("system", pack), "{s3}": ("system", "Windows' own apps"),
        "{t1}": ("application", "Contoso Pack"), "{t2}": ("application", "Contoso Pack"),
        "{t3}": ("application", "Contoso.10000001.Pack")}
    assert got["{o1}"].why == "Windows' own app MicrosoftWindows.10000001.Sample"
    assert got["{w2}"].why == "widgets.exe, of Windows' own app MicrosoftWindows.Client.Widgets"
    assert got["{s1}"].why == "Host.exe, in Windows' folder"
    assert (sort_rule(rules[0], windir=WINDIR).group, sort_rule(rules[0], windir=WINDIR).name) == ("system", "Windows' own apps")  # alone
    assert package_of(rf"C:\Windows\SystemApps\MicrosoftWindows.Client.Sample_{WINDOWS_PUBLISHER}\Host.exe") == (
        f"MicrosoftWindows.Client.Sample_{WINDOWS_PUBLISHER}", "MicrosoftWindows.Client.Sample")
    assert package_of(r"C:\Windows\SystemApps\Shared\x.exe") == ("", "")


def test_an_applications_programs_and_versions_have_one_name():
    edge = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    studio = rf"C:\Program Files\WindowsApps\Contoso.Studio_2.0.0.0_x64__{PUBLISHER}"
    paint = rf"C:\Program Files\WindowsApps\Fabrikam.Paint_3.0.0.0_x64__{PUBLISHER}"
    rules = [
        # a rule with no group (Windows' prompt makes them) named by the group its program's other rules, or its folder's, carry
        WinRule("{e1}", "Microsoft Edge (mDNS-In)", group="Microsoft Edge", source="Microsoft Edge", program=edge),
        WinRule("{e2}", "Microsoft Edge", program=edge.lower()),
        WinRule("{e3}", "Edge helper", program=r"C:\Program Files (x86)\Microsoft\Edge\Application\9.9\identity_helper.exe"),
        WinRule("{v1}", "Microsoft Edge (mDNS-In)", group="Microsoft Edge WebView2 Runtime",
                program=r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\9.9\msedgewebview2.exe"),
        # an app package no rule names: one name for its programs and versions, the one its rules carry, else the product
        # name most of its programs on disk carry
        WinRule("{a1}", "Contoso Studio", group=GUID, program=studio + r"\studio.exe", product="Contoso Studio"),
        WinRule("{a2}", "Contoso Studio", group=GUID, program=studio + r"\helper\render.exe", product="Contoso Render Engine"),
        WinRule("{a3}", "Contoso Studio", group=GUID, program=studio.replace("2.0.0.0", "1.0.0.0") + r"\studio.exe"),  # gone
        WinRule("{p1}", UNREAD, group=GUID, program=paint + r"\paint.exe", product="Fabrikam Paint"),
        WinRule("{p2}", UNREAD, group=GUID, program=paint + r"\launcher.exe", product="Fabrikam Paint"),
        WinRule("{p3}", UNREAD, group=GUID, program=paint + r"\engine\render.exe", product="Fabrikam Render Engine"),
        WinRule("{p4}", UNREAD, group=GUID, program=paint.replace("3.0.0.0", "2.0.0.0") + r"\paint.exe"),  # gone
        # elsewhere: the group, else the name, the rules for its folder carry; not each file's product or file name
        WinRule("{g1}", "Contoso Quest", program=r"D:\Games\Contoso Quest\Versions\Base1\quest.exe"),  # gone
        WinRule("{g2}", "Contoso Quest", program=r"D:\Games\Contoso Quest\Versions\Base2\quest.exe", product="Quest Engine",
                on_disk=r"D:\Games\Contoso Quest\Versions\Base2\quest.exe"),
        WinRule("{l1}", "Contoso Launcher", program=r"D:\GameA\launcher.exe", product="Launcher"),
        WinRule("{l2}", "Fabrikam Launcher", program=r"E:\GameB\launcher.exe", product="Launcher"),  # the same file name: apart
        WinRule("{t1}", "Contoso Tools (TCP-In)", group="Contoso Tools", program=r"D:\Tools\a.exe"),
        WinRule("{t2}", "b.exe", program=r"D:\Tools\b.exe"),
        WinRule("{m1}", "Fabrikam Sync", group="Fabrikam Sync", program=r"D:\Mixed\sync.exe"),
        WinRule("{m2}", "Contoso Backup", group="Contoso Backup", program=r"D:\Mixed\backup.exe"),
        WinRule("{m3}", "helper", program=r"D:\Mixed\helper.exe")]  # two groups in its folder: neither given to it
    got = {k: s.name for k, s in sort_rules(rules, windir=WINDIR).items()}
    assert got == {"{e1}": "Microsoft Edge", "{e2}": "Microsoft Edge", "{e3}": "Microsoft Edge",
                   "{v1}": "Microsoft Edge WebView2 Runtime",
                   "{a1}": "Contoso Studio", "{a2}": "Contoso Studio", "{a3}": "Contoso Studio",
                   "{p1}": "Fabrikam Paint", "{p2}": "Fabrikam Paint", "{p3}": "Fabrikam Paint", "{p4}": "Fabrikam Paint",
                   "{g1}": "Contoso Quest", "{g2}": "Contoso Quest", "{l1}": "Contoso Launcher", "{l2}": "Fabrikam Launcher",
                   "{t1}": "Contoso Tools", "{t2}": "Contoso Tools",
                   "{m1}": "Fabrikam Sync", "{m2}": "Contoso Backup", "{m3}": "helper"}
    assert [sort_rule(r, windir=WINDIR).name for r in rules[7:11]] == [  # each file alone would split the app
        "Fabrikam Paint", "Fabrikam Paint", "Fabrikam Render Engine", "Fabrikam.Paint"]


def test_turned_off_rules_are_shown_after_those_turned_on():
    quest = r"C:\Program Files (x86)\Contoso Quest\quest.exe"
    rules = [win_rule("RA-Off", "Remote Assistance (RA Server TCP-In)", "Remote Assistance", "@FirewallAPI.dll,-33002", enabled=False,
                      program=r"%SystemRoot%\system32\raserver.exe"),
             win_rule("ND-WSD", "Network Discovery (WSD-In)", "Network Discovery", "@FirewallAPI.dll,-32752", local="3702", program=SVCHOST),
             win_rule("RA-On", "Remote Assistance (SSDP TCP-In)", "Remote Assistance", "@FirewallAPI.dll,-33002", local="2869", program="System"),
             win_rule("ND-UPnP", "Network Discovery (UPnP-In)", "Network Discovery", "@FirewallAPI.dll,-32752", enabled=False, local="2869",
                      program="System"),
             win_rule("{G1}", "Contoso Quest", program=quest, enabled=False),
             win_rule("{B1}", "Block 9", action="Block", local="9", enabled=False),
             win_rule("{O1}", "Contoso Quest out", direction="Outbound", program=quest)]
    fw = plugin(FakeWindows(rules=rules))
    snap = fw.snapshot(wait=5)
    assert [r.id for r in snap.rules if PRESETS["in-allow"][1](r)] == ["RA-Off", "ND-WSD", "RA-On", "ND-UPnP", "{G1}"]
    assert [r.id for r in snap.rules if PRESETS["in-block"][1](r)] == ["{B1}"] and PRESETS["out"][1](snap.rules[-1])
    t = fw.status()["tables"][2]
    assert [r["key"] for r in t["rows"]] == [key_of(x) for x in ("ND-WSD", "RA-On", "RA-Off", "ND-UPnP", "{G1}")]  # on, then off
    assert [r.get("off", False) for r in t["rows"]] == [False, False, True, True, True]
    assert [text(r["cells"][0]) for r in t["rows"] if r.get("sub") == "system:remote assistance"] == [
        "Remote Assistance (SSDP TCP-In)", "Remote Assistance (RA Server TCP-In)"]  # in its heading too: RA Server's, turned off, after
    by = {g["id"]: g for g in t["groups"]}
    assert [(c["title"], c["count"]) for c in by["system"]["children"]] == [("Network Discovery", 2), ("Remote Assistance", 2)]
    assert [(c["title"], c["count"]) for c in by["application"]["children"]] == [("Contoso Quest", 1)]
    assert {c["value"]: c["note"] for c in t["options"][0]["choices"]} == {
        "in-allow": "5 rules, 3 turned off", "in-block": "1 rule", "out": "1 rule", "liminal": "0 rules", "off": "4 rules",
        "all": "7 rules, 4 turned off"}
    assert t["note"].startswith("5 shown (3 turned off): inbound allowed;")
    assert fw.show_rules("off")["ok"] and [r.id for r in fw.rules_shown()[1]] == ["RA-Off", "ND-UPnP", "{G1}", "{B1}"]  # it stays
    assert fw.status()["tables"][2]["note"].startswith("4 shown: turned off;")  # none of them on: nothing more to say
    fw.find_rules(None, 2869)  # a port: the rules naming it first, those turned on first among them alike
    assert [r.id for r in fw.rules_shown()[1]] == ["RA-On", "ND-UPnP", "{O1}", "RA-Off", "{G1}"]


def test_the_page_lists_every_rule_of_each_service_and_application_named_as_read():
    rules = [dict(win_rule("{S1}", "Contoso relay", program=SVCHOST), Service="contosorelay"),
             dict(win_rule("CoreNet-DHCP-In", "Core Networking - DHCP (DHCP-In)", "Core Networking", "@FirewallAPI.dll,-25301",
                           program=SVCHOST), Service="dhcp"),
             win_rule("{Q1}", "quest", program=r"c:\program files (x86)\contoso quest\versions\base1\quest.exe"),
             win_rule("{Q2}", "quest", program=r"c:\program files (x86)\contoso quest\versions\base2\quest.exe"),
             *(win_rule(f"FPS-{i}", f"File and Printer Sharing ({i}-In)", "File and Printer Sharing", "@FirewallAPI.dll,-28502", local=str(1000 + i))
               for i in range(ROWS + 10)),
             *(win_rule(f"ND-{i}", f"Network Discovery ({i}-In)", "Network Discovery", "@FirewallAPI.dll,-32752", local=str(3000 + i))
               for i in range(ROWS // 2))]
    fw = plugin(FakeWindows(rules=rules, services={"ContosoRelay": "Contoso Relay Service"}, programs={
        r"C:\Program Files (x86)\Contoso Quest\Versions\Base2\quest.exe": {
            "Path": r"C:\Program Files (x86)\Contoso Quest\Versions\Base2\Quest.exe", "Product": "Quest", "Description": "Quest"}}))
    fw.show_rules("all")
    t = fw.status()["tables"][2]
    by = {g["id"]: g for g in t["groups"]}
    assert [(c["title"], c["count"], c["listed"]) for c in by["system"]["children"]] == [
        ("Contoso Relay Service", 1, 1), ("Core Networking", 1, 1), ("File and Printer Sharing", ROWS + 10, ROWS),
        ("Network Discovery", ROWS // 2, ROWS // 2)]  # each service listed up to ROWS, the group past them
    assert by["system"]["listed"] == ROWS + ROWS // 2 + 2 > ROWS
    assert [(c["title"], c["count"]) for c in by["application"]["children"]] == [("Contoso Quest", 2)]  # spelled as on disk
    assert {r["sub"] for r in t["rows"] if r["group"] == "application"} == {"application:contoso quest"}
    assert {s.name for s in fw.sorted_rules().values()} == {"Contoso Relay Service", "Core Networking", "Contoso Quest",
                                                            "File and Printer Sharing", "Network Discovery"}
    assert fw._rt.sorted[0] is fw._rt.snap  # worked out once for each read


def test_a_read_before_0_4_0_still_parses_and_names_what_it_can():
    old = {"Rules": [dict(win_rule("{S1}", "Contoso relay", program=SVCHOST), Service="contosorelay"),
                     win_rule("{P1}", "quest", program=r"c:\program files (x86)\contoso quest\quest.exe")]}
    one, two = parse_snapshot(old, at=0, took=0).rules
    assert (one.service_name, two.product, two.file_description, two.on_disk) == ("", "", "", "")
    assert sort_rule(one, windir=WINDIR).name == "contosorelay" and sort_rule(two, windir=WINDIR).name == "contoso quest"
    new = dict(old, Services={"ContosoRelay": "Contoso Relay Service"}, Programs={
        r"C:\Program Files (x86)\Contoso Quest\quest.exe": {"Path": r"C:\Program Files (x86)\Contoso Quest\Quest.exe",
                                                            "Product": "Contoso Quest", "Description": "Contoso Quest Launcher"}})
    one, two = parse_snapshot(new, at=0, took=0).rules  # a service's and a program's names matched in any case
    assert one.service_name == "Contoso Relay Service"
    assert (two.product, two.file_description, two.on_disk) == ("Contoso Quest", "Contoso Quest Launcher",
                                                                r"C:\Program Files (x86)\Contoso Quest\Quest.exe")
    assert sort_rule(one, windir=WINDIR).name == "Contoso Relay Service" and sort_rule(two, windir=WINDIR).name == "Contoso Quest"
    odd = parse_snapshot(dict(old, Services=["x"], Programs={r"c:\program files (x86)\contoso quest\quest.exe": "x"}), at=0, took=0)
    assert (odd.rules[0].service_name, odd.rules[1].product) == ("", "")  # anything else in their place: nothing read


def test_the_read_names_the_services_and_programs_and_changes_nothing():
    script = READ_SCRIPT.read_text(encoding="utf-8")
    assert "Get-Service" in script and "[Diagnostics.FileVersionInfo]::GetVersionInfo" in script and "GetFileSystemEntries" in script
    assert "Services = $named; Programs = $programs" in script
    assert "-notmatch '^[A-Za-z]:\\\\'" in script  # a program on a share is not looked up: nothing over the network
    # nor on a network drive, a removable one or a disc (Windows' own table of drives says, the drive is not asked), nor a
    # file kept in the cloud only (Offline, RecallOnOpen, RecallOnDataAccess: reading its version would fetch it)
    assert "(New-Object IO.DriveInfo $drive).DriveType -eq [IO.DriveType]::Fixed" in script
    assert "$cloud = 0x1000 -bor 0x40000 -bor 0x400000" in script and "([int][IO.File]::GetAttributes($full)) -band $cloud" in script
    at = script.index  # each asked before what it guards
    assert at("[IO.DriveType]::Fixed") < at("[IO.File]::Exists($full)") < at("GetAttributes($full)") < at("GetVersionInfo($full)")
    code = "\n".join(line.split("#")[0] for line in script.splitlines())
    cmdlets = set(re.findall(r"\b([A-Z][a-z]+-[A-Z][A-Za-z]+)\b", code))
    assert cmdlets and {c.split("-")[0] for c in cmdlets} <= {"Get", "New", "Where", "ForEach", "Select"}, cmdlets
    assert {c for c in cmdlets if c.startswith("New-")} == {"New-Object"}  # the firewall's COM policy, read
