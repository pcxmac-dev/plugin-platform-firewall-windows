"""What every test here shares: the machine the tests run on never shows through. Not inside WSL (the library's
world.under_wsl, which a suite run inside a WSL distribution would otherwise find), and no init known (world._init), so
the World Wide Web tab's page reads alike on Windows, inside a WSL distribution and on any Linux. A test that wants
either says so itself."""
from __future__ import annotations

import pytest

from liminal_libs.machines import world


@pytest.fixture(autouse=True)
def _not_this_machine(monkeypatch):
    monkeypatch.setattr(world, "under_wsl", lambda *args, **kwargs: None)
    monkeypatch.setattr(world, "_init", lambda: "")
