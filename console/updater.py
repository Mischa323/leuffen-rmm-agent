"""Keeping the console up to date.

The agent updates itself silently because it runs as SYSTEM. The console cannot:
it is installed per machine, so replacing it needs elevation, and a background
process cannot elevate without asking. So this checks quietly and then *offers*
the update -- one click, one Windows permission prompt, and the installer takes
over while the console closes itself out of the way.

The check is the server's own `/api/console-release`, which resolves the newest
published build; the download is fetched from wherever that release lives.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile

from version import CONSOLE_VERSION

CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000      # re-check every six hours


def _parts(version: str) -> tuple:
    """`1.2.10` -> (1, 2, 10), so 1.2.10 sorts after 1.2.9 rather than before."""
    out = []
    for chunk in str(version or "").strip().split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out or [0])


def is_newer(candidate: str, current: str = CONSOLE_VERSION) -> bool:
    return _parts(candidate) > _parts(current)


def check(client) -> str:
    """Return the version available on the server if it is newer, else ""."""
    release = client.console_release() or {}
    if not release.get("available"):
        return ""
    version = str(release.get("version") or "").strip()
    return version if version and is_newer(version) else ""


def download(client, on_progress=None) -> str:
    """Fetch the installer to a temp file and return its path."""
    target = os.path.join(tempfile.gettempdir(), "leuffen-rmm-console-update.msi")
    client.download_console_msi(target, on_progress=on_progress)
    return target


def install(msi_path: str) -> None:
    """Hand the MSI to Windows and let it take over.

    `msiexec` is started detached: the installer has to outlive this process,
    since it is about to replace the very files it is running from. Windows
    raises its own permission prompt -- a per-machine install cannot be silent
    from an unelevated app, and pretending otherwise would just fail quietly.
    """
    if os.name != "nt":
        raise RuntimeError("The console updates itself on Windows only")
    flags = 0
    if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
        flags = subprocess.CREATE_NEW_PROCESS_GROUP | getattr(subprocess, "DETACHED_PROCESS", 0)
    subprocess.Popen(["msiexec", "/i", msi_path, "/passive", "/norestart"],
                     close_fds=True, creationflags=flags)


def running_installed() -> bool:
    """True when this is the installed build rather than a source checkout.

    A checkout has nothing for an MSI to replace, so it is never offered one.
    """
    return bool(getattr(sys, "frozen", False))
