"""Desktop console version — the single source of truth.

Versioned independently of the agent (they ship as separate MSIs from the same
repo, under `v*` and `console-v*` tags). CI bumps the patch on every push that
touches `console/`, and stamps this value into the MSI's ProductVersion.
"""
from __future__ import annotations

CONSOLE_VERSION = "1.0.3"
