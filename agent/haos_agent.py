"""Leuffen RMM agent for Home Assistant OS -- the add-on's entry point.

Home Assistant OS does not let anything run on the host itself, so the agent
ships as a Home Assistant add-on. This module turns the add-on's Configuration
tab into the agent's settings and runs the slim, dependency-free agent
(:mod:`syno_agent`) with the Home Assistant platform layer
(:mod:`haos_inventory`) in place of the Synology one. The protocol, the
reconnect logic and the file browser are shared; only how the box is inspected
and power-cycled differs.

Everything persistent -- the device id, the server-issued device secret --
lives in the add-on's ``/data``, which survives restarts, rebuilds and add-on
updates (and is wiped only when the add-on is uninstalled).
"""
from __future__ import annotations

import json
import logging
import os
import sys

OPTIONS_FILE = os.environ.get("RMM_OPTIONS_FILE", "/data/options.json")

# Add-on option -> the environment variable the agent already understands.
_OPTION_ENV = {
    "server_url": "RMM_SERVER_URL",
    "enrolment_key": "RMM_API_KEY",
    "server_fingerprint": "RMM_SERVER_FINGERPRINT",
}


def apply_options(path: str = OPTIONS_FILE) -> dict:
    """Read the options the Supervisor wrote and expose them to the agent."""
    os.environ.setdefault("RMM_DATA_DIR", "/data")
    try:
        with open(path, encoding="utf-8") as fh:
            options = json.load(fh)
    except (OSError, ValueError):
        options = {}
    if not isinstance(options, dict):
        options = {}
    for option, env in _OPTION_ENV.items():
        value = str(options.get(option) or "").strip()
        if value:
            os.environ[env] = value
    if "insecure_tls" in options:
        os.environ["RMM_INSECURE_TLS"] = "1" if options.get("insecure_tls") else "0"
    return options


def main() -> int:
    apply_options()
    # Imported only now: both read RMM_DATA_DIR and friends when they run.
    import haos_inventory
    import syno_agent

    log = logging.getLogger("rmm.haos")
    cfg = syno_agent._load_config()
    if not (cfg.get("server_url") and cfg.get("api_key")):
        log.error("Not configured yet. Open this add-on's Configuration tab, enter the "
                  "server address and an enrolment key from the RMM "
                  "(Downloads -> Home Assistant OS), save, and start the add-on again.")
        return 1
    if not haos_inventory._token():
        log.warning("No Supervisor token: the add-on needs 'hassio_api' access to report "
                    "Home Assistant details. Only basic metrics will be sent.")
    log.info("Leuffen RMM agent for Home Assistant OS v%s starting (server %s)",
             haos_inventory.AGENT_VERSION, cfg["server_url"])
    agent = syno_agent.Agent(
        cfg,
        inventory=haos_inventory,
        power=haos_inventory.power,
        update_message="Update the Leuffen RMM add-on from Home Assistant's add-on store",
    )
    agent.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
