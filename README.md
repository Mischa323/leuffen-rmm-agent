# Leuffen RMM Agent

Windows agent source, the technician-side desktop console, packaging, and CI for
the Leuffen RMM platform.

See `agent/` for the agent source, `console/` for the desktop console,
`packaging/windows/` for the MSI packaging (one `.wxs` each), and
`.github/workflows/` for the build/release pipelines.

For **Synology DSM**, `agent/syno_agent.py` + `agent/syno_inventory.py` are a
self-contained, pure-stdlib variant (no psutil/websockets — it implements the
WebSocket client itself and reads `/proc` + DSM CLIs). It's shipped as a `noarch`
Synology package: `packaging/synology/` holds the `INFO`/scripts/`conf`, and the
RMM server assembles the `.spk` on demand and serves it through a Package Center
*package source* (no separate release/CI step).

## Home Assistant OS

This repository is also a **Home Assistant add-on repository**
(`repository.yaml`, add-on in `homeassistant/leuffen_rmm/`). In Home Assistant:
**Settings → Add-ons → Add-on store → ⋮ → Repositories**, add
`https://github.com/Mischa323/leuffen-rmm-agent`, install **Leuffen RMM Agent**,
then paste the server address and enrolment key shown under **Downloads → Home
Assistant OS** in the dashboard.

`agent/haos_agent.py` + `agent/haos_inventory.py` run the Synology agent's loop
(`syno_agent.Agent`) with an inventory that reads the **Supervisor API**: host,
OS, Core and add-on state, pending updates (reported as `updates_available`),
and Core + every add-on as `services`. Reboot and shutdown go through the
Supervisor too. Files and the terminal work inside the add-on container, where
the Home Assistant configuration is mounted at `/homeassistant`. Remote desktop
isn't supported.

The add-on is built on the Home Assistant box and downloads those agent files
from the release tag named by `version` in `config.yaml`. That line must
therefore point at a **published** tag. `windows-agent-msi.yml` updates it after
each release, and that change is also what makes Home Assistant offer the update.
To build it locally the same way:

```sh
docker build --build-arg BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.22 \
  --build-arg BUILD_VERSION=<released version> homeassistant/leuffen_rmm
```

To build unreleased code, add `--build-arg AGENT_SRC=<url serving the agent/ files>`.

## Desktop console

`console/` is the **technician-side** Windows app: remote control, terminal and
file transfer as a native program, alongside — not instead of — the browser
viewer in the dashboard. Both talk to the **same** server endpoints, so a session
is identical whichever one starts it.

It is Python + Tk (the same stack as `agent/tray.py`), packaged by
`windows-console-msi.yml` into its own `leuffen-rmm-console.msi` and released
under **`console-v*`** tags, independently of the agent. Install it on your own
machine — never on a managed device.

| | |
|---|---|
| Version | `console/version.py` → `CONSOLE_VERSION` (CI bumps it on every push touching `console/`) |
| Settings | `%APPDATA%\Leuffen RMM Console\settings.json` |
| Sign-in token | `token.bin` in the same folder, encrypted with **Windows DPAPI** (current-user scope) |
| Crash log | `console.log` in the same folder |
| Second instance | `RMM_CONSOLE_PORT` moves the single-instance port, so a checkout can run alongside the installed console instead of handing it the deep link. |
| Run from source | `python console/main.py` (needs `websockets`, `pillow`, optionally `av` for H.264) |
| Updates | Checks the server every 6 hours and offers the new build in a banner. One click downloads it and hands it to `msiexec`; Windows asks for permission, because a per-machine install cannot be replaced without elevation. A source checkout is never offered one. |

**How it signs in.** The console has no cookie jar, so it uses a bearer token
from `POST /api/auth/app-token` — either by password (+ TOTP) typed into the app,
or by redeeming the **single-use ticket** the dashboard mints for its *"Open in
desktop app"* button and hands over through the `leuffenrmm://` URL scheme that
the MSI registers. The ticket route is what lets a **Microsoft 365 SSO** user in
without a password ever reaching the app. Self-signed servers are handled like
the agent handles them: trusting the certificate also **pins** it (SHA-256).

## Configuration

The agent reads its settings from environment variables first, then from
`rmm_config.json` in its data dir (`%ProgramData%\LeuffenRMM` on Windows). Env
vars win; the resolved config is persisted so it survives an MSI upgrade.

| Env var | Config key | Purpose |
|---|---|---|
| `RMM_SERVER_URL` | `server_url` | Server base URL (https assumed if no scheme). |
| `RMM_API_KEY` | `api_key` | One-time enrollment key (or org key) used on first connect. |
| `RMM_INSECURE_TLS` | `insecure_tls` | Accept the server's self-signed cert (default for the bundled setup). |
| `RMM_SERVER_FINGERPRINT` | `server_fingerprint` | SHA-256 of the server's TLS cert (hex, colons optional). When set, the agent **pins** that exact cert after connect — MITM-proof even with `insecure_tls`. |

### Secure connection

- **Cert pinning:** set `RMM_SERVER_FINGERPRINT` (or the `server_fingerprint`
  config key) to the server cert's SHA-256. The server exposes its own
  fingerprint at `GET /api/server-fingerprint` (admin) and logs it on startup.
- **Per-device secret:** the agent advertises `supports_secret` and stores a
  server-issued secret in `rmm_device_secret`, proving its identity on reconnect
  so a stolen `device_id` alone can't impersonate it. No setup required.
