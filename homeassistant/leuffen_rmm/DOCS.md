# Leuffen RMM Agent

Connects this Home Assistant server to your Leuffen RMM, so it shows up next to
your other devices: online status, CPU, memory, disk and temperature, pending
updates, and whether Home Assistant and its add-ons are running.

## Setting it up

1. In Leuffen RMM, open the organisation this server belongs to and go to
   **Downloads → Home Assistant OS**. Copy the server address and generate an
   **enrolment key** there.
2. In this add-on's **Configuration** tab, paste both and save.
3. Start the add-on. The server appears in the RMM's approval queue; approve it
   and it is monitored from then on.

An enrolment key works once. After the first connection the add-on keeps its
own identity in its data folder, so restarts and add-on updates reconnect on
their own. If you uninstall the add-on, generate a new key to connect again.

## Options

| Option | What it does |
|---|---|
| **Server address** | Your RMM, e.g. `rmm.example.com`. `https://` is assumed. |
| **Enrolment key** | The one-time key from **Downloads**. |
| **Accept a self-signed certificate** | Turn on when your RMM uses the certificate it generated itself. |
| **Certificate fingerprint** | Optional. The SHA-256 of your RMM's certificate: when set, only that exact certificate is accepted, which keeps a self-signed setup safe from interception. Find it in the RMM under **Settings → Security**. |

## What the RMM sees and can do

- **Metrics** — CPU, memory, uptime and network traffic of the whole machine,
  the data disk where the database and backups live, and the CPU temperature.
- **Updates** — pending updates for Home Assistant OS, Core, the Supervisor and
  every add-on, counted for the RMM's *Updates available* policy.
- **Services** — Home Assistant Core (as `homeassistant`) and every add-on (by
  its slug, e.g. `core_mosquitto`), so the *Service not running* policy can
  alert when one stops.
- **Software** — the installed add-ons and platform versions.
- **Power** — reboot and shut down the host.
- **Files** — `/homeassistant` (your configuration, writable, so a broken
  `configuration.yaml` can be fixed remotely), `/share`, and `/backup`
  (read-only).
- **Terminal** — runs commands inside this add-on's container, not on the host.

Remote desktop is not available: Home Assistant OS has no desktop.

## Permissions

The add-on asks for the Supervisor's *manager* role (to read versions and
pending updates, and to reboot the host), access to Home Assistant's API (to
tell whether Core is running), and host networking (to report the machine's
real addresses and traffic). It opens no ports.
