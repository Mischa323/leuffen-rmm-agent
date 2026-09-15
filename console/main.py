"""Leuffen RMM desktop console -- entry point.

Launched three ways:

  * from the Start menu (`leuffen-rmm-console.exe`);
  * by Windows handing over a `leuffenrmm://connect?...` URL, which is what the
    dashboard's "Open in desktop app" produces (the MSI registers the scheme);
  * from a source checkout: `python console/main.py`.

Only one console runs at a time. A second launch -- almost always a deep link
from the browser -- hands its URL to the running instance over loopback and
exits, so clicking "Open in desktop app" twice gives you one app with two
sessions rather than two apps.
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import traceback
import urllib.parse

# Frozen by PyInstaller with `--paths console`, so the modules next to this file
# import flat (`import api`). Make a source run behave the same.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config          # noqa: E402
import main_window     # noqa: E402

SCHEME = "leuffenrmm"
INSTANCE_PORT = 49723
INSTANCE_HOST = "127.0.0.1"


# --------------------------------------------------------------------------- #
# Deep links
# --------------------------------------------------------------------------- #
def parse_link(argv: list[str]) -> dict:
    """Pull `leuffenrmm://connect?server=&device=&ticket=` out of the arguments.

    Also accepts `--device <id>` so a script or shortcut can open a session
    without minting a ticket.
    """
    params: dict = {}
    for arg in argv[1:]:
        if arg.startswith(SCHEME + "://"):
            parts = urllib.parse.urlsplit(arg)
            query = urllib.parse.parse_qs(parts.query)
            params = {k: v[0] for k, v in query.items() if v}
            # `leuffenrmm://connect?...` and `leuffenrmm:///connect?...` both work.
            action = (parts.netloc or parts.path.strip("/")).lower()
            if action and action != "connect":
                params["action"] = action
        elif arg.startswith("--device="):
            params["device"] = arg.split("=", 1)[1]
    return params


# --------------------------------------------------------------------------- #
# Single instance
#
# The loopback listener is authenticated with a per-user secret file: any local
# process can connect to a listening port, and a forwarded link can open a
# remote session, so the secret keeps that to processes running as this user.
# --------------------------------------------------------------------------- #
def _secret() -> bytes:
    path = os.path.join(config.config_dir(), "instance.key")
    try:
        with open(path, "rb") as fh:
            value = fh.read().strip()
        if value:
            return value
    except OSError:
        pass
    import secrets
    value = secrets.token_hex(24).encode()
    try:
        with open(path, "wb") as fh:
            fh.write(value)
        if os.name != "nt":
            os.chmod(path, 0o600)
    except OSError:
        pass
    return value


def forward_to_running_instance(params: dict) -> bool:
    """True if another console took the link (so this process should exit)."""
    payload = _secret() + b"\n" + urllib.parse.urlencode(params).encode()
    try:
        with socket.create_connection((INSTANCE_HOST, INSTANCE_PORT), timeout=2) as sock:
            sock.sendall(payload)
        return True
    except OSError:
        return False


def start_listener(app) -> socket.socket | None:
    """Claim the single-instance port. None means someone else already has it."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Deliberately no SO_REUSEADDR: failing to bind is exactly the signal
        # that another console is already running.
        server.bind((INSTANCE_HOST, INSTANCE_PORT))
        server.listen(4)
    except OSError:
        server.close()
        return None

    secret = _secret()

    def serve() -> None:
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.settimeout(2)
                    data = conn.recv(8192)
                except OSError:
                    continue
                token, _, body = data.partition(b"\n")
                if token.strip() != secret:
                    continue
                params = {k: v[0] for k, v in
                          urllib.parse.parse_qs(body.decode("utf-8", "replace")).items() if v}
                try:
                    app.after(0, lambda p=params: app.handle_link(p))
                except RuntimeError:
                    return

    threading.Thread(target=serve, name="rmm-console-link", daemon=True).start()
    return server


# --------------------------------------------------------------------------- #
def _log_crash(exc: BaseException) -> None:
    """A frozen app has no console; leave the traceback where support can find it."""
    try:
        path = os.path.join(config.config_dir(), "console.log")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("".join(traceback.format_exception(
                type(exc), exc, exc.__traceback__)) + "\n")
    except OSError:
        pass


def main() -> int:
    params = parse_link(sys.argv)
    if forward_to_running_instance(params):
        return 0

    app = main_window.App()
    if start_listener(app) is None:
        # Lost the race against another launch that started in the meantime.
        if forward_to_running_instance(params):
            app.destroy()
            return 0

    app.report_callback_exception = lambda t, v, tb: _log_crash(v)

    if params.get("ticket"):
        app.handle_link(params)          # the ticket supersedes any stored token
    else:
        app.start()
        if params.get("device"):
            app.after(200, lambda: app.handle_link(params))
    app.mainloop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:          # noqa: BLE001 -- last-resort crash log
        _log_crash(error)
        raise
