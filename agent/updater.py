"""In-place agent self-update, driven from the dashboard.

The server sends an ``update_agent`` control message carrying short-lived,
token-authorised download URLs. The agent pulls the latest installer for its OS
and applies it while preserving its existing config + device id:

* Windows (frozen exe, installed via MSI): download the MSI and hand it to a
  detached helper that waits for this process to exit, runs ``msiexec`` quietly
  (a major-upgrade that swaps the binaries), then relaunches the agent.
* Linux (running from a source dir under systemd): download ``agent.zip`` and
  extract the code over the install directory (never touching the local config
  or device-id files), then restart the service.
"""
from __future__ import annotations

import logging
import os
import ssl
import subprocess
import sys
import tempfile
import urllib.request

log = logging.getLogger("rmm.agent.update")

# Local state files that must survive an update (identity + config + runtime).
_PRESERVE = {"rmm_config.json", "rmm_device_id", "status.json", "sync_request"}


def _download(url: str, dest: str, insecure: bool) -> None:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "leuffen-rmm-agent"})
    with urllib.request.urlopen(req, context=ctx, timeout=120) as r, open(dest, "wb") as f:
        while True:
            chunk = r.read(65536)
            if not chunk:
                break
            f.write(chunk)


def apply_update(msg: dict, install_dir: str, cfg: dict | None = None) -> dict:
    """Download and apply the latest agent build. Returns a result dict.

    On success the process is scheduled to exit/restart shortly after, so the
    caller should ack the returned payload before that happens. ``cfg`` is the
    agent's current configuration, re-applied so the upgrade keeps its identity.
    """
    insecure = bool(msg.get("insecure_tls"))
    if os.name == "nt":
        return _update_windows(msg.get("msi_url"), insecure, cfg or {})
    return _update_linux(msg.get("zip_url"), insecure, install_dir)


def _update_windows(msi_url: str | None, insecure: bool, cfg: dict) -> dict:
    if not msi_url:
        return {"ok": False, "error": "no MSI URL provided"}
    tmp = tempfile.mkdtemp(prefix="lrmm-upd-")
    msi = os.path.join(tmp, "leuffen-rmm-agent.msi")
    _download(msi_url, msi, insecure)
    log.info("downloaded update MSI to %s", msi)
    # The MSI stores server URL + key as machine env vars from its properties; a
    # major-upgrade reinstall without them would wipe the config. Re-pass the
    # current config so the upgraded agent keeps connecting.
    props = ""
    server_url, api_key = (cfg.get("server_url"), cfg.get("api_key"))
    if server_url and api_key:
        ins = "1" if cfg.get("insecure_tls") else "0"
        props = (f' RMM_SERVER_URL="{server_url}" RMM_API_KEY="{api_key}"'
                 f' RMM_INSECURE_TLS={ins}')
    bat = os.path.join(tmp, "apply_update.bat")
    log_path = os.path.join(tmp, "update.log")
    with open(bat, "w") as f:
        # Wait for the running agent to exit (releases file locks), run the MSI
        # upgrade, then start the agent via the scheduled task (SYSTEM, same as
        # normal operation). Do NOT use "start <exe>" — that runs in the wrong
        # session and leaves the scheduled task out of sync.
        f.write(
            "@echo off\r\n"
            "timeout /t 4 /nobreak >nul\r\n"
            f'msiexec /i "{msi}" /qn /norestart{props} /l*v "{log_path}"\r\n'
            "if %errorlevel% neq 0 (\r\n"
            f'  echo MSI failed with code %errorlevel% >> "{log_path}"\r\n'
            "  exit /b %errorlevel%\r\n"
            ")\r\n"
            "schtasks /run /tn LeuffenRMMAgent\r\n"
        )
    flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    subprocess.Popen(["cmd", "/c", bat], close_fds=True, creationflags=flags)
    # Give the helper a moment to start, then exit so the MSI can replace files.
    _exit_soon()
    return {"ok": True, "method": "msi", "note": "update started; agent will restart"}


def _update_linux(zip_url: str | None, insecure: bool, install_dir: str) -> dict:
    if not zip_url:
        return {"ok": False, "error": "no zip URL provided"}
    import zipfile

    tmp = tempfile.mkdtemp(prefix="lrmm-upd-")
    zpath = os.path.join(tmp, "agent.zip")
    _download(zip_url, zpath, insecure)
    log.info("downloaded update zip to %s", zpath)
    with zipfile.ZipFile(zpath) as z:
        for name in z.namelist():
            if name.endswith("/"):
                continue
            base = os.path.basename(name)
            # Never overwrite identity/config/runtime files, or escape the dir.
            if base in _PRESERVE or base.startswith("agent.log") or os.path.isabs(name) or ".." in name:
                continue
            target = os.path.join(install_dir, name)
            os.makedirs(os.path.dirname(target) or install_dir, exist_ok=True)
            with z.open(name) as src, open(target, "wb") as dst:
                dst.write(src.read())
    log.info("applied update to %s", install_dir)
    # Restart via systemd, detached, so we can ack first; fall back to a hard exit
    # (Restart=always brings us back) if systemctl isn't available.
    restart = (
        "sleep 2; "
        "systemctl restart leuffen-rmm 2>/dev/null || "
        f"kill {os.getpid()} 2>/dev/null"
    )
    subprocess.Popen(["/bin/sh", "-c", restart], close_fds=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"ok": True, "method": "zip", "note": "update applied; agent will restart"}


def _exit_soon() -> None:
    """Exit the process shortly so an external upgrader can replace our files."""
    import threading

    def _bye() -> None:
        import time
        time.sleep(2)
        os._exit(0)

    threading.Thread(target=_bye, daemon=True).start()
