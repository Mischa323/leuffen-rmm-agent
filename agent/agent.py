"""Leuffen RMM agent — cross-platform (Windows + Linux), low-footprint.

Holds a single outbound WebSocket to the server (works through NAT/firewalls). It
registers with full inventory, pushes metrics on an interval, and handles control
messages: shell, power, files, screen, Wake-on-LAN relay, and network scans (when
promoted to a node).

Design for low impact: event-driven (mostly asleep), cheap non-blocking metrics,
heavy screen deps imported only on demand, and below-normal process priority.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import sys
import time
import uuid

import psutil
import websockets

import handlers
import inventory
import netscan
import updater
from screen import ScreenSession

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("rmm.agent")

HERE = os.path.dirname(os.path.abspath(__file__))


def _data_dir() -> str:
    """Writable directory for config + device id (stable across runs).

    When packaged as a PyInstaller exe, ``__file__`` is a temp extraction dir, so
    use a fixed location (``RMM_DATA_DIR``, else %ProgramData%\\LeuffenRMM on
    Windows, else the executable's folder)."""
    env = os.environ.get("RMM_DATA_DIR")
    if env:
        os.makedirs(env, exist_ok=True)
        return env
    if getattr(sys, "frozen", False):
        if os.name == "nt":
            d = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "LeuffenRMM")
        else:
            d = os.path.dirname(sys.executable)
        os.makedirs(d, exist_ok=True)
        return d
    return HERE


def _load_config() -> dict:
    """Config precedence: env vars > bundled rmm_config.json."""
    cfg = {"server_url": os.environ.get("RMM_SERVER_URL"),
           "api_key": os.environ.get("RMM_API_KEY")}
    path = os.path.join(_data_dir(), "rmm_config.json")
    if os.path.exists(path):
        try:
            with open(path) as f:
                filecfg = json.load(f)
            cfg["server_url"] = cfg["server_url"] or filecfg.get("server_url")
            cfg["api_key"] = cfg["api_key"] or filecfg.get("api_key")
            cfg["insecure_tls"] = cfg.get("insecure_tls", filecfg.get("insecure_tls", False))
        except Exception:
            pass
    cfg["interval"] = float(os.environ.get("RMM_INTERVAL", "30"))
    # Env overrides file. Used to accept the server's self-signed certificate.
    env_insecure = os.environ.get("RMM_INSECURE_TLS")
    if env_insecure is not None:
        cfg["insecure_tls"] = env_insecure.lower() in ("1", "true", "yes")
    cfg["insecure_tls"] = bool(cfg.get("insecure_tls", False))
    # Tolerate a server URL typed without a scheme (default to https).
    su = (cfg.get("server_url") or "").strip()
    if su and not su.startswith(("http://", "https://")):
        su = "https://" + su
    cfg["server_url"] = su.rstrip("/") or None
    return cfg


def _persist_config(cfg: dict) -> None:
    """Write the resolved config to the data dir so it survives an MSI upgrade.

    The Windows MSI keeps server URL + key in machine env vars, which a reinstall
    can clear; the data dir (%ProgramData%) is never touched by the installer, so
    a copy here makes the agent self-sufficient across updates."""
    if not (cfg.get("server_url") and cfg.get("api_key")):
        return
    path = os.path.join(_data_dir(), "rmm_config.json")
    want = {"server_url": cfg["server_url"], "api_key": cfg["api_key"],
            "insecure_tls": bool(cfg.get("insecure_tls"))}
    try:
        if os.path.exists(path):
            with open(path) as f:
                if json.load(f) == want:
                    return
        with open(path, "w") as f:
            json.dump(want, f)
    except Exception:
        pass


def _device_id() -> str:
    """Stable per-machine id, persisted in the data directory."""
    path = os.path.join(_data_dir(), "rmm_device_id")
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    did = uuid.uuid4().hex
    try:
        with open(path, "w") as f:
            f.write(did)
    except Exception:
        pass
    return did


def _ws_url(server_url: str, api_key: str) -> str:
    base = server_url.replace("http://", "ws://").replace("https://", "wss://").rstrip("/")
    return f"{base}/api/agents/ws?key={api_key}"


def _lower_priority() -> None:
    try:
        p = psutil.Process()
        if os.name == "nt":
            p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
        else:
            p.nice(10)
    except Exception:
        pass


def _collect_disks() -> list[dict]:
    """Per-volume usage for every fixed drive (C:, D:, … / on Linux)."""
    out = []
    primary = "C:\\" if os.name == "nt" else "/"
    for part in psutil.disk_partitions(all=False):
        mp = part.mountpoint
        # Skip removable/optical media that isn't ready.
        if os.name == "nt" and "cdrom" in (part.opts or ""):
            continue
        try:
            u = psutil.disk_usage(mp)
        except Exception:
            continue
        out.append({"mount": mp, "fs": part.fstype, "total": u.total,
                    "used": u.used, "percent": u.percent,
                    "primary": os.path.normcase(mp) == os.path.normcase(primary)})
    return out


def _collect_metrics() -> dict:
    vm = psutil.virtual_memory()
    try:
        disk = psutil.disk_usage("C:\\" if os.name == "nt" else "/")
    except Exception:
        disk = None
    net = psutil.net_io_counters()
    return {
        "cpu_percent": psutil.cpu_percent(interval=None),
        "mem_percent": vm.percent, "mem_total": vm.total, "mem_used": vm.used,
        "disk_percent": disk.percent if disk else None,
        "disk_total": disk.total if disk else None,
        "disk_used": disk.used if disk else None,
        "disks": _collect_disks(),
        "uptime": (__import__("time").time() - psutil.boot_time()),
        "net_sent": net.bytes_sent, "net_recv": net.bytes_recv,
        # Lightweight, refreshed every heartbeat so the dashboard tracks the
        # signed-in user without waiting for a re-register.
        "logged_in_user": inventory._logged_in_user(),
    }


def _status_path() -> str:
    return os.path.join(_data_dir(), "status.json")


def _sync_flag_path() -> str:
    return os.path.join(_data_dir(), "sync_request")


class Agent:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.id = _device_id()
        self.role = "agent"
        self.subnets: list[str] = []
        self.ws = None
        self.screen: ScreenSession | None = None
        self.last_sync: float | None = None

    def _write_status(self, connected: bool) -> None:
        """Publish a small status file the tray app reads (best effort)."""
        try:
            with open(_status_path(), "w") as f:
                json.dump({"connected": connected, "last_sync": self.last_sync,
                           "server_url": self.cfg.get("server_url"),
                           "hostname": socket.gethostname(), "updated": time.time()}, f)
        except Exception:
            pass

    def _ssl_context(self, url: str):
        """SSL context for wss:// connections.

        For a server with a self-signed cert (``insecure_tls``) verification is
        disabled; with a real cert (Let's Encrypt / reverse proxy) it stays on.
        """
        if not url.startswith("wss://"):
            return None
        import ssl
        ctx = ssl.create_default_context()
        if self.cfg.get("insecure_tls"):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def run(self) -> None:
        _lower_priority()
        url = _ws_url(self.cfg["server_url"], self.cfg["api_key"])
        ssl_ctx = self._ssl_context(url)
        backoff = 2
        self._write_status(False)
        while True:
            try:
                async with websockets.connect(url, max_size=None, ping_interval=30,
                                              ssl=ssl_ctx) as ws:
                    self.ws = ws
                    await self._register()
                    self.last_sync = time.time()
                    self._write_status(True)
                    backoff = 2
                    await asyncio.gather(self._metrics_loop(), self._recv_loop(),
                                         self._control_loop())
            except Exception as exc:
                log.warning("connection lost (%s); retrying in %ss", exc, backoff)
                self._write_status(False)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)

    async def _sync_now(self) -> None:
        """Force an immediate push of inventory + metrics (used by the tray)."""
        await self._register()
        await self._send({"type": "metrics", "metrics": _collect_metrics()})
        self.last_sync = time.time()
        self._write_status(True)

    async def _control_loop(self) -> None:
        """Watch for a sync-request flag dropped by the tray app."""
        flag = _sync_flag_path()
        while True:
            await asyncio.sleep(2)
            if os.path.exists(flag):
                try:
                    os.remove(flag)
                except OSError:
                    pass
                try:
                    await self._sync_now()
                    log.info("forced sync")
                except Exception:
                    return

    async def _send(self, msg: dict) -> None:
        await self.ws.send(json.dumps(msg))

    async def _register(self) -> None:
        inv = inventory.collect()
        await self._send({"type": "register", "id": self.id,
                          "hostname": inv["hostname"], "inventory": inv})
        log.info("registered as %s (%s)", inv["hostname"], self.id)

    async def _metrics_loop(self) -> None:
        psutil.cpu_percent(interval=None)  # prime the delta
        while True:
            await asyncio.sleep(self.cfg["interval"])
            try:
                await self._send({"type": "metrics", "metrics": _collect_metrics()})
                self.last_sync = time.time()
                self._write_status(True)
            except Exception:
                return

    async def _recv_loop(self) -> None:
        async for raw in self.ws:
            if isinstance(raw, bytes):
                continue
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            await self._handle(msg)

    async def _ack(self, rid: str | None, payload: dict) -> None:
        if rid:
            await self._send({"type": "ack", "rid": rid, "payload": payload})

    async def _handle(self, msg: dict) -> None:
        t = msg.get("type")
        rid = msg.get("rid")
        if t == "set_role":
            self.role = msg.get("role", "agent")
            self.subnets = msg.get("subnets", [])
            log.info("role set to %s, subnets=%s", self.role, self.subnets)
        elif t == "agent_policy":
            # Admin-controlled device policy pushed from the server.
            if "enable_wol" in msg:
                if msg.get("enable_wol"):
                    _enable_wol()                       # arm NIC for magic packet
                    _set_fast_startup(enabled=False)    # keep NIC powered on shutdown
                else:
                    _set_fast_startup(enabled=True)     # restore Windows default
        elif t == "shell_run":
            res = await handlers.run_command(msg.get("cmd", ""))
            await self._ack(rid, res)
        elif t == "script_run":
            res = await handlers.run_script(msg.get("content", ""), msg.get("shell", "shell"),
                                            float(msg.get("timeout", 120)),
                                            env=msg.get("env"), files=msg.get("files"))
            await self._ack(rid, res)
        elif t == "shell_input":
            res = await handlers.run_command(msg.get("data", ""))
            await self._send({"type": "shell_output", "data": res["output"],
                              "code": res["code"]})
        elif t == "power":
            await self._ack(rid, handlers.power_action(msg.get("action", "")))
        elif t == "file_get":
            await self._ack(rid, handlers.file_get(msg.get("path", "")))
        elif t == "file_put":
            await self._ack(rid, handlers.file_put(msg.get("path", ""), msg.get("data", "")))
        elif t == "file_list":
            await self._ack(rid, handlers.file_list(msg.get("path", "")))
        elif t == "dir_size":
            await self._ack(rid, handlers.dir_size(msg.get("path", "")))
        elif t == "file_delete":
            await self._ack(rid, handlers.file_delete(msg.get("path", "")))
        elif t == "file_mkdir":
            await self._ack(rid, handlers.file_mkdir(msg.get("path", "")))
        elif t == "software_list":
            # Off-loop: the Windows registry scan can take tens of seconds and
            # would otherwise block the agent's event loop (and its heartbeat).
            loop = asyncio.get_event_loop()
            software = await loop.run_in_executor(None, inventory.installed_software)
            await self._ack(rid, {"ok": True, "software": software})
        elif t == "wol":
            try:
                netscan.send_magic_packet(msg["mac"], msg.get("broadcast") or "255.255.255.255",
                                          msg.get("port", 9))
                await self._ack(rid, {"ok": True})
            except Exception as exc:
                await self._ack(rid, {"ok": False, "error": str(exc)})
        elif t == "update_agent":
            asyncio.create_task(self._self_update(msg, rid))
        elif t == "scan":
            asyncio.create_task(self._do_scan(msg.get("subnets") or self.subnets))
        elif t == "screen_start":
            await self._screen_start(msg)
        elif t == "screen_stop":
            if self.screen:
                self.screen.stop()
                self.screen = None
        elif t == "input":
            if self.screen:
                self.screen.input(msg)

    async def _self_update(self, msg: dict, rid: str | None) -> None:
        """Download and apply the latest agent build (blocking work off-loop)."""
        log.info("update requested from server")
        loop = asyncio.get_event_loop()
        try:
            res = await loop.run_in_executor(None, updater.apply_update, msg, HERE, self.cfg)
        except Exception as exc:
            log.warning("update failed: %s", exc)
            res = {"ok": False, "error": str(exc)}
        await self._ack(rid, res)

    async def _do_scan(self, subnets: list[str]) -> None:
        if not subnets:
            return
        log.info("scanning %s", subnets)
        hosts = await netscan.scan(subnets)
        await self._send({"type": "scan_result", "hosts": hosts})

    async def _screen_start(self, msg: dict) -> None:
        if self.screen:
            self.screen.stop()

        async def send_bytes(b: bytes) -> None:
            await self.ws.send(b)

        async def on_error(err: str) -> None:
            await self._send({"type": "screen_error", "error": err})

        self.screen = ScreenSession(send_bytes, fps=msg.get("fps", 4),
                                    quality=msg.get("quality", 50), on_error=on_error)
        err = await self.screen.start()
        if err:
            # Surface on the screen channel so the remote viewer shows the reason
            # instead of hanging on "Connecting…".
            await self._send({"type": "screen_error", "error": err})
            self.screen = None


def _grant_users_writable(path: str) -> None:
    """On Windows, let the interactive user write to the data dir (the agent runs
    as SYSTEM; the tray runs per-user and drops a sync-request flag here)."""
    if os.name != "nt":
        return
    try:
        import subprocess
        subprocess.run(["icacls", path, "/grant", "*S-1-5-32-545:(OI)(CI)M", "/T", "/Q"],
                       capture_output=True, timeout=20)
    except Exception:
        pass


def _allow_inbound_ping() -> None:
    """Allow inbound ICMP echo (ping) on Windows so a network node can reliably
    discover this device and confirm it's reachable.

    A relay node often lives in a *different VLAN/subnet*, so when it pings across
    subnets the device sees the node's (non-local) source address — scoping to the
    local subnet would block that, so the rule allows ICMP echo from any source
    (echo only — nothing else is opened).

    For safety it applies only to the **Domain and Private** firewall profiles, so
    a laptop on an untrusted **Public** network (e.g. café/airport WiFi) still
    won't answer pings. Best-effort and idempotent; the agent runs as SYSTEM."""
    if os.name != "nt":
        return  # Linux hosts answer ICMP echo by default.
    try:
        import subprocess
        name = "Leuffen RMM Allow Ping"
        # Remove any prior copy first so re-runs don't stack duplicate rules.
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={name}"], capture_output=True, timeout=15)
        for proto in ("icmpv4:8,any", "icmpv6:128,any"):
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                            f"name={name}", f"protocol={proto}", "dir=in",
                            "action=allow", "remoteip=any", "profile=domain,private"],
                           capture_output=True, timeout=15)
        log.info("ensured inbound ICMP (ping) firewall rule (domain/private profiles)")
    except Exception:
        pass


def _enable_wol() -> None:
    """Apply the full set of NIC settings Wake-on-LAN needs (Windows), best-effort.

    This is benign — it only makes the adapter able to wake the machine on a magic
    packet; it doesn't change shutdown/power behaviour. Covers, where the driver
    exposes them:
      * Wake on Magic Packet = Enabled, wake on pattern off (magic-packet only)
      * 'Allow this device to wake the computer' (powercfg -deviceenablewake)
      * Shutdown Wake-On-Lan = Enabled (Intel)
      * Energy-Efficient / Green Ethernet / Ultra-Low-Power = Disabled (these can
        stop the NIC waking)
    Whether to also disable Fast Startup is a separate admin-controlled policy."""
    if os.name != "nt":
        return
    try:
        import subprocess
        ps = r"""
$ErrorActionPreference = 'SilentlyContinue'
Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
  $n = $_.Name
  try { Set-NetAdapterPowerManagement -Name $n -WakeOnMagicPacket Enabled -WakeOnPattern Disabled -NoRestart } catch {}
  foreach ($p in @(
      @('Wake on Magic Packet','Enabled'),
      @('Shutdown Wake-On-Lan','Enabled'),
      @('Shutdown Wake Up','Enabled'),
      @('Energy Efficient Ethernet','Disabled'),
      @('Green Ethernet','Disabled'),
      @('Ultra Low Power Mode','Disabled'),
      @('System Idle Power Saver','Disabled'))) {
    try { Set-NetAdapterAdvancedProperty -Name $n -DisplayName $p[0] -DisplayValue $p[1] -NoRestart } catch {}
  }
  try { & powercfg -deviceenablewake "$($_.InterfaceDescription)" } catch {}
}
"""
        subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                       capture_output=True, timeout=45)
        log.info("applied Wake-on-LAN NIC settings on physical adapters")
    except Exception:
        pass


def _set_fast_startup(enabled: bool) -> None:
    """Enable/disable Windows Fast Startup (HiberbootEnabled) per server policy.

    Fast Startup (hybrid shutdown) powers the NIC fully down, defeating WoL from a
    shutdown — so an admin who relies on WoL can turn it off. Default leaves it at
    the Windows default (on). Hibernation itself is unaffected."""
    if os.name != "nt":
        return
    try:
        import subprocess
        subprocess.run(["reg", "add",
                        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power",
                        "/v", "HiberbootEnabled", "/t", "REG_DWORD",
                        "/d", "1" if enabled else "0", "/f"],
                       capture_output=True, timeout=15)
        log.info("Fast Startup %s per server policy", "enabled" if enabled else "disabled")
    except Exception:
        pass


def _setup_file_logging() -> None:
    """Write the agent's logs to a rotating file in the data directory.

    On Windows that's %ProgramData%\\LeuffenRMM\\agent.log (the no-console service
    has nowhere else to log); elsewhere it sits next to the agent."""
    try:
        from logging.handlers import RotatingFileHandler
        path = os.path.join(_data_dir(), "agent.log")
        # Cap total log files at 10 (active + 9 rotated), ~1 MB each.
        handler = RotatingFileHandler(path, maxBytes=1_000_000, backupCount=9, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logging.getLogger().addHandler(handler)
        log.info("Leuffen RMM agent — logging to %s", path)
    except Exception:
        pass


def _single_instance() -> bool:
    """Ensure only one agent runs at a time (Windows named mutex, global across sessions).

    A non-admin user session cannot *create* a Global\\ mutex that SYSTEM already holds
    (ERROR_ACCESS_DENIED = 5), so we fall back to *opening* it — if that succeeds, a
    prior instance is running and we should exit.
    """
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        _NAME = "Global\\LeuffenRMMAgentSingleton"
        handle = k.CreateMutexW(None, False, _NAME)
        err = k.GetLastError()
        if err == 183:          # ERROR_ALREADY_EXISTS
            return False
        if not handle and err == 5:  # ERROR_ACCESS_DENIED — another session holds it
            h2 = k.OpenMutexW(0x100000, False, _NAME)  # SYNCHRONIZE
            if h2:
                k.CloseHandle(h2)
                return False
        return True
    except Exception:
        return True


def main() -> None:
    _setup_file_logging()
    if not _single_instance():
        log.info("Another Leuffen RMM agent is already running; exiting.")
        sys.exit(0)
    cfg = _load_config()
    if not cfg.get("server_url") or not cfg.get("api_key"):
        log.error("Missing server_url/api_key. Set RMM_SERVER_URL and RMM_API_KEY "
                  "or ship rmm_config.json next to the agent.")
        sys.exit(1)
    _persist_config(cfg)
    _grant_users_writable(_data_dir())
    _allow_inbound_ping()
    # Wake-on-LAN (NIC settings + Fast Startup) is applied only when the server's
    # agent_policy enables it — not unconditionally.
    asyncio.run(Agent(cfg).run())


if __name__ == "__main__":
    main()
