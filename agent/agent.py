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
import hashlib
import hmac
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import time
import uuid

import psutil
import websockets

import handlers
import inventory
import monitors
import netscan
import snmp
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
           "api_key": os.environ.get("RMM_API_KEY"),
           "fingerprint": os.environ.get("RMM_SERVER_FINGERPRINT")}
    path = os.path.join(_data_dir(), "rmm_config.json")
    if os.path.exists(path):
        try:
            with open(path) as f:
                filecfg = json.load(f)
            cfg["server_url"] = cfg["server_url"] or filecfg.get("server_url")
            cfg["api_key"] = cfg["api_key"] or filecfg.get("api_key")
            cfg["insecure_tls"] = cfg.get("insecure_tls", filecfg.get("insecure_tls", False))
            cfg["fingerprint"] = cfg["fingerprint"] or filecfg.get("server_fingerprint")
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
    # Normalise the cert pin (hex, colons/case optional) so it survives the file
    # round-trip and matches what _verify_pin compares against.
    cfg["fingerprint"] = (cfg.get("fingerprint") or "").replace(":", "").strip().lower() or None
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
    if cfg.get("fingerprint"):
        want["server_fingerprint"] = cfg["fingerprint"]
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


def _device_secret_path() -> str:
    return os.path.join(_data_dir(), "rmm_device_secret")


def _load_device_secret() -> str:
    """Per-device secret issued by the server (proves identity on reconnect)."""
    try:
        with open(_device_secret_path()) as f:
            return f.read().strip()
    except Exception:
        return ""


def _save_device_secret(secret: str) -> None:
    if not secret:
        return
    try:
        with open(_device_secret_path(), "w") as f:
            f.write(secret)
        if os.name != "nt":
            try:
                os.chmod(_device_secret_path(), 0o600)
            except Exception:
                pass
    except Exception:
        pass


def _ws_url(server_url: str, api_key: str) -> str:
    base = server_url.replace("http://", "ws://").replace("https://", "wss://").rstrip("/")
    return f"{base}/api/agents/ws?key={api_key}"


def _url_host(server_url: str) -> str:
    """Bare hostname of the server URL, for clearer connection diagnostics."""
    from urllib.parse import urlparse
    try:
        return urlparse(server_url).hostname or server_url
    except Exception:
        return server_url


def _is_dns_error(exc: BaseException) -> bool:
    """True if a connection failure is a name-resolution failure (rather than a
    refused/timed-out connection), so it can be logged distinctly. Walks the
    exception chain and, as a fallback, matches the platform gaierror strings."""
    seen = 0
    cur: BaseException | None = exc
    while cur is not None and seen < 8:
        if isinstance(cur, socket.gaierror):
            return True
        cur = cur.__cause__ or cur.__context__
        seen += 1
    text = str(exc).lower()
    return any(s in text for s in (
        "getaddrinfo failed", "name or service not known", "temporary failure in name resolution",
        "nodename nor servname", "name does not resolve", "[errno 11001]", "[errno -2]", "-3] temporary"))


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


# --- Optional sensors (GPU / temperature) -------------------------------------
# These can shell out to nvidia-smi / powershell, so they're collected off the
# event loop and throttled. Capability flags are probed once and cached so we
# don't keep spawning probes on hardware that can't answer (None=unprobed).
_sensor_caps: dict[str, bool | None] = {"nvidia": None, "win_gpu": None,
                                        "win_cputemp": None, "hyperv": None}
_sensor_cache: dict[str, object] = {"ts": 0.0, "data": {}}
SENSOR_MIN_INTERVAL = 25.0  # seconds; bounds the cost of probe subprocesses
SNMP_TICK = 10.0            # node SNMP poll-loop granularity (per-target intervals)


def _snmp_poll_target(t: dict) -> dict:
    """Poll one SNMP target's OIDs (blocking; runs in an executor). Returns an
    'snmp_result' message with one reading per OID."""
    oids_cfg = t.get("oids") or []
    oids = [o.get("oid") for o in oids_cfg if o.get("oid")]
    labels = {o.get("oid"): o.get("label") for o in oids_cfg}
    res = snmp.get(t.get("host", ""), t.get("community") or "public", oids,
                   version=t.get("version") or "2c", port=int(t.get("port") or 161),
                   timeout=float(t.get("timeout") or 2.0), retries=1)
    readings = []
    for oid, value, tname in res.get("varbinds", []):
        num = value if isinstance(value, (int, float)) and not isinstance(value, bool) else None
        readings.append({"oid": oid, "label": labels.get(oid),
                         "value": value, "num": num, "type": tname})
    return {"type": "snmp_result", "target_id": t.get("id"), "ok": res.get("ok", False),
            "error": res.get("error"), "readings": readings}


def _run(cmd: list[str], timeout: float) -> str:
    """Run a short probe command, returning stdout ('' on any failure)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout or ""
    except Exception:
        return ""


def _win_gpu_counter() -> float | None:
    # ToString(InvariantCulture) so a non-English locale doesn't emit "30,8".
    txt = _run(["powershell", "-NoProfile", "-Command",
                "$s=(Get-Counter '\\GPU Engine(*)\\Utilization Percentage' "
                "-ErrorAction Stop).CounterSamples | "
                "Measure-Object -Property CookedValue -Sum; "
                "([math]::Round($s.Sum,1)).ToString([Globalization.CultureInfo]::InvariantCulture)"], 12).strip()
    if not txt:
        return None
    try:
        return min(round(float(txt.replace(",", ".")), 1), 100.0)
    except ValueError:
        return None


def _gpu_stats() -> dict:
    """Best-effort GPU utilisation / temperature / VRAM. NVIDIA is fully covered
    via nvidia-smi on any OS; other vendors get utilisation only (Linux sysfs or
    Windows GPU performance counters), with temperature left as None."""
    out = {"gpu_percent": None, "gpu_temp": None, "gpu_mem_percent": None}
    if _sensor_caps["nvidia"] is None:
        _sensor_caps["nvidia"] = bool(shutil.which("nvidia-smi"))
    if _sensor_caps["nvidia"]:
        txt = _run(["nvidia-smi",
                    "--query-gpu=utilization.gpu,temperature.gpu,memory.used,memory.total",
                    "--format=csv,noheader,nounits"], 8)
        best = None  # report the busiest GPU on multi-GPU hosts
        for line in txt.splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 4:
                continue
            try:
                util, temp, used, total = (float(parts[0]), float(parts[1]),
                                           float(parts[2]), float(parts[3]))
            except ValueError:
                continue
            mem = (used / total * 100) if total else None
            if best is None or util > best[0]:
                best = (util, temp, mem)
        if best:
            out["gpu_percent"] = round(best[0], 1)
            out["gpu_temp"] = round(best[1], 1)
            out["gpu_mem_percent"] = round(best[2], 1) if best[2] is not None else None
            return out
    if os.name != "nt":
        # AMD on Linux exposes utilisation via sysfs; cheap file read, no process.
        try:
            import glob
            vals = []
            for path in glob.glob("/sys/class/drm/card*/device/gpu_busy_percent"):
                try:
                    with open(path) as f:
                        vals.append(float(f.read().strip()))
                except Exception:
                    pass
            if vals:
                out["gpu_percent"] = round(max(vals), 1)
        except Exception:
            pass
        return out
    # Windows, non-NVIDIA: aggregate the GPU Engine performance counters. Covers
    # AMD/Intel/NVIDIA, but the counter path is English-locale only, so treat a
    # first empty result as "unsupported" and stop probing.
    if _sensor_caps["win_gpu"] is not False:
        pct = _win_gpu_counter()
        if pct is not None:
            _sensor_caps["win_gpu"] = True
            out["gpu_percent"] = pct
        elif _sensor_caps["win_gpu"] is None:
            _sensor_caps["win_gpu"] = False
    return out


# LibreHardwareMonitor reads the real CPU die temperature on Windows (the same
# Digital Thermal Sensor HWMonitor uses). It needs its bundled managed DLLs and
# loads an embedded kernel driver on Open(), which requires SYSTEM (the agent is).
# The old ACPI thermal-zone reading is gone — it reported a different, often-bogus
# sensor. If LHM can't load (DLL missing, driver blocked by HVCI), CPU temp is N/A.
#
# OPT-IN: the kernel driver (WinRing0) is on Microsoft's vulnerable-driver
# blocklist, so Defender removes it. We therefore DON'T load LHM by default — the
# agent ships clean. The server turns it on per device/org via agent_policy
# (enable_cpu_temp_driver) only where the operator accepts that tradeoff.
_cpu_temp_driver_enabled = False


def _set_cpu_temp_driver(enabled: bool) -> None:
    """Toggle the opt-in Windows CPU-die sensor (LibreHardwareMonitor/WinRing0)."""
    global _cpu_temp_driver_enabled
    enabled = bool(enabled)
    if enabled and not _cpu_temp_driver_enabled:
        _lhm_cache["ts"] = 0.0   # force a fresh read on enable (clear any backoff)
    _cpu_temp_driver_enabled = enabled


_lhm_cache: dict[str, object] = {"ts": 0.0, "val": None, "ttl": 0.0}
_LHM_TTL = 60.0          # refresh interval for a working sensor (driver load isn't free)
_LHM_BACKOFF = 1800.0    # retry interval where LHM can't load, so we don't poll constantly

_LHM_PS = (
    "$ErrorActionPreference='Stop'; $d=$env:LHM_DIR;"
    "Add-Type -Path (Join-Path $d 'HidSharp.dll') -ErrorAction SilentlyContinue;"
    "Add-Type -Path (Join-Path $d 'LibreHardwareMonitorLib.dll');"
    "$c=New-Object LibreHardwareMonitor.Hardware.Computer; $c.IsCpuEnabled=$true; $c.Open();"
    "$o=@(); foreach($h in $c.Hardware){ $h.Update(); foreach($s in $h.Sensors){"
    "  if($s.SensorType -eq 'Temperature' -and $null -ne $s.Value){"
    "    $o+=[pscustomobject]@{name=[string]$s.Name;"
    "      value=([double]$s.Value).ToString([Globalization.CultureInfo]::InvariantCulture)} } } }"
    "$c.Close(); $o | ConvertTo-Json -Compress"
)


def _lhm_dll_dir() -> str | None:
    """Directory holding LibreHardwareMonitorLib.dll: the PyInstaller bundle when
    frozen, else a vendored folder beside the agent (dev / source installs)."""
    for d in (getattr(sys, "_MEIPASS", None), os.path.join(HERE, "vendor"), HERE):
        if d and os.path.exists(os.path.join(d, "LibreHardwareMonitorLib.dll")):
            return d
    return None


def _select_cpu_temp(sensors: list) -> float | None:
    """Most representative CPU temperature from LHM's sensors: Intel 'CPU Package'
    / AMD 'Core (Tctl/Tdie)' first, then a core max, then the hottest reading."""
    vals = []
    for s in sensors:
        if not isinstance(s, dict):
            continue
        try:
            vals.append((str(s.get("name") or "").lower(),
                         float(str(s.get("value")).replace(",", "."))))
        except (TypeError, ValueError):
            pass
    if not vals:
        return None
    def pick(pred):
        m = [v for n, v in vals if pred(n)]
        return max(m) if m else None
    return (pick(lambda n: "package" in n)
            or pick(lambda n: "tctl" in n or "tdie" in n)
            or pick(lambda n: "max" in n)
            or max(v for _, v in vals))


def _win_lhm_cpu_temp() -> float | None:
    d = _lhm_dll_dir()
    if not d:
        return None
    env = dict(os.environ); env["LHM_DIR"] = d
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                            "-Command", _LHM_PS], capture_output=True, text=True,
                           timeout=30, env=env)
        txt = (r.stdout or "").strip()
    except Exception:
        return None
    if not txt:
        return None
    try:
        import json as _json
        data = _json.loads(txt)
    except Exception:
        return None
    t = _select_cpu_temp(data if isinstance(data, list) else [data])
    return round(t, 1) if t is not None and 0 < t < 150 else None


def _cpu_temp() -> float | None:
    """CPU temperature in °C. psutil hardware sensors on Linux; the CPU die sensor
    via LibreHardwareMonitor on Windows (cached, since opening it loads a driver)."""
    try:
        read = getattr(psutil, "sensors_temperatures", None)
        if read:
            temps = read()
            for key in ("coretemp", "k10temp", "zenpower", "cpu_thermal", "acpitz"):
                entries = temps.get(key)
                if entries:
                    pkg = [e.current for e in entries
                           if e.label and "package" in e.label.lower() and e.current]
                    vals = pkg or [e.current for e in entries if e.current]
                    if vals:
                        return round(max(vals), 1)
            allvals = [e.current for v in temps.values() for e in v if e.current]
            if allvals:
                return round(max(allvals), 1)
    except Exception:
        pass
    if os.name == "nt":
        if not _cpu_temp_driver_enabled:
            return None   # opt-in only — the LHM/WinRing0 driver is off by default
        now = time.time()
        ttl = float(_lhm_cache.get("ttl") or _LHM_TTL)
        if _lhm_cache.get("ts") and now - float(_lhm_cache["ts"]) < ttl:  # type: ignore[arg-type]
            return _lhm_cache["val"]  # type: ignore[return-value]
        t = _win_lhm_cpu_temp()
        _lhm_cache["ts"] = now
        _lhm_cache["val"] = t
        _lhm_cache["ttl"] = _LHM_TTL if t is not None else _LHM_BACKOFF
        return t
    return None


# Outputs 'NOHV' when the Hyper-V role/module is absent; otherwise a compact JSON
# object {present, vms:[...]}. The Get-VM guard avoids loading the module on hosts
# that don't have it. ConvertTo-Json (no -AsArray, which is PS7-only) may collapse
# a single VM to an object, so the Python side normalises that.
_HYPERV_PS = (
    "if(-not (Get-Command Get-VM -ErrorAction SilentlyContinue)){'NOHV';return};"
    "$vms=@(Get-VM | ForEach-Object { [pscustomobject]@{"
    "name=$_.Name; state=$_.State.ToString(); cpu=[int]$_.CPUUsage;"
    "mem_assigned=[int64]$_.MemoryAssigned; mem_demand=[int64]$_.MemoryDemand;"
    "uptime=[int64]$_.Uptime.TotalSeconds; vcpu=[int]$_.ProcessorCount;"
    "status=[string]$_.Status} });"
    "[pscustomobject]@{present=$true; vms=$vms} | ConvertTo-Json -Depth 4 -Compress"
)


def _hyperv_stats() -> dict | None:
    """Hyper-V host summary + per-VM usage (Windows only). None when the role
    isn't present; capability is probed once and then skipped."""
    if os.name != "nt" or _sensor_caps["hyperv"] is False:
        return None
    txt = _run(["powershell", "-NoProfile", "-Command", _HYPERV_PS], 30).strip()
    if not txt or txt == "NOHV":
        if _sensor_caps["hyperv"] is None:
            _sensor_caps["hyperv"] = False
        return None
    try:
        import json as _json
        data = _json.loads(txt)
    except Exception:
        return None
    if not isinstance(data, dict) or not data.get("present"):
        _sensor_caps["hyperv"] = False
        return None
    _sensor_caps["hyperv"] = True
    raw = data.get("vms")
    items = [raw] if isinstance(raw, dict) else (raw if isinstance(raw, list) else [])
    vms, running = [], 0
    for vm in items:
        if not isinstance(vm, dict):
            continue
        state = str(vm.get("state") or "")
        if state.lower() == "running":
            running += 1
        vms.append({"name": vm.get("name"), "state": state, "cpu": vm.get("cpu"),
                    "mem_assigned": vm.get("mem_assigned"), "mem_demand": vm.get("mem_demand"),
                    "uptime": vm.get("uptime"), "vcpu": vm.get("vcpu"),
                    "status": vm.get("status")})
    # Running VMs first, then alphabetical.
    vms.sort(key=lambda v: (v["state"].lower() != "running", (v.get("name") or "").lower()))
    return {"present": True, "total": len(vms), "running": running, "vms": vms}


def _collect_sensors() -> dict:
    """GPU + temperature + Hyper-V probe, throttled and meant to run off the event
    loop (it may shell out). Returns cached values between refreshes."""
    now = time.time()
    cached = _sensor_cache.get("data") or {}
    if cached and now - float(_sensor_cache.get("ts") or 0) < SENSOR_MIN_INTERVAL:
        return dict(cached)  # type: ignore[arg-type]
    data = {"gpu_percent": None, "gpu_temp": None, "gpu_mem_percent": None, "cpu_temp": None}
    try:
        data.update(_gpu_stats())
    except Exception:
        pass
    try:
        data["cpu_temp"] = _cpu_temp()
    except Exception:
        pass
    try:
        hv = _hyperv_stats()
        if hv is not None:
            data["hyperv"] = hv
    except Exception:
        pass
    _sensor_cache["ts"] = now
    _sensor_cache["data"] = data
    return data


# Service list changes slowly and can be largish (Windows has hundreds), so
# collect + send it only once per interval rather than on every heartbeat.
_services_last = {"ts": 0.0}
SERVICES_MIN_INTERVAL = 300.0


def _collect_services() -> list[dict] | None:
    now = time.time()
    if _services_last["ts"] and now - _services_last["ts"] < SERVICES_MIN_INTERVAL:
        return None
    _services_last["ts"] = now
    try:
        return inventory.services() or None
    except Exception:
        return None


def _status_path() -> str:
    return os.path.join(_data_dir(), "status.json")


def _sync_flag_path() -> str:
    return os.path.join(_data_dir(), "sync_request")


def _notify_path() -> str:
    # A queued desktop notification the tray (running in the user session) shows.
    return os.path.join(_data_dir(), "notify.json")


class Agent:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.id = _device_id()
        self.role = "agent"
        self.subnets: list[str] = []
        self.snmp_targets: list[dict] = []
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

    def _write_notify(self, title: str, body: str) -> None:
        """Queue a desktop notification for the per-user tray to show (best effort;
        the agent runs as SYSTEM and can't raise UI in the user's session itself)."""
        try:
            with open(_notify_path(), "w") as f:
                json.dump({"title": title, "body": body, "ts": time.time()}, f)
        except Exception:
            pass

    def _ssl_context(self, url: str):
        """SSL context for wss:// connections.

        For a server with a self-signed cert (``insecure_tls``) verification is
        disabled; with a real cert (Let's Encrypt / reverse proxy) it stays on.
        Either way, if ``RMM_SERVER_FINGERPRINT`` is set the server's certificate
        is pinned after connect (see ``_verify_pin``), which defeats MITM even in
        insecure_tls mode.
        """
        if not url.startswith("wss://"):
            return None
        import ssl
        ctx = ssl.create_default_context()
        if self.cfg.get("insecure_tls"):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _verify_pin(self, ws) -> None:
        """Pin the server's TLS certificate when a fingerprint is configured.

        The pin comes from ``RMM_SERVER_FINGERPRINT`` or the ``server_fingerprint``
        key in ``rmm_config.json`` (resolved into ``cfg['fingerprint']`` by
        ``_load_config``). The value is the SHA-256 of the server cert (DER), hex,
        colons optional. When set, only that exact certificate is accepted -- so a
        self-signed / ``insecure_tls`` deployment is still safe against
        man-in-the-middle, because an attacker's substituted cert won't match the
        pin."""
        pin = (self.cfg.get("fingerprint") or "").replace(":", "").strip().lower()
        if not pin:
            return
        try:
            ssl_obj = ws.transport.get_extra_info("ssl_object")
            der = ssl_obj.getpeercert(binary_form=True)
            got = hashlib.sha256(der).hexdigest()
        except Exception as exc:
            raise RuntimeError(f"cannot read server certificate to verify fingerprint: {exc}")
        if not hmac.compare_digest(got, pin):
            raise RuntimeError("server certificate fingerprint mismatch — possible MITM; refusing")

    def _ssl_context_for(self, url: str):
        return self._ssl_context(url)

    async def run(self) -> None:
        _lower_priority()
        url = _ws_url(self.cfg["server_url"], self.cfg["api_key"])
        host = _url_host(self.cfg["server_url"])
        ssl_ctx = self._ssl_context(url)
        backoff = 2
        self._write_status(False)
        while True:
            try:
                async with websockets.connect(url, max_size=None, ping_interval=30,
                                              ssl=ssl_ctx) as ws:
                    self._verify_pin(ws)   # certificate pinning (if configured)
                    self.ws = ws
                    await self._register()
                    self.last_sync = time.time()
                    self._write_status(True)
                    backoff = 2
                    await asyncio.gather(self._metrics_loop(), self._recv_loop(),
                                         self._control_loop(), self._snmp_loop())
            except Exception as exc:
                if _is_dns_error(exc):
                    # Distinct from a refused/timed-out server: the hostname itself
                    # won't resolve (dead/wrong DNS, or the server's DNS record was
                    # removed). Surfaces the same failure operators see as the
                    # browser's "server not found".
                    log.warning("DNS resolution failed for %r — cannot reach the "
                                "server by name (check DNS / the server hostname); "
                                "retrying in %ss", host, backoff)
                else:
                    log.warning("connection lost (%s); retrying in %ss", exc, backoff)
                self._write_status(False)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)

    async def _sync_now(self) -> None:
        """Force an immediate push of inventory + metrics (used by the tray)."""
        await self._register()
        await self._send({"type": "metrics", "metrics": await self._metrics_with_sensors()})
        self.last_sync = time.time()
        self._write_status(True)

    async def _metrics_with_sensors(self) -> dict:
        """Cheap psutil metrics plus the optional GPU/temperature probe, which is
        run in a thread so its subprocesses never block the event loop."""
        m = _collect_metrics()
        try:
            loop = asyncio.get_event_loop()
            m.update(await loop.run_in_executor(None, _collect_sensors))
        except Exception:
            pass
        try:
            svcs = await loop.run_in_executor(None, _collect_services)
            if svcs:
                m["services"] = svcs
        except Exception:
            pass
        # Extended health monitors (disk/SMART, reboot-pending, Windows security,
        # event log, processes) — throttled internally, best-effort.
        try:
            m.update(await loop.run_in_executor(None, monitors.collect))
        except Exception:
            pass
        return m

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
        # ``device_secret`` proves this is the same device on reconnect; the agent
        # advertises support so the server can issue one (trust-on-first-use) and
        # require it thereafter. Empty on the very first connect.
        await self._send({"type": "register", "id": self.id,
                          "hostname": inv["hostname"], "inventory": inv,
                          "supports_secret": True,
                          "device_secret": _load_device_secret()})
        log.info("registered as %s (%s)", inv["hostname"], self.id)

    async def _metrics_loop(self) -> None:
        psutil.cpu_percent(interval=None)  # prime the delta
        while True:
            await asyncio.sleep(self.cfg["interval"])
            try:
                await self._send({"type": "metrics", "metrics": await self._metrics_with_sensors()})
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
            if "snmp_targets" in msg:
                self.snmp_targets = msg.get("snmp_targets") or []
            log.info("role set to %s, subnets=%s, snmp_targets=%d",
                     self.role, self.subnets, len(self.snmp_targets))
        elif t == "device_secret":
            # Server-issued per-device secret (trust-on-first-use); persist it so
            # subsequent reconnects can prove this device's identity.
            _save_device_secret(msg.get("secret", ""))
            log.info("stored server-issued device secret")
        elif t == "agent_policy":
            # Admin-controlled device policy pushed from the server.
            if "enable_wol" in msg:
                if msg.get("enable_wol"):
                    _enable_wol()                       # arm NIC for magic packet
                    _set_fast_startup(enabled=False)    # keep NIC powered on shutdown
                else:
                    _set_fast_startup(enabled=True)     # restore Windows default
            if "enable_cpu_temp_driver" in msg:
                _set_cpu_temp_driver(msg.get("enable_cpu_temp_driver"))
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
        elif t == "notify":
            # Show a desktop toast to the signed-in user. The agent runs as SYSTEM
            # (no UI), so drop it for the per-user tray to display.
            self._write_notify(msg.get("title") or "Leuffen RMM", msg.get("body") or "")
            await self._ack(rid, {"ok": True})
        elif t == "update_agent":
            asyncio.create_task(self._self_update(msg, rid))
        elif t == "scan":
            asyncio.create_task(self._do_scan(msg.get("subnets") or self.subnets))
        elif t == "snmp_config":
            self.snmp_targets = msg.get("targets") or []
            log.info("snmp_config: %d target(s)", len(self.snmp_targets))
        elif t == "snmp_poll":
            # On-demand poll of one target (or all) regardless of interval.
            tid = msg.get("target_id")
            for tg in list(self.snmp_targets):
                if tid is None or tg.get("id") == tid:
                    asyncio.create_task(self._poll_snmp_target(tg))
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
        # Guarantee the persistent config is on disk (%ProgramData%) before the MSI
        # major-upgrade runs, so the relaunched agent always finds its server URL/key
        # even if the installer's machine-env-var propagation lags. See _persist_config.
        _persist_config(self.cfg)
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

    async def _snmp_loop(self) -> None:
        """Poll configured SNMP targets (node only) at each target's interval."""
        last: dict = {}
        while True:
            await asyncio.sleep(SNMP_TICK)
            if self.role != "node" or not self.snmp_targets:
                continue
            now = time.time()
            for t in list(self.snmp_targets):
                tid = t.get("id")
                interval = max(int(t.get("interval") or 300), 30)
                if now - last.get(tid, 0.0) >= interval:
                    last[tid] = now
                    asyncio.create_task(self._poll_snmp_target(t))

    async def _poll_snmp_target(self, t: dict) -> None:
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, _snmp_poll_target, t)
            await self._send(result)
        except Exception as exc:
            log.warning("snmp poll failed for %s: %s", t.get("host"), exc)

    async def _screen_start(self, msg: dict) -> None:
        if self.screen:
            self.screen.stop()

        async def send_bytes(b: bytes) -> None:
            await self.ws.send(b)

        async def on_error(err: str) -> None:
            await self._send({"type": "screen_error", "error": err})

        async def on_info(info: dict) -> None:
            # Codec negotiation info for the viewer (e.g. {codec:"h264", ...}).
            await self._send({"type": "video_info", **info})

        self.screen = ScreenSession(send_bytes, fps=msg.get("fps", 4),
                                    quality=msg.get("quality", 50),
                                    max_edge=msg.get("max_edge", 1600),
                                    on_error=on_error,
                                    purpose=msg.get("purpose", "control"),
                                    codecs=msg.get("codecs"),
                                    on_info=on_info)
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
        # Cap total log files at 10 (active + 9 rotated), ~50 KB each.
        handler = RotatingFileHandler(path, maxBytes=50_000, backupCount=9, encoding="utf-8")
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
    if not (cfg.get("server_url") and cfg.get("api_key")):
        # Config can be momentarily absent right after an MSI self-update: the
        # installer re-sets the server URL/key as machine env vars, but those don't
        # always reach the relaunched task immediately (and the persistent
        # %ProgramData% copy may still be landing). Wait for it to appear instead of
        # crash-looping offline; give up only after the upgrade window elapses.
        deadline = time.time() + 120
        while not (cfg.get("server_url") and cfg.get("api_key")):
            if time.time() >= deadline:
                log.error("Missing server_url/api_key after waiting. Set RMM_SERVER_URL "
                          "and RMM_API_KEY or ship rmm_config.json next to the agent.")
                sys.exit(1)
            log.warning("server_url/api_key not ready (likely a self-update in "
                        "progress); retrying in 5s")
            time.sleep(5)
            cfg = _load_config()
    _persist_config(cfg)
    _grant_users_writable(_data_dir())
    _allow_inbound_ping()
    # Wake-on-LAN (NIC settings + Fast Startup) is applied only when the server's
    # agent_policy enables it — not unconditionally.
    asyncio.run(Agent(cfg).run())


if __name__ == "__main__":
    # When launched in the interactive session as a screen-capture helper, run
    # that loop instead of the full agent (skips the single-instance lock).
    if "--screen-helper" in sys.argv:
        from screen import run_screen_helper
        run_screen_helper(sys.argv)
    else:
        main()
