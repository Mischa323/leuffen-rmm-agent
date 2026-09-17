"""Home Assistant OS inventory and metrics for the slim agent.

Home Assistant OS is an appliance: nothing can be installed on the host, so the
agent runs as a Home Assistant add-on (a container managed by the Supervisor).
From there it reads two sources:

  * ``/proc`` -- CPU, memory and uptime are host-wide even inside the container,
    and with ``host_network`` so are the network counters. The generic readers
    are shared with the Synology agent.
  * the **Supervisor API** (``http://supervisor``, authorised by the token the
    Supervisor injects) -- for everything that makes this box a Home Assistant
    box: the OS and Core versions, pending updates, the data disk, the add-ons,
    and reboot/shutdown.

Two things map onto monitors the server already has, so they work for Home
Assistant without any server change:

  * pending updates (OS, Core, Supervisor, add-ons) are reported as
    ``updates_available`` -> the "Updates available" policy;
  * add-ons, plus Home Assistant Core itself as ``homeassistant``, are reported
    as ``services`` -> the "Service not running" policy.

Shapes match :mod:`syno_inventory` (and ``inventory.collect`` on Windows) so the
server treats the device like any other Linux machine.
"""
from __future__ import annotations

import glob
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request

import syno_inventory as _proc
from syno_inventory import AGENT_VERSION  # one version for every slim agent

__all__ = ["AGENT_VERSION", "prime", "collect", "metrics", "installed_software", "power"]

# Overridable for testing against a stand-in Supervisor.
SUPERVISOR_URL = os.environ.get("RMM_SUPERVISOR_URL", "http://supervisor").rstrip("/")

_UPDATES_TTL = 300.0       # the Supervisor itself refreshes versions a few times a day
_ADDONS_TTL = 60.0
_HOST_TTL = 60.0

# Interfaces whose traffic is containers talking to each other on this very box;
# counting them would double every byte an add-on sends out.
_VIRTUAL_IFACE_PREFIXES = ("lo", "docker", "hassio", "veth", "br-")


# --------------------------------------------------------------------------- #
# Supervisor API
# --------------------------------------------------------------------------- #
def _token() -> str:
    """The Supervisor token.

    Present in the environment for a plain container command; under the base
    image's s6 init it may only be in s6's container environment directory.
    """
    for name in ("SUPERVISOR_TOKEN", "HASSIO_TOKEN"):
        value = os.environ.get(name)
        if value:
            return value.strip()
    for path in ("/run/s6/container_environment/SUPERVISOR_TOKEN",
                 "/var/run/s6/container_environment/SUPERVISOR_TOKEN"):
        try:
            with open(path, encoding="utf-8") as fh:
                value = fh.read().strip()
            if value:
                return value
        except OSError:
            continue
    return ""


def supervisor(path: str, method: str = "GET", timeout: float = 15.0) -> dict | None:
    """Call the Supervisor; return its ``data`` object, or None on any failure.

    Every answer is wrapped as ``{"result": "ok", "data": {...}}``; anything
    else (an error result, an unreachable Supervisor, a bad token) is None so
    callers can simply fall back.
    """
    request = urllib.request.Request(
        SUPERVISOR_URL + path, method=method,
        data=b"{}" if method == "POST" else None,
        headers={"Authorization": "Bearer " + _token(),
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            body = json.loads(resp.read() or b"{}")
    except (urllib.error.URLError, OSError, ValueError):
        return None
    if not isinstance(body, dict) or body.get("result") != "ok":
        return None
    data = body.get("data")
    return data if isinstance(data, dict) else {}


_cache: dict[str, tuple[float, object]] = {}
_cache_lock = threading.Lock()


def _cached(key: str, ttl: float, produce):
    """Serve a recent value, refreshing it at most once per ``ttl``."""
    now = time.time()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < ttl:
            return hit[1]
    value = produce()
    with _cache_lock:
        _cache[key] = (now, value)
    return value


def _host() -> dict:
    return _cached("host", _HOST_TTL, lambda: supervisor("/host/info") or {})


def _os() -> dict:
    return _cached("os", _UPDATES_TTL, lambda: supervisor("/os/info") or {})


def _core() -> dict:
    return _cached("core", _UPDATES_TTL, lambda: supervisor("/core/info") or {})


def _supervisor_info() -> dict:
    return _cached("supervisor", _UPDATES_TTL, lambda: supervisor("/supervisor/info") or {})


def _addons() -> list[dict]:
    def load():
        data = supervisor("/addons") or {}
        items = data.get("addons")
        return items if isinstance(items, list) else []
    return _cached("addons", _ADDONS_TTL, load)


def _core_running() -> bool | None:
    """Is Home Assistant itself answering? None when we cannot tell.

    The Supervisor proxies Core's REST API; its root answers "API running."
    only while Core is up. A failure is only meaningful when the Supervisor
    itself is reachable -- otherwise we know nothing either way.
    """
    request = urllib.request.Request(
        SUPERVISOR_URL + "/core/api/",
        headers={"Authorization": "Bearer " + _token()})
    try:
        with urllib.request.urlopen(request, timeout=10) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return True        # the proxy reached Core, and Core itself answered
        if exc.code in (502, 503, 504):
            return False       # the proxy could not reach Core
        return None
    except (urllib.error.URLError, OSError):
        return False if supervisor("/supervisor/ping") is not None else None


# --------------------------------------------------------------------------- #
# Host facts
# --------------------------------------------------------------------------- #
def _network() -> dict:
    """Primary interface address and MAC, as the Supervisor sees them."""
    data = supervisor("/network/info") or {}
    best: dict = {}
    for iface in data.get("interfaces") or []:
        if not isinstance(iface, dict) or not iface.get("enabled", True):
            continue
        addresses = ((iface.get("ipv4") or {}).get("address") or [])
        ip = addresses[0].split("/")[0] if addresses else None
        candidate = {"ip": ip, "mac": iface.get("mac"), "name": iface.get("interface")}
        if iface.get("primary") and ip:
            return candidate
        if ip and not best:
            best = candidate
    if best:
        return best
    # Fallback: the address the kernel would use to reach the outside.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            return {"ip": probe.getsockname()[0], "mac": None, "name": None}
    except OSError:
        return {"ip": None, "mac": None, "name": None}


def _board_name(board: str | None) -> str | None:
    known = {
        "generic-x86-64": "Generic x86-64", "ova": "Virtual machine",
        "green": "Home Assistant Green", "yellow": "Home Assistant Yellow",
        "rpi5-64": "Raspberry Pi 5", "rpi4-64": "Raspberry Pi 4", "rpi4": "Raspberry Pi 4",
        "rpi3-64": "Raspberry Pi 3", "rpi3": "Raspberry Pi 3",
        "odroid-n2": "ODROID-N2", "odroid-m1": "ODROID-M1",
    }
    return known.get(board or "", board)


def _disk() -> dict | None:
    """The data disk, where Home Assistant's database and backups live."""
    host = _host()
    total_gb, used_gb = host.get("disk_total"), host.get("disk_used")
    if isinstance(total_gb, (int, float)) and total_gb > 0 and isinstance(used_gb, (int, float)):
        total = int(total_gb * 1024 ** 3)
        used = int(used_gb * 1024 ** 3)
    else:
        try:
            st = os.statvfs("/data")
        except OSError:
            return None
        total = st.f_frsize * st.f_blocks
        used = total - st.f_frsize * st.f_bavail
        if total <= 0:
            return None
    return {"mount": "/data", "label": "Data disk", "total": total, "used": used,
            "free": max(total - used, 0), "percent": round(used / total * 100, 1),
            "primary": True}


def _temperature() -> float | None:
    """Hottest CPU/SoC thermal zone, in degrees Celsius.

    Zones named for the CPU or SoC win; only when there are none is the
    hottest zone of any kind used (a Pi exposes just one, a PC several)."""
    cpu_zones, other_zones = [], []
    for zone in glob.glob("/sys/class/thermal/thermal_zone*"):
        kind = _proc._read(os.path.join(zone, "type")).strip().lower()
        raw = _proc._read(os.path.join(zone, "temp")).strip()
        if not raw.lstrip("-").isdigit():
            continue
        value = int(raw) / 1000.0 if abs(int(raw)) > 200 else float(raw)
        if not 0 < value < 150:
            continue
        is_cpu = any(k in kind for k in ("cpu", "soc", "x86_pkg", "package"))
        (cpu_zones if is_cpu else other_zones).append(value)
    pool = cpu_zones or other_zones
    if pool:
        return round(max(pool), 1)
    for sensor in glob.glob("/sys/class/hwmon/hwmon*/temp1_input"):
        raw = _proc._read(sensor).strip()
        if raw.isdigit():
            return round(int(raw) / 1000.0, 1)
    return None


def _net_bytes() -> tuple[int, int]:
    """Bytes in/out on the physical interfaces only."""
    rx = tx = 0
    for line in _proc._read("/proc/net/dev").splitlines():
        if ":" not in line:
            continue
        iface, _, rest = line.partition(":")
        if iface.strip().startswith(_VIRTUAL_IFACE_PREFIXES):
            continue
        cols = rest.split()
        if len(cols) >= 9:
            try:
                rx += int(cols[0])
                tx += int(cols[8])
            except ValueError:
                pass
    return rx, tx


# --------------------------------------------------------------------------- #
# Updates and add-ons
# --------------------------------------------------------------------------- #
def pending_updates() -> list[dict]:
    """Everything the Supervisor says can be updated right now."""
    pending = []
    for label, info in (("Home Assistant OS", _os()),
                        ("Home Assistant Core", _core()),
                        ("Supervisor", _supervisor_info())):
        if info.get("update_available"):
            pending.append({"name": label, "version": info.get("version"),
                            "latest": info.get("version_latest")})
    for addon in _addons():
        if addon.get("update_available"):
            pending.append({"name": addon.get("name") or addon.get("slug"),
                            "version": addon.get("version"),
                            "latest": addon.get("version_latest")})
    return pending


def services() -> list[dict]:
    """Home Assistant Core and every add-on, in the service monitor's shape.

    ``name`` is the add-on slug (stable, what a policy should name), ``display``
    its friendly name, and ``status`` is "running" only while it runs.
    """
    out = []
    core = _core_running()
    if core is not None:
        out.append({"name": "homeassistant", "display": "Home Assistant Core",
                    "status": "running" if core else "stopped", "start": "auto"})
    for addon in _addons():
        state = (addon.get("state") or "unknown").lower()
        out.append({"name": addon.get("slug") or addon.get("name") or "?",
                    "display": addon.get("name") or addon.get("slug") or "?",
                    "status": "running" if state == "started" else state,
                    "start": ""})
    return out


def installed_software() -> list[dict]:
    """The platform components and every installed add-on."""
    out = []
    for label, info in (("Home Assistant OS", _os()),
                        ("Home Assistant Core", _core()),
                        ("Home Assistant Supervisor", _supervisor_info())):
        if info.get("version"):
            out.append({"name": label, "version": info.get("version"),
                        "publisher": "Home Assistant"})
    for addon in _addons():
        out.append({"name": addon.get("name") or addon.get("slug"),
                    "version": addon.get("version"),
                    "publisher": addon.get("repository") or "Home Assistant add-on"})
    out.sort(key=lambda d: (d.get("name") or "").lower())
    return out


# --------------------------------------------------------------------------- #
# Public API (the slim agent calls these)
# --------------------------------------------------------------------------- #
def prime() -> None:
    _proc._cpu_percent()


def collect() -> dict:
    host, osi, core, sup = _host(), _os(), _core(), _supervisor_info()
    net = _network()
    cpu = _proc._cpu_info()
    os_version = osi.get("version") or ""
    os_name = host.get("operating_system") or f"Home Assistant OS {os_version}".strip()
    return {
        "os": os_name,
        "os_version": os_version,
        "os_arch": sup.get("arch") or core.get("arch") or os.uname().machine,
        "kernel": host.get("kernel") or os.uname().release,
        "hostname": host.get("hostname") or socket.gethostname(),
        "fqdn": host.get("hostname") or socket.getfqdn(),
        "logged_in_user": None,
        "agent_version": AGENT_VERSION,
        "cpu": cpu["cpu"] or os.uname().machine,
        "cpu_cores_logical": cpu["logical"],
        "cpu_cores_physical": cpu["physical"],
        "ram_total": _proc._meminfo()["total"] or None,
        "ip": net.get("ip"),
        "mac": net.get("mac"),
        "manufacturer": "Home Assistant",
        "model": _board_name(osi.get("board")),
        "serial": None,
        "gpu": None,
        "is_server": True,
        "boot_time": time.time() - _proc._uptime(),
        "platform": "home_assistant",
        "home_assistant": {
            "os_version": os_version or None,
            "core_version": core.get("version"),
            "supervisor_version": sup.get("version"),
            "board": osi.get("board"),
            "deployment": host.get("deployment"),
            "chassis": host.get("chassis"),
        },
    }


def metrics() -> dict:
    mem = _proc._meminfo()
    rx, tx = _net_bytes()
    disk = _disk()
    m = {
        "cpu_percent": _proc._cpu_percent(),
        "mem_percent": mem["percent"], "mem_total": mem["total"], "mem_used": mem["used"],
        "disk_percent": disk["percent"] if disk else None,
        "disk_total": disk["total"] if disk else None,
        "disk_used": disk["used"] if disk else None,
        "disks": [disk] if disk else [],
        "uptime": _proc._uptime(),
        "net_sent": tx, "net_recv": rx,
        "logged_in_user": None,
    }
    temp = _temperature()
    if temp is not None:
        m["cpu_temp"] = temp
    pending = _cached("pending", _UPDATES_TTL, pending_updates)
    m["updates_available"] = len(pending)
    m["home_assistant"] = {"pending_updates": pending}
    svcs = _cached("services", _ADDONS_TTL, services)
    if svcs:
        m["services"] = svcs
    return m


def power(action: str) -> dict:
    """Reboot or shut down the Home Assistant host through the Supervisor."""
    path = {"reboot": "/host/reboot", "shutdown": "/host/shutdown"}.get(action)
    if path is None:
        return {"ok": False,
                "error": f"'{action}' is not available on Home Assistant OS "
                         "(reboot and shutdown are)"}
    if supervisor(path, method="POST", timeout=30) is None:
        return {"ok": False, "error": "The Supervisor refused or did not answer"}
    return {"ok": True, "action": action}
