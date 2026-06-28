"""Synology DSM inventory + metrics — pure standard library (no psutil).

The Windows/Linux agent leans on ``psutil`` for its inventory and metrics, but a
DSM package can't reliably ship C extensions across every Synology CPU arch. This
module reproduces the same payload shapes as :mod:`inventory` / ``agent._collect_metrics``
by reading ``/proc``, ``/sys`` and the DSM CLI tools directly, so the slim agent
(:mod:`syno_agent`) stays dependency-free and ``noarch``.

Keep ``AGENT_VERSION`` in sync with :mod:`inventory` — the SPK's catalog version is
stamped from ``inventory.AGENT_VERSION`` server-side, and this value is what the NAS
reports for the dashboard's "agent version".
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
import time

# Keep in sync with inventory.AGENT_VERSION (single source of truth for the SPK
# version is inventory.py; this constant is the value the running NAS reports).
AGENT_VERSION = "2.2.22"


# --------------------------------------------------------------------------- #
# Small /proc + CLI helpers
# --------------------------------------------------------------------------- #
def _read(path: str, default: str = "") -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return default


def _run(cmd: list[str], timeout: float = 8.0) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


def _synoinfo(key: str) -> str | None:
    """Read a key from synoinfo.conf (DSM key=value store)."""
    out = _run(["/usr/syno/bin/synogetkeyvalue", "/etc.defaults/synoinfo.conf", key]).strip()
    if out:
        return out
    for path in ("/etc.defaults/synoinfo.conf", "/etc/synoinfo.conf"):
        m = re.search(rf'^{re.escape(key)}\s*=\s*"?([^"\n]+)"?', _read(path), re.MULTILINE)
        if m:
            return m.group(1).strip()
    return None


def _dsm_version() -> tuple[str, str]:
    """(product version, build number) e.g. ('7.2.1', '69057')."""
    blob = _read("/etc.defaults/VERSION") or _read("/etc/VERSION")
    vals = dict(re.findall(r'^(\w+)="?([^"\n]*)"?', blob, re.MULTILINE))
    prod = vals.get("productversion") or vals.get("majorversion", "")
    build = vals.get("buildnumber", "")
    smallfix = vals.get("smallfixnumber")
    if smallfix and smallfix not in ("0", ""):
        prod = f"{prod} Update {smallfix}"
    return prod, build


# --------------------------------------------------------------------------- #
# Network
# --------------------------------------------------------------------------- #
def _primary_ip() -> str | None:
    """Best-effort primary outbound IPv4 (no traffic actually sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def _iface_ipv4(name: str) -> str | None:
    """IPv4 of an interface via SIOCGIFADDR (Linux ioctl); best-effort."""
    try:
        import fcntl
        import struct
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        packed = struct.pack("256s", name[:15].encode())
        res = fcntl.ioctl(s.fileno(), 0x8915, packed)  # SIOCGIFADDR
        s.close()
        return socket.inet_ntoa(res[20:24])
    except Exception:
        return None


def _nics() -> list[dict]:
    """Interfaces with their MAC + IPv4, mirroring inventory._nics shape."""
    out = []
    base = "/sys/class/net"
    try:
        names = sorted(os.listdir(base))
    except Exception:
        names = []
    for name in names:
        if name == "lo":
            continue
        mac = _read(os.path.join(base, name, "address")).strip() or None
        if mac == "00:00:00:00:00:00":
            mac = None
        ip = _iface_ipv4(name)
        if ip or mac:
            out.append({"name": name, "ipv4": [ip] if ip else [], "ipv6": [], "mac": mac})
    return out


def _primary_mac(nics: list[dict], primary_ip: str | None) -> str | None:
    for n in nics:
        if primary_ip and primary_ip in n.get("ipv4", []):
            return n.get("mac")
    for n in nics:
        if n.get("mac"):
            return n.get("mac")
    return None


def _logged_in_user() -> str | None:
    """Interactive users (best-effort) via ``who``."""
    names: list[str] = []
    for line in _run(["who"]).splitlines():
        u = line.split()[0] if line.split() else ""
        if u and u not in names:
            names.append(u)
    return ", ".join(names) if names else None


# --------------------------------------------------------------------------- #
# CPU / memory
# --------------------------------------------------------------------------- #
def _cpu_info() -> dict:
    txt = _read("/proc/cpuinfo")
    model = None
    logical = 0
    physical_ids: set[str] = set()
    core_ids: set[str] = set()
    cur_phys = ""
    for line in txt.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k, v = k.strip(), v.strip()
        if k in ("model name", "Processor", "Hardware") and not model:
            model = v
        elif k == "processor":
            logical += 1
        elif k == "physical id":
            cur_phys = v
            physical_ids.add(v)
        elif k == "core id":
            core_ids.add(f"{cur_phys}:{v}")
    physical = len(core_ids) or len(physical_ids) or logical or None
    return {"cpu": model, "logical": logical or None, "physical": physical}


def _meminfo() -> dict:
    txt = _read("/proc/meminfo")
    vals = {}
    for line in txt.splitlines():
        m = re.match(r"^(\w+):\s+(\d+)\s*kB", line)
        if m:
            vals[m.group(1)] = int(m.group(2)) * 1024
    total = vals.get("MemTotal", 0)
    avail = vals.get("MemAvailable")
    if avail is None:
        avail = vals.get("MemFree", 0) + vals.get("Buffers", 0) + vals.get("Cached", 0)
    used = max(total - avail, 0)
    percent = round(used / total * 100, 1) if total else 0.0
    return {"total": total, "used": used, "percent": percent}


# CPU% needs two samples of /proc/stat; remember the previous totals.
_prev_cpu: tuple[int, int] | None = None


def _cpu_percent() -> float:
    global _prev_cpu

    def sample() -> tuple[int, int]:
        for line in _read("/proc/stat").splitlines():
            if line.startswith("cpu "):
                parts = [int(x) for x in line.split()[1:]]
                idle = parts[3] + (parts[4] if len(parts) > 4 else 0)  # idle + iowait
                return sum(parts), idle
        return 0, 0

    cur = sample()
    if _prev_cpu is None:
        time.sleep(0.1)
        prev = cur
        cur = sample()
    else:
        prev = _prev_cpu
    _prev_cpu = cur
    dt = cur[0] - prev[0]
    di = cur[1] - prev[1]
    if dt <= 0:
        return 0.0
    return round((1 - di / dt) * 100, 1)


def _uptime() -> float:
    try:
        return float(_read("/proc/uptime").split()[0])
    except Exception:
        return 0.0


# --------------------------------------------------------------------------- #
# Storage (volumes) + Synology disk health/temperature
# --------------------------------------------------------------------------- #
def _volumes() -> list[dict]:
    """Per data-volume usage (mirrors agent._collect_disks 'disks' shape).

    DSM mounts user storage at ``/volume1``, ``/volume2``… plus the system
    partition at ``/``; we report the data volumes (and fall back to ``/``)."""
    out = []
    seen: set[str] = set()
    for line in _read("/proc/mounts").splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        dev, mp, fs = parts[0], parts[1], parts[2]
        if mp in seen:
            continue
        is_vol = re.match(r"^/volume(USB)?\d+$", mp)
        if not (is_vol or mp == "/"):
            continue
        try:
            st = os.statvfs(mp)
        except Exception:
            continue
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        used = total - (st.f_bfree * st.f_frsize)
        if total <= 0:
            continue
        seen.add(mp)
        out.append({"mount": mp, "fs": fs, "total": total, "used": used,
                    "percent": round(used / total * 100, 1) if total else 0.0,
                    "primary": False})
    # Mark the largest data volume primary (else '/').
    data = [d for d in out if d["mount"] != "/"] or out
    if data:
        big = max(data, key=lambda d: d["total"])
        big["primary"] = True
    return out


def _disk_health() -> list[dict]:
    """Physical-disk health + temperature via ``synodisk --enum`` (best-effort)."""
    out = []
    blob = _run(["/usr/syno/bin/synodisk", "--enum", "-output_format", "json"]) or \
        _run(["/usr/syno/bin/synodisk", "--enum"])
    # Newer DSM emits JSON; older emits "Disk path:/dev/sata1 ... Temp:38".
    try:
        import json
        data = json.loads(blob)
        items = data.get("disks") or data.get("data") or []
        for d in items:
            out.append({"name": d.get("dev_path") or d.get("disk_path") or d.get("name"),
                        "model": d.get("model"),
                        "temp": d.get("temperature") or d.get("temp"),
                        "health": d.get("smart_status") or d.get("status")})
        if out:
            return out
    except Exception:
        pass
    cur: dict = {}
    for line in blob.splitlines():
        line = line.strip()
        m = re.match(r"(?i)disk path\s*:?\s*(\S+)", line)
        if m:
            if cur:
                out.append(cur)
            cur = {"name": m.group(1)}
        mt = re.search(r"(?i)temp(?:erature)?\s*:?\s*(\d+)", line)
        if mt and cur:
            cur["temp"] = int(mt.group(1))
        ms = re.search(r"(?i)(smart\s*status|status)\s*:?\s*(\S+)", line)
        if ms and cur:
            cur["health"] = ms.group(2)
    if cur:
        out.append(cur)
    return out


def _system_temp() -> float | None:
    """System/CPU temperature (°C). DSM exposes it via synobios or hwmon."""
    out = _run(["/usr/syno/bin/synobios", "get_temperature"])
    m = re.search(r"(\d+)", out)
    if m:
        try:
            v = int(m.group(1))
            if 0 < v < 150:
                return float(v)
        except Exception:
            pass
    # hwmon fallback (millidegrees).
    import glob
    for p in glob.glob("/sys/class/hwmon/hwmon*/temp1_input"):
        raw = _read(p).strip()
        if raw.isdigit():
            v = int(raw)
            return round(v / 1000.0, 1) if v > 1000 else float(v)
    return None


# --------------------------------------------------------------------------- #
# Installed software (= installed DSM packages)
# --------------------------------------------------------------------------- #
def installed_software() -> list[dict]:
    """List installed DSM packages from /var/packages/*/INFO ({name,version,publisher})."""
    out: list[dict] = []
    base = "/var/packages"
    try:
        names = os.listdir(base)
    except Exception:
        return out
    for pkg in names:
        info = _read(os.path.join(base, pkg, "INFO"))
        if not info:
            continue
        vals = dict(re.findall(r'^(\w+)="?([^"\n]*)"?', info, re.MULTILINE))
        out.append({"name": vals.get("dname") or vals.get("package") or pkg,
                    "version": vals.get("version") or None,
                    "publisher": vals.get("maintainer") or "Synology"})
    out.sort(key=lambda d: (d["name"] or "").lower())
    return out


# --------------------------------------------------------------------------- #
# Public API (shapes match inventory.collect / agent._collect_metrics)
# --------------------------------------------------------------------------- #
def collect() -> dict:
    prod, build = _dsm_version()
    cpu = _cpu_info()
    nics = _nics()
    primary_ip = _primary_ip()
    uname = os.uname()
    model = _synoinfo("upnpmodelname") or _read("/proc/sys/kernel/syno_hw_version").strip() or None
    serial = _read("/proc/sys/kernel/syno_serial").strip() or _synoinfo("serial") or None
    return {
        "os": f"Synology DSM {prod}".strip(),
        "os_version": build,
        "os_arch": uname.machine,
        "kernel": uname.release,
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "logged_in_user": _logged_in_user(),
        "agent_version": AGENT_VERSION,
        "cpu": cpu["cpu"] or uname.machine,
        "cpu_cores_logical": cpu["logical"],
        "cpu_cores_physical": cpu["physical"],
        "ram_total": _meminfo()["total"] or None,
        "ip": primary_ip,
        "mac": _primary_mac(nics, primary_ip),
        "nics": nics,
        "manufacturer": "Synology",
        "model": model,
        "serial": serial,
        "gpu": None,
        "is_server": True,
        "boot_time": time.time() - _uptime(),
    }


# Net counters: sum rx/tx bytes across real interfaces from /proc/net/dev.
def _net_bytes() -> tuple[int, int]:
    rx = tx = 0
    for line in _read("/proc/net/dev").splitlines():
        if ":" not in line:
            continue
        iface, _, rest = line.partition(":")
        if iface.strip() == "lo":
            continue
        cols = rest.split()
        if len(cols) >= 9:
            try:
                rx += int(cols[0])
                tx += int(cols[8])
            except ValueError:
                pass
    return rx, tx


def metrics() -> dict:
    mem = _meminfo()
    vols = _volumes()
    primary = next((v for v in vols if v["primary"]), vols[0] if vols else None)
    rx, tx = _net_bytes()
    health = _disk_health()
    m = {
        "cpu_percent": _cpu_percent(),
        "mem_percent": mem["percent"], "mem_total": mem["total"], "mem_used": mem["used"],
        "disk_percent": primary["percent"] if primary else None,
        "disk_total": primary["total"] if primary else None,
        "disk_used": primary["used"] if primary else None,
        "disks": vols,
        "uptime": _uptime(),
        "net_sent": tx, "net_recv": rx,
        "logged_in_user": _logged_in_user(),
    }
    temp = _system_temp()
    if temp is not None:
        m["cpu_temp"] = temp
    if health:
        # Captured for the dashboard; folded under the volume disks for context.
        m["synology"] = {"disks": health}
    return m
