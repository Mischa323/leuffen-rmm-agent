"""Cross-platform device inventory collection (Windows + Linux).

Uses only ``psutil`` + the stdlib so the idle agent stays light. Manufacturer/
model/serial come from WMI on Windows and ``/sys/class/dmi/id`` on Linux, both
best-effort with graceful fallbacks.
"""
from __future__ import annotations

import platform
import socket
import subprocess
import uuid

import psutil

AGENT_VERSION = "2.2.10"


def installed_software() -> list[dict]:
    """Installed programs: the Windows uninstall registry, or the Linux package
    manager. Best-effort; returns [{name, version, publisher}]."""
    if platform.system() == "Windows":
        return _software_windows()
    return _software_linux()


def _software_windows() -> list[dict]:
    import json as _json
    # Include HKLM (machine-wide), WOW6432Node (32-bit on 64-bit OS), and every
    # loaded user hive under HKU (catches user-installed apps even when the agent
    # runs as SYSTEM, where HKCU is the system account with no installs).
    ps = r"""
$uninstall = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
$paths = @(
    "HKLM:\$uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\$uninstall\*"
)
# Add each loaded user hive (HKU\<SID>) that isn't a system/service account.
Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object {
    $sid = $_.PSChildName
    if ($sid -notmatch '^S-1-5-18|^S-1-5-19|^S-1-5-20|_Classes$') {
        $paths += "HKU:\$sid\$uninstall\*"
        $paths += "HKU:\$sid\SOFTWARE\WOW6432Node\$uninstall\*"
    }
}
# Mount HKU: drive if not already present.
if (-not (Get-PSDrive HKU -ErrorAction SilentlyContinue)) {
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
}
Get-ItemProperty $paths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -and -not $_.SystemComponent } |
    Select-Object @{n='name';e={$_.DisplayName}},
                  @{n='version';e={$_.DisplayVersion}},
                  @{n='publisher';e={$_.Publisher}} |
    Sort-Object name -Unique |
    ConvertTo-Json -Compress -AsArray
"""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=90,
        )
        raw = (out.stdout or "").strip()
        if not raw:
            return []
        data = _json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        return [{"name": d.get("name"), "version": d.get("version"), "publisher": d.get("publisher")}
                for d in data if d.get("name")]
    except Exception:
        return []


def _software_linux() -> list[dict]:
    import shutil
    out: list[dict] = []
    try:
        if shutil.which("dpkg-query"):
            r = subprocess.run(["dpkg-query", "-W", "-f=${Package}\\t${Version}\\n"],
                               capture_output=True, text=True, timeout=30)
            for line in r.stdout.splitlines():
                p = line.split("\t")
                if p and p[0]:
                    out.append({"name": p[0], "version": p[1] if len(p) > 1 else None, "publisher": "dpkg"})
        elif shutil.which("rpm"):
            r = subprocess.run(["rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n"],
                               capture_output=True, text=True, timeout=30)
            for line in r.stdout.splitlines():
                p = line.split("\t")
                if p and p[0]:
                    out.append({"name": p[0], "version": p[1] if len(p) > 1 else None, "publisher": "rpm"})
        elif shutil.which("apk"):
            r = subprocess.run(["apk", "list", "--installed"], capture_output=True, text=True, timeout=30)
            for line in r.stdout.splitlines():
                # "name-1.2.3-r0 x86_64 {origin} (license) [installed]"
                tok = line.split(" ", 1)[0]
                out.append({"name": tok, "version": None, "publisher": "apk"})
    except Exception:
        return out
    out.sort(key=lambda x: (x["name"] or "").lower())
    return out


def _gpus() -> str | None:
    """Best-effort GPU name(s). WMI on Windows; lspci / nvidia-smi on Linux."""
    names: list[str] = []
    try:
        if platform.system() == "Windows":
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-CimInstance Win32_VideoController | "
                 "Where-Object { $_.Name } | ForEach-Object { $_.Name }"],
                capture_output=True, text=True, timeout=15)
            names = [l.strip() for l in out.stdout.splitlines() if l.strip()]
        else:
            try:
                out = subprocess.run(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
                                     capture_output=True, text=True, timeout=8)
                names = [l.strip() for l in out.stdout.splitlines() if l.strip()]
            except Exception:
                names = []
            if not names:
                out = subprocess.run(["sh", "-c", "lspci | grep -Ei 'vga|3d|display'"],
                                     capture_output=True, text=True, timeout=8)
                for line in out.stdout.splitlines():
                    # "... VGA compatible controller: <name>"
                    if ":" in line:
                        names.append(line.split(":", 2)[-1].strip())
    except Exception:
        pass
    # De-dup while preserving order.
    seen, uniq = set(), []
    for n in names:
        if n and n not in seen:
            seen.add(n); uniq.append(n)
    return ", ".join(uniq) or None


def _logged_in_user() -> str | None:
    """Best-effort name of the interactive/console user currently signed in."""
    try:
        users = psutil.users()
    except Exception:
        users = []
    names: list[str] = []
    for u in users:
        if u.name and u.name not in names:
            names.append(u.name)
    if names:
        return ", ".join(names)
    # Fallback to the process owner on Windows (agent runs as SYSTEM there, so
    # this is mostly useful on Linux/desktop).
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return None


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


def _nics() -> list[dict]:
    out = []
    addrs = psutil.net_if_addrs()
    for name, snics in addrs.items():
        ipv4, ipv6, mac = [], [], None
        for a in snics:
            if a.family == socket.AF_INET:
                ipv4.append(a.address)
            elif a.family == socket.AF_INET6:
                ipv6.append(a.address.split("%")[0])
            elif getattr(a, "family", None) == psutil.AF_LINK:
                if a.address and a.address != "00:00:00:00:00:00":
                    mac = a.address
        if ipv4 or mac:
            out.append({"name": name, "ipv4": ipv4, "ipv6": ipv6, "mac": mac})
    return out


def _primary_mac(nics: list[dict], primary_ip: str | None) -> str | None:
    for n in nics:
        if primary_ip and primary_ip in n["ipv4"] and n["mac"]:
            return n["mac"]
    for n in nics:
        if n["mac"]:
            return n["mac"]
    # Fallback to uuid.getnode()
    node = uuid.getnode()
    return ":".join(f"{(node >> e) & 0xff:02x}" for e in range(40, -1, -8))


def _hardware_linux() -> dict:
    def read(path: str) -> str | None:
        try:
            with open(path) as f:
                return f.read().strip()
        except Exception:
            return None
    return {
        "manufacturer": read("/sys/class/dmi/id/sys_vendor"),
        "model": read("/sys/class/dmi/id/product_name"),
        "serial": read("/sys/class/dmi/id/product_serial"),
    }


def _hardware_windows() -> dict:
    info = {"manufacturer": None, "model": None, "serial": None, "is_server": False}
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "$c=Get-CimInstance Win32_ComputerSystem; $b=Get-CimInstance Win32_BIOS; "
             "$o=Get-CimInstance Win32_OperatingSystem; "
             "Write-Output $c.Manufacturer; Write-Output $c.Model; "
             "Write-Output $b.SerialNumber; Write-Output $o.ProductType"],
            capture_output=True, text=True, timeout=15,
        )
        lines = [l.strip() for l in out.stdout.splitlines() if l.strip()]
        if len(lines) >= 3:
            info["manufacturer"], info["model"], info["serial"] = lines[0], lines[1], lines[2]
        if len(lines) >= 4:
            # ProductType: 1=workstation, 2=domain controller, 3=server
            info["is_server"] = lines[3] in ("2", "3")
    except Exception:
        pass
    return info


def collect() -> dict:
    sysname = platform.system()
    nics = _nics()
    primary_ip = _primary_ip()
    hw = _hardware_windows() if sysname == "Windows" else _hardware_linux()
    try:
        ram_total = psutil.virtual_memory().total
    except Exception:
        ram_total = None
    inv = {
        "os": f"{sysname} {platform.release()}".strip(),
        "os_version": platform.version(),
        "os_arch": platform.machine(),
        "kernel": platform.release(),
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "logged_in_user": _logged_in_user(),
        "agent_version": AGENT_VERSION,
        "cpu": platform.processor() or platform.machine(),
        "cpu_cores_logical": psutil.cpu_count(),
        "cpu_cores_physical": psutil.cpu_count(logical=False),
        "ram_total": ram_total,
        "ip": primary_ip,
        "mac": _primary_mac(nics, primary_ip),
        "nics": nics,
        "manufacturer": hw.get("manufacturer"),
        "model": hw.get("model"),
        "serial": hw.get("serial"),
        "gpu": _gpus(),
        "is_server": hw.get("is_server", False),
        "boot_time": psutil.boot_time(),
    }
    return inv
