"""Extended health monitors for the Leuffen RMM agent (Windows + Linux).

Best-effort collectors that back the standard-policy monitors:

  * disk / SMART health         (Windows Get-PhysicalDisk, Linux smartctl)
  * pending reboot required     (Windows registry, Linux /var/run/reboot-required)
  * Windows security posture    (Defender, firewall, BitLocker, failed logons)
  * Windows event-log errors    (System + Application, Critical/Error)
  * running-process set          (for the "process not running" monitor)

Every probe is wrapped so a failure returns ``None``/``[]`` and never breaks the
heartbeat. Because several shell out to PowerShell, the whole set is collected at
most once per ``_TTL`` seconds and cached — ``collect()`` is cheap to call on
every heartbeat.
"""
from __future__ import annotations

import os
import platform
import re
import subprocess
import threading
import time

try:
    import psutil
except Exception:  # pragma: no cover - psutil is a hard dep in practice
    psutil = None

_IS_WIN = platform.system() == "Windows"

_cache: dict = {"ts": 0.0, "data": {}}
_TTL = 90.0  # seconds; these signals change slowly, so polling can be relaxed


def _run(cmd: list[str], timeout: float) -> str:
    """Run a short probe command, returning stdout ('' on any failure). On
    Windows, CREATE_NO_WINDOW keeps a console from flashing in a user session."""
    kw: dict = {"capture_output": True, "text": True, "timeout": timeout}
    if os.name == "nt":
        kw["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    try:
        return subprocess.run(cmd, **kw).stdout or ""
    except Exception:
        return ""


def _ps(script: str, timeout: float = 25) -> str:
    return _run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                 "Bypass", "-Command", script], timeout)


# --------------------------------------------------------------------------- #
# Disk / SMART health
# --------------------------------------------------------------------------- #
def disk_health() -> list[dict] | None:
    """Per-physical-disk health. Each: {name, status} where status is 'Healthy',
    'Warning', 'Unhealthy' (Windows) or the SMART overall-health result (Linux).
    ``None`` when it can't be determined (so the server won't evaluate)."""
    if _IS_WIN:
        txt = _ps("Get-PhysicalDisk | ForEach-Object { \"$($_.FriendlyName)|$($_.HealthStatus)\" }", 25)
        out = []
        for line in txt.splitlines():
            line = line.strip()
            if "|" not in line:
                continue
            name, status = line.split("|", 1)
            name, status = name.strip(), status.strip()
            if name:
                out.append({"name": name, "status": status or "Unknown"})
        return out or None
    # Linux — requires smartmontools + privileges; entirely best-effort.
    import shutil
    if not shutil.which("smartctl"):
        return None
    devs = []
    for line in _run(["smartctl", "--scan"], 10).splitlines():
        m = re.match(r"(/dev/\S+)", line.strip())
        if m:
            devs.append(m.group(1))
    out = []
    for d in devs[:16]:
        res = re.search(r"self-assessment test result:\s*(\S+)",
                        _run(["smartctl", "-H", d], 10))
        if res:
            r = res.group(1)
            out.append({"name": d, "status": "Healthy" if r.upper() in ("PASSED", "PASS", "OK") else r})
    return out or None


# --------------------------------------------------------------------------- #
# Pending reboot
# --------------------------------------------------------------------------- #
def reboot_pending() -> bool:
    """True if the OS is waiting on a reboot (patched but not restarted)."""
    if _IS_WIN:
        script = (
            "$p=$false;"
            "if(Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending'){$p=$true};"
            "if(Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'){$p=$true};"
            "if(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue){$p=$true};"
            "if($p){'1'}else{'0'}")
        return _ps(script, 15).strip().endswith("1")
    return os.path.exists("/var/run/reboot-required")


# --------------------------------------------------------------------------- #
# Windows security posture (Defender / firewall / BitLocker / failed logons)
# --------------------------------------------------------------------------- #
_SEC_PS = r"""
$o=@()
try{$s=Get-MpComputerStatus -ErrorAction Stop; $o+="av_realtime=$($s.RealTimeProtectionEnabled)"; $o+="av_enabled=$($s.AntivirusEnabled)"; $o+="av_sigage=$($s.AntivirusSignatureAge)"}catch{}
try{$t=@(Get-MpThreat -ErrorAction SilentlyContinue | Where-Object {$_.IsActive}); $o+="av_threats=$($t.Count)"}catch{}
try{Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { $o+="fw_$($_.Name)=$($_.Enabled)" }}catch{}
try{Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object {$_.VolumeType -eq 'OperatingSystem'} | ForEach-Object { $o+="bl=$($_.ProtectionStatus)" }}catch{}
try{$o+="failed_logons=$(@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddMinutes(-15)} -ErrorAction SilentlyContinue).Count)"}catch{}
$o -join "`n"
""".strip()


def _to_bool(v: str) -> bool | None:
    v = (v or "").strip().lower()
    if v in ("true", "1", "on", "enabled"):
        return True
    if v in ("false", "0", "off", "disabled"):
        return False
    return None


def windows_security() -> dict | None:
    if not _IS_WIN:
        return None
    txt = _ps(_SEC_PS, 30)
    if not txt.strip():
        return None
    kv: dict[str, str] = {}
    for line in txt.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    sec: dict = {}
    av: dict = {}
    if "av_realtime" in kv:
        av["realtime"] = _to_bool(kv["av_realtime"])
    if "av_enabled" in kv:
        av["enabled"] = _to_bool(kv["av_enabled"])
    if kv.get("av_sigage", "").isdigit():
        av["sig_age_days"] = int(kv["av_sigage"])
    if kv.get("av_threats", "").isdigit():
        av["threats"] = int(kv["av_threats"])
    if av:
        sec["av"] = av
    fw = {}
    for prof in ("Domain", "Private", "Public"):
        b = _to_bool(kv.get(f"fw_{prof}", ""))
        if b is not None:
            fw[prof.lower()] = b
    if fw:
        sec["firewall"] = fw
    if "bl" in kv:
        # ProtectionStatus: 'On'/'Off' or 1/0
        sec["bitlocker_system"] = kv["bl"].strip().lower() in ("on", "1")
    if kv.get("failed_logons", "").isdigit():
        sec["failed_logons_15m"] = int(kv["failed_logons"])
    return sec or None


# --------------------------------------------------------------------------- #
# Windows event log (recent Critical/Error events, System + Application)
# --------------------------------------------------------------------------- #
_EVT_PS = r"""
try {
  Get-WinEvent -FilterHashtable @{LogName='System','Application';Level=1,2;StartTime=(Get-Date).AddMinutes(-15)} -MaxEvents 40 -ErrorAction SilentlyContinue |
  ForEach-Object {
    $m = ''
    if ($_.Message) { $m = ($_.Message -replace "[`r`n]+"," ").Trim(); if ($m.Length -gt 200) { $m = $m.Substring(0,200) } }
    "$($_.LogName)|$($_.Id)|$($_.LevelDisplayName)|$($_.ProviderName)|$m"
  }
} catch {}
""".strip()


def windows_events() -> list[dict] | None:
    if not _IS_WIN:
        return None
    out = []
    for line in _ps(_EVT_PS, 30).splitlines():
        parts = line.split("|", 4)
        if len(parts) < 4:
            continue
        log, eid, level, source = parts[0], parts[1], parts[2], parts[3]
        msg = parts[4] if len(parts) > 4 else ""
        if not eid.strip().isdigit():
            continue
        out.append({"log": log.strip(), "id": int(eid.strip()),
                    "level": level.strip(), "source": source.strip(), "msg": msg.strip()})
    return out  # [] is meaningful (no recent errors) so the server can clear


# --------------------------------------------------------------------------- #
# Running processes (for the "process not running" monitor)
# --------------------------------------------------------------------------- #
def process_names() -> list[str] | None:
    if psutil is None:
        return None
    names = set()
    try:
        for p in psutil.process_iter(["name"]):
            n = (p.info.get("name") or "").strip()
            if n:
                names.add(n)
    except Exception:
        return None
    return sorted(names)[:600] or None


# --------------------------------------------------------------------------- #
# Available OS updates (Windows Update / apt / dnf-yum)
# --------------------------------------------------------------------------- #
# The update probe is slow and network-bound, so it runs in a background thread
# and is refreshed at most every _UPDATES_TTL; ``updates_available()`` only ever
# returns the cached value and never blocks a heartbeat (a slow probe must not
# delay metrics and trip a false 'offline').
_UPDATES_TTL = 6 * 3600.0
_UPDATES_BACKOFF = 1800.0   # retry sooner while we still have no count
_updates_state: dict = {"count": None, "ts": 0.0, "running": False}


def _win_updates() -> int | None:
    txt = _ps(
        "try{$s=New-Object -ComObject Microsoft.Update.Session;"
        "$r=$s.CreateUpdateSearcher().Search(\"IsInstalled=0 and IsHidden=0 and Type='Software'\");"
        "[Console]::Out.Write($r.Updates.Count)}catch{}", 120)
    txt = (txt or "").strip()
    return int(txt) if txt.isdigit() else None


def _linux_updates() -> int | None:
    if os.path.exists("/usr/bin/apt-get"):
        txt = _run(["apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade"], 60)
        if txt:
            return sum(1 for ln in txt.splitlines() if ln.startswith("Inst "))
    for tool in ("/usr/bin/dnf", "/usr/bin/yum"):
        if os.path.exists(tool):
            txt = _run([tool, "-q", "check-update"], 90)
            return sum(1 for ln in txt.splitlines()
                       if ln.strip() and len(ln.split()) >= 3
                       and not ln.startswith(("Last metadata", "Obsoleting", "Security")))
    return None


def _refresh_updates() -> None:
    try:
        count = _win_updates() if _IS_WIN else _linux_updates()
    except Exception:
        count = None
    _updates_state["ts"] = time.time()
    if count is not None:
        _updates_state["count"] = count
    _updates_state["running"] = False


def updates_available() -> int | None:
    """Number of OS updates ready to install (Windows Update / apt / dnf-yum), or
    None when it can't be determined. Non-blocking: kicks a background refresh
    when the cached value is stale and returns whatever is cached."""
    st = _updates_state
    ttl = _UPDATES_TTL if st["count"] is not None else _UPDATES_BACKOFF
    if not st["running"] and time.time() - st["ts"] >= ttl:
        st["running"] = True
        threading.Thread(target=_refresh_updates, daemon=True).start()
    return st["count"]


# --------------------------------------------------------------------------- #
# Throttled aggregate
# --------------------------------------------------------------------------- #
def collect() -> dict:
    """Return the extended-monitor metrics, cached for ``_TTL`` seconds. Safe to
    call every heartbeat; runs the real probes at most once per interval."""
    now = time.time()
    if _cache["data"] and now - _cache["ts"] < _TTL:
        return _cache["data"]
    data: dict = {}
    try:
        dh = disk_health()
        if dh:
            data["disk_health"] = dh
    except Exception:
        pass
    try:
        data["reboot_pending"] = reboot_pending()
    except Exception:
        pass
    try:
        uc = updates_available()
        if uc is not None:
            data["updates_available"] = uc
    except Exception:
        pass
    try:
        procs = process_names()
        if procs:
            data["processes"] = procs
    except Exception:
        pass
    if _IS_WIN:
        try:
            sec = windows_security()
            if sec:
                data["security"] = sec
        except Exception:
            pass
        try:
            ev = windows_events()
            if ev is not None:
                data["events"] = ev
        except Exception:
            pass
    _cache["ts"] = now
    _cache["data"] = data
    return data
