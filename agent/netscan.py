"""Node capabilities: Wake-on-LAN relay + network discovery scan.

Only active when the agent is promoted to a **node**. Discovery prefers **nmap**
when it's installed on the node (reliable host discovery + accurate vendor data),
and otherwise falls back to a built-in sweep: an ICMP ping plus a TCP-connect
probe so hosts that drop ICMP are still found, with IP↔MAC from the ARP cache and
vendor names from a bundled IEEE OUI database (a tiny built-in table is the last
resort). Either way it returns ``{ip, mac, hostname, manufacturer, online}``.
"""
from __future__ import annotations

import asyncio
import errno
import ipaddress
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET

IS_WIN = platform.system() == "Windows"
HERE = os.path.dirname(os.path.abspath(__file__))

# Tiny OUI fallback, used only when the bundled vendor database isn't available
# (e.g. source installs). The full list comes from the bundled nmap-mac-prefixes.
_OUI = {
    "001122": "Cimsys", "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi",
    "f0def1": "Wistron", "001a2b": "Ayecom", "3c5ab4": "Google",
    "0050c2": "IEEE", "001517": "Intel", "000c29": "VMware", "005056": "VMware",
    "080027": "PCS/VirtualBox", "525400": "QEMU/KVM",
}

# Common ports probed for TCP liveness when ICMP is dropped/filtered.
_COMMON_PORTS = (443, 80, 445, 22, 3389, 135, 139, 8080)

_oui_db: dict[str, str] | None = None
_OUI_FILES = ("nmap-mac-prefixes", "oui.txt")


def _oui_db_path() -> str | None:
    """Locate the bundled OUI database: the PyInstaller bundle when frozen, else a
    vendored folder beside the agent."""
    for d in (getattr(sys, "_MEIPASS", None), os.path.join(HERE, "vendor"), HERE):
        if not d:
            continue
        for name in _OUI_FILES:
            p = os.path.join(d, name)
            if os.path.exists(p):
                return p
    return None


def _load_oui() -> dict[str, str]:
    """Parse the bundled vendor database once. Lines are ``AABBCC Vendor Name``
    (the nmap-mac-prefixes format); blank/comment lines are skipped."""
    global _oui_db
    if _oui_db is not None:
        return _oui_db
    _oui_db = {}
    path = _oui_db_path()
    if path:
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        key = parts[0].lower().replace(":", "").replace("-", "")[:6]
                        if len(key) == 6:
                            _oui_db[key] = parts[1].strip()
        except Exception:
            pass
    return _oui_db


def _mac_vendor(mac: str | None) -> str | None:
    if not mac:
        return None
    prefix = mac.lower().replace(":", "").replace("-", "")[:6]
    return _load_oui().get(prefix) or _OUI.get(prefix)


def send_magic_packet(mac: str, broadcast: str = "255.255.255.255", port: int = 9) -> None:
    clean = mac.replace(":", "").replace("-", "")
    packet = b"\xff" * 6 + bytes.fromhex(clean) * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(packet, (broadcast, port))


def _ping(ip: str) -> bool:
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", "500", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        return subprocess.run(cmd, capture_output=True, timeout=3).returncode == 0
    except Exception:
        return False


def _tcp_alive(ip: str, ports: tuple = _COMMON_PORTS, timeout: float = 0.6) -> bool:
    """True if any common port is open or *actively refused* — both mean the host
    is up (a refusal is an RST from a live host), so ICMP-droppers are found."""
    for p in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                rc = s.connect_ex((ip, p))
            if rc == 0 or rc == errno.ECONNREFUSED or (IS_WIN and rc == 10061):
                return True
        except OSError:
            pass
    return False


def _arp_table() -> dict[str, str]:
    """Return {ip: mac} from the OS ARP cache."""
    table: dict[str, str] = {}
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return table
    for line in out.splitlines():
        ipm = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        macm = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
        if ipm and macm:
            table[ipm.group(1)] = macm.group(0).replace("-", ":").lower()
    return table


def _ip_key(ip: str):
    try:
        return tuple(int(o) for o in ip.split("."))
    except ValueError:
        return (0, 0, 0, 0)


def _parse_nmap_xml(data: bytes) -> list[dict]:
    hosts: list[dict] = []
    root = ET.fromstring(data)
    for h in root.findall("host"):
        st = h.find("status")
        if st is not None and st.get("state") != "up":
            continue
        ip = mac = vendor = hostname = None
        for a in h.findall("address"):
            t = a.get("addrtype")
            if t == "ipv4":
                ip = a.get("addr")
            elif t == "mac":
                mac = (a.get("addr") or "").lower() or None
                vendor = a.get("vendor")
        hn = h.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name")
        if not ip:
            continue
        hosts.append({"ip": ip, "mac": mac, "hostname": hostname,
                      "manufacturer": vendor or _mac_vendor(mac), "online": True})
    hosts.sort(key=lambda x: _ip_key(x["ip"]))
    return hosts


async def _nmap_scan(cidrs: list[str]) -> list[dict] | None:
    """Host discovery via ``nmap -sn`` (ping scan, no port scan). Returns hosts,
    or None when nmap isn't installed/usable so the caller can fall back."""
    if not shutil.which("nmap"):
        return None
    try:
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sn", "--max-retries", "1", "-oX", "-", *cidrs,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=900)
    except Exception:
        return None
    # Non-zero exit (e.g. Windows without Npcap) or no hosts → fall back.
    if proc.returncode != 0 or not out:
        return None
    try:
        hosts = _parse_nmap_xml(out)
    except Exception:
        return None
    return hosts or None


async def _builtin_scan(cidrs: list[str], concurrency: int) -> list[dict]:
    targets: list[str] = []
    nets = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        nets.append(net)
        targets.extend(str(h) for h in net.hosts())
    targets = targets[:4096]  # safety cap

    sem = asyncio.Semaphore(concurrency)
    alive: set[str] = set()

    async def probe(ip: str) -> None:
        async with sem:
            loop = asyncio.get_event_loop()
            # ICMP first (cheap); the ping also primes the ARP cache. Hosts that
            # drop ICMP get a second chance via a TCP-connect probe.
            if await loop.run_in_executor(None, _ping, ip):
                alive.add(ip)
            elif await loop.run_in_executor(None, _tcp_alive, ip):
                alive.add(ip)

    await asyncio.gather(*(probe(ip) for ip in targets))

    arp = _arp_table()

    def _in_scope(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in nets)

    found = set(alive)
    found.update(ip for ip in arp if _in_scope(ip))

    hosts = []
    for ip in sorted(found, key=_ip_key):
        mac = arp.get(ip)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = None
        hosts.append({"ip": ip, "mac": mac, "hostname": hostname,
                      "manufacturer": _mac_vendor(mac), "online": True})
    return hosts


async def scan(cidrs: list[str], concurrency: int = 64) -> list[dict]:
    """Discover hosts on the given CIDRs — nmap when available, else a built-in
    ICMP+TCP sweep. Returns ``[{ip, mac, hostname, manufacturer, online}]``."""
    cidrs = [c for c in (cidrs or []) if c]
    if not cidrs:
        return []
    nm = await _nmap_scan(cidrs)
    if nm is not None:
        return nm
    return await _builtin_scan(cidrs, concurrency)
