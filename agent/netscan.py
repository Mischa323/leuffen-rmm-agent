"""Node capabilities: Wake-on-LAN relay + network discovery scan.

Only active when the agent is promoted to a **node**. The scanner does a bounded
ping sweep across configured CIDRs, reads the ARP table for IP↔MAC, resolves
hostnames, and labels manufacturers via an OUI prefix table (best-effort).
"""
from __future__ import annotations

import asyncio
import ipaddress
import platform
import re
import socket
import subprocess

IS_WIN = platform.system() == "Windows"

# Minimal OUI → vendor hints; extend as needed. Best-effort only.
_OUI = {
    "001122": "Cimsys", "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi",
    "f0def1": "Wistron", "001a2b": "Ayecom", "3c5ab4": "Google",
    "0050c2": "IEEE", "001517": "Intel", "000c29": "VMware", "005056": "VMware",
    "0800271": "PCS/VirtualBox", "525400": "QEMU/KVM",
}


def _mac_vendor(mac: str | None) -> str | None:
    if not mac:
        return None
    prefix = mac.lower().replace(":", "").replace("-", "")[:6]
    return _OUI.get(prefix)


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


async def scan(cidrs: list[str], concurrency: int = 64) -> list[dict]:
    targets: list[str] = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            targets.extend(str(h) for h in net.hosts())
        except ValueError:
            continue
    targets = targets[:4096]  # safety cap

    nets = []
    for cidr in cidrs:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue

    sem = asyncio.Semaphore(concurrency)
    alive: set[str] = set()

    async def probe(ip: str) -> None:
        async with sem:
            if await asyncio.get_event_loop().run_in_executor(None, _ping, ip):
                alive.add(ip)

    # The ping sweep also populates the ARP cache via the underlying ARP requests,
    # so hosts that are up but drop ICMP (e.g. Windows' default firewall) still get
    # an ARP entry — we fold those in below so discovery isn't limited to pingers.
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
    for ip in sorted(found, key=lambda x: tuple(int(o) for o in x.split("."))):
        mac = arp.get(ip)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = None
        hosts.append({"ip": ip, "mac": mac, "hostname": hostname,
                      "manufacturer": _mac_vendor(mac), "online": True})
    return hosts
