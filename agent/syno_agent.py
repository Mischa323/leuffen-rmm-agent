"""Leuffen RMM agent for Synology DSM — pure standard library, no dependencies.

The cross-platform agent (:mod:`agent`) needs ``psutil`` + ``websockets``, which are
awkward to ship across every Synology CPU arch. This slim variant speaks the same
JSON-over-WebSocket protocol to the server (so a NAS shows up like any other device)
but implements the WebSocket client itself over ``socket``/``ssl`` and reads metrics
from ``/proc`` via :mod:`syno_inventory`. It reuses :mod:`handlers` for the file
browser; shell + power are handled here with DSM-friendly commands.

Distributed as a Synology package (``.spk``) the RMM server assembles on demand and
serves through a Package Center *package source*; config (server URL + enrolment key)
is baked into ``rmm_config.json`` at download time, so install needs no typing.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import handlers
import syno_inventory

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("rmm.syno")

HERE = os.path.dirname(os.path.abspath(__file__))


# --------------------------------------------------------------------------- #
# Config + identity (mirrors agent.py, DSM paths)
# --------------------------------------------------------------------------- #
def _data_dir() -> str:
    """Writable directory for config + device id (stable across upgrades).

    The SPK's start script points ``RMM_DATA_DIR`` at the package's persistent
    ``var`` area; fall back to a dot-dir under HOME, then the script dir."""
    env = os.environ.get("RMM_DATA_DIR")
    candidates = [env] if env else []
    candidates += [os.path.join(os.path.expanduser("~"), ".leuffen-rmm"), HERE]
    for d in candidates:
        if not d:
            continue
        try:
            os.makedirs(d, exist_ok=True)
            if os.access(d, os.W_OK):
                return d
        except Exception:
            continue
    return HERE


def _load_config() -> dict:
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
    env_insecure = os.environ.get("RMM_INSECURE_TLS")
    if env_insecure is not None:
        cfg["insecure_tls"] = env_insecure.lower() in ("1", "true", "yes")
    cfg["insecure_tls"] = bool(cfg.get("insecure_tls", False))
    su = (cfg.get("server_url") or "").strip()
    if su and not su.startswith(("http://", "https://")):
        su = "https://" + su
    cfg["server_url"] = su.rstrip("/") or None
    cfg["fingerprint"] = (cfg.get("fingerprint") or "").replace(":", "").strip().lower() or None
    return cfg


def _device_id() -> str:
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
        os.chmod(_device_secret_path(), 0o600)
    except Exception:
        pass


def _ws_url(server_url: str, api_key: str) -> str:
    base = server_url.replace("http://", "ws://").replace("https://", "wss://").rstrip("/")
    return f"{base}/api/agents/ws?key={api_key}"


# --------------------------------------------------------------------------- #
# Minimal RFC 6455 WebSocket client (stdlib only)
# --------------------------------------------------------------------------- #
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class WSClient:
    """A tiny client-side WebSocket over a (TLS) socket. Text frames only."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self._buf = b""
        self._send_lock = threading.Lock()
        self._closed = False

    @classmethod
    def connect(cls, url: str, *, insecure: bool = False, fingerprint: str | None = None,
                timeout: float = 30.0, read_timeout: float = 90.0) -> "WSClient":
        scheme, _, rest = url.partition("://")
        host_port, _, path = rest.partition("/")
        path = "/" + path
        if ":" in host_port:
            host, port_s = host_port.rsplit(":", 1)
            port = int(port_s)
        else:
            host = host_port
            port = 443 if scheme == "wss" else 80
        raw = socket.create_connection((host, port), timeout=timeout)
        if scheme == "wss":
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=host)
            if fingerprint:
                der = sock.getpeercert(binary_form=True)
                got = hashlib.sha256(der).hexdigest() if der else ""
                if got != fingerprint:
                    sock.close()
                    raise RuntimeError("server certificate fingerprint mismatch — refusing")
        else:
            sock = raw
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET {path} HTTP/1.1\r\n"
               f"Host: {host}:{port}\r\n"
               "Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        sock.sendall(req.encode())
        self = cls(sock)
        line = self._read_http_response()
        if " 101 " not in line:
            sock.close()
            raise RuntimeError(f"websocket upgrade failed: {line.strip()}")
        accept = base64.b64encode(hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()
        if accept.lower() not in self._resp_headers.lower():
            log.debug("server did not echo expected accept token (continuing)")
        sock.settimeout(read_timeout)
        return self

    def _read_http_response(self) -> str:
        while b"\r\n\r\n" not in self._buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("connection closed during handshake")
            self._buf += chunk
        head, _, self._buf = self._buf.partition(b"\r\n\r\n")
        text = head.decode("latin-1")
        self._resp_headers = text
        return text.split("\r\n", 1)[0]

    def _read(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("connection closed")
            self._buf += chunk
        data, self._buf = self._buf[:n], self._buf[n:]
        return data

    def _read_frame(self) -> tuple[bool, int, bytes]:
        b0, b1 = self._read(2)
        fin = bool(b0 & 0x80)
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        length = b1 & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._read(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._read(8))[0]
        mask = self._read(4) if masked else b""
        payload = self._read(length) if length else b""
        if masked:
            payload = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
        return fin, opcode, payload

    def recv(self) -> str | None:
        """Return the next text message, or None when the peer closes."""
        chunks: list[bytes] = []
        cur_op: int | None = None
        while True:
            fin, opcode, payload = self._read_frame()
            if opcode == 0x8:        # close
                self._safe(lambda: self._send_frame(0x8, payload[:2]))
                self._closed = True
                return None
            if opcode == 0x9:        # ping -> pong
                self._safe(lambda: self._send_frame(0xA, payload))
                continue
            if opcode == 0xA:        # pong
                continue
            if opcode == 0x0:        # continuation
                chunks.append(payload)
            else:
                cur_op = opcode
                chunks = [payload]
            if not fin:
                continue
            data = b"".join(chunks)
            op, cur_op, chunks = cur_op, None, []
            if op == 0x1:
                return data.decode("utf-8", "replace")
            # binary frames are ignored; keep reading.

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        header = bytearray([0x80 | opcode])
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack("!H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack("!Q", n)
        mask = os.urandom(4)
        header += mask
        masked = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
        with self._send_lock:
            self.sock.sendall(bytes(header) + masked)

    def send(self, text: str) -> None:
        self._send_frame(0x1, text.encode("utf-8"))

    def close(self) -> None:
        if not self._closed:
            self._safe(lambda: self._send_frame(0x8, b""))
            self._closed = True
        self._safe(self.sock.close)

    @staticmethod
    def _safe(fn) -> None:
        try:
            fn()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Local shell + power (DSM-aware)
# --------------------------------------------------------------------------- #
def _run_command(cmd: str, timeout: float = 60) -> dict:
    try:
        r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True, timeout=timeout)
        return {"output": (r.stdout or "") + (r.stderr or ""), "code": r.returncode}
    except subprocess.TimeoutExpired:
        return {"output": "(timed out)", "code": 124}
    except Exception as exc:
        return {"output": f"error: {exc}", "code": 1}


def _run_script(content: str, timeout: float, env: dict | None, files: list | None) -> dict:
    import shutil
    import tempfile
    workdir = tempfile.mkdtemp(prefix="rmm-")
    path = os.path.join(workdir, "script.sh")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        for item in (files or []):
            name = os.path.basename(item.get("name") or "")
            if name:
                with open(os.path.join(workdir, name), "wb") as f:
                    f.write(base64.b64decode(item.get("b64") or ""))
        run_env = dict(os.environ)
        for k, v in (env or {}).items():
            run_env[str(k)] = str(v)
        os.chmod(path, 0o700)
        r = subprocess.run(["/bin/sh", path], capture_output=True, text=True,
                           cwd=workdir, env=run_env, timeout=timeout)
        return {"output": (r.stdout or "") + (r.stderr or ""), "code": r.returncode}
    except subprocess.TimeoutExpired:
        return {"output": "(timed out)", "code": 124}
    except Exception as exc:
        return {"output": f"error: {exc}", "code": 1}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _power(action: str) -> dict:
    """Reboot/shutdown the NAS, preferring DSM tools with a generic fallback."""
    chains = {
        "reboot": [["/usr/syno/sbin/synoreboot"], ["reboot"], ["shutdown", "-r", "now"]],
        "shutdown": [["/usr/syno/sbin/synopoweroff"], ["poweroff"], ["shutdown", "-h", "now"]],
    }
    if action not in chains:
        return {"ok": False, "error": f"unsupported action {action}"}
    last = ""
    for argv in chains[action]:
        if argv[0].startswith("/") and not os.path.exists(argv[0]):
            continue
        try:
            subprocess.Popen(argv)
            return {"ok": True, "action": action}
        except Exception as exc:
            last = str(exc)
    return {"ok": False, "error": last or "no power command available"}


# --------------------------------------------------------------------------- #
# Agent
# --------------------------------------------------------------------------- #
class Agent:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.id = _device_id()
        self.ws: WSClient | None = None
        self._pool = ThreadPoolExecutor(max_workers=4)

    def run_forever(self) -> None:
        url = _ws_url(self.cfg["server_url"], self.cfg["api_key"])
        backoff = 2
        while True:
            try:
                self._session(url)
                backoff = 2
            except Exception as exc:
                log.warning("connection lost (%s); retrying in %ss", exc, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)

    def _session(self, url: str) -> None:
        ws = WSClient.connect(url, insecure=self.cfg["insecure_tls"],
                              fingerprint=self.cfg["fingerprint"])
        self.ws = ws
        self._register()
        log.info("registered as %s (%s)", socket.gethostname(), self.id)
        stop = threading.Event()
        hb = threading.Thread(target=self._heartbeat, args=(stop,), daemon=True)
        hb.start()
        try:
            while True:
                msg = ws.recv()
                if msg is None:
                    break
                try:
                    data = json.loads(msg)
                except Exception:
                    continue
                self._handle(data)
        finally:
            stop.set()
            ws.close()

    def _heartbeat(self, stop: threading.Event) -> None:
        syno_inventory._cpu_percent()  # prime the delta
        while not stop.wait(self.cfg["interval"]):
            try:
                self._send({"type": "metrics", "metrics": syno_inventory.metrics()})
            except Exception:
                return

    def _send(self, msg: dict) -> None:
        self.ws.send(json.dumps(msg))

    def _register(self) -> None:
        inv = syno_inventory.collect()
        self._send({"type": "register", "id": self.id, "hostname": inv["hostname"],
                    "inventory": inv, "supports_secret": True,
                    "device_secret": _load_device_secret()})

    def _ack(self, rid: str | None, payload: dict) -> None:
        if rid:
            self._send({"type": "ack", "rid": rid, "payload": payload})

    def _submit(self, rid: str | None, fn) -> None:
        def job():
            try:
                res = fn()
            except Exception as exc:
                res = {"ok": False, "error": str(exc)}
            self._ack(rid, res)
        self._pool.submit(job)

    def _handle(self, msg: dict) -> None:
        t = msg.get("type")
        rid = msg.get("rid")
        if t == "device_secret":
            _save_device_secret(msg.get("secret", ""))
            log.info("stored server-issued device secret")
        elif t == "shell_run":
            self._submit(rid, lambda: _run_command(msg.get("cmd", "")))
        elif t == "script_run":
            self._submit(rid, lambda: _run_script(msg.get("content", ""),
                                                  float(msg.get("timeout", 120)),
                                                  msg.get("env"), msg.get("files")))
        elif t == "shell_input":
            self._pool.submit(self._shell_input, msg)
        elif t == "power":
            self._submit(rid, lambda: _power(msg.get("action", "")))
        elif t == "file_get":
            self._submit(rid, lambda: handlers.file_get(msg.get("path", "")))
        elif t == "file_put":
            self._submit(rid, lambda: handlers.file_put(msg.get("path", ""), msg.get("data", "")))
        elif t == "file_list":
            self._submit(rid, lambda: handlers.file_list(msg.get("path", "")))
        elif t == "dir_size":
            self._submit(rid, lambda: handlers.dir_size(msg.get("path", "")))
        elif t == "file_delete":
            self._submit(rid, lambda: handlers.file_delete(msg.get("path", "")))
        elif t == "file_mkdir":
            self._submit(rid, lambda: handlers.file_mkdir(msg.get("path", "")))
        elif t == "software_list":
            self._submit(rid, lambda: {"ok": True, "software": syno_inventory.installed_software()})
        elif t == "update_agent":
            self._ack(rid, {"ok": False,
                            "error": "Synology agent updates are managed via Package Center"})
        # set_role / agent_policy / snmp_* / screen_* / scan: not applicable to a NAS.

    def _shell_input(self, msg: dict) -> None:
        res = _run_command(msg.get("data", ""))
        self._send({"type": "shell_output", "data": res["output"], "code": res["code"]})


def main() -> int:
    cfg = _load_config()
    if not (cfg.get("server_url") and cfg.get("api_key")):
        log.error("missing server_url/api_key — set RMM_SERVER_URL/RMM_API_KEY or "
                  "rmm_config.json in %s", _data_dir())
        return 2
    log.info("Leuffen RMM Synology agent v%s starting (server %s)",
             syno_inventory.AGENT_VERSION, cfg["server_url"])
    Agent(cfg).run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
