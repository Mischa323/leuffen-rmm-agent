"""Remote desktop: screen capture + input injection.

Heavy GUI/imaging deps (``mss``, ``Pillow``, ``pynput``) are imported lazily so an
idle agent never loads them, and the module degrades gracefully with no display.

On Windows the agent runs as SYSTEM in session 0, which **cannot** capture the
interactive user's desktop (``BitBlt`` fails). So on Windows the capture + input
injection run in a short-lived **helper** process launched inside the active
user's session (via ``handlers._run_in_active_session``). The helper streams JPEG
frames back to the agent over a loopback TCP socket and receives input events the
same way. On Linux (or when already interactive) the agent captures directly.
"""
from __future__ import annotations

import asyncio
import io
import json
import os
import platform
import socket
import subprocess
import sys
import threading


# --------------------------------------------------------------------------- #
# Length-prefixed framing over the loopback socket (4-byte big-endian length).
# --------------------------------------------------------------------------- #
def _recv_exact(sock, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except Exception:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def _send_msg(sock, data: bytes) -> bool:
    try:
        sock.sendall(len(data).to_bytes(4, "big") + data)
        return True
    except Exception:
        return False


def _recv_msg(sock) -> bytes | None:
    hdr = _recv_exact(sock, 4)
    if not hdr:
        return None
    n = int.from_bytes(hdr, "big")
    if n <= 0 or n > 64 * 1024 * 1024:
        return None
    return _recv_exact(sock, n)


def _inject(ev: dict, state: dict) -> None:
    """Inject one mouse/keyboard event via pynput (runs in the user session)."""
    try:
        kind = ev.get("kind")
        if kind in ("move", "click", "scroll"):
            if state.get("mouse") is None:
                from pynput.mouse import Controller
                state["mouse"] = Controller()
            m = state["mouse"]
            if kind == "move":
                m.position = (ev["x"], ev["y"])
            elif kind == "click":
                from pynput.mouse import Button
                m.position = (ev["x"], ev["y"])
                m.click(Button.right if ev.get("button") == "right" else Button.left)
            elif kind == "scroll":
                m.scroll(0, ev.get("dy", 0))
        elif kind == "key":
            if state.get("keyboard") is None:
                from pynput.keyboard import Controller
                state["keyboard"] = Controller()
            state["keyboard"].type(ev.get("text", ""))
        elif kind == "hotkey":
            from pynput.keyboard import Controller as KC, Key
            kb = state.get("keyboard") or KC()
            keys = [getattr(Key, k, k) for k in ev.get("keys", [])]
            for k in keys:
                kb.press(k)
            for k in reversed(keys):
                kb.release(k)
    except Exception:
        pass


class ScreenSession:
    def __init__(self, send_bytes, fps: int = 4, quality: int = 50, on_error=None):
        self.send_bytes = send_bytes
        self.on_error = on_error
        self.fps = max(1, min(fps, 15))
        self.quality = max(10, min(quality, 90))
        self._task: asyncio.Task | None = None
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._sock = None
        self._stop = False
        self._state = {"mouse": None, "keyboard": None}

    async def start(self) -> str | None:
        try:
            import mss  # noqa: F401
            from PIL import Image  # noqa: F401
        except Exception as exc:
            return f"screen deps unavailable: {exc}"
        self._loop = asyncio.get_event_loop()
        if platform.system() == "Windows":
            # Capture must run in the interactive session; the SYSTEM agent in
            # session 0 cannot grab the user's desktop. Bridge to a helper there.
            self._thread = threading.Thread(target=self._win_bridge, daemon=True)
            self._thread.start()
            return None
        # Linux / already interactive: capture directly.
        self._task = asyncio.create_task(self._loop_direct())
        return None

    # ---- Windows: bridge to a user-session helper over loopback TCP ----
    def _win_bridge(self) -> None:
        import secrets
        srv = None
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            srv.settimeout(20)
            port = srv.getsockname()[1]
            token = secrets.token_hex(16)
            if not self._launch_helper(port, token):
                self._fail("could not start capture in the user session")
                return
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                self._fail("capture helper did not connect (is a user signed in?)")
                return
            finally:
                try:
                    srv.close()
                except Exception:
                    pass
                srv = None
            conn.settimeout(30)
            got = _recv_msg(conn)
            if got is None or got.decode("utf-8", "replace") != token:
                try:
                    conn.close()
                except Exception:
                    pass
                self._fail("capture helper authentication failed")
                return
            self._sock = conn
            # Read frames until stopped or the helper disconnects.
            while not self._stop:
                frame = _recv_msg(conn)
                if frame is None:
                    break
                fut = asyncio.run_coroutine_threadsafe(self.send_bytes(frame), self._loop)
                try:
                    fut.result(timeout=15)
                except Exception:
                    break
            if not self._stop:
                self._fail("capture stream ended")
        except Exception as exc:
            self._fail(f"capture bridge error: {exc}")
        finally:
            if srv is not None:
                try:
                    srv.close()
                except Exception:
                    pass

    def _launch_helper(self, port: int, token: str) -> bool:
        try:
            from handlers import _run_in_active_session
        except Exception:
            return False
        args = f"--screen-helper {port} {token} {self.fps} {self.quality}"
        if getattr(sys, "frozen", False):
            cmdline = f'"{sys.executable}" {args}'
        else:
            script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.py")
            cmdline = f'"{sys.executable}" "{script}" {args}'
        try:
            return bool(_run_in_active_session(cmdline))
        except Exception:
            return False

    def _fail(self, msg: str) -> None:
        if self.on_error and self._loop and not self._stop:
            try:
                asyncio.run_coroutine_threadsafe(
                    self.on_error(f"capture failed: {msg}"), self._loop)
            except Exception:
                pass

    # ---- Direct capture (Linux / already-interactive) ----
    async def _loop_direct(self) -> None:
        import mss
        from PIL import Image
        interval = 1.0 / self.fps
        try:
            with mss.mss() as sct:
                monitor = sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0]
                while True:
                    shot = sct.grab(monitor)
                    img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
                    buf = io.BytesIO()
                    img.save(buf, format="JPEG", quality=self.quality)
                    await self.send_bytes(buf.getvalue())
                    await asyncio.sleep(interval)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            if self.on_error:
                try:
                    await self.on_error(f"capture failed: {exc}")
                except Exception:
                    pass

    def stop(self) -> None:
        self._stop = True
        if self._task:
            self._task.cancel()
            self._task = None
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def input(self, ev: dict) -> None:
        """Forward an input event to the user-session helper, or inject directly."""
        try:
            kind = ev.get("kind")
            # Ctrl+Alt+Del must be triggered from the SYSTEM agent via the SAS API.
            if (platform.system() == "Windows" and kind == "hotkey"
                    and ev.get("keys") == ["ctrl", "alt", "delete"]):
                _send_sas()
                return
            if self._sock is not None:
                _send_msg(self._sock, json.dumps(ev).encode("utf-8"))
                return
            _inject(ev, self._state)
        except Exception:
            pass


def run_screen_helper(argv) -> None:
    """User-session helper: capture frames + inject input over a loopback socket.

    Launched by the SYSTEM agent inside the interactive session as
    ``agent.exe --screen-helper <port> <token> <fps> <quality>``.
    """
    try:
        i = argv.index("--screen-helper")
        port = int(argv[i + 1])
        token = argv[i + 2]
        fps = max(1, min(int(argv[i + 3]), 15))
        quality = max(10, min(int(argv[i + 4]), 90))
    except Exception:
        return
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=15)
    except Exception:
        return
    if not _send_msg(s, token.encode("utf-8")):
        try:
            s.close()
        except Exception:
            pass
        return

    stop = threading.Event()
    state = {"mouse": None, "keyboard": None}

    def _input_reader():
        while not stop.is_set():
            data = _recv_msg(s)
            if data is None:
                break
            try:
                _inject(json.loads(data.decode("utf-8", "replace")), state)
            except Exception:
                pass
        stop.set()

    threading.Thread(target=_input_reader, daemon=True).start()

    try:
        import time
        import mss
        from PIL import Image
        interval = 1.0 / fps
        with mss.mss() as sct:
            mon = sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0]
            while not stop.is_set():
                shot = sct.grab(mon)
                img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
                buf = io.BytesIO()
                img.save(buf, format="JPEG", quality=quality)
                if not _send_msg(s, buf.getvalue()):
                    break
                time.sleep(interval)
    except Exception:
        pass
    finally:
        stop.set()
        try:
            s.close()
        except Exception:
            pass


def _send_sas() -> None:
    """Trigger Ctrl+Alt+Del via the Windows Secure Attention Sequence API."""
    ps = (
        "Add-Type -TypeDefinition '"
        "using System; using System.Runtime.InteropServices; "
        "public class SAS { "
        "[DllImport(\"sas.dll\")] public static extern void SendSAS(bool asUser); "
        "}'; [SAS]::SendSAS($false)"
    )
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, timeout=8,
        )
    except Exception:
        pass
