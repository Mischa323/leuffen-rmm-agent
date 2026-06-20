"""Remote desktop: screen capture + input injection.

Heavy GUI/imaging deps (``mss``, ``Pillow``, ``pynput``) are imported lazily so an
idle agent never loads them, and the module degrades gracefully with no display.

On Windows the agent runs as SYSTEM in session 0, which **cannot** capture the
interactive user's desktop (``BitBlt`` fails). So on Windows the capture + input
injection run in a short-lived **helper** process launched inside the active
session. Two launch paths are tried, in order:

  1. the signed-in user's session (input then acts as that user); and
  2. failing that, the console session as SYSTEM -- this covers the case where
     **nobody is logged in** (the login screen) or the workstation is **locked**.

The helper attaches its thread to the active *input* desktop
(``OpenInputDesktop``/``SetThreadDesktop``) on every frame, so it follows the
switch to/from the secure ``Winlogon`` desktop (login, lock screen, UAC) -- the
same trick remote-support tools use to see the sign-in screen. It streams JPEG
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


# --------------------------------------------------------------------------- #
# Windows: follow the active *input* desktop so capture/injection keep working
# across the secure-desktop switch (Default <-> Winlogon for login/lock/UAC).
# --------------------------------------------------------------------------- #
_WIN_DESK_API_READY = False


def _win_desk_api():
    """Lazily configure ctypes signatures for the desktop APIs (once)."""
    global _WIN_DESK_API_READY
    import ctypes
    from ctypes import wintypes
    user32 = ctypes.windll.user32
    if not _WIN_DESK_API_READY:
        # Handles are pointers -- without explicit restype they'd be truncated on
        # 64-bit, handing SetThreadDesktop a garbage handle.
        user32.OpenInputDesktop.restype = wintypes.HANDLE
        user32.OpenInputDesktop.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        user32.SetThreadDesktop.argtypes = [wintypes.HANDLE]
        user32.CloseDesktop.argtypes = [wintypes.HANDLE]
        user32.GetUserObjectInformationW.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        _WIN_DESK_API_READY = True
    return user32


def _win_desktop_name(user32, hdesk) -> str:
    import ctypes
    from ctypes import wintypes
    buf = ctypes.create_unicode_buffer(256)
    needed = wintypes.DWORD(0)
    try:
        # UOI_NAME = 2
        user32.GetUserObjectInformationW(hdesk, 2, buf, ctypes.sizeof(buf),
                                         ctypes.byref(needed))
    except Exception:
        return ""
    return buf.value or ""


def _attach_input_desktop(state: dict) -> None:
    """Attach the calling thread to the current input desktop.

    ``state`` caches the open handle + name across calls so we only re-attach
    when the desktop actually switches. Sets ``state['changed']`` on a switch so
    callers (e.g. the capture loop) know to rebuild desktop-bound resources."""
    try:
        user32 = _win_desk_api()
    except Exception:
        return
    # 0 flags; GENERIC_ALL access so we can both read pixels and inject input.
    hdesk = user32.OpenInputDesktop(0, False, 0x10000000)
    if not hdesk:
        return
    name = _win_desktop_name(user32, hdesk)
    if name and name == state.get("desk_name"):
        user32.CloseDesktop(hdesk)
        return
    if user32.SetThreadDesktop(hdesk):
        old = state.get("desk_handle")
        if old:
            try:
                user32.CloseDesktop(old)
            except Exception:
                pass
        state["desk_handle"] = hdesk
        state["desk_name"] = name
        state["changed"] = True
    else:
        user32.CloseDesktop(hdesk)


def _inject(ev: dict, state: dict) -> None:
    """Inject one mouse/keyboard event via pynput (runs in the helper)."""
    try:
        # On Windows, make sure this thread is on the desktop that currently owns
        # input before injecting, so events reach the login/lock screen too.
        if platform.system() == "Windows":
            _attach_input_desktop(state)
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

    # ---- Windows: bridge to a session helper over loopback TCP ----
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
                self._fail("could not start capture helper in the active session")
                return
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                self._fail("capture helper did not connect")
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
            from handlers import (_run_in_active_session,
                                  _run_in_console_session_as_system)
        except Exception:
            return False
        args = f"--screen-helper {port} {token} {self.fps} {self.quality}"
        if getattr(sys, "frozen", False):
            cmdline = f'"{sys.executable}" {args}'
        else:
            script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.py")
            cmdline = f'"{sys.executable}" "{script}" {args}'
        # Prefer the signed-in user's session (input acts as the user). If nobody
        # is signed in or the box is locked, fall back to a SYSTEM helper in the
        # console session, which can attach to the secure Winlogon desktop.
        try:
            if _run_in_active_session(cmdline):
                return True
        except Exception:
            pass
        try:
            return bool(_run_in_console_session_as_system(cmdline))
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
        """Forward an input event to the session helper, or inject directly."""
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
    """Session helper: capture frames + inject input over a loopback socket.

    Launched by the SYSTEM agent inside the interactive session (or, when nobody
    is signed in, inside the console session as SYSTEM) as
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
    # Each thread keeps its own desktop-attach state (a desktop binding is
    # per-thread on Windows), so capture and input track the input desktop
    # independently.
    cap_state = {"mouse": None, "keyboard": None}
    inj_state = {"mouse": None, "keyboard": None}

    def _input_reader():
        while not stop.is_set():
            data = _recv_msg(s)
            if data is None:
                break
            try:
                _inject(json.loads(data.decode("utf-8", "replace")), inj_state)
            except Exception:
                pass
        stop.set()

    threading.Thread(target=_input_reader, daemon=True).start()

    is_win = platform.system() == "Windows"
    sct = None
    try:
        import time
        import mss
        from PIL import Image
        interval = 1.0 / fps
        while not stop.is_set():
            if is_win:
                # Follow the active input desktop (Default / Winlogon). On a
                # switch, mss's cached device context is stale -- rebuild it.
                cap_state["changed"] = False
                _attach_input_desktop(cap_state)
                if sct is None or cap_state.get("changed"):
                    if sct is not None:
                        try:
                            sct.close()
                        except Exception:
                            pass
                    sct = mss.mss()
            elif sct is None:
                sct = mss.mss()
            mon = sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0]
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
        if sct is not None:
            try:
                sct.close()
            except Exception:
                pass
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
