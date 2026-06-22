"""Remote desktop: screen capture + input injection.

Heavy GUI/imaging deps (``mss``, ``Pillow``, ``pynput``) are imported lazily so an
idle agent never loads them, and the module degrades gracefully with no display.

On Windows the agent runs as SYSTEM in session 0, which **cannot** capture the
interactive user's desktop (``BitBlt`` fails). So on Windows the capture + input
injection run in a short-lived **helper** process launched inside the active
session. Two launch paths are tried, in order:

  1. the signed-in user's session (``mode=user``; input acts as that user, and a
     consent banner is shown); and
  2. failing that, the console session as SYSTEM (``mode=system``) -- this covers
     the case where **nobody is logged in** (the login screen) or the
     workstation is **locked**, where there is no user to show a banner to.

The helper attaches its thread to the active *input* desktop
(``OpenInputDesktop``/``SetThreadDesktop``) on every frame, so it follows the
switch to/from the secure ``Winlogon`` desktop (login, lock screen, UAC) -- the
same trick remote-support tools use to see the sign-in screen. It streams JPEG
frames back to the agent over a loopback TCP socket and receives input events the
same way. On Linux (or when already interactive) the agent captures directly.

Frames whose longest edge exceeds ``max_edge`` (sent by the viewer's speed
preset) are downscaled before JPEG to keep the stream fast; injected mouse
coordinates are scaled back to native pixels so clicks still land right.

Clipboard text syncs both ways: ``clip_paste`` sets the remote clipboard and
sends Ctrl+V; ``clip_get`` reads the remote clipboard and ships it back to the
viewer as a small ``LRMMCLIP``-tagged binary blob (the server already relays
agent binary to the viewer, so this needs no server change).

When launched in a user session the helper also shows an always-on-top banner so
the person at the device clearly sees that a remote session is active and can end
it themselves with a Disconnect button (which stops capture and tears the session
down).
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

# Default cap on the longest edge of a captured frame before JPEG encoding; the
# viewer overrides it per speed preset (smaller = higher fps, larger = crisper).
# Input coordinates are scaled back up so control stays pixel-accurate.
_MAX_EDGE = 1600

# Magic header marking a clipboard payload on the (otherwise JPEG) frame stream.
# JPEG always starts with FF D8 FF, so there's no collision with a real frame.
_CLIP_MAGIC = b"LRMMCLIP"


# --------------------------------------------------------------------------- #
# Logbook — both the agent (SYSTEM, session 0) and the capture helper write here
# so we can see exactly what happens during a remote session, especially why the
# login/lock (secure Winlogon) screen does or doesn't come through. Lives next to
# the agent log: %ProgramData%\LeuffenRMM\screen.log on Windows.
# --------------------------------------------------------------------------- #
def _log_dir() -> str:
    env = os.environ.get("RMM_DATA_DIR")
    if env:
        return env
    if os.name == "nt":
        return os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "LeuffenRMM")
    return os.path.join(os.path.expanduser("~"), ".leuffen-rmm")


def _hlog(msg: str) -> None:
    """Append one timestamped line to screen.log (best-effort, never raises)."""
    try:
        import datetime
        d = _log_dir()
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "screen.log")
        # Keep it from growing without bound: roll over past ~2 MB.
        try:
            if os.path.getsize(path) > 2_000_000:
                os.replace(path, path + ".1")
        except OSError:
            pass
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{ts} [pid {os.getpid()}] {msg}\n")
    except Exception:
        pass


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
# Clipboard (Windows): read/write CF_UNICODETEXT. Handles are kept pointer-wide
# (c_void_p) so nothing is truncated on 64-bit.
# --------------------------------------------------------------------------- #
def _clip_get() -> str | None:
    if platform.system() != "Windows":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        u32, k32 = ctypes.windll.user32, ctypes.windll.kernel32
        u32.OpenClipboard.argtypes = [ctypes.c_void_p]
        u32.GetClipboardData.restype = ctypes.c_void_p
        u32.GetClipboardData.argtypes = [wintypes.UINT]
        k32.GlobalLock.restype = ctypes.c_void_p
        k32.GlobalLock.argtypes = [ctypes.c_void_p]
        k32.GlobalUnlock.argtypes = [ctypes.c_void_p]
        if not u32.OpenClipboard(None):
            return None
        try:
            h = u32.GetClipboardData(13)  # CF_UNICODETEXT
            if not h:
                return None
            p = k32.GlobalLock(h)
            if not p:
                return None
            try:
                return ctypes.c_wchar_p(p).value
            finally:
                k32.GlobalUnlock(h)
        finally:
            u32.CloseClipboard()
    except Exception:
        return None


def _clip_set(text: str) -> bool:
    if platform.system() != "Windows":
        return False
    try:
        import ctypes
        from ctypes import wintypes
        u32, k32 = ctypes.windll.user32, ctypes.windll.kernel32
        u32.OpenClipboard.argtypes = [ctypes.c_void_p]
        u32.SetClipboardData.restype = ctypes.c_void_p
        u32.SetClipboardData.argtypes = [wintypes.UINT, ctypes.c_void_p]
        k32.GlobalAlloc.restype = ctypes.c_void_p
        k32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        k32.GlobalLock.restype = ctypes.c_void_p
        k32.GlobalLock.argtypes = [ctypes.c_void_p]
        k32.GlobalUnlock.argtypes = [ctypes.c_void_p]
        k32.GlobalFree.argtypes = [ctypes.c_void_p]
        data = text.encode("utf-16-le") + b"\x00\x00"
        h = k32.GlobalAlloc(0x0002, len(data))  # GMEM_MOVEABLE
        if not h:
            return False
        p = k32.GlobalLock(h)
        if not p:
            k32.GlobalFree(h)
            return False
        ctypes.memmove(p, data, len(data))
        k32.GlobalUnlock(h)
        if not u32.OpenClipboard(None):
            k32.GlobalFree(h)
            return False
        try:
            u32.EmptyClipboard()
            if not u32.SetClipboardData(13, h):  # CF_UNICODETEXT
                k32.GlobalFree(h)
                return False
            return True  # the clipboard owns the memory now
        finally:
            u32.CloseClipboard()
    except Exception:
        return False


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
        import ctypes
        user32 = _win_desk_api()
    except Exception:
        return
    # 0 flags; GENERIC_ALL access so we can both read pixels and inject input.
    hdesk = user32.OpenInputDesktop(0, False, 0x10000000)
    if not hdesk:
        # Throttle: only log the first failure (e.g. a non-SYSTEM helper denied
        # access to the secure Winlogon desktop) until it next succeeds.
        if not state.get("_openfail"):
            state["_openfail"] = True
            _hlog(f"OpenInputDesktop failed (err={ctypes.GetLastError()}) -- cannot "
                  f"attach to the input desktop (err 5 = access denied means this "
                  f"helper is not SYSTEM, so the lock/login screen can't be captured)")
        return
    state["_openfail"] = False
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
        _hlog(f"attached to input desktop '{name or '?'}'")
    else:
        _hlog(f"SetThreadDesktop('{name or '?'}') failed (err={ctypes.GetLastError()})")
        user32.CloseDesktop(hdesk)


def _inject(ev: dict, state: dict) -> None:
    """Inject one mouse/keyboard/clipboard event (runs in the helper)."""
    try:
        # On Windows, make sure this thread is on the desktop that currently owns
        # input before injecting, so events reach the login/lock screen too.
        if platform.system() == "Windows":
            _attach_input_desktop(state)
        kind = ev.get("kind")

        def _pt(x, y):
            # Map viewer (possibly downscaled) coordinates back to native pixels.
            geom = state.get("geom")
            if geom and geom.get("scale"):
                sc = geom["scale"]
                return (geom.get("left", 0) + x / sc, geom.get("top", 0) + y / sc)
            return (x, y)

        if kind in ("move", "click", "scroll", "down", "up"):
            if state.get("mouse") is None:
                from pynput.mouse import Controller
                state["mouse"] = Controller()
            m = state["mouse"]
            if kind == "move":
                m.position = _pt(ev["x"], ev["y"])
            elif kind == "scroll":
                m.scroll(0, ev.get("dy", 0))
            else:
                # down / up (press-and-hold for dragging) and legacy click.
                from pynput.mouse import Button
                b = ev.get("button")
                btn = (Button.right if b == "right"
                       else Button.middle if b == "middle" else Button.left)
                m.position = _pt(ev["x"], ev["y"])
                if kind == "down":
                    m.press(btn)
                elif kind == "up":
                    m.release(btn)
                else:
                    m.click(btn)
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
        elif kind == "clip_paste":
            # Put the text on the remote clipboard, then paste it.
            from pynput.keyboard import Controller as KC, Key
            kb = state.get("keyboard") or KC()
            state["keyboard"] = kb
            if _clip_set(ev.get("text", "")):
                kb.press(Key.ctrl); kb.press("v"); kb.release("v"); kb.release(Key.ctrl)
            else:
                kb.type(ev.get("text", ""))  # fallback: type it
        elif kind == "clip_get":
            txt = _clip_get()
            sock, lock = state.get("sock"), state.get("sendlock")
            if sock is not None and txt:
                blob = _CLIP_MAGIC + txt.encode("utf-8")
                if lock is not None:
                    with lock:
                        _send_msg(sock, blob)
                else:
                    _send_msg(sock, blob)
    except Exception:
        pass


class ScreenSession:
    def __init__(self, send_bytes, fps: int = 4, quality: int = 50,
                 max_edge: int = 1600, on_error=None, purpose: str = "control"):
        self.send_bytes = send_bytes
        self.on_error = on_error
        # 'control' = interactive remote session (shows the consent banner);
        # 'screenshot' = one-shot still grabbed by the dashboard (no banner).
        self.purpose = purpose or "control"
        self.fps = max(1, min(fps, 24))
        self.quality = max(10, min(quality, 90))
        try:
            self.max_edge = max(320, min(int(max_edge or _MAX_EDGE), 4096))
        except Exception:
            self.max_edge = _MAX_EDGE
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
            _hlog(f"screen session starting (bridge on 127.0.0.1:{port}, "
                  f"fps={self.fps}, quality={self.quality}, max_edge={self.max_edge})")
            if not self._launch_helper(port, token):
                _hlog("no capture helper could be launched")
                self._fail("could not start capture helper in the active session")
                return
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                _hlog("capture helper did not connect within 20s")
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
            # Relay helper -> viewer until stopped or the helper disconnects. Both
            # JPEG frames and the LRMMCLIP clipboard blob are forwarded as binary.
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
                # The helper went away on its own -- most often because the user
                # at the device clicked Disconnect on the consent banner. Tell the
                # operator clearly (not as a "capture failed" error).
                self._notify("The remote session was ended at the device.")
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
        base = f"--screen-helper {port} {token} {self.fps} {self.quality}"
        if getattr(sys, "frozen", False):
            prefix = f'"{sys.executable}"'
        else:
            script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.py")
            prefix = f'"{sys.executable}" "{script}"'
        # Args after base: <mode> <max_edge>. A 'screenshot' session runs the
        # helper without the consent banner (it's a single still, not an ongoing
        # session); a normal 'control' session shows the banner in the user's
        # session ('user' mode).
        mode = "screenshot" if self.purpose == "screenshot" else "user"
        tail = f"{mode} {self.max_edge}"
        # Launch as SYSTEM in the console session FIRST. Only a SYSTEM process can
        # attach to the secure Winlogon desktop (lock screen / sign-in), so this is
        # the path that makes the login screen work -- and it also captures the
        # normal desktop fine. The banner still shows (on the user's desktop). Fall
        # back to the user's own session only if the SYSTEM launch fails.
        try:
            if _run_in_console_session_as_system(f"{prefix} {base} {tail}"):
                _hlog("helper launched as SYSTEM in the console session")
                return True
            _hlog("console-session SYSTEM launch returned false; trying user session")
        except Exception as exc:
            _hlog(f"console-session SYSTEM launch raised {exc!r}; trying user session")
        try:
            if _run_in_active_session(f"{prefix} {base} {tail}"):
                _hlog("helper launched in the user session (fallback)")
                return True
            _hlog("user-session launch returned false")
            return False
        except Exception as exc:
            _hlog(f"user-session launch raised {exc!r}")
            return False

    def _fail(self, msg: str) -> None:
        if self.on_error and self._loop and not self._stop:
            try:
                asyncio.run_coroutine_threadsafe(
                    self.on_error(f"capture failed: {msg}"), self._loop)
            except Exception:
                pass

    def _notify(self, msg: str) -> None:
        """Send an informational message to the viewer (no 'capture failed' prefix)."""
        if self.on_error and self._loop and not self._stop:
            try:
                asyncio.run_coroutine_threadsafe(self.on_error(msg), self._loop)
            except Exception:
                pass

    # ---- Direct capture (Linux / already-interactive) ----
    async def _loop_direct(self) -> None:
        import mss
        import time
        from PIL import Image
        interval = 1.0 / self.fps
        try:
            with mss.mss() as sct:
                monitor = sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0]
                while True:
                    t0 = time.monotonic()
                    shot = sct.grab(monitor)
                    img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
                    buf = io.BytesIO()
                    img.save(buf, format="JPEG", quality=self.quality)
                    await self.send_bytes(buf.getvalue())
                    await asyncio.sleep(max(0.0, interval - (time.monotonic() - t0)))
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


# --------------------------------------------------------------------------- #
# Helper process (runs in the interactive/console session).
# --------------------------------------------------------------------------- #
def _capture_loop(s, fps: int, quality: int, stop: threading.Event,
                  geom: dict | None = None, send_lock: threading.Lock | None = None,
                  max_edge: int = _MAX_EDGE) -> None:
    """Grab the screen and stream JPEG frames until ``stop`` is set or the socket
    drops. On Windows it follows the active input desktop so it keeps working
    across the secure-desktop switch, downscales big frames, and survives the odd
    BitBlt failure (e.g. mid secure-desktop switch) instead of ending."""
    is_win = platform.system() == "Windows"
    cap_state: dict = {}
    sct = None
    frames = 0
    fails = 0
    reason = "stopped"

    def _send(data: bytes) -> bool:
        if send_lock is not None:
            with send_lock:
                return _send_msg(s, data)
        return _send_msg(s, data)

    try:
        import time
        import mss
        from PIL import Image
        interval = 1.0 / fps
        while not stop.is_set():
            t0 = time.monotonic()
            try:
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
                nw, nh = img.width, img.height
                scale = 1.0
                if max(nw, nh) > max_edge:
                    scale = max_edge / float(max(nw, nh))
                    img = img.resize((max(1, int(nw * scale)), max(1, int(nh * scale))),
                                     Image.BILINEAR)
                if geom is not None:
                    geom["left"] = mon.get("left", 0)
                    geom["top"] = mon.get("top", 0)
                    geom["scale"] = scale
                buf = io.BytesIO()
                img.save(buf, format="JPEG", quality=quality)
                data = buf.getvalue()
            except Exception as exc:
                # Transient (desktop switch, resolution change, secure-desktop
                # BitBlt). Log sparsely, rebuild the grabber, and keep going.
                fails += 1
                if fails == 1 or fails % 50 == 0:
                    _hlog(f"frame grab error x{fails} (recovering): {exc!r}")
                if sct is not None:
                    try:
                        sct.close()
                    except Exception:
                        pass
                sct = None
                if fails > 200:
                    reason = f"giving up after {fails} grab errors: {exc!r}"
                    break
                time.sleep(0.2)
                continue
            fails = 0
            if not _send(data):
                reason = "viewer/socket closed"
                break
            frames += 1
            if frames == 1:
                _hlog(f"first frame sent ({img.width}x{img.height} @scale {scale:.2f}, "
                      f"{len(data)} bytes)")
            elif frames % 200 == 0:
                _hlog(f"{frames} frames sent (last {img.width}x{img.height}, {len(data)} bytes)")
            # Pace to the target fps but subtract the time already spent grabbing
            # and encoding, so a slow frame doesn't stack on top of a full
            # interval (which capped the real rate well below the requested fps).
            time.sleep(max(0.0, interval - (time.monotonic() - t0)))
    except Exception as exc:
        reason = f"error: {exc!r}"
    finally:
        _hlog(f"capture loop ended after {frames} frames ({reason})")
        # Whatever ended the loop, make sure the banner/other threads wind down.
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


def _show_consent_banner(stop: threading.Event) -> None:
    """Show an always-on-top banner telling the person at the device that a remote
    session is active, with a Disconnect button that ends it. Blocks (runs the Tk
    loop) until the user disconnects or capture stops, then sets ``stop``.

    Degrades to a plain wait if no GUI/Tk is available, so capture is unaffected.
    """
    try:
        import tkinter as tk
    except Exception:
        stop.wait()
        return
    try:
        root = tk.Tk()
    except Exception:
        stop.wait()
        return
    try:
        root.title("Leuffen RMM — remote session")
        root.overrideredirect(True)        # borderless banner
        root.attributes("-topmost", True)  # stay above other windows
        try:
            root.attributes("-toolwindow", True)  # keep it off the taskbar (Windows)
        except Exception:
            pass

        bg = "#b00020"  # alert red
        frame = tk.Frame(root, bg=bg, padx=14, pady=10)
        frame.pack(fill="both", expand=True)
        tk.Label(
            frame,
            text="●  Remote support is connected — someone can see and control this screen.",
            bg=bg, fg="white",
            font=("Segoe UI", 10, "bold"),
        ).pack(side="left", padx=(0, 14))

        def _disconnect(*_):
            stop.set()
            try:
                root.destroy()
            except Exception:
                pass

        tk.Button(
            frame, text="Disconnect", command=_disconnect,
            bg="white", fg=bg, font=("Segoe UI", 10, "bold"),
            relief="flat", padx=12, pady=2, cursor="hand2",
        ).pack(side="right")

        # Top-centre of the primary monitor.
        root.update_idletasks()
        w = max(root.winfo_reqwidth(), 460)
        h = max(root.winfo_reqheight(), 48)
        sw = root.winfo_screenwidth()
        root.geometry(f"{w}x{h}+{(sw - w) // 2}+24")

        # Close the banner if capture stops for any other reason (operator ended
        # the session, socket dropped, etc.).
        def _poll():
            if stop.is_set():
                try:
                    root.destroy()
                except Exception:
                    pass
                return
            root.after(400, _poll)

        root.after(400, _poll)
        root.mainloop()
    except Exception:
        pass
    finally:
        stop.set()


def run_screen_helper(argv) -> None:
    """Session helper: capture frames + inject input over a loopback socket.

    Launched by the SYSTEM agent as
    ``agent.exe --screen-helper <port> <token> <fps> <quality> [mode] [max_edge]``
    where ``mode`` is ``user`` (interactive remote session; shows the consent
    banner), ``screenshot`` (one-shot still grabbed by the dashboard; no banner),
    or ``system`` (console session, e.g. the login/lock screen; no banner).
    """
    try:
        i = argv.index("--screen-helper")
        port = int(argv[i + 1])
        token = argv[i + 2]
        fps = max(1, min(int(argv[i + 3]), 24))
        quality = max(10, min(int(argv[i + 4]), 90))
        mode = argv[i + 5] if len(argv) > i + 5 else "user"
        try:
            max_edge = max(320, min(int(argv[i + 6]), 4096)) if len(argv) > i + 6 else _MAX_EDGE
        except Exception:
            max_edge = _MAX_EDGE
    except Exception:
        return
    _hlog(f"helper started (mode={mode}, fps={fps}, quality={quality}, max_edge={max_edge})")
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=15)
    except Exception as exc:
        _hlog(f"helper could not connect to the bridge: {exc!r}")
        return
    if not _send_msg(s, token.encode("utf-8")):
        _hlog("helper failed to send auth token")
        try:
            s.close()
        except Exception:
            pass
        return

    stop = threading.Event()
    send_lock = threading.Lock()
    # Shared geometry (downscale factor + monitor origin) so the input thread can
    # map viewer coordinates back to native pixels; sock + sendlock let the input
    # thread ship a clipboard reply without interleaving with frame sends.
    geom = {"scale": 1.0, "left": 0, "top": 0}
    inj_state = {"mouse": None, "keyboard": None, "geom": geom,
                 "sock": s, "sendlock": send_lock}

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

    # In a real user session, run capture in a background thread and give the
    # main thread to the consent banner (Tk must own the main thread). Otherwise
    # (login/lock screen, or a one-shot 'screenshot') just capture on the main
    # thread -- no banner is shown.
    show_banner = mode == "user" and platform.system() == "Windows"
    _hlog(f"consent banner {'enabled' if show_banner else 'disabled'} for this session")
    if show_banner:
        cap = threading.Thread(target=_capture_loop,
                               args=(s, fps, quality, stop, geom, send_lock, max_edge),
                               daemon=True)
        cap.start()
        _show_consent_banner(stop)
        stop.set()
        cap.join(timeout=5)
    else:
        _capture_loop(s, fps, quality, stop, geom, send_lock, max_edge)
    _hlog("helper exiting")

    try:
        s.close()
    except Exception:
        pass


def _ensure_software_sas() -> bool:
    """Allow a SYSTEM service to generate the Secure Attention Sequence.

    ``SendSAS(asUser=False)`` is *silently ignored* unless the SoftwareSASGeneration
    policy permits services — which Windows does not enable by default, so the
    Ctrl+Alt+Del button appears to do nothing (notably on the Server login screen).
    The SYSTEM agent can set this itself; it takes effect without a reboot.

    Bit values: 1 = Services, 2 = Ease-of-Access apps. We OR-in Services and keep
    any existing bits. Returns True if the policy now permits services."""
    try:
        import winreg
        path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                winreg.KEY_READ | winreg.KEY_WRITE) as k:
            try:
                cur = int(winreg.QueryValueEx(k, "SoftwareSASGeneration")[0])
            except FileNotFoundError:
                cur = 0
            want = cur | 1
            if want != cur:
                winreg.SetValueEx(k, "SoftwareSASGeneration", 0, winreg.REG_DWORD, want)
                _hlog(f"sas: enabled SoftwareSASGeneration ({cur} -> {want})")
        return True
    except Exception as exc:
        _hlog(f"sas: could not set SoftwareSASGeneration (agent not SYSTEM?): {exc}")
        return False


def _send_sas() -> None:
    """Trigger Ctrl+Alt+Del via the Windows Secure Attention Sequence API.

    Requires the agent to run as SYSTEM and the SoftwareSASGeneration policy to
    permit services (enabled on demand by :func:`_ensure_software_sas`)."""
    _ensure_software_sas()
    ps = (
        "Add-Type -TypeDefinition '"
        "using System; using System.Runtime.InteropServices; "
        "public class SAS { "
        "[DllImport(\"sas.dll\")] public static extern void SendSAS(bool asUser); "
        "}'; [SAS]::SendSAS($false)"
    )
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, timeout=8,
        )
        if r.returncode != 0:
            err = (r.stderr or b"").decode("utf-8", "replace").strip()
            _hlog(f"sas: SendSAS rc={r.returncode} {err[:200]}")
        else:
            _hlog("sas: SendSAS invoked")
    except Exception as exc:
        _hlog(f"sas: SendSAS failed: {exc}")
