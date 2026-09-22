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
preset) are downscaled before encoding to keep the stream fast; injected mouse
coordinates are scaled back to native pixels so clicks still land right.

Inside the helper, grabbing, encoding and sending run as three parallel
stages on an absolute clock (see :func:`_capture_loop`), because doing them
one after another inside a single display refresh made the frame rate jump
between whole divisors of the refresh rate.

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
import queue
import socket
import subprocess
import sys
import threading
import time

import screen_h264

# Default cap on the longest edge of a captured frame before JPEG encoding; the
# viewer overrides it per speed preset (smaller = higher fps, larger = crisper).
# Input coordinates are scaled back up so control stays pixel-accurate.
_MAX_EDGE = 1600

# A downscale that only shaves a few percent off (a 2560 screen against a 2400
# cap) is not worth doing for JPEG: PIL's resample costs ~24 ms per frame there
# while encoding the full frame costs ~5 ms, and the extra bytes are marginal.
_JPEG_SKIP_RESIZE_ABOVE = 0.9

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
                 max_edge: int = 1600, on_error=None, purpose: str = "control",
                 codecs=None, on_info=None):
        self.send_bytes = send_bytes
        self.on_error = on_error
        self.on_info = on_info
        # 'control' = interactive remote session (shows the consent banner);
        # 'screenshot' = one-shot still grabbed by the dashboard (no banner).
        self.purpose = purpose or "control"
        # 32, not 30: a display running a hair fast (or a viewer asking for
        # headroom) should not be clamped down to half its refresh rate.
        self.fps = max(1, min(fps, 32))
        self.quality = max(10, min(quality, 90))
        try:
            self.max_edge = max(320, min(int(max_edge or _MAX_EDGE), 4096))
        except Exception:
            self.max_edge = _MAX_EDGE
        # Wire codec: H.264 when the viewer supports it (WebCodecs) AND this build
        # can encode it (PyAV present); otherwise full-frame JPEG (the fallback).
        want_h264 = bool(codecs) and "h264" in codecs
        h264_ok = screen_h264.available()
        self.codec = "h264" if (want_h264 and h264_ok) else "jpeg"
        _hlog(f"codec decision: requested={codecs} want_h264={want_h264} "
              f"h264_available={h264_ok} chosen={self.codec}"
              + (f" av_error={screen_h264.import_error()}" if (want_h264 and not h264_ok) else ""))
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
        # Tell the viewer the codec before any frame arrives so it can configure
        # its decoder. No video_info => the viewer stays in JPEG mode.
        if self.codec == "h264" and self.on_info:
            try:
                await self.on_info({"codec": "h264", "codecString": screen_h264.CODEC_STRING})
            except Exception:
                pass
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
            broke_on_send = False
            while not self._stop:
                frame = _recv_msg(conn)
                if frame is None:
                    break
                fut = asyncio.run_coroutine_threadsafe(self.send_bytes(frame), self._loop)
                try:
                    fut.result(timeout=15)
                except Exception:
                    broke_on_send = True
                    break
            if not self._stop:
                if broke_on_send:
                    # A frame couldn't be delivered within the timeout — the link
                    # is too slow for the current quality (the stream backs up),
                    # NOT an operator ending the session. Say so, so it isn't
                    # misread as someone clicking Disconnect at the device.
                    _hlog("bridge: frame send stalled >15s (link too slow for the quality)")
                    self._notify("Connection stalled — try a lower quality preset if this keeps happening.")
                else:
                    # The helper closed cleanly — the person at the device clicked
                    # Disconnect on the consent banner, OR the helper's capture/input
                    # threads wound down (see the helper's own screen.log lines for
                    # the precise reason).
                    _hlog("bridge: helper closed the capture socket "
                          "(reported to viewer as 'ended at the device')")
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
        tail = f"{mode} {self.max_edge} {self.codec}"
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
        enc = None
        try:
            with mss.mss() as sct:
                monitor = sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0]
                deadline = time.monotonic()
                while True:
                    shot = sct.grab(monitor)
                    img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
                    if self.codec == "h264":
                        if enc is None:
                            enc = screen_h264.H264Encoder(img.width, img.height, self.fps, self.quality)
                        for au in enc.encode(img):
                            await self.send_bytes(au)
                    else:
                        buf = io.BytesIO()
                        img.save(buf, format="JPEG", quality=self.quality)
                        await self.send_bytes(buf.getvalue())
                    # Absolute clock, so one slow frame doesn't push the rest late.
                    deadline += interval
                    now = time.monotonic()
                    if deadline < now - interval:
                        deadline = now
                    await asyncio.sleep(max(0.0, deadline - now))
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
# Rates the pacer steps through when a device or link cannot hold the one the
# viewer asked for, and climbs back up when it can. Steady beats fast: a stream
# sitting on 24 looks far better than one flipping between 30 and 15.
_RATE_STEPS = (32, 30, 24, 20, 15, 12, 10, 8, 5, 3, 2, 1)


def _raw_pixels(shot):
    """The BGRA bytes of a grab without the extra whole-frame copy that
    ``.bgra`` makes (1.4 ms on a 2256x1504 screen). ``raw`` is a fresh bytearray
    per grab, so handing it to another thread is safe."""
    raw = getattr(shot, "raw", None)
    return shot.bgra if raw is None else raw


class _FrameSource:
    """Grabs the screen on its own thread and keeps only the newest frame.

    A grab blocks until the display's next vertical blank, so a loop that grabs
    *and then* encodes pays both costs inside one refresh period. The moment the
    pair crosses that period, the next grab has to wait for the period after it
    and the frame rate halves -- measured on a 32 Hz panel, 15 ms of extra encode
    work took the stream from 32 fps to exactly 16. That is the jumping frame
    rate: the stream lands on whole divisors of the refresh rate and flips
    between them as the encode cost drifts across the boundary. Grabbing here,
    while the encoder works on the previous frame, makes the rate follow the
    slower stage instead of the sum of both (32 fps with that same extra work).
    """

    def __init__(self, stop: threading.Event, interval) -> None:
        self._stop = stop
        self._interval = interval       # callable -> the current tick, in seconds
        self._cond = threading.Condition()
        self._frame = None              # (pixels, width, height, left, top)
        self._seq = 0
        self._taken = True
        self.grabs = 0
        self.error: str | None = None
        self._thread = threading.Thread(target=self._run, name="rmm-screen-grab",
                                        daemon=True)

    def start(self) -> None:
        self._thread.start()

    def latest(self, seen: int, timeout: float):
        """The newest frame and its sequence number, waiting up to ``timeout``
        for one newer than ``seen``. Hands back the frame it already gave (same
        sequence number) rather than nothing, so the caller can hold its cadence
        through a display that had nothing new to offer."""
        deadline = time.monotonic() + timeout
        with self._cond:
            while self._seq == seen and not self._stop.is_set():
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                self._cond.wait(left)
            self._taken = True
            self._cond.notify_all()
            return self._frame, self._seq

    def _run(self) -> None:
        import mss
        is_win = platform.system() == "Windows"
        cap_state: dict = {}
        sct = None
        fails = 0
        nxt = time.monotonic()
        while not self._stop.is_set():
            # The encoder still hasn't taken the last frame: another grab would
            # only overwrite it, and a grab is the most expensive thing this
            # process does. Wait for it to be picked up instead.
            with self._cond:
                while (self._frame is not None and not self._taken
                       and not self._stop.is_set()):
                    self._cond.wait(0.1)
            if self._stop.is_set():
                break
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
                    self.error = f"giving up after {fails} grab errors: {exc!r}"
                    break
                self._stop.wait(0.2)
                continue
            fails = 0
            self.grabs += 1
            with self._cond:
                self._frame = (_raw_pixels(shot), shot.width, shot.height,
                               mon.get("left", 0), mon.get("top", 0))
                self._seq += 1
                self._taken = False
                self._cond.notify_all()
            # Pace the grabs too, a shade ahead of the tick so a fresh frame is
            # usually waiting when the encoder wants one. Grabbing flat out would
            # spend a core on frames nobody encodes.
            nxt += self._interval() * 0.85
            now = time.monotonic()
            if nxt <= now:
                nxt = now           # fell behind: carry on, don't burst
            else:
                self._stop.wait(nxt - now)
        if sct is not None:
            try:
                sct.close()
            except Exception:
                pass
        with self._cond:            # wake a caller waiting on a frame that won't come
            self._cond.notify_all()


class _Sender:
    """Ships encoded frames to the agent on its own thread.

    Writing to the socket from the encode loop meant a busy link pushed the next
    frame late, which is the jitter this pipeline exists to avoid. Frames are
    queued in order -- H.264 deltas can be neither reordered nor dropped -- and
    the queue is deliberately short, so a link that cannot keep up shows up as
    backpressure, which the pacer answers by lowering the rate.
    """

    # Two frames: enough to ride out one slow write, short enough that a link
    # which cannot keep up starts pushing back within ~60 ms instead of building
    # up a backlog of video the viewer would watch late.
    DEPTH = 2

    def __init__(self, sock, lock, stop: threading.Event) -> None:
        self._sock = sock
        self._lock = lock
        self._stop = stop
        self._q: queue.Queue = queue.Queue(maxsize=self.DEPTH)
        self.closed = False
        self._thread = threading.Thread(target=self._run, name="rmm-screen-send",
                                        daemon=True)

    def start(self) -> None:
        self._thread.start()

    def put(self, payloads) -> float:
        """Queue one frame's payloads. Returns the seconds spent waiting for
        room; the pacer counts that as part of what the frame cost."""
        t0 = time.monotonic()
        while not self._stop.is_set() and not self.closed:
            try:
                self._q.put(payloads, timeout=0.25)
                break
            except queue.Full:
                continue
        return time.monotonic() - t0

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._q.get(timeout=0.25)
            except queue.Empty:
                continue
            for payload in item:
                if self._lock is not None:
                    with self._lock:
                        ok = _send_msg(self._sock, payload)
                else:
                    ok = _send_msg(self._sock, payload)
                if not ok:
                    self.closed = True
                    self._stop.set()
                    return


class _Pacer:
    """Keeps the frame rate on one number.

    The viewer asks for a rate, but whether a device can hold it depends on the
    screen, the encoder and the link -- none of which are known up front, and the
    link changes under us. So watch what a frame actually costs (encode, plus any
    wait for the socket) and step the rate down when that stops fitting in a
    tick, back up when it fits again with room to spare. The asymmetry is
    deliberate: quick to back off, slow to climb, so the rate settles instead of
    oscillating -- oscillation being the thing we are getting rid of.

    A rate that has already failed gets a growing cooling-off period before it is
    tried again. When the *link* is the limit this matters: at the lower rate
    nothing is waiting on the socket, so a frame looks cheap and the climb looks
    safe -- right up until the higher rate saturates the link again. Doubling the
    wait after each failed attempt turns that into a few brief probes rather than
    a permanent see-saw.
    """

    WINDOW = 2.0        # evidence gathered before any change
    SETTLE = 8.0        # ... and the quiet spell required before climbing back
    RETRY = 30.0        # first cooling-off for a rate that has failed once
    MAX_RETRY = 240.0   # ... doubling up to this for one that keeps failing

    # JPEG carries the whole picture every frame, so its bitrate is the frame
    # rate times a full still: 30 fps of 1600px JPEG measured 22 Mbit/s against
    # H.264's 2.7. The fallback stays at a rate a normal link can carry.
    JPEG_CEILING = 20

    def __init__(self, requested: int, codec: str = "h264") -> None:
        if codec != "h264":
            requested = min(requested, self.JPEG_CEILING)
        steps = [r for r in _RATE_STEPS if r <= requested]
        if not steps or steps[0] != requested:
            steps.insert(0, requested)
        self.steps = steps
        self.requested = requested
        self.target = requested
        self.work_ms = 0.0
        self.achieved = 0.0
        self._i = 0
        self._n = 0
        self._sum = 0.0
        self._start = time.monotonic()
        self._primed = False
        self._bad = 0               # consecutive windows this rate fell short
        # Skip the first seconds: the encoder's first frames (keyframe, ramp-up)
        # are not what the steady state costs.
        self._until = time.monotonic() + 3.0
        self._changed = 0.0
        self._retry_at: dict[int, float] = {}   # step -> when it may be tried again
        self._wait: dict[int, float] = {}       # step -> how long that wait now is

    def interval(self) -> float:
        return 1.0 / self.target

    def frame(self, work: float, blocked: float) -> None:
        """Book one delivered frame and, once a window's worth has gone by,
        decide whether this rate is the right one to be holding."""
        now = time.monotonic()
        self._n += 1
        self._sum += work + blocked
        if now < self._until or self._n < 8:
            return
        span = max(1e-6, now - self._start)
        achieved = self._n / span
        mean = self._sum / self._n
        self.work_ms = mean * 1000
        self.achieved = achieved
        self._n = 0
        self._sum = 0.0
        self._start = now
        self._until = now + self.WINDOW
        if not self._primed:
            # The first window after a start or a change is the encoder warming
            # up or the pipeline settling into a new rate -- not evidence.
            self._primed = True
            return
        # Two ways to be over the line: the frames cost more than a tick has to
        # give (a slow device), or they are simply not coming out at the rate we
        # asked for (a link that cannot carry them -- where the cost of a frame
        # says nothing, because the wait lands on whichever frame fills the
        # socket buffer).
        short = achieved < self.target * 0.9
        if not (short or mean > self.interval() * 0.92):
            self._bad = 0
        else:
            self._bad += 1
        # Two windows, so a passing squall -- a background job on the device, a
        # blip on the link -- doesn't cost the session its frame rate.
        if self._bad >= 2 and self._i + 1 < len(self.steps):
            why = (f"{achieved:.1f} fps delivered of {self.target}" if short else
                   f"{mean * 1000:.0f} ms a frame does not fit "
                   f"{self.interval() * 1000:.0f} ms")
            wait = self._wait.get(self._i, self.RETRY)
            self._retry_at[self._i] = now + wait
            self._wait[self._i] = min(wait * 2, self.MAX_RETRY)
            self._step(self._i + 1, why)
        elif (self._i > 0 and now - self._changed > self.SETTLE
                and now >= self._retry_at.get(self._i - 1, 0.0)
                and achieved >= self.target * 0.97
                and mean < 0.6 / self.steps[self._i - 1]):
            self._step(self._i - 1, f"holding {achieved:.1f} fps on "
                                    f"{mean * 1000:.0f} ms a frame")

    def _step(self, i: int, why: str) -> None:
        was = self.target
        self._i = i
        self._bad = 0
        self._primed = False        # let the new rate settle before judging it
        self.target = self.steps[i]
        self._changed = time.monotonic()
        _hlog(f"pacing: {was} -> {self.target} fps ({why})")


def _capture_loop(s, fps: int, quality: int, stop: threading.Event,
                  geom: dict | None = None, send_lock: threading.Lock | None = None,
                  max_edge: int = _MAX_EDGE, codec: str = "jpeg") -> None:
    """Stream the screen until ``stop`` is set or the socket drops. ``codec`` is
    'jpeg' (full frames) or 'h264' (Annex-B, delta-encoded).

    Grabbing (:class:`_FrameSource`), encoding (here) and sending
    (:class:`_Sender`) run in parallel, because chaining them inside one display
    refresh is what made the frame rate jump between whole divisors of the
    refresh rate. Each tick encodes the newest grabbed frame on an absolute
    clock; a tick that finds nothing new re-encodes the last frame, which in
    H.264 costs a few hundred bytes and keeps the viewer's cadence constant
    (a repeated JPEG would cost a whole frame for nothing, so those are skipped).
    """
    from PIL import Image

    pacer = _Pacer(fps, codec)
    src = _FrameSource(stop, pacer.interval)
    sender = _Sender(s, send_lock, stop)
    enc = None          # lazily-created H.264 encoder (recreated on size change)
    enc_size = None
    seen = 0
    frames = 0
    enc_fails = 0
    reason = "stopped"
    frame_w = frame_h = 0
    hb_frames = 0       # frames/bytes/repeats since the last heartbeat log
    hb_bytes = 0
    hb_dups = 0
    hb_grabs = 0
    hb_last = 0.0

    try:
        src.start()
        sender.start()
        deadline = time.monotonic() + pacer.interval()
        while not stop.is_set():
            if src.error:
                # The grabber gave up. Without this the loop would happily go on
                # re-encoding the last frame, showing the operator a screen that
                # is frozen rather than a session that ended.
                reason = src.error
                break
            # Wait for a fresh frame only while this tick still has time to
            # spare -- leaving room for the encode, or the waiting alone would
            # push every tick late. Past that, serve the tick with the frame
            # already in hand.
            slack = deadline - time.monotonic() - max(0.003, pacer.work_ms / 1000.0)
            frame, seq = src.latest(seen, timeout=max(0.0, slack))
            if frame is None:
                stop.wait(0.005)                # nothing grabbed yet
                continue
            repeat = seq == seen
            seen = seq
            t0 = time.monotonic()
            raw, nw, nh, left, top = frame
            scale = 1.0
            if max(nw, nh) > max_edge:
                scale = max_edge / float(max(nw, nh))
            try:
                if codec == "h264":
                    # Straight from the grab: swscale converts and scales in one
                    # pass (see H264Encoder.encode_bgra). No PIL image at all.
                    out_w = max(2, int(nw * scale))
                    out_h = max(2, int(nh * scale))
                    if enc is None or enc_size != (out_w, out_h):
                        enc = screen_h264.H264Encoder(out_w, out_h, pacer.requested, quality)
                        enc_size = (out_w, out_h)
                    payloads = enc.encode_bgra(raw, nw, nh)
                    # The encoder rounds to even dimensions; report and map input
                    # against what it actually sends.
                    frame_w, frame_h = enc.width, enc.height
                    if scale < 1.0:
                        scale = enc.width / float(nw)
                elif repeat:
                    payloads = []               # see the docstring
                else:
                    if scale >= _JPEG_SKIP_RESIZE_ABOVE:
                        scale = 1.0
                    img = Image.frombytes("RGB", (nw, nh), bytes(raw), "raw", "BGRX")
                    if scale < 1.0:
                        img = img.resize((max(1, int(nw * scale)), max(1, int(nh * scale))),
                                         Image.BILINEAR, reducing_gap=2.0)
                    buf = io.BytesIO()
                    img.save(buf, format="JPEG", quality=quality)
                    payloads = [buf.getvalue()]
                    frame_w, frame_h = img.width, img.height
                enc_fails = 0
            except Exception as exc:
                enc_fails += 1
                if enc_fails == 1 or enc_fails % 50 == 0:
                    _hlog(f"frame encode error x{enc_fails} (recovering): {exc!r}")
                if enc_fails > 100:
                    reason = f"giving up after {enc_fails} encode errors: {exc!r}"
                    break
                enc = None                      # rebuild on the next frame
                payloads = []
            if geom is not None:
                geom["left"] = left
                geom["top"] = top
                geom["scale"] = scale
            blocked = 0.0
            if payloads:
                blocked = sender.put(payloads)
                if sender.closed:
                    reason = "viewer/socket closed"
                    break
                frames += 1
                hb_frames += 1
                hb_bytes += sum(len(p) for p in payloads)
                if repeat:
                    hb_dups += 1
                # Only frames that were really encoded and shipped say anything
                # about what this device and link can carry; a skipped JPEG
                # repeat costs nothing and would flatter the average.
                pacer.frame(time.monotonic() - t0, blocked)
            now = time.monotonic()
            if frames == 1:
                _hlog(f"first frame sent ({frame_w}x{frame_h} @scale {scale:.2f}, "
                      f"codec={codec}, {hb_bytes} bytes)")
                hb_last = now
                hb_grabs = src.grabs
            elif now - hb_last >= 10.0:
                # Time-based heartbeat: the real fps/throughput over the last
                # window, so a stall (fps -> 0) or a healthy stream is visible
                # right up to the moment a session drops. 'screen' is how often
                # the display actually had something new; the difference is the
                # repeats that keep the cadence even.
                _dt = now - hb_last
                _hlog(f"streaming: {frames} total, {hb_frames / _dt:.1f} fps "
                      f"(target {pacer.target}, screen {(src.grabs - hb_grabs) / _dt:.1f}, "
                      f"{hb_dups} repeats), {hb_bytes / 1024 / _dt:.0f} KB/s, "
                      f"{pacer.work_ms:.0f} ms/frame, codec={codec}, "
                      f"last {frame_w}x{frame_h}")
                hb_frames = hb_bytes = hb_dups = 0
                hb_grabs = src.grabs
                hb_last = now
            # Hold the cadence on an absolute clock: sleeping "the rest of the
            # interval" lets every overrun push the frames after it late, which
            # is how a steady rate turns into a wandering one.
            interval = pacer.interval()
            deadline += interval
            if deadline < now - interval:
                deadline = now                  # far behind: resync, don't burst
            stop.wait(max(0.0, deadline - time.monotonic()))
    except Exception as exc:
        reason = f"error: {exc!r}"
    finally:
        _hlog(f"capture loop ended after {frames} frames ({reason})")
        # Whatever ended the loop, make sure the banner/other threads wind down.
        stop.set()
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
    import time as _time

    # The banner is re-shown if its window closes for any reason OTHER than the
    # user clicking Disconnect (e.g. Windows switching the interactive desktop
    # when the machine goes idle, or a screensaver kicking in). A transient banner
    # loss must NOT tear down the remote session — that was causing sessions on an
    # unattended machine to drop every 20-50s ("ended at the device").
    disconnected = [False]
    while not stop.is_set():
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
                disconnected[0] = True
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

            # Close the banner promptly once the session is genuinely ending.
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
        if disconnected[0] or stop.is_set():
            break
        # Window closed on its own (not a Disconnect) — keep the session alive and
        # re-show the banner shortly. The brief pause avoids a busy loop if Tk
        # can't stay up at all.
        _hlog("consent banner closed unexpectedly; re-showing (session continues)")
        _time.sleep(1.5)
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
        fps = max(1, min(int(argv[i + 3]), 32))
        quality = max(10, min(int(argv[i + 4]), 90))
        mode = argv[i + 5] if len(argv) > i + 5 else "user"
        try:
            max_edge = max(320, min(int(argv[i + 6]), 4096)) if len(argv) > i + 6 else _MAX_EDGE
        except Exception:
            max_edge = _MAX_EDGE
        codec = argv[i + 7] if len(argv) > i + 7 else "jpeg"
    except Exception:
        return
    _hlog(f"helper started (mode={mode}, fps={fps}, quality={quality}, "
          f"max_edge={max_edge}, codec={codec})")
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=15)
    except Exception as exc:
        _hlog(f"helper could not connect to the bridge: {exc!r}")
        return
    # create_connection leaves its 15s timeout ON the socket. The input channel is
    # sporadic — an operator who is only *watching* sends nothing for long stretches
    # — and _recv_exact turns ANY exception (incl. socket.timeout) into None, which
    # the input reader treats as EOF and ends the session. That silently killed
    # unattended sessions ~15-50s after the last input ("the remote session was
    # ended at the device"). Clear the timeout: a real dead socket still yields an
    # empty recv (true EOF); idle no longer looks like a disconnect.
    s.settimeout(None)
    _hlog(f"helper connected to bridge (input timeout cleared); mode next")
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
        n_in = 0
        while not stop.is_set():
            data = _recv_msg(s)
            if data is None:
                _hlog(f"input channel closed (loopback EOF after {n_in} events); "
                      f"stopping session")
                break
            n_in += 1
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
                               args=(s, fps, quality, stop, geom, send_lock, max_edge, codec),
                               daemon=True)
        cap.start()
        _show_consent_banner(stop)
        stop.set()
        cap.join(timeout=5)
    else:
        _capture_loop(s, fps, quality, stop, geom, send_lock, max_edge, codec)
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
