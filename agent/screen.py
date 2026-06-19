"""Remote desktop: screen capture + input injection.

Heavy GUI/imaging deps (``mss``, ``Pillow``, ``pynput``) are imported lazily here
so an idle agent never loads them. Degrades gracefully when no display is present
(e.g. a headless server) by reporting an error instead of crashing.
"""
from __future__ import annotations

import asyncio
import io
import platform
import subprocess


class ScreenSession:
    def __init__(self, send_bytes, fps: int = 4, quality: int = 50, on_error=None):
        self.send_bytes = send_bytes
        self.on_error = on_error
        self.fps = max(1, min(fps, 15))
        self.quality = max(10, min(quality, 90))
        self._task: asyncio.Task | None = None
        self._mouse = None
        self._keyboard = None

    async def start(self) -> str | None:
        try:
            import mss  # noqa: F401
            from PIL import Image  # noqa: F401
        except Exception as exc:
            return f"screen deps unavailable: {exc}"
        self._task = asyncio.create_task(self._loop())
        return None

    async def _loop(self) -> None:
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
            # Common cause on Windows: the agent runs as SYSTEM in session 0 and
            # cannot capture the interactive user's desktop. Report it so the
            # viewer shows a reason instead of hanging.
            if self.on_error:
                try:
                    await self.on_error(f"capture failed: {exc}")
                except Exception:
                    pass

    def stop(self) -> None:
        if self._task:
            self._task.cancel()
            self._task = None

    def input(self, ev: dict) -> None:
        """Inject a mouse/keyboard event (best-effort)."""
        try:
            kind = ev.get("kind")
            if kind in ("move", "click", "scroll"):
                if self._mouse is None:
                    from pynput.mouse import Controller
                    self._mouse = Controller()
                if kind == "move":
                    self._mouse.position = (ev["x"], ev["y"])
                elif kind == "click":
                    from pynput.mouse import Button
                    self._mouse.position = (ev["x"], ev["y"])
                    btn = Button.right if ev.get("button") == "right" else Button.left
                    self._mouse.click(btn)
                elif kind == "scroll":
                    self._mouse.scroll(0, ev.get("dy", 0))
            elif kind == "key":
                if self._keyboard is None:
                    from pynput.keyboard import Controller
                    self._keyboard = Controller()
                self._keyboard.type(ev.get("text", ""))
            elif kind == "hotkey":
                keys_raw = ev.get("keys", [])
                # Ctrl+Alt+Del cannot be injected by user-mode code on Windows;
                # use sas.dll (Secure Attention Sequence) instead.
                if platform.system() == "Windows" and keys_raw == ["ctrl", "alt", "delete"]:
                    _send_sas()
                else:
                    from pynput.keyboard import Controller as KC, Key
                    kb = self._keyboard or KC()
                    keys = [getattr(Key, k, k) for k in keys_raw]
                    for k in keys:
                        kb.press(k)
                    for k in reversed(keys):
                        kb.release(k)
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
