"""WebSocket plumbing between Tk (single-threaded) and asyncio.

Tk owns the main thread and is not thread-safe, so every socket lives in one
shared background asyncio loop and talks to the UI through a plain
`queue.Queue`: the window drains it from a `after()` tick. Nothing touches a Tk
widget off the main thread, and nothing blocks the UI on the network.

Events pushed to the UI queue:

    ("open",)                 the socket is up
    ("json", obj)             a JSON control message from the server
    ("binary", data)          a frame (screen) -- raw bytes
    ("closed", code, reason)  the socket ended
    ("error", message)        it could not be opened, or it failed
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import queue
import ssl
import threading

import websockets

from tasks import alive


class _Loop:
    """The one background event loop, started lazily and shared by all sessions."""

    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()

    def get(self) -> asyncio.AbstractEventLoop:
        with self._lock:
            if self._loop is None:
                self._loop = asyncio.new_event_loop()
                threading.Thread(target=self._run, name="rmm-ws", daemon=True).start()
            return self._loop

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()


_LOOP = _Loop()


def _verify_pin(ws, pin: str) -> None:
    """Certificate pinning, identical in spirit to the agent's `_verify_pin`."""
    if not pin:
        return
    try:
        ssl_obj = ws.transport.get_extra_info("ssl_object")
        der = ssl_obj.getpeercert(binary_form=True)
        got = hashlib.sha256(der).hexdigest()
    except Exception as exc:
        raise ssl.SSLError(f"cannot read server certificate to verify fingerprint: {exc}")
    if not hmac.compare_digest(got, pin):
        raise ssl.SSLError("server certificate fingerprint mismatch -- possible MITM; refusing")


class Session:
    """One interactive WebSocket (a screen or terminal channel)."""

    def __init__(self, url: str, ssl_context=None, pin: str = ""):
        self.url = url
        self.events: queue.Queue = queue.Queue()
        self._ssl = ssl_context
        self._pin = pin or ""
        self._loop = _LOOP.get()
        self._outbox: asyncio.Queue | None = None
        self._task: asyncio.Task | None = None
        self._closing = False

    # -- lifecycle ---------------------------------------------------------- #
    def start(self) -> None:
        self._closing = False
        asyncio.run_coroutine_threadsafe(self._spawn(), self._loop)

    async def _spawn(self) -> None:
        # close() can land between start() and this coroutine actually running;
        # if it did, never open the socket at all.
        if self._closing:
            return
        self._outbox = asyncio.Queue()
        self._task = asyncio.create_task(self._run())

    def close(self) -> None:
        """Ask the socket to shut down. Safe to call from the Tk thread, and
        safe to call twice (a user-initiated close plus window teardown)."""
        self._closing = True
        task = self._task
        if task is not None:
            self._loop.call_soon_threadsafe(task.cancel)

    @property
    def closing(self) -> bool:
        return self._closing

    # -- sending ------------------------------------------------------------ #
    def send_json(self, payload: dict) -> None:
        """Queue a control message. Dropped silently if the socket is not up --
        input events are worthless once a session has ended."""
        outbox = self._outbox
        if outbox is None or self._closing:
            return
        try:
            self._loop.call_soon_threadsafe(outbox.put_nowait, json.dumps(payload))
        except RuntimeError:
            pass

    # -- the socket --------------------------------------------------------- #
    async def _run(self) -> None:
        try:
            async with websockets.connect(self.url, max_size=None, ping_interval=30,
                                          ping_timeout=20, ssl=self._ssl,
                                          open_timeout=20) as ws:
                _verify_pin(ws, self._pin)
                self.events.put(("open",))
                writer = asyncio.create_task(self._write(ws))
                try:
                    async for message in ws:
                        if isinstance(message, bytes):
                            self.events.put(("binary", message))
                        else:
                            try:
                                self.events.put(("json", json.loads(message)))
                            except ValueError:
                                pass
                finally:
                    writer.cancel()
            self.events.put(("closed", 1000, ""))
        except asyncio.CancelledError:
            self.events.put(("closed", 1000, "closed by the operator"))
            raise
        except websockets.exceptions.ConnectionClosed as exc:
            self.events.put(("closed", exc.rcvd.code if exc.rcvd else 1006,
                             (exc.rcvd.reason if exc.rcvd else "") or ""))
        except Exception as exc:
            self.events.put(("error", _explain(exc)))

    async def _write(self, ws) -> None:
        assert self._outbox is not None
        while True:
            payload = await self._outbox.get()
            try:
                await ws.send(payload)
            except Exception:
                return


def _explain(exc: Exception) -> str:
    """Map a connect failure onto something actionable in the UI."""
    text = str(exc) or exc.__class__.__name__
    status = getattr(exc, "status_code", None) or getattr(
        getattr(exc, "response", None), "status_code", None)
    if status in (401, 403) or "4401" in text or "4403" in text:
        return "Your sign-in is no longer valid for this device."
    if isinstance(exc, ssl.SSLError):
        return f"TLS error: {text}"
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "The server did not respond in time."
    if "getaddrinfo" in text:
        return "That server name could not be resolved."
    if "refused" in text.lower():
        return "The server refused the connection."
    return text


def drain(session: Session, handler, widget, interval_ms: int = 16) -> None:
    """Pump a session's events into `handler` on the Tk thread until the widget
    is destroyed. Re-arms itself; call once per session."""
    def tick() -> None:
        if not alive(widget):
            return
        try:
            while True:
                handler(session.events.get_nowait())
        except queue.Empty:
            pass
        except Exception:
            pass
        if alive(widget):
            try:
                widget.after(interval_ms, tick)
            except Exception:
                pass

    widget.after(interval_ms, tick)
