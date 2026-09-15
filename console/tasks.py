"""Run blocking work off the Tk thread and deliver the result back on it.

Every REST call goes through here. Tk is single-threaded and the network is not
fast, so a worker thread does the call and the callbacks are re-scheduled onto
the UI thread with `after(0, ...)` -- the only thread-safe way back into Tk.
"""
from __future__ import annotations

import threading
import tkinter as tk
import traceback


def alive(widget: tk.Misc) -> bool:
    """True while `widget` can still be touched.

    `winfo_exists()` alone is not enough: when the whole interpreter is being
    torn down (the app quitting with session windows still open) the call itself
    raises, and every self-rearming `after` timer would print a Tcl error on the
    way out."""
    try:
        return bool(widget.winfo_exists())
    except Exception:
        return False


def run(widget: tk.Misc, work, on_ok=None, on_error=None) -> threading.Thread:
    """Call `work()` in a worker thread.

    `on_ok(result)` or `on_error(exception)` then runs on the UI thread -- unless
    the window has been destroyed in the meantime, in which case the result is
    simply dropped (nobody is left to show it to).
    """
    def deliver(callback, argument) -> None:
        def fire() -> None:
            try:
                if alive(widget) and callback is not None:
                    callback(argument)
            except tk.TclError:
                pass
        try:
            widget.after(0, fire)
        except (tk.TclError, RuntimeError):
            pass

    def body() -> None:
        try:
            result = work()
        except Exception as exc:  # noqa: BLE001 -- surfaced through on_error
            if on_error is None:
                traceback.print_exc()
            deliver(on_error, exc)
        else:
            deliver(on_ok, result)

    thread = threading.Thread(target=body, daemon=True)
    thread.start()
    return thread
