"""Leuffen RMM — Windows system-tray companion.

Runs in the interactive user session (the main agent runs as SYSTEM in session 0,
which has no tray). It reads the agent's status file and shows the Leuffen shield
with a connection indicator:

  green dot = connected to the server
  red dot   = disconnected

Right-click menu: connection status, last sync, **Force sync now**, **Settings…**
(requires admin — elevates via UAC), open the dashboard, and quit.

Run with ``--settings`` to open just the settings dialog (used for elevation).

Dependencies: pystray, Pillow (Tk ships with Python). Packaged to
leuffen-rmm-tray.exe by CI.
"""
from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser

import pystray
from PIL import Image, ImageDraw

POLL_SECONDS = 3
ACCENT  = (59, 130, 246, 255)   # brand blue
GOOD    = (34, 197, 94, 255)
BAD     = (239, 68, 68, 255)

# ---------- dark-theme palette (matches web CSS variables) ----------
BG      = "#0d1117"
SURFACE = "#161b22"
SURF2   = "#1c2128"
BORDER  = "#30363d"
TEXT    = "#e6edf3"
TEXTDIM = "#8b949e"
ACCENT_HEX = "#3b82f6"
BAD_HEX    = "#ef4444"
FONT    = "Segoe UI"            # Onest isn't bundled on Windows; Segoe is next best


def _data_dir() -> str:
    env = os.environ.get("RMM_DATA_DIR")
    if env:
        return env
    if os.name == "nt":
        return os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "LeuffenRMM")
    return os.path.dirname(os.path.abspath(__file__))


STATUS_PATH = os.path.join(_data_dir(), "status.json")
CONFIG_PATH = os.path.join(_data_dir(), "rmm_config.json")
SYNC_FLAG   = os.path.join(_data_dir(), "sync_request")


def _read_status() -> dict:
    try:
        with open(STATUS_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _read_config() -> dict:
    """Read persisted server config (written by the agent on first connect)."""
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _logo(connected: bool) -> Image.Image:
    """Leuffen shield with a connection-status dot."""
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    shield = [(13, 13), (51, 13), (51, 33), (32, 55), (13, 33)]
    d.polygon(shield, fill=ACCENT)
    d.line([(24, 28), (30, 35), (42, 21)], fill=(255, 255, 255, 235), width=4, joint="curve")
    col = GOOD if connected else BAD
    d.ellipse((41, 41, 61, 61), fill=col, outline=(13, 17, 24, 255), width=3)
    return img


def _rel(ts) -> str:
    if not ts:
        return "never"
    s = time.time() - ts
    if s < 60:
        return "just now"
    if s < 3600:
        return f"{int(s // 60)} min ago"
    if s < 86400:
        return f"{int(s // 3600)} h ago"
    return f"{int(s // 86400)} d ago"


# --------------------------------------------------------------------------- #
# Settings dialog — dark themed, styled like the web UI
# --------------------------------------------------------------------------- #
def _restart_agent() -> None:
    for args in (["schtasks", "/end", "/tn", "LeuffenRMMAgent"],
                 ["taskkill", "/F", "/IM", "leuffen-rmm-agent.exe"],
                 ["schtasks", "/run", "/tn", "LeuffenRMMAgent"]):
        try:
            subprocess.run(args, capture_output=True, timeout=20)
        except Exception:
            pass


def _apply_settings(url: str, key: str, insecure: bool) -> None:
    """Persist config to machine env (needs admin) and restart the agent."""
    for name, val in (("RMM_SERVER_URL", url), ("RMM_API_KEY", key),
                      ("RMM_INSECURE_TLS", "1" if insecure else "0")):
        subprocess.run(["setx", "/M", name, val], capture_output=True, timeout=20)
    _restart_agent()


def _is_configured() -> bool:
    return bool(os.environ.get("RMM_SERVER_URL") and os.environ.get("RMM_API_KEY")) \
        or bool(_read_status().get("server_url")) \
        or bool(_read_config().get("server_url"))


def _self_exe() -> str:
    return sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)


def _test_connection(url: str, insecure: bool) -> str | None:
    """Return None on success, or an error string on failure."""
    import ssl
    try:
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.urlopen(url.rstrip("/") + "/health", context=ctx, timeout=8)
        req.read()
        return None
    except urllib.error.URLError as e:
        reason = str(e.reason)
        if "timed out" in reason.lower():
            return "Connection timed out. Check the URL and firewall."
        if "refused" in reason.lower():
            return "Connection refused. Is the server running?"
        if "certificate" in reason.lower() or "ssl" in reason.lower():
            return "TLS error. Enable 'Accept self-signed certificate' if using a self-signed cert."
        return f"Cannot reach server: {reason}"
    except Exception as e:
        return f"Cannot reach server: {e}"


def _elevate(args: str) -> None:
    if getattr(sys, "frozen", False):
        target, params = _self_exe(), args
    else:
        target, params = sys.executable, f'"{_self_exe()}" {args}'
    ctypes.windll.shell32.ShellExecuteW(None, "runas", target, params, None, 1)


def settings_dialog() -> None:
    import tkinter as tk
    from tkinter import ttk

    status = _read_status()
    saved  = _read_config()   # written by agent; survives elevation / SYSTEM session

    # ---- resolve current values (env > saved file > status) ----
    cur_url      = os.environ.get("RMM_SERVER_URL") or saved.get("server_url") or status.get("server_url") or ""
    cur_key      = os.environ.get("RMM_API_KEY")    or saved.get("api_key")    or ""
    cur_insecure = saved.get("insecure_tls", os.environ.get("RMM_INSECURE_TLS", "1") == "1")

    root = tk.Tk()
    root.title("Leuffen RMM")
    root.resizable(False, False)
    root.configure(bg=BG)
    try:
        root.attributes("-topmost", True)
    except Exception:
        pass

    # ---- ttk style ----
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", background=BG, foreground=TEXT, font=(FONT, 9),
                    bordercolor=BORDER, troughcolor=SURF2, insertcolor=TEXT)
    style.configure("TFrame",  background=BG)
    style.configure("Card.TFrame", background=SURFACE, relief="flat")
    style.configure("TLabel",  background=BG, foreground=TEXT, font=(FONT, 9))
    style.configure("Dim.TLabel", background=BG, foreground=TEXTDIM, font=(FONT, 8))
    style.configure("Head.TLabel", background=BG, foreground=TEXT, font=(FONT, 13, "bold"))
    style.configure("Sub.TLabel",  background=BG, foreground=TEXTDIM, font=(FONT, 9))
    style.configure("TEntry", fieldbackground=SURF2, foreground=TEXT, bordercolor=BORDER,
                    insertcolor=TEXT, font=(FONT, 9), padding=6)
    style.configure("TCheckbutton", background=BG, foreground=TEXTDIM, font=(FONT, 9))
    style.map("TCheckbutton", background=[("active", BG)])
    # Primary button
    style.configure("Accent.TButton", background=ACCENT_HEX, foreground="#ffffff",
                    bordercolor=ACCENT_HEX, font=(FONT, 9, "bold"), padding=(14, 7), relief="flat")
    style.map("Accent.TButton",
              background=[("active", "#2563eb"), ("pressed", "#1d4ed8")],
              bordercolor=[("active", "#2563eb")])
    # Ghost button
    style.configure("Ghost.TButton", background=BG, foreground=TEXTDIM,
                    bordercolor=BORDER, font=(FONT, 9), padding=(12, 6), relief="flat")
    style.map("Ghost.TButton",
              background=[("active", SURF2)],
              foreground=[("active", TEXT)])
    # Status badge
    style.configure("OK.TLabel",  background=BG, foreground="#22c55e", font=(FONT, 9, "bold"))
    style.configure("Bad.TLabel", background=BG, foreground=BAD_HEX,  font=(FONT, 9, "bold"))

    # ---- outer padding ----
    outer = ttk.Frame(root, padding=24)
    outer.grid(row=0, column=0, sticky="nsew")

    # ---- header ----
    hdr = ttk.Frame(outer)
    hdr.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 20))

    # Shield icon (small canvas)
    shield_cv = tk.Canvas(hdr, width=36, height=36, bg=BG, highlightthickness=0)
    shield_cv.grid(row=0, column=0, rowspan=2, padx=(0, 10))
    shield_cv.create_polygon([7,7, 29,7, 29,20, 18,32, 7,20],
                              fill=ACCENT_HEX, outline="")
    shield_cv.create_line(12,18, 17,23, 25,13, fill="white", width=2)

    ttk.Label(hdr, text="Leuffen RMM", style="Head.TLabel").grid(row=0, column=1, sticky="w")
    ttk.Label(hdr, text="Agent settings", style="Sub.TLabel").grid(row=1, column=1, sticky="w")

    # ---- connection status banner ----
    conn = bool(status.get("connected")) and (time.time() - status.get("updated", 0) < 120)
    banner = ttk.Frame(outer, padding=(14, 10), style="Card.TFrame")
    banner.configure(style="Card.TFrame")
    banner.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 18))
    banner.configure()
    _dot_col = "#22c55e" if conn else BAD_HEX
    dot_cv = tk.Canvas(banner, width=10, height=10, bg=SURFACE, highlightthickness=0)
    dot_cv.grid(row=0, column=0, padx=(0, 8))
    dot_cv.create_oval(1, 1, 9, 9, fill=_dot_col, outline="")
    sty = "OK.TLabel" if conn else "Bad.TLabel"
    ttk.Label(banner, text="Connected" if conn else "Disconnected",
              style=sty, background=SURFACE).grid(row=0, column=1, sticky="w")
    if status.get("last_sync"):
        ttk.Label(banner, text=f"Last sync: {_rel(status.get('last_sync'))}",
                  style="Dim.TLabel", background=SURFACE).grid(row=0, column=2, sticky="e", padx=(20, 0))

    # ---- form fields ----
    def _label(row, text, hint=None):
        ttk.Label(outer, text=text).grid(row=row, column=0, sticky="nw",
                                          padx=(0, 16), pady=(0, 2))
        if hint:
            ttk.Label(outer, text=hint, style="Dim.TLabel").grid(
                row=row + 1, column=1, sticky="w", pady=(0, 10))

    def _entry(row, show=None):
        e = ttk.Entry(outer, width=42, show=show or "")
        e.grid(row=row, column=1, sticky="ew", pady=(0, 2))
        return e

    _label(2, "Server URL", "e.g. https://rmm.example.com:8000")
    url_e = _entry(2)
    url_e.insert(0, cur_url)

    _label(4, "Enrollment key", "Settings → your org → Downloads → Enrollment key")
    key_e = _entry(4, show="•")
    key_e.insert(0, cur_key)

    # Show/hide toggle for key
    def _toggle_key():
        key_e.configure(show="" if key_e.cget("show") else "•")
        eye_btn.configure(text="Hide" if not key_e.cget("show") else "Show")
    eye_btn = ttk.Button(outer, text="Show", style="Ghost.TButton", command=_toggle_key, width=6)
    eye_btn.grid(row=4, column=2, padx=(6, 0))

    insecure = tk.BooleanVar(value=bool(cur_insecure))
    cb = ttk.Checkbutton(outer, text="Accept self-signed certificate",
                          variable=insecure)
    cb.grid(row=6, column=1, sticky="w", pady=(4, 18))
    ttk.Label(outer, text="Leave on for the default server setup",
              style="Dim.TLabel").grid(row=7, column=1, sticky="w", pady=(0, 18))

    # ---- separator ----
    sep = tk.Frame(outer, height=1, bg=BORDER)
    sep.grid(row=8, column=0, columnspan=3, sticky="ew", pady=(0, 16))

    # ---- error label ----
    err_var = tk.StringVar()
    err_lbl = ttk.Label(outer, textvariable=err_var, foreground=BAD_HEX,
                         background=BG, font=(FONT, 9), wraplength=380)
    err_lbl.grid(row=9, column=0, columnspan=3, sticky="w", pady=(0, 8))

    # ---- buttons ----
    btns = ttk.Frame(outer)
    btns.grid(row=10, column=0, columnspan=3, sticky="e")

    save_btn: list = []  # mutable container so inner functions can rebind

    def _do_save(u, k):
        if _is_admin():
            _apply_settings(u, k, bool(insecure.get()))
            _msgbox(root, "Settings saved. The agent is reconnecting.")
            root.destroy()
            return
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(path, "w") as f:
            json.dump({"url": u, "key": k, "insecure": bool(insecure.get())}, f)
        _elevate(f'--apply "{path}"')
        _msgbox(root, "Approve the administrator prompt to finish saving.")
        root.destroy()

    def save():
        u, k = url_e.get().strip(), key_e.get().strip()
        if not u:
            err_var.set("Server URL is required.")
            return
        if not k:
            err_var.set("Enrollment key is required.")
            return
        if not u.startswith(("http://", "https://")):
            u = "https://" + u
            url_e.delete(0, "end")
            url_e.insert(0, u)
        err_var.set("")
        if save_btn:
            save_btn[0].configure(text="Testing connection…", state="disabled")

        def _run():
            err = _test_connection(u, bool(insecure.get()))
            def _update():
                if save_btn:
                    save_btn[0].configure(text="Save settings", state="normal")
                if err:
                    err_var.set(err)
                else:
                    _do_save(u, k)
            root.after(0, _update)

        threading.Thread(target=_run, daemon=True).start()

    ttk.Button(btns, text="Cancel", style="Ghost.TButton",
               command=root.destroy).pack(side="right", padx=(6, 0))
    btn = ttk.Button(btns, text="Save settings", style="Accent.TButton", command=save)
    btn.pack(side="right")
    save_btn.append(btn)

    outer.columnconfigure(1, weight=1)
    root.mainloop()


def _msgbox(parent, msg: str) -> None:
    """Simple dark-themed info box (avoids the Windows-default white popup)."""
    import tkinter as tk
    from tkinter import ttk
    win = tk.Toplevel(parent)
    win.title("Leuffen RMM")
    win.configure(bg=BG)
    win.resizable(False, False)
    try:
        win.attributes("-topmost", True)
    except Exception:
        pass
    ttk.Label(win, text=msg, background=BG, foreground=TEXT,
              font=(FONT, 9), wraplength=300, padding=(24, 20)).pack()
    ttk.Button(win, text="OK", style="Accent.TButton",
               command=win.destroy).pack(pady=(0, 16))
    win.grab_set()
    win.wait_window()


# --------------------------------------------------------------------------- #
# Tray
# --------------------------------------------------------------------------- #
class Tray:
    def __init__(self):
        self.status = _read_status()
        self.icon = pystray.Icon("leuffen-rmm", _logo(self._connected()),
                                 "Leuffen RMM", menu=self._menu())

    def _connected(self) -> bool:
        st = self.status
        return bool(st.get("connected")) and (time.time() - st.get("updated", 0) < 120)

    def _menu(self) -> pystray.Menu:
        conn  = self._connected()
        admin = _is_admin()
        return pystray.Menu(
            pystray.MenuItem(f"{'● Connected' if conn else '● Disconnected'}", None, enabled=False),
            pystray.MenuItem(f"Last sync: {_rel(self.status.get('last_sync'))}", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Force sync now", self._force_sync),
            pystray.MenuItem("Settings…" + ("" if admin else " (admin)"), self._open_settings),
            pystray.MenuItem("Open dashboard", self._open_dashboard,
                             enabled=bool(self.status.get("server_url"))),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self._quit),
        )

    def _force_sync(self, icon=None, item=None):
        try:
            with open(SYNC_FLAG, "w") as f:
                f.write(str(time.time()))
            icon.notify("Sync requested", "Leuffen RMM")
        except Exception:
            pass

    def _open_settings(self, icon=None, item=None):
        try:
            if _is_admin():
                if getattr(sys, "frozen", False):
                    subprocess.Popen([_self_exe(), "--settings"])
                else:
                    subprocess.Popen([sys.executable, _self_exe(), "--settings"])
            else:
                _elevate("--settings")
        except Exception:
            pass

    def _open_dashboard(self, icon=None, item=None):
        url = self.status.get("server_url") or _read_config().get("server_url")
        if url:
            webbrowser.open(url)

    def _quit(self, icon=None, item=None):
        self.icon.stop()

    def _refresh(self, icon):
        icon.visible = True
        while True:
            time.sleep(POLL_SECONDS)
            self.status = _read_status()
            icon.icon = _logo(self._connected())
            icon.menu = self._menu()
            icon.update_menu()

    def run(self):
        self.icon.run(setup=self._refresh)


def _do_apply(path: str) -> None:
    """Elevated re-entry: apply settings from a temp file."""
    import tkinter as tk
    try:
        with open(path) as f:
            d = json.load(f)
        _apply_settings(d["url"], d["key"], bool(d.get("insecure", True)))
    except Exception:
        return
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    try:
        r = tk.Tk(); r.withdraw()
        _msgbox(r, "Settings saved. The agent is reconnecting.")
        r.destroy()
    except Exception:
        pass


if __name__ == "__main__":
    try:
        if "--apply" in sys.argv:
            _do_apply(sys.argv[sys.argv.index("--apply") + 1])
        elif "--settings" in sys.argv:
            settings_dialog()
        else:
            if os.name == "nt" and not _is_configured():
                settings_dialog()
            Tray().run()
    except Exception:
        sys.exit(1)
