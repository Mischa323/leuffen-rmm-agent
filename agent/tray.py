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

# ---------- dark-theme palette (matches the web UI design tokens) ----------
BG        = "#0a0c11"
SURFACE   = "#12161e"
SURF2     = "#171c26"
SURF3     = "#1c222e"
BORDER    = "#232b37"
BORDERSTR = "#2f3947"
TEXT      = "#e6ebf3"
TEXTDIM   = "#97a3b4"
TEXTFAINT = "#5f6b7c"
ACCENT_HEX = "#3b82f6"
GOOD_HEX   = "#22c55e"
BAD_HEX    = "#ef4444"
FONT    = "Segoe UI"            # Onest isn't bundled on Windows; Segoe is next best
MONO    = "Consolas"           # technical fields: URL, key, fingerprint


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
NOTIFY_PATH = os.path.join(_data_dir(), "notify.json")


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
def _round_rect(cv, x0, y0, x1, y1, r, **kw):
    """Draw a rounded rectangle on a Tk canvas (smoothed polygon)."""
    pts = [x0 + r, y0, x1 - r, y0, x1, y0, x1, y0 + r, x1, y1 - r, x1, y1,
           x1 - r, y1, x0 + r, y1, x0, y1, x0, y1 - r, x0, y0 + r, x0, y0]
    return cv.create_polygon(pts, smooth=True, **kw)


def _pill(cv, x0, y0, x1, y1, fill):
    """Draw a capsule/pill (two circles + a bridging rectangle)."""
    r = (y1 - y0) / 2
    cv.create_oval(x0, y0, x0 + 2 * r, y1, fill=fill, outline="")
    cv.create_oval(x1 - 2 * r, y0, x1, y1, fill=fill, outline="")
    cv.create_rectangle(x0 + r, y0, x1 - r, y1, fill=fill, outline="")


def _restart_agent() -> None:
    for args in (["schtasks", "/end", "/tn", "LeuffenRMMAgent"],
                 ["taskkill", "/F", "/IM", "leuffen-rmm-agent.exe"],
                 ["schtasks", "/run", "/tn", "LeuffenRMMAgent"]):
        try:
            subprocess.run(args, capture_output=True, timeout=20)
        except Exception:
            pass


def _apply_settings(url: str, key: str, insecure: bool, fingerprint: str = "") -> None:
    """Persist config to machine env (needs admin) and restart the agent."""
    for name, val in (("RMM_SERVER_URL", url), ("RMM_API_KEY", key),
                      ("RMM_INSECURE_TLS", "1" if insecure else "0"),
                      ("RMM_SERVER_FINGERPRINT", (fingerprint or "").strip())):
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
    cur_fp       = os.environ.get("RMM_SERVER_FINGERPRINT") or saved.get("server_fingerprint") or ""

    root = tk.Tk()
    root.title("Leuffen RMM — Agent settings")
    root.resizable(False, False)
    root.configure(bg=BG)
    try:
        root.attributes("-topmost", True)
    except Exception:
        pass

    # ttk is used only for the two footer buttons; everything else is plain tk so
    # we get exact control over the dark palette, borders and the pill toggle.
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("Accent.TButton", background=ACCENT_HEX, foreground="#ffffff",
                    bordercolor=ACCENT_HEX, font=(FONT, 9, "bold"), padding=(15, 7), relief="flat")
    style.map("Accent.TButton",
              background=[("active", "#2f74e6"), ("pressed", "#1d4ed8"), ("disabled", SURF3)],
              foreground=[("disabled", TEXTDIM)], bordercolor=[("active", "#2f74e6")])
    style.configure("Ghost.TButton", background=SURF2, foreground=TEXT,
                    bordercolor=BORDER, font=(FONT, 9), padding=(13, 6), relief="flat")
    style.map("Ghost.TButton", background=[("active", SURF3)], bordercolor=[("active", BORDERSTR)])

    outer = tk.Frame(root, bg=BG, padx=24, pady=22)
    outer.pack(fill="both", expand=True)

    # ---- header: rounded accent tile + shield glyph, title + subtitle ----
    hdr = tk.Frame(outer, bg=BG)
    hdr.pack(fill="x", pady=(0, 18))
    sh = tk.Canvas(hdr, width=40, height=40, bg=BG, highlightthickness=0)
    sh.pack(side="left", padx=(0, 12))
    _round_rect(sh, 0, 0, 40, 40, 10, fill=ACCENT_HEX, outline="")
    sh.create_polygon([11, 11, 29, 11, 29, 22, 20, 31, 11, 22], fill="white", outline="")
    sh.create_line(16, 20, 19, 23, 25, 15, fill=ACCENT_HEX, width=2)
    htxt = tk.Frame(hdr, bg=BG)
    htxt.pack(side="left", anchor="w")
    tk.Label(htxt, text="Agent settings", bg=BG, fg=TEXT, font=(FONT, 14, "bold")).pack(anchor="w")
    tk.Label(htxt, text="Connect this PC to your Leuffen RMM server", bg=BG, fg=TEXTDIM,
             font=(FONT, 9)).pack(anchor="w")

    # ---- connection banner (surface-2 card) ----
    conn = bool(status.get("connected")) and (time.time() - status.get("updated", 0) < 120)
    banner = tk.Frame(outer, bg=SURF2, highlightthickness=1, highlightbackground=BORDER)
    banner.pack(fill="x", pady=(0, 18))
    bin_ = tk.Frame(banner, bg=SURF2)
    bin_.pack(fill="x", padx=14, pady=11)
    dot_cv = tk.Canvas(bin_, width=10, height=10, bg=SURF2, highlightthickness=0)
    dot_cv.pack(side="left", padx=(0, 8))
    dot_cv.create_oval(0, 0, 9, 9, fill=(GOOD_HEX if conn else BAD_HEX), outline="")
    tk.Label(bin_, text="Connected" if conn else "Disconnected", bg=SURF2,
             fg=(GOOD_HEX if conn else BAD_HEX), font=(FONT, 10, "bold")).pack(side="left")
    _meta = []
    if status.get("last_sync"):
        _meta.append(f"Last sync: {_rel(status.get('last_sync'))}")
    _ver = status.get("version") or saved.get("version")
    if _ver:
        _meta.append(f"agent v{_ver}")
    if _meta:
        tk.Label(bin_, text="  ·  ".join(_meta), bg=SURF2, fg=TEXTFAINT,
                 font=(FONT, 8)).pack(side="right")

    # ---- field helpers (plain tk for exact dark styling + focus border) ----
    def _field(label, hint, show=None, initial="", trailing=None):
        fr = tk.Frame(outer, bg=BG)
        fr.pack(fill="x", pady=(0, 13))
        tk.Label(fr, text=label.upper(), bg=BG, fg=TEXTFAINT,
                 font=(FONT, 8, "bold")).pack(anchor="w", pady=(0, 5))
        row = tk.Frame(fr, bg=BG)
        row.pack(fill="x")
        e = tk.Entry(row, show=show or "", bg=SURF2, fg=TEXT, insertbackground=TEXT, relief="flat",
                     highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT_HEX,
                     font=(MONO, 10))
        if initial:
            e.insert(0, initial)
        e.pack(side="left", fill="x", expand=True, ipady=6, ipadx=8)
        if trailing is not None:
            trailing(row, e)
        if hint:
            tk.Label(fr, text=hint, bg=BG, fg=TEXTDIM, font=(FONT, 8),
                     wraplength=440, justify="left").pack(anchor="w", pady=(5, 0))
        return e

    url_e = _field("Server URL", "The address of your Leuffen RMM server, e.g. https://rmm.example.com:8000",
                   initial=cur_url)

    def _key_trailing(row, entry):
        def _toggle():
            entry.configure(show="" if entry.cget("show") else "•")
            eye_btn.configure(text="Hide" if not entry.cget("show") else "Show")
        eye_btn = ttk.Button(row, text="Show", style="Ghost.TButton", width=6, command=_toggle)
        eye_btn.pack(side="left", padx=(6, 0))
    key_e = _field("Enrollment key", "Dashboard → your org → Downloads → Enrollment key",
                   show="•", initial=cur_key, trailing=_key_trailing)

    fp_e = _field("Server fingerprint  ·  optional",
                  "SHA-256 of the server's TLS certificate — MITM-proof even on a self-signed setup. "
                  "Leave blank to skip.", initial=cur_fp)

    # ---- divider ----
    tk.Frame(outer, height=1, bg=BORDER).pack(fill="x", pady=(3, 15))

    # ---- pill toggle: accept self-signed certificate ----
    insecure = tk.BooleanVar(value=bool(cur_insecure))
    trow = tk.Frame(outer, bg=BG)
    trow.pack(fill="x", pady=(0, 3))
    ttxt = tk.Frame(trow, bg=BG)
    ttxt.pack(side="left", fill="x", expand=True)
    tk.Label(ttxt, text="Accept self-signed certificate", bg=BG, fg=TEXT,
             font=(FONT, 10, "bold")).pack(anchor="w")
    tk.Label(ttxt, text="Leave on for the default bundled server setup.", bg=BG, fg=TEXTDIM,
             font=(FONT, 8)).pack(anchor="w")
    pill = tk.Canvas(trow, width=44, height=25, bg=BG, highlightthickness=0, cursor="hand2")
    pill.pack(side="right")

    def _draw_pill():
        pill.delete("all")
        if insecure.get():
            _pill(pill, 0, 0, 44, 25, ACCENT_HEX)
            _pill(pill, 21, 3, 40, 22, "#ffffff")
        else:
            _pill(pill, 0, 0, 44, 25, BORDERSTR)
            _pill(pill, 1, 1, 43, 24, SURF3)
            _pill(pill, 3, 3, 22, 22, TEXTFAINT)
    pill.bind("<Button-1>", lambda e: (insecure.set(not insecure.get()), _draw_pill()))
    _draw_pill()

    # ---- divider ----
    tk.Frame(outer, height=1, bg=BORDER).pack(fill="x", pady=(15, 14))

    # ---- footer: inline status (left) + Cancel / Save (right) ----
    foot = tk.Frame(outer, bg=BG)
    foot.pack(fill="x")
    status_var = tk.StringVar()
    status_lbl = tk.Label(foot, textvariable=status_var, bg=BG, fg=BAD_HEX,
                          font=(FONT, 9), wraplength=300, justify="left")
    status_lbl.pack(side="left", fill="x", expand=True)

    save_btn: list = []

    def _do_save(u, k, fp):
        if _is_admin():
            _apply_settings(u, k, bool(insecure.get()), fp)
            _msgbox(root, "Settings saved. The agent is reconnecting.")
            root.destroy()
            return
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(path, "w") as f:
            json.dump({"url": u, "key": k, "insecure": bool(insecure.get()), "fingerprint": fp}, f)
        _elevate(f'--apply "{path}"')
        _msgbox(root, "Approve the administrator prompt to finish saving.")
        root.destroy()

    def save():
        u, k = url_e.get().strip(), key_e.get().strip()
        fp = fp_e.get().strip()
        status_lbl.configure(fg=BAD_HEX)
        if not u:
            status_var.set("Server URL is required.")
            return
        if not k:
            status_var.set("Enrollment key is required.")
            return
        if not u.startswith(("http://", "https://")):
            u = "https://" + u
            url_e.delete(0, "end")
            url_e.insert(0, u)
        status_var.set("")
        if save_btn:
            save_btn[0].configure(text="Testing connection…", state="disabled")

        def _run():
            err = _test_connection(u, bool(insecure.get()))
            def _update():
                if save_btn:
                    save_btn[0].configure(text="Save settings", state="normal")
                if err:
                    status_lbl.configure(fg=BAD_HEX)
                    status_var.set(err)
                else:
                    status_lbl.configure(fg=GOOD_HEX)
                    status_var.set("✓ Connection verified")
                    _do_save(u, k, fp)
            root.after(0, _update)

        threading.Thread(target=_run, daemon=True).start()

    btn = ttk.Button(foot, text="Save settings", style="Accent.TButton", command=save)
    btn.pack(side="right")
    ttk.Button(foot, text="Cancel", style="Ghost.TButton",
               command=root.destroy).pack(side="right", padx=(0, 8))
    save_btn.append(btn)

    root.update_idletasks()
    root.minsize(root.winfo_reqwidth(), root.winfo_reqheight())
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

    def _check_notify(self, icon):
        """Show any desktop notification the agent queued (updates ready, etc.),
        then clear it. Stale (>5 min) notifications are dropped, not shown late."""
        try:
            if not os.path.exists(NOTIFY_PATH):
                return
            with open(NOTIFY_PATH) as f:
                n = json.load(f)
            os.remove(NOTIFY_PATH)
            body = (n.get("body") or "").strip()
            if body and (time.time() - float(n.get("ts") or 0)) < 300:
                icon.notify(body, n.get("title") or "Leuffen RMM")
        except Exception:
            pass

    def _refresh(self, icon):
        icon.visible = True
        while True:
            time.sleep(POLL_SECONDS)
            self.status = _read_status()
            icon.icon = _logo(self._connected())
            icon.menu = self._menu()
            icon.update_menu()
            self._check_notify(icon)

    def run(self):
        self.icon.run(setup=self._refresh)


def _do_apply(path: str) -> None:
    """Elevated re-entry: apply settings from a temp file."""
    import tkinter as tk
    try:
        with open(path) as f:
            d = json.load(f)
        _apply_settings(d["url"], d["key"], bool(d.get("insecure", True)), d.get("fingerprint", ""))
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
