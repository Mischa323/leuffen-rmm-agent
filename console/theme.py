"""Design tokens + shared widgets for the desktop console.

The palette is a direct port of the dashboard's `styles.css` custom properties
(dark and light ramps), so the native app and the web UI are recognisably the
same product. Tk has no CSS, so the tokens live here as plain dicts and the ttk
widgets are restyled from them at start-up.
"""
from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk

from tasks import alive

# --- token ramps (see styles.css :root / [data-theme="light"]) -------------- #
DARK = {
    "bg": "#0a0c11", "surface": "#12161e", "surface2": "#171c26",
    "surface3": "#1c222e", "hover": "#1a212c",
    "border": "#232b37", "border_soft": "#1b222d", "border_strong": "#303a48",
    "text": "#e9eef6", "dim": "#97a3b4", "faint": "#5f6b7c",
    "term_bg": "#070a0f", "screen_bg": "#05070c", "meter": "#0c0f15",
}
LIGHT = {
    "bg": "#f4f6fa", "surface": "#ffffff", "surface2": "#f6f8fc",
    "surface3": "#eef2f8", "hover": "#f2f5fa",
    "border": "#e4e9f1", "border_soft": "#edf1f7", "border_strong": "#d3dbe7",
    "text": "#111826", "dim": "#5d6b7e", "faint": "#93a0b2",
    "term_bg": "#0b0f16", "screen_bg": "#0b0f16", "meter": "#eaeef4",
}
SEMANTIC = {"accent": "#3b82f6", "good": "#34d399", "warn": "#fbbf24", "bad": "#f87171"}

# Accent swatches offered in the dashboard's Appearance settings.
ACCENTS = ["#3b82f6", "#6366f1", "#8b5cf6", "#06b6d4",
           "#10b981", "#f59e0b", "#ef4444", "#ec4899"]

C: dict[str, str] = {}          # the live palette, filled by `apply()`


def _pick_font(root: tk.Misc, *candidates: str) -> str:
    """First installed family of `candidates` (the brand fonts are web fonts, so
    on a technician's machine we usually land on the platform default)."""
    have = {f.lower() for f in tkfont.families(root)}
    for name in candidates:
        if name.lower() in have:
            return name
    return candidates[-1]


class Fonts:
    """Resolved font tuples, set up once by `apply()`."""
    ui = ("Segoe UI", 10)
    ui_sm = ("Segoe UI", 9)
    ui_bold = ("Segoe UI", 10, "bold")
    h1 = ("Segoe UI", 16, "bold")
    h2 = ("Segoe UI", 12, "bold")
    mono = ("Consolas", 10)
    mono_sm = ("Consolas", 9)


def mix(fg: str, bg: str, pct: int) -> str:
    """Blend `pct`% of `fg` into `bg` -- the flat stand-in for CSS `color-mix`,
    which is how the web UI builds every soft tint."""
    f = tuple(int(fg[i:i + 2], 16) for i in (1, 3, 5))
    b = tuple(int(bg[i:i + 2], 16) for i in (1, 3, 5))
    out = tuple(round(f[i] * pct / 100 + b[i] * (100 - pct) / 100) for i in range(3))
    return "#%02x%02x%02x" % out


def apply(root: tk.Misc, theme: str = "dark", accent: str = "#3b82f6") -> None:
    """Load the palette and restyle every ttk widget class the app uses."""
    C.clear()
    C.update(DARK if theme != "light" else LIGHT)
    C.update(SEMANTIC)
    C["accent"] = accent or SEMANTIC["accent"]
    C["accent_soft"] = mix(C["accent"], C["surface"], 16)
    C["accent_hover"] = mix("#ffffff", C["accent"], 12)
    C["good_soft"] = mix(C["good"], C["surface"], 15)
    C["bad_soft"] = mix(C["bad"], C["surface"], 15)
    C["warn_soft"] = mix(C["warn"], C["surface"], 15)
    C["theme"] = theme

    ui = _pick_font(root, "Onest", "Segoe UI Variable Text", "Segoe UI")
    mono = _pick_font(root, "JetBrains Mono", "Cascadia Mono", "Consolas")
    Fonts.ui = (ui, 10)
    Fonts.ui_sm = (ui, 9)
    Fonts.ui_bold = (ui, 10, "bold")
    Fonts.h1 = (ui, 16, "bold")
    Fonts.h2 = (ui, 12, "bold")
    Fonts.mono = (mono, 10)
    Fonts.mono_sm = (mono, 9)

    st = ttk.Style(root)
    st.theme_use("clam")
    st.configure(".", background=C["bg"], foreground=C["text"],
                 fieldbackground=C["surface2"], font=Fonts.ui, borderwidth=0)
    st.configure("TFrame", background=C["bg"])
    st.configure("Card.TFrame", background=C["surface"])
    st.configure("Bar.TFrame", background=C["surface"])
    st.configure("TLabel", background=C["bg"], foreground=C["text"], font=Fonts.ui)
    st.configure("Card.TLabel", background=C["surface"], foreground=C["text"])
    st.configure("Dim.TLabel", background=C["bg"], foreground=C["dim"], font=Fonts.ui_sm)
    st.configure("CardDim.TLabel", background=C["surface"], foreground=C["dim"],
                 font=Fonts.ui_sm)
    st.configure("H1.TLabel", background=C["bg"], foreground=C["text"], font=Fonts.h1)
    st.configure("H2.TLabel", background=C["surface"], foreground=C["text"], font=Fonts.h2)
    st.configure("Mono.TLabel", background=C["surface"], foreground=C["dim"],
                 font=Fonts.mono_sm)

    # Entries / combos
    st.configure("TEntry", fieldbackground=C["surface2"], foreground=C["text"],
                 bordercolor=C["border"], lightcolor=C["border"], darkcolor=C["border"],
                 insertcolor=C["text"], padding=7, relief="flat")
    st.map("TEntry", bordercolor=[("focus", C["accent"])])
    st.configure("TCombobox", fieldbackground=C["surface2"], background=C["surface2"],
                 foreground=C["text"], bordercolor=C["border"], arrowcolor=C["dim"],
                 lightcolor=C["border"], darkcolor=C["border"], padding=5, relief="flat")
    st.map("TCombobox", fieldbackground=[("readonly", C["surface2"])],
           foreground=[("readonly", C["text"])], bordercolor=[("focus", C["accent"])])
    root.option_add("*TCombobox*Listbox.background", C["surface2"])
    root.option_add("*TCombobox*Listbox.foreground", C["text"])
    root.option_add("*TCombobox*Listbox.selectBackground", C["accent"])
    root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")

    # Device / file tables
    st.configure("Treeview", background=C["surface"], fieldbackground=C["surface"],
                 foreground=C["text"], rowheight=30, borderwidth=0, font=Fonts.ui)
    st.configure("Treeview.Heading", background=C["surface2"], foreground=C["faint"],
                 font=Fonts.ui_sm, relief="flat", padding=(10, 8), anchor="w")
    st.map("Treeview.Heading", background=[("active", C["surface3"])])
    st.map("Treeview", background=[("selected", C["accent_soft"])],
           foreground=[("selected", C["text"])])

    st.configure("TScrollbar", background=C["surface3"], troughcolor=C["bg"],
                 bordercolor=C["bg"], arrowcolor=C["dim"], relief="flat")
    st.map("TScrollbar", background=[("active", C["border_strong"])])
    st.configure("TSeparator", background=C["border"])
    st.configure("TProgressbar", background=C["accent"], troughcolor=C["surface3"],
                 bordercolor=C["surface3"], lightcolor=C["accent"], darkcolor=C["accent"])
    st.configure("TNotebook", background=C["bg"], borderwidth=0, tabmargins=(0, 0, 0, 0))
    st.configure("TNotebook.Tab", background=C["surface2"], foreground=C["dim"],
                 padding=(14, 8), borderwidth=0, font=Fonts.ui_sm)
    st.map("TNotebook.Tab", background=[("selected", C["surface"])],
           foreground=[("selected", C["text"])])


# --------------------------------------------------------------------------- #
# Widgets
#
# ttk buttons cannot be themed convincingly on Windows (the native engine wins),
# so the app's buttons are Labels with their own hover/press states -- the same
# flat, tinted look as the web `.btn`.
# --------------------------------------------------------------------------- #
class Button(tk.Label):
    """Flat button. `kind`: accent | default | ghost | danger | warn."""

    def __init__(self, parent, text: str, command=None, kind: str = "default",
                 padx: int = 14, pady: int = 7, font=None, **kw):
        self._kind = kind
        self._command = command
        self._enabled = True
        bg, fg = self._colors()
        super().__init__(parent, text=text, bg=bg, fg=fg, padx=padx, pady=pady,
                         font=font or Fonts.ui_sm, cursor="hand2",
                         bd=0, highlightthickness=0, **kw)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)

    def _colors(self) -> tuple[str, str]:
        if not self._enabled:
            return C["surface2"], C["faint"]
        return {
            "accent": (C["accent"], "#ffffff"),
            "danger": (C["bad_soft"], C["bad"]),
            "warn": (C["warn_soft"], C["warn"]),
            "ghost": (C["surface"], C["dim"]),
        }.get(self._kind, (C["surface2"], C["text"]))

    def _on_enter(self, _=None):
        if not self._enabled:
            return
        base = self._colors()[0]
        hot = C["accent_hover"] if self._kind == "accent" else mix(C["text"], base, 8)
        self.configure(bg=hot)

    def _on_leave(self, _=None):
        self.configure(bg=self._colors()[0])

    def _on_press(self, _=None):
        if self._enabled:
            self.configure(bg=mix("#000000", self._colors()[0], 12))

    def _on_release(self, ev=None):
        self._on_leave()
        if not self._enabled or self._command is None:
            return
        # Only fire when the pointer is still over the button (drag-off cancels).
        if ev is not None and not (0 <= ev.x <= self.winfo_width()
                                   and 0 <= ev.y <= self.winfo_height()):
            return
        self._command()

    def set_enabled(self, on: bool) -> None:
        self._enabled = bool(on)
        bg, fg = self._colors()
        self.configure(bg=bg, fg=fg, cursor="hand2" if on else "arrow")

    def set_text(self, text: str) -> None:
        self.configure(text=text)

    def flash(self, text: str, ms: int = 1400) -> None:
        """Briefly swap the label (used for 'Copied' style feedback)."""
        original = self.cget("text")
        self.configure(text=text)
        self.after(ms, lambda: alive(self) and self.configure(text=original))


class Card(tk.Frame):
    """Surface panel with a hairline border -- the `.panel` / `.rc-card` look."""

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=C["border"], bd=0, highlightthickness=0)
        self.body = tk.Frame(self, bg=C["surface"], bd=0, highlightthickness=0)
        self.body.pack(fill="both", expand=True, padx=1, pady=1)
        if kw:
            self.body.configure(**kw)


class StatusDot(tk.Canvas):
    """The `.status` LED: a filled dot with a soft ring."""

    def __init__(self, parent, bg: str, size: int = 10):
        super().__init__(parent, width=size + 6, height=size + 6, bg=bg,
                         highlightthickness=0, bd=0)
        self._size = size
        self.set(C["faint"])

    def set(self, colour: str) -> None:
        self.delete("all")
        s, pad = self._size, 3
        self.create_oval(pad - 2, pad - 2, pad + s + 2, pad + s + 2,
                         fill=mix(colour, self["bg"], 25), outline="")
        self.create_oval(pad, pad, pad + s, pad + s, fill=colour, outline="")


def toast(parent: tk.Misc, message: str, kind: str = "ok", ms: int = 2600) -> None:
    """Transient notice pinned to the bottom of a window (the web `.toast`)."""
    colour = {"ok": C["good"], "bad": C["bad"], "warn": C["warn"]}.get(kind, C["accent"])
    win = tk.Toplevel(parent)
    win.overrideredirect(True)
    win.attributes("-topmost", True)
    frame = tk.Frame(win, bg=C["border_strong"])
    frame.pack(fill="both", expand=True)
    inner = tk.Frame(frame, bg=C["surface2"])
    inner.pack(fill="both", expand=True, padx=1, pady=1)
    tk.Frame(inner, bg=colour, width=3).pack(side="left", fill="y")
    tk.Label(inner, text=message, bg=C["surface2"], fg=C["text"], font=Fonts.ui_sm,
             padx=14, pady=10, justify="left", wraplength=380).pack(side="left")
    try:
        win.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - win.winfo_width()) // 2
        y = parent.winfo_rooty() + parent.winfo_height() - win.winfo_height() - 28
        win.geometry("+%d+%d" % (max(x, 0), max(y, 0)))
    except tk.TclError:
        pass
    win.after(ms, lambda: alive(win) and win.destroy())


def center(win: tk.Misc, width: int, height: int) -> None:
    """Size a window and put it in the middle of the screen."""
    sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
    win.geometry("%dx%d+%d+%d" % (width, height, (sw - width) // 2,
                                  max((sh - height) // 2 - 30, 0)))
