"""Remote terminal window.

Talks to `/api/devices/{id}/terminal`, the same bridge the dashboard uses. The
agent runs each line through PowerShell on Windows (`/bin/sh` elsewhere) as a
*separate* process, so this is a command runner rather than a live shell: there
is no persistent working directory or environment between lines. The UI says so
once, up front, instead of letting people discover it by `cd`-ing and wondering.
"""
from __future__ import annotations

import tkinter as tk

import theme
import wsbridge
from theme import C, Button, Fonts

MAX_LINES = 5000       # ring the transcript so a chatty command cannot grow forever


class TerminalWindow(tk.Toplevel):
    def __init__(self, parent, client, device: dict, on_close=None):
        super().__init__(parent)
        self.client = client
        self.device = device
        self.device_id = device.get("id", "")
        self._on_close = on_close
        self.session: wsbridge.Session | None = None
        self._history: list[str] = []
        self._history_at = 0
        self._busy = False

        hostname = device.get("hostname") or self.device_id
        self.title(f"Terminal - {hostname}")
        self.configure(bg=C["bg"])
        theme.center(self, 940, 620)
        self.minsize(560, 360)

        self._build()
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.connect()

    def _build(self) -> None:
        bar = tk.Frame(self, bg=C["surface"])
        bar.pack(fill="x")
        tk.Label(bar, text=self.device.get("hostname") or self.device_id,
                 bg=C["surface"], fg=C["text"], font=Fonts.h2,
                 padx=16, pady=10).pack(side="left")
        shell = "PowerShell" if (self.device.get("os") or "").lower().startswith("win") \
            else "Shell"
        tk.Label(bar, text=f"{shell} - each command runs on its own",
                 bg=C["surface"], fg=C["faint"], font=Fonts.ui_sm).pack(side="left")
        self.status = tk.Label(bar, text="Connecting...", bg=C["surface"], fg=C["dim"],
                               font=Fonts.ui_sm, padx=16)
        self.status.pack(side="right")
        Button(bar, "Clear", self.clear, kind="ghost").pack(side="right", pady=8)
        tk.Frame(self, bg=C["border"], height=1).pack(fill="x")

        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=14, pady=(12, 0))
        wrap = tk.Frame(body, bg=C["border"])
        wrap.pack(fill="both", expand=True)
        self.output = tk.Text(wrap, bg=C["term_bg"], fg=C["text"], font=Fonts.mono_sm,
                              insertbackground=C["text"], bd=0, highlightthickness=0,
                              wrap="char", padx=12, pady=10, state="disabled")
        self.output.pack(side="left", fill="both", expand=True, padx=1, pady=1)
        scroll = tk.Scrollbar(wrap, command=self.output.yview, bd=0,
                              highlightthickness=0, troughcolor=C["term_bg"],
                              bg=C["surface3"], activebackground=C["border_strong"])
        scroll.pack(side="right", fill="y", padx=(0, 1), pady=1)
        self.output.configure(yscrollcommand=scroll.set)
        self.output.tag_configure("cmd", foreground=C["accent"])
        self.output.tag_configure("err", foreground=C["bad"])
        self.output.tag_configure("meta", foreground=C["faint"])

        entry_row = tk.Frame(self, bg=C["bg"])
        entry_row.pack(fill="x", padx=14, pady=12)
        prompt = tk.Frame(entry_row, bg=C["border"])
        prompt.pack(side="left", fill="x", expand=True)
        self.entry = tk.Entry(prompt, bg=C["surface2"], fg=C["text"], font=Fonts.mono,
                              insertbackground=C["text"], bd=0, highlightthickness=0)
        self.entry.pack(fill="x", padx=1, pady=1, ipady=8, ipadx=10)
        self.entry.bind("<Return>", lambda _e: self.run())
        self.entry.bind("<Up>", self._history_back)
        self.entry.bind("<Down>", self._history_forward)
        self.btn_run = Button(entry_row, "Run", self.run, kind="accent")
        self.btn_run.pack(side="left", padx=(8, 0))
        self.after(150, self.entry.focus_set)

    # ------------------------------------------------------------ session -- #
    def connect(self) -> None:
        url = self.client.ws_url(f"/api/devices/{self.device_id}/terminal")
        self.session = wsbridge.Session(url, self.client.ws_ssl_context(),
                                        self.client.ws_pin())
        session = self.session
        wsbridge.drain(session, lambda ev: self._on_event(session, ev), self)
        session.start()

    def _on_event(self, session, event) -> None:
        if session is not self.session:
            return
        kind = event[0]
        if kind == "open":
            self.status.configure(text="Connected", fg=C["good"])
            self._write("Connected. Type a command and press Enter.\n\n", "meta")
        elif kind == "json":
            message = event[1]
            if message.get("error"):
                self._write(str(message["error"]) + "\n", "err")
                self._set_busy(False)
                return
            if message.get("type") in (None, "shell_output"):
                self._write(message.get("data", ""))
                code = message.get("code")
                if code not in (None, 0):
                    self._write(f"[exit code {code}]\n", "err")
                self._write("\n")
                self._set_busy(False)
        elif kind == "closed":
            self.status.configure(text="Disconnected", fg=C["bad"])
            self._set_busy(False)
        elif kind == "error":
            self.status.configure(text="Disconnected", fg=C["bad"])
            self._write(str(event[1]) + "\n", "err")
            self._set_busy(False)

    # ---------------------------------------------------------------- run -- #
    def run(self) -> None:
        command = self.entry.get().strip()
        if not command or self._busy or self.session is None:
            return
        self.entry.delete(0, "end")
        if not self._history or self._history[-1] != command:
            self._history.append(command)
        self._history_at = len(self._history)
        self._write(f"> {command}\n", "cmd")
        self._set_busy(True)
        self.session.send_json({"data": command})

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.btn_run.set_text("Running..." if busy else "Run")
        self.btn_run.set_enabled(not busy)

    def _history_back(self, _event) -> str:
        if self._history and self._history_at > 0:
            self._history_at -= 1
            self.entry.delete(0, "end")
            self.entry.insert(0, self._history[self._history_at])
        return "break"

    def _history_forward(self, _event) -> str:
        if self._history_at < len(self._history) - 1:
            self._history_at += 1
            self.entry.delete(0, "end")
            self.entry.insert(0, self._history[self._history_at])
        else:
            self._history_at = len(self._history)
            self.entry.delete(0, "end")
        return "break"

    # -------------------------------------------------------------- output -- #
    def _write(self, text: str, tag: str = "") -> None:
        if not text:
            return
        self.output.configure(state="normal")
        self.output.insert("end", text, tag or ())
        excess = int(self.output.index("end-1c").split(".")[0]) - MAX_LINES
        if excess > 0:
            self.output.delete("1.0", f"{excess}.0")
        self.output.see("end")
        self.output.configure(state="disabled")

    def clear(self) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")

    def close(self) -> None:
        if self.session is not None:
            self.session.close()
            self.session = None
        if self._on_close is not None:
            self._on_close(self)
        self.destroy()
