"""File transfer window.

Browses the remote filesystem over the same REST endpoints the dashboard uses
(`/api/devices/{id}/files/...`), which relay to the agent's `file_*` handlers.
Every call is a round trip to a machine that may be busy or far away, so all of
them run through `tasks.run` and the window stays responsive while they do.
"""
from __future__ import annotations

import datetime
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import tasks
import theme
from api import ApiError
from theme import C, Button, Fonts

UPLOAD_LIMIT = 25 * 1024 * 1024        # the server's own cap on a single upload


def human_size(value) -> str:
    if value in (None, ""):
        return ""
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return ""


def human_time(stamp) -> str:
    if not stamp:
        return ""
    try:
        return datetime.datetime.fromtimestamp(float(stamp)).strftime("%Y-%m-%d %H:%M")
    except (ValueError, OSError, OverflowError):
        return ""


class FilesWindow(tk.Toplevel):
    def __init__(self, parent, client, device: dict, on_close=None):
        super().__init__(parent)
        self.client = client
        self.device = device
        self.device_id = device.get("id", "")
        self._on_close = on_close
        self.path = ""
        self.parent_path: str | None = None
        self.entries: list[dict] = []

        hostname = device.get("hostname") or self.device_id
        self.title(f"Files - {hostname}")
        self.configure(bg=C["bg"])
        theme.center(self, 900, 600)
        self.minsize(620, 380)

        self._build()
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.navigate("")

    def _build(self) -> None:
        bar = tk.Frame(self, bg=C["surface"])
        bar.pack(fill="x")
        tk.Label(bar, text=self.device.get("hostname") or self.device_id,
                 bg=C["surface"], fg=C["text"], font=Fonts.h2,
                 padx=16, pady=10).pack(side="left")
        Button(bar, "Refresh", lambda: self.navigate(self.path), kind="ghost").pack(
            side="right", padx=(0, 12), pady=8)
        tk.Frame(self, bg=C["border"], height=1).pack(fill="x")

        nav = tk.Frame(self, bg=C["bg"])
        nav.pack(fill="x", padx=14, pady=(12, 8))
        self.btn_up = Button(nav, "Up", self.go_up)
        self.btn_up.pack(side="left", padx=(0, 8))
        crumb = tk.Frame(nav, bg=C["border"])
        crumb.pack(side="left", fill="x", expand=True)
        self.path_label = tk.Label(crumb, text="This computer", bg=C["surface2"],
                                   fg=C["text"], font=Fonts.mono_sm, anchor="w",
                                   padx=12, pady=8)
        self.path_label.pack(fill="x", padx=1, pady=1)

        table = tk.Frame(self, bg=C["border"])
        table.pack(fill="both", expand=True, padx=14)
        self.tree = ttk.Treeview(table, columns=("size", "modified"), show="tree headings",
                                 selectmode="browse")
        self.tree.heading("#0", text="Name", anchor="w")
        self.tree.heading("size", text="Size", anchor="e")
        self.tree.heading("modified", text="Modified", anchor="e")
        self.tree.column("#0", width=430, anchor="w")
        self.tree.column("size", width=110, anchor="e")
        self.tree.column("modified", width=150, anchor="e")
        self.tree.pack(side="left", fill="both", expand=True, padx=1, pady=1)
        scroll = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        scroll.pack(side="right", fill="y", padx=(0, 1), pady=1)
        self.tree.configure(yscrollcommand=scroll.set)
        # Folders are tinted rather than icon-prefixed: Treeview's `#0` column
        # has no image we can theme, and the agent already sorts folders first.
        self.tree.tag_configure("folder", foreground=C["accent"])
        self.tree.bind("<Double-1>", self._on_open)
        self.tree.bind("<Return>", self._on_open)

        tools = tk.Frame(self, bg=C["bg"])
        tools.pack(fill="x", padx=14, pady=12)
        Button(tools, "Download", self.download).pack(side="left", padx=(0, 6))
        Button(tools, "Upload...", self.upload, kind="accent").pack(side="left", padx=(0, 6))
        Button(tools, "New folder", self.mkdir).pack(side="left", padx=(0, 6))
        Button(tools, "Delete", self.delete, kind="danger").pack(side="left")
        self.status = tk.Label(tools, text="", bg=C["bg"], fg=C["faint"],
                               font=Fonts.ui_sm)
        self.status.pack(side="right")

    # ---------------------------------------------------------- navigation -- #
    def navigate(self, path: str) -> None:
        self._set_status("Loading...")
        tasks.run(self, lambda: self.client.files_list(self.device_id, path),
                  on_ok=lambda res: self._show(path, res), on_error=self._fail)

    def _show(self, path: str, result: dict) -> None:
        if not result.get("ok", True) and result.get("error"):
            self._set_status(str(result["error"]), bad=True)
            return
        self.path = result.get("path", path) or ""
        self.parent_path = result.get("parent")
        self.entries = result.get("entries") or []
        self.path_label.configure(text=self.path or "This computer")
        self.btn_up.set_enabled(bool(self.path))
        self.tree.delete(*self.tree.get_children())
        for index, entry in enumerate(self.entries):
            is_dir = bool(entry.get("is_dir"))
            self.tree.insert("", "end", iid=str(index),
                             text="  " + (entry.get("name") or ""),
                             tags=("folder",) if is_dir else (),
                             values=("" if is_dir else human_size(entry.get("size")),
                                     human_time(entry.get("modified"))))
        count = len(self.entries)
        self._set_status(f"{count} item{'s' if count != 1 else ''}")

    def _selected(self) -> dict | None:
        selection = self.tree.selection()
        if not selection:
            return None
        try:
            return self.entries[int(selection[0])]
        except (ValueError, IndexError):
            return None

    def _on_open(self, _event=None) -> None:
        entry = self._selected()
        if entry is None:
            return
        if entry.get("is_dir"):
            self.navigate(entry.get("path", ""))
        else:
            self.download()

    def go_up(self) -> None:
        if self.parent_path is not None:
            self.navigate(self.parent_path)
        elif self.path:
            self.navigate("")

    # ------------------------------------------------------------ transfer -- #
    def download(self) -> None:
        entry = self._selected()
        if entry is None or entry.get("is_dir"):
            self._set_status("Select a file to download", bad=True)
            return
        name = entry.get("name", "download")
        target = filedialog.asksaveasfilename(parent=self, initialfile=name,
                                              title="Save file as")
        if not target:
            return
        self._set_status(f"Downloading {name}...")

        def work():
            data, _ = self.client.file_download(self.device_id, entry.get("path", ""))
            with open(target, "wb") as fh:
                fh.write(data)
            return len(data)

        tasks.run(self, work,
                  on_ok=lambda n: self._done(f"Saved {name} ({human_size(n)})"),
                  on_error=self._fail)

    def upload(self) -> None:
        if not self.path:
            self._set_status("Open a folder on the device first", bad=True)
            return
        source = filedialog.askopenfilename(parent=self, title="Upload a file")
        if not source:
            return
        try:
            size = os.path.getsize(source)
        except OSError as exc:
            self._set_status(str(exc), bad=True)
            return
        if size > UPLOAD_LIMIT:
            messagebox.showwarning(
                "File too large",
                f"The server accepts uploads up to {human_size(UPLOAD_LIMIT)}. "
                f"This file is {human_size(size)}.", parent=self)
            return
        name = os.path.basename(source)
        self._set_status(f"Uploading {name}...")
        tasks.run(self, lambda: self.client.file_upload(self.device_id, self.path, source),
                  on_ok=lambda _r: self._done(f"Uploaded {name}", refresh=True),
                  on_error=self._fail)

    def mkdir(self) -> None:
        if not self.path:
            self._set_status("Open a folder on the device first", bad=True)
            return
        name = _prompt(self, "New folder", "Folder name")
        if not name:
            return
        separator = "\\" if ("\\" in self.path or self.path[1:2] == ":") else "/"
        target = self.path.rstrip("\\/") + separator + name
        tasks.run(self, lambda: self.client.files_mkdir(self.device_id, target),
                  on_ok=lambda _r: self._done(f"Created {name}", refresh=True),
                  on_error=self._fail)

    def delete(self) -> None:
        entry = self._selected()
        if entry is None:
            return
        name = entry.get("name", "")
        kind = "folder and everything in it" if entry.get("is_dir") else "file"
        if not messagebox.askyesno(
                "Delete", f"Delete the {kind}?\n\n{entry.get('path', name)}\n\n"
                          "This cannot be undone.", parent=self, icon="warning"):
            return
        tasks.run(self, lambda: self.client.files_delete(self.device_id, entry.get("path", "")),
                  on_ok=lambda _r: self._done(f"Deleted {name}", refresh=True),
                  on_error=self._fail)

    # -------------------------------------------------------------- status -- #
    def _done(self, message: str, refresh: bool = False) -> None:
        self._set_status(message)
        theme.toast(self, message)
        if refresh:
            self.navigate(self.path)

    def _fail(self, exc: Exception) -> None:
        message = exc.message if isinstance(exc, ApiError) else str(exc)
        self._set_status(message, bad=True)

    def _set_status(self, message: str, bad: bool = False) -> None:
        self.status.configure(text=message, fg=C["bad"] if bad else C["faint"])

    def close(self) -> None:
        if self._on_close is not None:
            self._on_close(self)
        self.destroy()


def _prompt(parent: tk.Misc, title: str, label: str) -> str:
    """Small themed text prompt (Tk's `simpledialog` ignores our palette)."""
    win = tk.Toplevel(parent)
    win.title(title)
    win.configure(bg=C["surface"])
    win.transient(parent)
    win.resizable(False, False)
    theme.center(win, 380, 160)
    tk.Label(win, text=label, bg=C["surface"], fg=C["dim"],
             font=Fonts.ui_sm).pack(anchor="w", padx=20, pady=(22, 6))
    holder = tk.Frame(win, bg=C["border"])
    holder.pack(fill="x", padx=20)
    entry = tk.Entry(holder, bg=C["surface2"], fg=C["text"], font=Fonts.ui,
                     insertbackground=C["text"], bd=0, highlightthickness=0)
    entry.pack(fill="x", padx=1, pady=1, ipady=7, ipadx=8)
    result = {"value": ""}

    def ok() -> None:
        result["value"] = entry.get().strip()
        win.destroy()

    row = tk.Frame(win, bg=C["surface"])
    row.pack(fill="x", padx=20, pady=18)
    Button(row, "Create", ok, kind="accent").pack(side="right")
    Button(row, "Cancel", win.destroy, kind="ghost").pack(side="right", padx=(0, 8))
    entry.bind("<Return>", lambda _e: ok())
    entry.focus_set()
    win.grab_set()
    parent.wait_window(win)
    return result["value"]
