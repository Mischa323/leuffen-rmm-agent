"""The console's main window: sign-in, then the device browser.

One root window that swaps between two views, plus a session window per action
(remote control, terminal, files). Sessions are tracked so signing out can tear
them all down -- a token that is no longer valid must not leave a live screen
sharing session open behind it.
"""
from __future__ import annotations

import time
import tkinter as tk
from tkinter import messagebox, ttk

import api
import config
import files_view
import login_view
import remote_view
import tasks
import terminal_view
import theme
import updater
from api import ApiError
from theme import C, Button, Fonts
from version import CONSOLE_VERSION

REFRESH_SECONDS = 30
POWER_ACTIONS = [("Lock", "lock"), ("Restart", "restart"),
                 ("Shut down", "shutdown"), ("Wake on LAN", "wake")]


def relative_time(stamp) -> str:
    if not stamp:
        return "never"
    delta = time.time() - float(stamp)
    if delta < 60:
        return "just now"
    if delta < 3600:
        return f"{int(delta // 60)} min ago"
    if delta < 86400:
        return f"{int(delta // 3600)} h ago"
    return f"{int(delta // 86400)} d ago"


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.settings = config.load()
        self.withdraw()
        theme.apply(self, self.settings.get("theme", "dark"),
                    self.settings.get("accent", "#3b82f6"))
        self.title("Leuffen RMM Console")
        self.configure(bg=C["bg"])
        theme.center(self, 1180, 740)
        self.minsize(820, 520)
        try:
            self.iconbitmap(default=_icon_path())
        except tk.TclError:
            pass

        self.client: api.ApiClient | None = None
        self.view: tk.Frame | None = None
        self.sessions: list[tk.Toplevel] = []
        self.update_bar: tk.Frame | None = None
        self._update_version = ""
        self._update_job = None
        self._pending_device = ""          # a deep link waiting for sign-in
        self.protocol("WM_DELETE_WINDOW", self.quit_app)
        self.deiconify()

    # ------------------------------------------------------------ updates -- #
    def start_update_checks(self) -> None:
        """Ask the server whether a newer console has been published.

        Only ever *offers* the update. Installing replaces files under Program
        Files, which needs elevation, and a background app cannot elevate
        without asking -- so the honest shape is a banner and one click, not a
        silent swap that would fail with a permission error nobody sees.
        """
        if self._update_job is not None:
            self.after_cancel(self._update_job)
            self._update_job = None
        if self.client is None or not updater.running_installed():
            return          # a source checkout has no MSI to replace
        tasks.run(self, lambda: updater.check(self.client),
                  on_ok=self._offer_update, on_error=lambda _e: None)
        self._update_job = self.after(updater.CHECK_INTERVAL_MS, self.start_update_checks)

    def _offer_update(self, version: str) -> None:
        if not version or version == self._update_version:
            return
        self._update_version = version
        self._show_update_bar(f"Version {version} of the console is available.")

    def _show_update_bar(self, message: str, busy: bool = False) -> None:
        if self.update_bar is not None:
            self.update_bar.destroy()
        bar = tk.Frame(self, bg=theme.mix(C["accent"], C["surface"], 18))
        bar.pack(fill="x", side="top", before=self.view if self.view else None)
        self.update_bar = bar
        tk.Label(bar, text=message, bg=bar["bg"], fg=C["text"], font=Fonts.ui_sm,
                 padx=16, pady=9).pack(side="left")
        if not busy:
            Button(bar, "Dismiss", self._hide_update_bar, kind="ghost").pack(
                side="right", padx=(0, 12), pady=6)
            Button(bar, "Update now", self._run_update, kind="accent").pack(
                side="right", padx=(0, 8), pady=6)

    def _hide_update_bar(self) -> None:
        if self.update_bar is not None:
            self.update_bar.destroy()
            self.update_bar = None

    def _run_update(self) -> None:
        if self.client is None:
            return
        if self.sessions and not messagebox.askyesno(
                "Update the console",
                f"{len(self.sessions)} session(s) are open. Updating closes the "
                "console and installs the new version. Continue?", parent=self):
            return
        self._show_update_bar("Downloading the update\u2026", busy=True)

        def progress(done: int, total: int) -> None:
            if total:
                self.after(0, lambda: self._update_progress(done, total))

        tasks.run(self, lambda: updater.download(self.client, progress),
                  on_ok=self._install_update, on_error=self._update_failed)

    def _update_progress(self, done: int, total: int) -> None:
        if self.update_bar is None:
            return
        label = self.update_bar.winfo_children()[0]
        label.configure(text=f"Downloading the update\u2026 {done * 100 // max(total, 1)}%")

    def _install_update(self, msi_path: str) -> None:
        try:
            updater.install(msi_path)
        except Exception as exc:  # noqa: BLE001 -- surfaced to the user below
            self._update_failed(exc)
            return
        # The installer is about to replace the files this process is running
        # from, so get out of its way. Windows asks for permission first.
        self._show_update_bar("Installing\u2026 the console will close.", busy=True)
        self.after(1200, self.destroy)

    def _update_failed(self, exc: Exception) -> None:
        message = exc.message if isinstance(exc, ApiError) else str(exc)
        self._show_update_bar(f"The update could not be installed: {message}")

    # -------------------------------------------------------------- views -- #
    def _swap(self, view: tk.Frame) -> None:
        if self.view is not None:
            self.view.destroy()
        self.view = view
        view.pack(fill="both", expand=True)
        if self.update_bar is not None:      # keep the banner above the view
            self.update_bar.pack_configure(before=view)

    def show_login(self, message: str = "") -> None:
        view = login_view.LoginView(self, self)
        self._swap(view)
        if message:
            view.say(message)

    def show_devices(self) -> None:
        self._swap(DevicesView(self, self))

    def start(self) -> None:
        """Resume a stored session if there is one, else ask for credentials."""
        token = config.load_token()
        server = self.settings.get("server_url", "")
        if token and server:
            client = api.ApiClient(server, token,
                                   self.settings.get("insecure_tls", False),
                                   self.settings.get("fingerprint", ""))
            self.show_devices_when_valid(client)
        else:
            self.show_login()

    def show_devices_when_valid(self, client: api.ApiClient) -> None:
        """Verify a stored token before showing anything -- otherwise the device
        list would just fill with authentication errors."""
        splash = tk.Frame(self, bg=C["bg"])
        tk.Label(splash, text="Signing in...", bg=C["bg"], fg=C["dim"],
                 font=Fonts.h2).place(relx=0.5, rely=0.5, anchor="center")
        self._swap(splash)

        def ok(_me) -> None:
            self.signed_in(client)

        def failed(exc: Exception) -> None:
            if isinstance(exc, ApiError) and exc.is_auth:
                config.clear_token()
                self.show_login("Your session has expired. Sign in again.")
            else:
                message = exc.message if isinstance(exc, ApiError) else str(exc)
                self.show_login(message)

        tasks.run(self, client.me, on_ok=ok, on_error=failed)

    def signed_in(self, client: api.ApiClient) -> None:
        self.client = client
        self.show_devices()
        self.after(5000, self.start_update_checks)
        if self._pending_device:
            device_id, self._pending_device = self._pending_device, ""
            self.open_device(device_id, "remote")

    def sign_out(self) -> None:
        for window in list(self.sessions):
            try:
                window.destroy()
            except tk.TclError:
                pass
        self.sessions.clear()
        config.clear_token()
        self.client = None
        self._hide_update_bar()
        if self._update_job is not None:
            self.after_cancel(self._update_job)
            self._update_job = None
        self.show_login()

    def quit_app(self) -> None:
        if self.sessions and not messagebox.askyesno(
                "Quit", f"{len(self.sessions)} session(s) are still open. Close them "
                        "and quit?", parent=self):
            return
        config.save(self.settings)
        self.destroy()

    # --------------------------------------------------------- deep links -- #
    def handle_link(self, params: dict) -> None:
        """Act on a `leuffenrmm://connect?...` URL (see `main.py`).

        Called both at start-up and, for an already-running console, when a
        second launch forwards its URL over the single-instance socket."""
        device_id = params.get("device", "")
        ticket = params.get("ticket", "")
        server = config.normalise_url(params.get("server", ""))

        if ticket and server:
            insecure = params.get("insecure") == "1" or self.settings.get("insecure_tls", False)
            fingerprint = self.settings.get("fingerprint", "") \
                if server == self.settings.get("server_url") else ""
            client = api.ApiClient(server, insecure_tls=insecure, fingerprint=fingerprint)
            self._pending_device = device_id

            def ok(_res) -> None:
                self.settings.update(server_url=client.server_url, email=client.email,
                                     insecure_tls=client.insecure_tls,
                                     fingerprint=client.fingerprint)
                config.save(self.settings)
                config.save_token(client.token)
                self.signed_in(client)

            def failed(exc: Exception) -> None:
                message = exc.message if isinstance(exc, ApiError) else str(exc)
                self.show_login(message)

            tasks.run(self, lambda: client.redeem_ticket(ticket), on_ok=ok, on_error=failed)
            return

        if device_id:
            if self.client is not None:
                self.open_device(device_id, "remote")
            else:
                self._pending_device = device_id
        self.lift()
        self.focus_force()

    # ------------------------------------------------------------ sessions -- #
    def open_device(self, device_id: str, action: str = "remote") -> None:
        """Open a session window for a device id, fetching its details first."""
        if self.client is None:
            return
        tasks.run(self, lambda: self.client.device(device_id),
                  on_ok=lambda device: self.open_session(device, action),
                  on_error=lambda exc: messagebox.showerror(
                      "Could not open the device",
                      exc.message if isinstance(exc, ApiError) else str(exc), parent=self))

    def open_session(self, device: dict, action: str) -> None:
        if self.client is None or not device:
            return
        if not device.get("online", True):
            messagebox.showinfo("Device offline",
                                f"{device.get('hostname') or 'This device'} is offline.",
                                parent=self)
            return
        factory = {"remote": lambda: remote_view.RemoteWindow(
            self, self.client, device, self.settings, on_close=self._session_closed),
            "terminal": lambda: terminal_view.TerminalWindow(
                self, self.client, device, on_close=self._session_closed),
            "files": lambda: files_view.FilesWindow(
                self, self.client, device, on_close=self._session_closed)}.get(action)
        if factory is None:
            return
        window = factory()
        self.sessions.append(window)

    def _session_closed(self, window: tk.Toplevel) -> None:
        if window in self.sessions:
            self.sessions.remove(window)


class DevicesView(tk.Frame):
    """Org picker + searchable device table + the per-device actions."""

    def __init__(self, parent, app: App):
        super().__init__(parent, bg=C["bg"])
        self.app = app
        self.client = app.client
        self.orgs: list[dict] = []
        self.devices: list[dict] = []
        self.shown: list[dict] = []
        self.org_id = ""
        self._refresh_job = None
        self._build()
        self.load_orgs()

    # ------------------------------------------------------------------ UI -- #
    def _build(self) -> None:
        bar = tk.Frame(self, bg=C["surface"])
        bar.pack(fill="x")
        tk.Label(bar, text="Leuffen RMM", bg=C["surface"], fg=C["text"],
                 font=Fonts.h2, padx=16, pady=12).pack(side="left")

        self.org_var = tk.StringVar()
        self.org_combo = ttk.Combobox(bar, textvariable=self.org_var, state="readonly",
                                      width=28, values=[])
        self.org_combo.pack(side="left", padx=(6, 0), pady=12)
        self.org_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_org())

        holder = tk.Frame(bar, bg=C["border"])
        holder.pack(side="left", padx=12, pady=12)
        self.search = tk.Entry(holder, bg=C["surface2"], fg=C["text"], font=Fonts.ui_sm,
                               insertbackground=C["text"], bd=0, highlightthickness=0,
                               width=26)
        self.search.pack(padx=1, pady=1, ipady=6, ipadx=8)
        self.search.bind("<KeyRelease>", lambda _e: self._apply_filter())

        Button(bar, "Sign out", self.app.sign_out, kind="ghost").pack(
            side="right", padx=(0, 14), pady=10)
        tk.Label(bar, text=(self.client.email if self.client else ""), bg=C["surface"],
                 fg=C["dim"], font=Fonts.ui_sm).pack(side="right", padx=(0, 6))
        Button(bar, "Refresh", self.load_devices, kind="ghost").pack(side="right", pady=10)
        tk.Frame(self, bg=C["border"], height=1).pack(fill="x")

        table = tk.Frame(self, bg=C["border"])
        table.pack(fill="both", expand=True, padx=16, pady=(14, 0))
        columns = ("os", "ip", "status", "cpu", "seen")
        self.tree = ttk.Treeview(table, columns=columns, show="tree headings",
                                 selectmode="browse")
        self.tree.heading("#0", text="Device", anchor="w")
        for key, title, width, anchor in (("os", "OS", 190, "w"), ("ip", "Address", 140, "w"),
                                          ("status", "Status", 100, "w"),
                                          ("cpu", "CPU", 80, "e"),
                                          ("seen", "Last seen", 120, "e")):
            self.tree.heading(key, text=title, anchor=anchor)
            self.tree.column(key, width=width, anchor=anchor)
        self.tree.column("#0", width=280, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True, padx=1, pady=1)
        scroll = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        scroll.pack(side="right", fill="y", padx=(0, 1), pady=1)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.tag_configure("offline", foreground=C["faint"])
        self.tree.bind("<Double-1>", lambda _e: self.open("remote"))
        self.tree.bind("<Return>", lambda _e: self.open("remote"))
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._sync_buttons())

        tools = tk.Frame(self, bg=C["bg"])
        tools.pack(fill="x", padx=16, pady=14)
        self.btn_remote = Button(tools, "Remote control", lambda: self.open("remote"),
                                 kind="accent")
        self.btn_remote.pack(side="left", padx=(0, 6))
        self.btn_terminal = Button(tools, "Terminal", lambda: self.open("terminal"))
        self.btn_terminal.pack(side="left", padx=(0, 6))
        self.btn_files = Button(tools, "Files", lambda: self.open("files"))
        self.btn_files.pack(side="left", padx=(0, 6))
        self.btn_power = Button(tools, "Power", self._power_menu)
        self.btn_power.pack(side="left")
        self.status = tk.Label(tools, text="Loading...", bg=C["bg"], fg=C["faint"],
                               font=Fonts.ui_sm)
        self.status.pack(side="right")
        self._sync_buttons()

    # ---------------------------------------------------------------- data -- #
    def load_orgs(self) -> None:
        tasks.run(self, self.client.orgs, on_ok=self._got_orgs, on_error=self._fail)

    def _got_orgs(self, orgs: list) -> None:
        self.orgs = [o for o in orgs if o.get("id")]
        self.org_combo.configure(values=[o.get("name", o["id"]) for o in self.orgs])
        if not self.orgs:
            self._set_status("No organisations are shared with this account.")
            return
        self.org_id = self.orgs[0]["id"]
        self.org_var.set(self.orgs[0].get("name", self.org_id))
        self.load_devices()

    def _on_org(self) -> None:
        name = self.org_var.get()
        for org in self.orgs:
            if org.get("name", org["id"]) == name:
                self.org_id = org["id"]
                break
        self.load_devices()

    def load_devices(self) -> None:
        if not self.org_id:
            return
        org_id = self.org_id
        tasks.run(self, lambda: self.client.devices(org_id),
                  on_ok=lambda rows: self._got_devices(org_id, rows), on_error=self._fail)

    def _got_devices(self, org_id: str, rows: list) -> None:
        if org_id != self.org_id:
            return                                  # the user switched org mid-flight
        self.devices = rows or []
        self._apply_filter()
        online = sum(1 for d in self.devices if d.get("online"))
        self._set_status(f"{online} of {len(self.devices)} online")
        self._schedule_refresh()

    def _schedule_refresh(self) -> None:
        if self._refresh_job is not None:
            self.after_cancel(self._refresh_job)
        self._refresh_job = self.after(REFRESH_SECONDS * 1000, self.load_devices)

    def _apply_filter(self) -> None:
        needle = self.search.get().strip().lower()
        self.shown = [d for d in self.devices
                      if not needle or needle in " ".join(
                          str(d.get(k, "")) for k in ("hostname", "os", "ip",
                                                      "logged_in_user")).lower()]
        selected = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        for index, device in enumerate(self.shown):
            online = bool(device.get("online"))
            latest = device.get("latest") or {}
            cpu = latest.get("cpu_percent")
            self.tree.insert(
                "", "end", iid=str(index), text="  " + (device.get("hostname") or device.get("id", "")),
                tags=() if online else ("offline",),
                values=(device.get("os") or "", device.get("ip") or "",
                        "Online" if online else "Offline",
                        f"{cpu:.0f}%" if isinstance(cpu, (int, float)) else "",
                        relative_time(device.get("last_seen"))))
        if selected and selected[0] in self.tree.get_children():
            self.tree.selection_set(selected[0])
        self._sync_buttons()

    # ------------------------------------------------------------- actions -- #
    def selected(self) -> dict | None:
        selection = self.tree.selection()
        if not selection:
            return None
        try:
            return self.shown[int(selection[0])]
        except (ValueError, IndexError):
            return None

    def _sync_buttons(self) -> None:
        device = self.selected()
        online = bool(device and device.get("online"))
        for button in (self.btn_remote, self.btn_terminal, self.btn_power):
            button.set_enabled(online)
        self.btn_files.set_enabled(online)

    def open(self, action: str) -> None:
        device = self.selected()
        if device is not None:
            self.app.open_session(device, action)

    def _power_menu(self) -> None:
        device = self.selected()
        if device is None:
            return
        menu = tk.Menu(self, tearoff=0, bg=C["surface2"], fg=C["text"],
                       activebackground=C["accent"], activeforeground="#ffffff",
                       bd=0, font=Fonts.ui_sm)
        for label, action in POWER_ACTIONS:
            menu.add_command(label=label,
                             command=lambda a=action, d=device: self._power(d, a))
        try:
            menu.tk_popup(self.btn_power.winfo_rootx(),
                          self.btn_power.winfo_rooty() + self.btn_power.winfo_height())
        finally:
            menu.grab_release()

    def _power(self, device: dict, action: str) -> None:
        name = device.get("hostname") or device.get("id", "")
        if action in ("restart", "shutdown") and not messagebox.askyesno(
                action.capitalize(), f"{action.capitalize()} {name}?", parent=self,
                icon="warning"):
            return
        self._set_status(f"Sending {action} to {name}...")
        tasks.run(self, lambda: self.client.power(device.get("id", ""), action),
                  on_ok=lambda _r: self._set_status(f"{action.capitalize()} sent to {name}"),
                  on_error=self._fail)

    # -------------------------------------------------------------- status -- #
    def _set_status(self, message: str, bad: bool = False) -> None:
        self.status.configure(text=message, fg=C["bad"] if bad else C["faint"])

    def _fail(self, exc: Exception) -> None:
        if isinstance(exc, ApiError) and exc.is_auth:
            config.clear_token()
            self.app.show_login("Your session has expired. Sign in again.")
            return
        self._set_status(exc.message if isinstance(exc, ApiError) else str(exc), bad=True)
        self._schedule_refresh()


def _icon_path() -> str:
    import os
    import sys
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "leuffen.ico")


def about_text() -> str:
    return f"Leuffen RMM Console {CONSOLE_VERSION}"
