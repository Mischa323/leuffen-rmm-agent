"""Sign-in screen.

Two routes in, matching the server's `/api/auth/app-token`:

  * **Password (+ authenticator code)** for local accounts, typed here.
  * **A hand-off from the dashboard** for Microsoft 365 SSO -- the browser has
    already authenticated the person, so it mints a single-use ticket and the
    `leuffenrmm://` deep link brings it here. Nothing to type, and no password
    ever reaches this app.

Self-signed servers (the bundled setup) are handled in one tick: trusting the
certificate also **pins** it, so the connection stays MITM-proof afterwards --
the same trade-off the agent makes with `RMM_SERVER_FINGERPRINT`.
"""
from __future__ import annotations

import tkinter as tk

import api
import config
import tasks
import theme
from api import ApiError, MfaRequired
from theme import C, Button, Fonts


class LoginView(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C["bg"])
        self.app = app
        self._fingerprint = ""
        self._mfa_visible = False
        self._build()

    # ------------------------------------------------------------------ UI -- #
    def _build(self) -> None:
        shell = tk.Frame(self, bg=C["bg"])
        shell.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(shell, text="Leuffen RMM", bg=C["bg"], fg=C["text"],
                 font=Fonts.h1).pack(anchor="w")
        tk.Label(shell, text="Desktop console", bg=C["bg"], fg=C["dim"],
                 font=Fonts.ui_sm).pack(anchor="w", pady=(2, 18))

        card = theme.Card(shell)
        card.pack(fill="x")
        body = tk.Frame(card.body, bg=C["surface"])
        body.pack(fill="both", expand=True, padx=26, pady=24)
        body.configure(width=420)

        self.server = self._field(body, "Server address (e.g. rmm.example.com)")
        self.username = self._field(body, "Username or email")
        self.password = self._field(body, "Password", show="*")
        self.code = self._field(body, "Authenticator code")
        self.code_row.pack_forget()          # revealed only when the server asks

        self.trust_var = tk.BooleanVar(value=False)
        trust = tk.Checkbutton(
            body, text="Trust this server's certificate (self-signed)",
            variable=self.trust_var, command=self._on_trust_toggle,
            bg=C["surface"], fg=C["dim"], font=Fonts.ui_sm,
            activebackground=C["surface"], activeforeground=C["text"],
            selectcolor=C["surface2"], bd=0, highlightthickness=0,
            anchor="w", cursor="hand2")
        trust.pack(fill="x", pady=(4, 0))
        self.fingerprint_label = tk.Label(body, text="", bg=C["surface"], fg=C["faint"],
                                          font=Fonts.mono_sm, anchor="w",
                                          justify="left", wraplength=380)

        self.message = tk.Label(body, text="", bg=C["surface"], fg=C["bad"],
                                font=Fonts.ui_sm, anchor="w", justify="left",
                                wraplength=380)
        self.message.pack(fill="x", pady=(10, 0))

        self.submit = Button(body, "Sign in", self.sign_in, kind="accent",
                             pady=9, font=Fonts.ui)
        self.submit.pack(fill="x", pady=(14, 0))

        tk.Label(body, text="Using Microsoft 365? Sign in to the dashboard and choose "
                            "Remote control -> Open in desktop app.",
                 bg=C["surface"], fg=C["faint"], font=Fonts.ui_sm, anchor="w",
                 justify="left", wraplength=380).pack(fill="x", pady=(14, 0))

        for entry in (self.server, self.username, self.password, self.code):
            entry.bind("<Return>", lambda _e: self.sign_in())

        stored = self.app.settings
        self.server.insert(0, stored.get("server_url", ""))
        self.username.insert(0, stored.get("email", ""))
        if stored.get("insecure_tls") or stored.get("fingerprint"):
            self.trust_var.set(True)
            self._fingerprint = stored.get("fingerprint", "")
            self._show_fingerprint()
        self.after(150, (self.username if stored.get("server_url") else self.server).focus_set)

    def _field(self, parent, label: str, show: str = "") -> tk.Entry:
        row = tk.Frame(parent, bg=C["surface"])
        row.pack(fill="x", pady=(0, 12))
        tk.Label(row, text=label, bg=C["surface"], fg=C["faint"], font=Fonts.ui_sm,
                 anchor="w").pack(fill="x", pady=(0, 5))
        holder = tk.Frame(row, bg=C["border"])
        holder.pack(fill="x")
        entry = tk.Entry(holder, bg=C["surface2"], fg=C["text"], font=Fonts.ui,
                         insertbackground=C["text"], bd=0, highlightthickness=0,
                         show=show)
        entry.pack(fill="x", padx=1, pady=1, ipady=8, ipadx=9)
        if label.startswith("Authenticator"):
            self.code_row = row
        return entry

    # ------------------------------------------------------------- actions -- #
    def _on_trust_toggle(self) -> None:
        if self.trust_var.get():
            self._fetch_fingerprint()
        else:
            self._fingerprint = ""
            self.fingerprint_label.pack_forget()

    def _fetch_fingerprint(self) -> None:
        url = config.normalise_url(self.server.get())
        if not url.startswith("https"):
            return
        self.fingerprint_label.configure(text="Reading the server certificate...")
        self.fingerprint_label.pack(fill="x", pady=(6, 0))
        tasks.run(self, lambda: api.peek_fingerprint(url),
                  on_ok=self._got_fingerprint,
                  on_error=lambda exc: self.fingerprint_label.configure(
                      text=f"Could not read the certificate: {exc}"))

    def _got_fingerprint(self, digest: str) -> None:
        self._fingerprint = digest
        self._show_fingerprint()

    def _show_fingerprint(self) -> None:
        if not self._fingerprint:
            return
        self.fingerprint_label.configure(
            text="Pinned certificate SHA-256\n" + api.pretty_fingerprint(self._fingerprint))
        self.fingerprint_label.pack(fill="x", pady=(6, 0))

    def say(self, message: str, bad: bool = True) -> None:
        self.message.configure(text=message, fg=C["bad"] if bad else C["dim"])

    def _busy(self, busy: bool) -> None:
        self.submit.set_text("Signing in..." if busy else "Sign in")
        self.submit.set_enabled(not busy)

    def sign_in(self) -> None:
        server = config.normalise_url(self.server.get())
        username = self.username.get().strip()
        password = self.password.get()
        code = self.code.get().strip() if self._mfa_visible else ""
        if not server:
            self.say("Enter the server address.")
            return
        trust = self.trust_var.get()
        client = api.ApiClient(server, insecure_tls=trust,
                               fingerprint=self._fingerprint if trust else "")
        self.say("", bad=False)
        self._busy(True)
        tasks.run(self, lambda: client.sign_in(username, password, code),
                  on_ok=lambda res: self._ok(client, res),
                  on_error=lambda exc: self._failed(client, exc))

    def _ok(self, client, _result) -> None:
        self._busy(False)
        settings = self.app.settings
        settings["server_url"] = client.server_url
        settings["email"] = client.email
        settings["insecure_tls"] = client.insecure_tls
        settings["fingerprint"] = client.fingerprint
        config.save(settings)
        config.save_token(client.token)
        self.app.signed_in(client)

    def _failed(self, client, exc: Exception) -> None:
        self._busy(False)
        if isinstance(exc, MfaRequired):
            if not self._mfa_visible:
                self._mfa_visible = True
                self.code_row.pack(fill="x", pady=(0, 12))
            self.code.focus_set()
            self.say("Enter the code from your authenticator app.", bad=False)
            return
        message = exc.message if isinstance(exc, ApiError) else str(exc)
        self.say(message)
        # A certificate failure is the one error with an obvious next step -- show
        # the fingerprint so it can be confirmed and pinned.
        if "certificate" in message.lower() and not self.trust_var.get():
            self.trust_var.set(True)
            self._fetch_fingerprint()
