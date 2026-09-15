"""Remote desktop window.

The native counterpart of `static/remote.js`: it speaks the exact same protocol
to the exact same server endpoint (`/api/devices/{id}/screen`), so both viewers
stay interchangeable and the agent needs no idea which one is driving it.

What the desktop build adds over the browser:

  * real keyboard capture -- Alt+Tab, Win, Ctrl+W and friends go to the *remote*
    machine instead of being swallowed by the browser or the tab strip;
  * no browser clipboard permission prompt;
  * frame pacing: only the newest frame is painted, so a slow link or a busy
    UI thread can never build up a backlog of stale screens.
"""
from __future__ import annotations

import time
import tkinter as tk
from tkinter import ttk

import tasks
import theme
import video
import wsbridge
from theme import C, Button, Fonts

# Speed presets, identical to the web viewer's (the agent clamps fps <= 24,
# quality <= 90, max_edge <= 4096).
PRESETS = {
    "balanced": {"fps": 20, "quality": 72, "max_edge": 2400},
    "sharp": {"fps": 15, "quality": 88, "max_edge": 2880},
    "smooth": {"fps": 24, "quality": 60, "max_edge": 1920},
}
PRESET_LABELS = {
    "balanced": "Balanced - crisp & smooth",
    "sharp": "Sharp - full resolution",
    "smooth": "Smooth - highest frame rate",
}

MAX_RECONNECT = 8
MOVE_INTERVAL = 0.016          # ~60 pointer updates/second is plenty
CLIP_PULL_DELAY_MS = 180       # let the remote finish copying before we read it

# Tk keysym -> the agent's key names (`pynput` vocabulary, see screen.py).
KEYMAP = {
    "Return": "enter", "KP_Enter": "enter", "BackSpace": "backspace",
    "Tab": "tab", "Escape": "esc", "Delete": "delete", "Insert": "insert",
    "Up": "up", "Down": "down", "Left": "left", "Right": "right",
    "Home": "home", "End": "end", "Prior": "page_up", "Next": "page_down",
    "space": "space",
    **{f"F{n}": f"f{n}" for n in range(1, 13)},
}
MODIFIER_KEYSYMS = {
    "Control_L": "ctrl", "Control_R": "ctrl",
    "Alt_L": "alt", "Alt_R": "alt",
    "Shift_L": "shift", "Shift_R": "shift",
    "Super_L": "cmd", "Super_R": "cmd", "Win_L": "cmd", "Win_R": "cmd",
}


class RemoteWindow(tk.Toplevel):
    """One remote-control session. Independent window, independent socket."""

    def __init__(self, parent, client, device: dict, settings: dict, on_close=None):
        super().__init__(parent)
        self.client = client
        self.device = device
        self.device_id = device.get("id", "")
        self.settings = settings
        self._on_close = on_close

        hostname = device.get("hostname") or self.device_id
        self.title(f"{hostname} - Leuffen RMM")
        self.configure(bg=C["bg"])
        theme.center(self, 1280, 820)
        self.minsize(720, 480)

        # --- stream state ---
        self.session: wsbridge.Session | None = None
        self.decoder = None                 # video.H264Decoder once negotiated
        self._next_jpeg: bytes | None = None
        self._next_image = None             # newest decoded frame awaiting paint
        self._photo = None
        self._canvas_item = None
        self.native_w = 0
        self.native_h = 0
        self._draw_scale = 1.0
        self._offset = (0, 0)

        # --- input state ---
        self._modifiers: set[str] = set()
        self._dragging = False
        self._last_move = 0.0

        # --- session bookkeeping ---
        self._frames = 0
        self._bytes = 0
        self._user_closed = False
        self._attempts = 0
        self._reconnect_job = None
        self._started_at = ""
        self.quality = settings.get("quality", "balanced")
        self.fit = settings.get("remote_scaling", "fit") != "actual"

        self._build()
        self.protocol("WM_DELETE_WINDOW", self.disconnect)
        self.bind("<F11>", lambda _e: self.toggle_fullscreen())
        self.bind("<Control-Alt-Shift-Escape>", lambda _e: self.disconnect())
        self.after(1000, self._tick_stats)
        self.after(16, self._tick_paint)
        self.connect()

    # ------------------------------------------------------------------ UI -- #
    def _build(self) -> None:
        bar = tk.Frame(self, bg=C["surface"], height=54)
        bar.pack(fill="x", side="top")
        tk.Frame(self, bg=C["border"], height=1).pack(fill="x", side="top")

        left = tk.Frame(bar, bg=C["surface"])
        left.pack(side="left", padx=(16, 0), pady=9)
        tk.Label(left, text=self.device.get("hostname") or self.device_id,
                 bg=C["surface"], fg=C["text"], font=Fonts.h2,
                 anchor="w").pack(anchor="w")
        subtitle = " - ".join(x for x in (self.device.get("os"), self.device.get("ip")) if x)
        tk.Label(left, text=subtitle or "-", bg=C["surface"], fg=C["faint"],
                 font=Fonts.mono_sm, anchor="w").pack(anchor="w")

        # Connection pill
        pill = tk.Frame(bar, bg=C["surface2"])
        pill.pack(side="left", padx=18)
        self.dot = theme.StatusDot(pill, bg=C["surface2"])
        self.dot.pack(side="left", padx=(9, 4), pady=6)
        self.conn_label = tk.Label(pill, text="Connecting...", bg=C["surface2"],
                                   fg=C["dim"], font=Fonts.ui_sm)
        self.conn_label.pack(side="left", padx=(0, 12), pady=6)

        self.stats_label = tk.Label(bar, text="-", bg=C["surface"], fg=C["faint"],
                                    font=Fonts.mono_sm)
        self.stats_label.pack(side="left")

        Button(bar, "Disconnect", self.disconnect, kind="danger").pack(
            side="right", padx=(8, 16), pady=11)
        Button(bar, "Fullscreen", self.toggle_fullscreen, kind="ghost").pack(
            side="right", pady=11)

        # --- screen ---
        stage = tk.Frame(self, bg=C["bg"])
        stage.pack(fill="both", expand=True, padx=14, pady=(12, 0))
        self.viewport = tk.Frame(stage, bg=C["border_strong"])
        self.viewport.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(self.viewport, bg=C["screen_bg"], highlightthickness=0,
                                bd=0, cursor="arrow")
        self.canvas.pack(fill="both", expand=True, padx=1, pady=1)

        self.overlay = tk.Label(self.canvas, text="Connecting...", bg=C["screen_bg"],
                                fg=C["dim"], font=Fonts.h2)
        self.overlay.place(relx=0.5, rely=0.5, anchor="center")
        self.overlay_sub = tk.Label(self.canvas, text="Negotiating an encrypted session",
                                    bg=C["screen_bg"], fg=C["faint"], font=Fonts.ui_sm)
        self.overlay_sub.place(relx=0.5, rely=0.5, anchor="n", y=18)

        self._bind_input()

        # --- toolbar ---
        tools = tk.Frame(self, bg=C["bg"])
        tools.pack(fill="x", padx=14, pady=12)
        self.btn_size = Button(tools, "Actual size", self.toggle_scaling)
        self.btn_size.pack(side="left")
        tk.Frame(tools, bg=C["border"], width=1, height=24).pack(side="left", padx=9, pady=4)
        self.btn_copy = Button(tools, "Copy from remote", self.copy_from_remote)
        self.btn_copy.pack(side="left", padx=(0, 6))
        self.btn_paste = Button(tools, "Paste to remote", self.paste_to_remote)
        self.btn_paste.pack(side="left", padx=(0, 6))
        Button(tools, "Ctrl+Alt+Del", self.send_cad).pack(side="left", padx=(0, 6))
        self.btn_lock = Button(tools, "Lock", self.lock_device)
        self.btn_lock.pack(side="left")
        tk.Frame(tools, bg=C["border"], width=1, height=24).pack(side="left", padx=9, pady=4)
        Button(tools, "Reconnect", self.reconnect_now).pack(side="left")

        tk.Label(tools, text="Quality", bg=C["bg"], fg=C["faint"],
                 font=Fonts.ui_sm).pack(side="right", padx=(0, 8))
        self.quality_var = tk.StringVar(value=PRESET_LABELS.get(self.quality, ""))
        combo = ttk.Combobox(tools, textvariable=self.quality_var, state="readonly",
                             width=26, values=list(PRESET_LABELS.values()))
        combo.pack(side="right")
        combo.bind("<<ComboboxSelected>>", self._on_quality)

        status = tk.Frame(self, bg=C["surface"])
        status.pack(fill="x", side="bottom")
        self.status_label = tk.Label(status, text="", bg=C["surface"], fg=C["faint"],
                                     font=Fonts.ui_sm, anchor="w", padx=16, pady=6)
        self.status_label.pack(side="left")
        self.proto_label = tk.Label(status, text="TLS - JPEG", bg=C["surface"],
                                    fg=C["faint"], font=Fonts.mono_sm, padx=16)
        self.proto_label.pack(side="right")

    def _bind_input(self) -> None:
        cv = self.canvas
        cv.bind("<Motion>", self._on_motion)
        cv.bind("<ButtonPress-1>", lambda e: self._on_button(e, "left", True))
        cv.bind("<ButtonPress-2>", lambda e: self._on_button(e, "middle", True))
        cv.bind("<ButtonPress-3>", lambda e: self._on_button(e, "right", True))
        # Release binds on the window: a drag that ends off-canvas must still
        # deliver the button-up, or the remote keeps dragging.
        self.bind("<ButtonRelease-1>", lambda e: self._on_button(e, "left", False))
        self.bind("<ButtonRelease-2>", lambda e: self._on_button(e, "middle", False))
        self.bind("<ButtonRelease-3>", lambda e: self._on_button(e, "right", False))
        cv.bind("<MouseWheel>", self._on_wheel)
        cv.bind("<Button-4>", lambda e: self._send({"kind": "scroll", "dy": 1}))
        cv.bind("<Button-5>", lambda e: self._send({"kind": "scroll", "dy": -1}))
        cv.bind("<KeyPress>", self._on_key_press)
        cv.bind("<KeyRelease>", self._on_key_release)
        cv.bind("<FocusOut>", lambda _e: self._modifiers.clear())
        cv.bind("<Configure>", lambda _e: self._repaint())
        cv.bind("<Button-1>", lambda _e: cv.focus_set(), add="+")
        cv.configure(takefocus=True)
        self.after(120, cv.focus_set)

    # ------------------------------------------------------------ session -- #
    def connect(self) -> None:
        self._cancel_reconnect()
        if self.session is not None:
            self.session.close()
            self.session = None
        self._close_decoder()
        self._frames = self._bytes = 0
        self._set_state("connecting",
                        "Reconnecting..." if self._attempts else "Connecting...")
        url = self.client.ws_url(f"/api/devices/{self.device_id}/screen")
        self.session = wsbridge.Session(url, self.client.ws_ssl_context(),
                                        self.client.ws_pin())
        session = self.session
        wsbridge.drain(session, lambda ev: self._on_event(session, ev), self)
        session.start()

    def _on_event(self, session, event) -> None:
        if session is not self.session:
            return                       # a superseded socket; ignore its tail
        kind = event[0]
        if kind == "open":
            self._attempts = 0
            self._start_capture()
            self._set_state("connecting", "Starting capture...")
        elif kind == "binary":
            self._on_binary(event[1])
        elif kind == "json":
            self._on_json(event[1])
        elif kind == "closed":
            self.session = None
            if self._user_closed:
                self._set_state("bad", "Disconnected")
            else:
                self._schedule_reconnect()
        elif kind == "error":
            self.session = None
            self._set_state("bad", event[1])
            if not self._user_closed:
                self._schedule_reconnect()

    def _on_json(self, message: dict) -> None:
        if message.get("type") == "video_info" and message.get("codec") == "h264":
            self._setup_decoder()
            return
        error = message.get("error")
        if error:
            self._set_state("bad", str(error))

    def _on_binary(self, data: bytes) -> None:
        if video.is_clipboard(data):
            self._receive_clipboard(video.clipboard_text(data))
            return
        self._bytes += len(data)
        if self.decoder is not None:
            for image in self.decoder.decode(data):
                self._next_image = image      # keep only the newest
            return
        self._next_jpeg = data                # stale JPEGs are never decoded

    def _start_capture(self) -> None:
        preset = PRESETS.get(self.quality, PRESETS["balanced"])
        codecs = ["h264", "jpeg"] if video.h264_available() else ["jpeg"]
        self._send({"type": "screen_start", **preset, "codecs": codecs})

    def _send(self, payload: dict) -> None:
        if self.session is not None:
            self.session.send_json(payload)

    def _schedule_reconnect(self) -> None:
        if self._user_closed or self._reconnect_job is not None:
            return
        if self._attempts >= MAX_RECONNECT:
            self._set_state("bad", "Disconnected - press Reconnect")
            return
        self._attempts += 1
        delay = int(min(400 * (1.7 ** (self._attempts - 1)), 5000))
        self._set_state("connecting", f"Reconnecting... ({self._attempts})")
        self._reconnect_job = self.after(delay, self._do_reconnect)

    def _do_reconnect(self) -> None:
        self._reconnect_job = None
        self.connect()

    def _cancel_reconnect(self) -> None:
        if self._reconnect_job is not None:
            self.after_cancel(self._reconnect_job)
            self._reconnect_job = None

    def reconnect_now(self) -> None:
        self._user_closed = False
        self._attempts = 0
        self.connect()

    def disconnect(self) -> None:
        self._user_closed = True
        self._cancel_reconnect()
        if self.session is not None:
            self.session.close()
            self.session = None
        self._close_decoder()
        if self._on_close is not None:
            self._on_close(self)
        self.destroy()

    # ------------------------------------------------------------ decoding -- #
    def _setup_decoder(self) -> None:
        self._close_decoder()
        try:
            self.decoder = video.H264Decoder()
            self.proto_label.configure(text="TLS - H.264")
        except Exception:
            self.decoder = None            # stay on JPEG; the agent still sends it
            self.proto_label.configure(text="TLS - JPEG")

    def _close_decoder(self) -> None:
        if self.decoder is not None:
            self.decoder.close()
            self.decoder = None
        self.proto_label.configure(text="TLS - JPEG")

    # ------------------------------------------------------------ painting -- #
    def _tick_paint(self) -> None:
        """Paint at most one frame per tick -- the newest one."""
        if not tasks.alive(self):
            return
        if self._next_jpeg is not None:
            data, self._next_jpeg = self._next_jpeg, None
            image = video.decode_jpeg(data)
            if image is not None:
                self._next_image = image
        if self._next_image is not None:
            image, self._next_image = self._next_image, None
            self._paint(image)
        self.after(16, self._tick_paint)

    def _paint(self, image) -> None:
        from PIL import Image, ImageTk

        self.native_w, self.native_h = image.size
        view_w = max(self.canvas.winfo_width(), 1)
        view_h = max(self.canvas.winfo_height(), 1)

        if self.fit:
            scale = min(view_w / image.width, view_h / image.height, 1.0)
            if scale < 0.999:
                image = image.resize((max(int(image.width * scale), 1),
                                      max(int(image.height * scale), 1)),
                                     Image.BILINEAR)
            self._draw_scale = scale if scale < 0.999 else 1.0
        else:
            self._draw_scale = 1.0

        x = max((view_w - image.width) // 2, 0)
        y = max((view_h - image.height) // 2, 0)
        self._offset = (x, y)

        if self._photo is not None and (self._photo.width(), self._photo.height()) == image.size:
            self._photo.paste(image)       # in-place blit: no new Tk image object
        else:
            self._photo = ImageTk.PhotoImage(image)
            if self._canvas_item is not None:
                self.canvas.delete(self._canvas_item)
            self._canvas_item = self.canvas.create_image(x, y, anchor="nw",
                                                         image=self._photo)
        if self._canvas_item is not None:
            self.canvas.coords(self._canvas_item, x, y)
        self._frames += 1
        if self.overlay.winfo_ismapped():
            self._set_state("ok", "Connected")

    def _repaint(self) -> None:
        """A window resize changes the fit scale; the next frame settles it."""
        if self._canvas_item is not None and self._photo is not None:
            view_w = max(self.canvas.winfo_width(), 1)
            view_h = max(self.canvas.winfo_height(), 1)
            x = max((view_w - self._photo.width()) // 2, 0)
            y = max((view_h - self._photo.height()) // 2, 0)
            self._offset = (x, y)
            self.canvas.coords(self._canvas_item, x, y)

    def toggle_scaling(self) -> None:
        self.fit = not self.fit
        self.btn_size.set_text("Actual size" if self.fit else "Fit to window")
        self.settings["remote_scaling"] = "fit" if self.fit else "actual"

    def toggle_fullscreen(self) -> None:
        full = not bool(self.attributes("-fullscreen"))
        self.attributes("-fullscreen", full)
        if full:
            self.bind("<Escape>", lambda _e: self.toggle_fullscreen())
        else:
            self.unbind("<Escape>")

    # --------------------------------------------------------------- input -- #
    def _to_native(self, event) -> tuple[int, int]:
        """Canvas coordinates -> native pixels on the remote display."""
        ox, oy = self._offset
        scale = self._draw_scale or 1.0
        return (int(round((event.x - ox) / scale)), int(round((event.y - oy) / scale)))

    def _in_frame(self, x: int, y: int) -> bool:
        return 0 <= x < (self.native_w or 1) and 0 <= y < (self.native_h or 1)

    def _on_motion(self, event) -> None:
        now = time.monotonic()
        if now - self._last_move < MOVE_INTERVAL:
            return
        self._last_move = now
        x, y = self._to_native(event)
        if self._in_frame(x, y) or self._dragging:
            self._send({"kind": "move", "x": x, "y": y})

    def _on_button(self, event, button: str, pressed: bool) -> str | None:
        if pressed:
            self.canvas.focus_set()
            x, y = self._to_native(event)
            if not self._in_frame(x, y):
                return None
            self._dragging = True
            self._send({"kind": "down", "x": x, "y": y, "button": button})
        else:
            if not self._dragging:
                return None
            self._dragging = False
            # A release bound on the window reports coordinates relative to the
            # widget under the pointer; re-base them onto the canvas.
            x = event.x_root - self.canvas.winfo_rootx()
            y = event.y_root - self.canvas.winfo_rooty()
            ox, oy = self._offset
            scale = self._draw_scale or 1.0
            self._send({"kind": "up", "button": button,
                        "x": int(round((x - ox) / scale)),
                        "y": int(round((y - oy) / scale))})
        return "break"

    def _on_wheel(self, event) -> str:
        self._send({"kind": "scroll", "dy": 1 if event.delta > 0 else -1})
        return "break"

    def _on_key_press(self, event) -> str:
        keysym = event.keysym
        modifier = MODIFIER_KEYSYMS.get(keysym)
        if modifier:
            self._modifiers.add(modifier)
            return "break"
        base = KEYMAP.get(keysym)
        if base is None and len(keysym) == 1:
            base = keysym.lower()
        combo = self._modifiers - {"shift"}
        if combo:
            # Ctrl/Alt/Win chord -- e.g. Ctrl+C, Alt+Tab, Win+R. `event.char` is a
            # control code here, so the key comes from the keysym.
            if base is None:
                return "break"
            # Ctrl+C / Ctrl+V are made to mean what people expect. Sent through
            # as plain hotkeys they act only on the *remote* machine's own
            # clipboard, so text could only cross between the two computers via
            # the toolbar buttons.
            clip_only = combo <= {"ctrl", "cmd"}
            if clip_only and base == "v":
                self.paste_to_remote()      # this computer's clipboard -> there
                return "break"
            keys = [m for m in ("ctrl", "alt", "cmd") if m in self._modifiers]
            if "shift" in self._modifiers:
                keys.append("shift")
            keys.append(base)
            self._send({"kind": "hotkey", "keys": keys})
            if clip_only and base in ("c", "x"):
                # The remote needs a moment to fill its clipboard; then mirror
                # it into this computer's.
                self.after(CLIP_PULL_DELAY_MS, self.copy_from_remote)
            return "break"
        if keysym in KEYMAP and keysym != "space":
            self._send({"kind": "hotkey", "keys": [KEYMAP[keysym]]})
            return "break"
        char = event.char
        if char and (char.isprintable() or char == " "):
            self._send({"kind": "key", "text": char})
        return "break"

    def _on_key_release(self, event) -> str:
        modifier = MODIFIER_KEYSYMS.get(event.keysym)
        if modifier:
            self._modifiers.discard(modifier)
        return "break"

    def send_cad(self) -> None:
        self._send({"kind": "hotkey", "keys": ["ctrl", "alt", "delete"]})

    # ----------------------------------------------------------- clipboard -- #
    def copy_from_remote(self) -> None:
        self._send({"kind": "clip_get"})

    def _receive_clipboard(self, text: str) -> None:
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.btn_copy.flash("Copied")
        except tk.TclError:
            self.btn_copy.flash("Copy failed")

    def paste_to_remote(self) -> None:
        try:
            text = self.clipboard_get()
        except tk.TclError:
            self.btn_paste.flash("Clipboard empty")
            return
        if text:
            self._send({"kind": "clip_paste", "text": text})
            self.btn_paste.flash("Pasted")

    def lock_device(self) -> None:
        tasks.run(self, lambda: self.client.power(self.device_id, "lock"),
                  on_ok=lambda _r: self.btn_lock.flash("Locked"),
                  on_error=lambda _e: self.btn_lock.flash("Failed"))

    def _on_quality(self, _event=None) -> None:
        label = self.quality_var.get()
        for key, text in PRESET_LABELS.items():
            if text == label:
                self.quality = key
                break
        self.settings["quality"] = self.quality
        if self.session is not None:
            self._start_capture()

    # --------------------------------------------------------------- chrome -- #
    def _set_state(self, state: str, message: str) -> None:
        colours = {"ok": C["good"], "bad": C["bad"]}
        self.dot.set(colours.get(state, C["warn"]))
        self.conn_label.configure(text=message,
                                  fg=colours.get(state, C["dim"]))
        connected = state == "ok"
        if connected and not self._started_at:
            self._started_at = time.strftime("%H:%M")
        for widget in (self.overlay, self.overlay_sub):
            if connected:
                widget.place_forget()
            elif not widget.winfo_ismapped():
                if widget is self.overlay:
                    widget.place(relx=0.5, rely=0.5, anchor="center")
                else:
                    widget.place(relx=0.5, rely=0.5, anchor="n", y=18)
        if not connected:
            self.overlay.configure(text=message)
        started = f"Session started {self._started_at}" if self._started_at else ""
        self.status_label.configure(text=" - ".join(x for x in (message, started) if x))

    def _tick_stats(self) -> None:
        if not tasks.alive(self):
            return
        if self.session is None:
            self.stats_label.configure(text="-")
        else:
            bits = self._bytes * 8
            rate = (f"{bits / 1e6:.1f} Mbps" if bits >= 1e6 else f"{round(bits / 1e3)} kbps")
            size = f"{self.native_w}x{self.native_h}" if self.native_w else "-"
            self.stats_label.configure(text=f"{self._frames} fps - {rate} - {size}")
        self._frames = self._bytes = 0
        self.after(1000, self._tick_stats)
