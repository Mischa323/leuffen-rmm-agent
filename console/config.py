"""Console settings + credential storage.

Settings live in `%APPDATA%\\Leuffen RMM Console\\settings.json` (per-user, so a
shared workstation keeps each technician's servers and preferences apart).

The sign-in token is a bearer credential, so it is **not** kept in that file: it
goes through Windows DPAPI (`CryptProtectData`, current-user scope) into
`token.bin`, which means the ciphertext is useless to another account on the
same machine and to anyone who copies the file elsewhere. If DPAPI is
unavailable (a non-Windows dev run), it falls back to a plain file with
owner-only permissions and says so through `token_protected()`.
"""
from __future__ import annotations

import ctypes
import json
import os
import sys
from ctypes import wintypes

APP_DIR_NAME = "Leuffen RMM Console"

DEFAULTS: dict = {
    "server_url": "",
    "insecure_tls": False,
    "fingerprint": "",
    "email": "",
    "theme": "dark",
    "accent": "#3b82f6",
    "quality": "balanced",
    "remote_scaling": "fit",
    "window": "",
}


def config_dir() -> str:
    override = os.environ.get("RMM_CONSOLE_DIR")
    if override:
        base = override
    elif os.name == "nt":
        base = os.path.join(os.environ.get("APPDATA")
                            or os.path.expanduser(r"~\AppData\Roaming"), APP_DIR_NAME)
    else:
        base = os.path.join(os.path.expanduser("~"), ".leuffen-rmm-console")
    os.makedirs(base, exist_ok=True)
    return base


def _settings_path() -> str:
    return os.path.join(config_dir(), "settings.json")


def _token_path() -> str:
    return os.path.join(config_dir(), "token.bin")


# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #
def load() -> dict:
    cfg = dict(DEFAULTS)
    try:
        with open(_settings_path(), encoding="utf-8") as fh:
            stored = json.load(fh)
        if isinstance(stored, dict):
            cfg.update({k: v for k, v in stored.items() if k in DEFAULTS})
    except (OSError, ValueError):
        pass
    cfg["server_url"] = normalise_url(cfg.get("server_url") or "")
    return cfg


def save(cfg: dict) -> None:
    """Persist settings. Best-effort: a locked/read-only profile must not crash
    the app, it just means preferences do not stick."""
    try:
        data = {k: cfg.get(k, v) for k, v in DEFAULTS.items()}
        tmp = _settings_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, _settings_path())
    except OSError:
        pass


def normalise_url(url: str) -> str:
    """Accept what a technician actually types: `rmm.example.com`,
    `https://rmm.example.com/`, or a full URL with a port."""
    url = (url or "").strip().rstrip("/")
    if not url:
        return ""
    if "://" not in url:
        url = "https://" + url
    return url


# --------------------------------------------------------------------------- #
# Token storage (DPAPI)
# --------------------------------------------------------------------------- #
class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]

    @classmethod
    def of(cls, data: bytes) -> "_Blob":
        buf = ctypes.create_string_buffer(data, len(data))
        return cls(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))

    def value(self) -> bytes:
        return ctypes.string_at(self.pbData, self.cbData)


_CRYPTPROTECT_UI_FORBIDDEN = 0x01
_DESCRIPTION = "Leuffen RMM Console sign-in"


def _dpapi(fn_name: str, data: bytes) -> bytes | None:
    if os.name != "nt" or not data:
        return None
    try:
        crypt32 = ctypes.windll.crypt32
        fn = getattr(crypt32, fn_name)
        blob_in, blob_out = _Blob.of(data), _Blob()
        desc = ctypes.c_wchar_p(_DESCRIPTION) if fn_name == "CryptProtectData" else None
        ok = fn(ctypes.byref(blob_in), desc, None, None, None,
                _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out))
        if not ok:
            return None
        try:
            return blob_out.value()
        finally:
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    except Exception:
        return None


def token_protected() -> bool:
    """True when the stored token is encrypted with DPAPI rather than plain."""
    return os.name == "nt"


def load_token() -> str:
    try:
        with open(_token_path(), "rb") as fh:
            raw = fh.read()
    except OSError:
        return ""
    if not raw:
        return ""
    if raw.startswith(b"dpapi:"):
        plain = _dpapi("CryptUnprotectData", raw[6:])
        # A token minted under a different Windows account (roamed profile,
        # restored backup) cannot be decrypted -- treat it as "not signed in".
        return plain.decode("utf-8", "replace") if plain else ""
    return raw.decode("utf-8", "replace")


def save_token(token: str) -> None:
    path = _token_path()
    if not token:
        try:
            os.remove(path)
        except OSError:
            pass
        return
    blob = _dpapi("CryptProtectData", token.encode())
    data = b"dpapi:" + blob if blob else token.encode()
    try:
        with open(path, "wb") as fh:
            fh.write(data)
        if os.name != "nt":
            os.chmod(path, 0o600)
    except OSError:
        pass


def clear_token() -> None:
    save_token("")


def is_frozen() -> bool:
    """True inside the PyInstaller bundle (vs. a source checkout)."""
    return bool(getattr(sys, "frozen", False))
