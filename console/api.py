"""REST client for the Leuffen RMM server.

Mirrors the security model the agent already uses: an optional `insecure_tls`
escape hatch for the bundled self-signed setup, made safe again by **certificate
pinning** (SHA-256 of the server's DER cert). Where the agent pins its
WebSocket, this pins every HTTPS call too, so a MITM can't stand between the
console and the server even when the cert is not publicly trusted.

Authentication is the app token minted by `POST /api/auth/app-token`, sent as
`Authorization: Bearer ...`.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import mimetypes
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid

from version import CONSOLE_VERSION

USER_AGENT = f"LeuffenRMMConsole/{CONSOLE_VERSION}"
TIMEOUT = 20.0


class ApiError(Exception):
    """An HTTP failure carrying the server's own `detail` message."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message

    @property
    def is_auth(self) -> bool:
        """401/403 -- the stored token is gone, expired, or lost its access."""
        return self.status in (401, 403)


class MfaRequired(Exception):
    """The account has TOTP enabled and the call carried no code."""


def clean_fingerprint(value: str) -> str:
    return (value or "").replace(":", "").replace(" ", "").strip().lower()


def _verify_pin(sock, pin: str) -> None:
    der = sock.getpeercert(binary_form=True)
    got = hashlib.sha256(der or b"").hexdigest()
    if not hmac.compare_digest(got, pin):
        raise ssl.SSLError(
            "server certificate fingerprint mismatch -- possible MITM; refusing")


def peek_fingerprint(server_url: str, timeout: float = 10.0) -> str:
    """SHA-256 of the server's certificate, fetched without verifying it.

    Used by the sign-in screen so a self-signed deployment can be pinned in one
    click: the technician sees the fingerprint, confirms it out-of-band once,
    and from then on only that exact certificate is accepted.
    """
    parts = urllib.parse.urlsplit(server_url)
    if parts.scheme != "https":
        return ""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443,
                                       context=ctx, timeout=timeout)
    try:
        conn.connect()
        der = conn.sock.getpeercert(binary_form=True)
        return hashlib.sha256(der or b"").hexdigest()
    finally:
        conn.close()


def pretty_fingerprint(hex_digest: str) -> str:
    h = clean_fingerprint(hex_digest)
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2)).upper()


class ApiClient:
    """One client per server. Thread-safe for concurrent GETs (urllib opens a
    fresh connection per request), which is all the UI does from its workers."""

    def __init__(self, server_url: str = "", token: str = "",
                 insecure_tls: bool = False, fingerprint: str = ""):
        self.server_url = (server_url or "").rstrip("/")
        self.token = token or ""
        self.insecure_tls = bool(insecure_tls)
        self.fingerprint = clean_fingerprint(fingerprint)
        self.email = ""
        self.is_global_admin = False

    # -- plumbing ----------------------------------------------------------- #
    def _ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if self.insecure_tls or self.fingerprint:
            # A pin is a stronger check than the CA chain, and the bundled setup
            # ships a self-signed cert -- so pinning implies we verify by pin.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _opener(self) -> urllib.request.OpenerDirector:
        ctx, pin = self._ssl_context(), self.fingerprint

        def factory(host, **kw):
            conn = http.client.HTTPSConnection(host, context=ctx, **kw)
            if pin:
                inner = conn.connect

                def connect_and_pin():
                    inner()
                    _verify_pin(conn.sock, pin)

                conn.connect = connect_and_pin
            return conn

        class Handler(urllib.request.HTTPSHandler):
            def https_open(self, req):
                return self.do_open(factory, req)

        # No cookie jar and no redirect to another host: this client only ever
        # talks to the one server it was configured with.
        return urllib.request.build_opener(Handler(context=ctx))

    def _url(self, path: str, params: dict | None = None) -> str:
        url = self.server_url + path
        if params:
            url += "?" + urllib.parse.urlencode({k: v for k, v in params.items()
                                                 if v is not None})
        return url

    def _request(self, method: str, path: str, *, params: dict | None = None,
                 body: dict | None = None, raw_body: bytes | None = None,
                 content_type: str = "", timeout: float = TIMEOUT,
                 authed: bool = True, raw_response: bool = False):
        data = raw_body
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if content_type:
            headers["Content-Type"] = content_type
        if authed and self.token:
            headers["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(self._url(path, params), data=data,
                                     headers=headers, method=method)
        try:
            with self._opener().open(req, timeout=timeout) as resp:
                payload = resp.read()
                if raw_response:
                    return payload, dict(resp.headers)
        except urllib.error.HTTPError as exc:
            raise ApiError(exc.code, _detail(exc)) from None
        except urllib.error.URLError as exc:
            raise ApiError(0, _reason(exc.reason)) from None
        except (ssl.SSLError, OSError) as exc:
            raise ApiError(0, str(exc)) from None
        if not payload:
            return None
        try:
            return json.loads(payload)
        except ValueError:
            return payload

    # -- auth --------------------------------------------------------------- #
    def sign_in(self, username: str, password: str, code: str = "") -> dict:
        """Password (+ TOTP) sign-in. Raises `MfaRequired` when a code is needed."""
        res = self._request("POST", "/api/auth/app-token", authed=False,
                            body={"username": username, "password": password,
                                  "code": code})
        return self._accept(res)

    def redeem_ticket(self, ticket: str) -> dict:
        """Exchange a `leuffenrmm://` hand-off ticket for a token (the SSO path)."""
        res = self._request("POST", "/api/auth/app-token", authed=False,
                            body={"ticket": ticket})
        return self._accept(res)

    def _accept(self, res: dict | None) -> dict:
        if isinstance(res, dict) and res.get("mfa_required"):
            raise MfaRequired()
        if not isinstance(res, dict) or not res.get("token"):
            raise ApiError(0, "The server did not return a sign-in token")
        self.token = res["token"]
        self.email = res.get("email", "")
        self.is_global_admin = bool(res.get("is_global_admin"))
        return res

    def me(self) -> dict:
        res = self._request("GET", "/api/me") or {}
        self.email = res.get("email", self.email)
        self.is_global_admin = bool(res.get("is_global_admin"))
        return res

    def auth_config(self) -> dict:
        """Sign-in modes the server offers -- probed before the token exists, so
        it doubles as the 'can I reach this server at all?' check."""
        return self._request("GET", "/api/auth/config", authed=False) or {}

    # -- inventory ---------------------------------------------------------- #
    def orgs(self) -> list:
        return self._request("GET", "/api/orgs") or []

    def devices(self, org_id: str) -> list:
        return self._request("GET", f"/api/orgs/{org_id}/devices") or []

    def device(self, device_id: str) -> dict:
        return self._request("GET", f"/api/devices/{device_id}") or {}

    # -- actions ------------------------------------------------------------ #
    def power(self, device_id: str, action: str) -> dict:
        return self._request("POST", f"/api/devices/{device_id}/power",
                             body={"action": action}, timeout=30) or {}

    def run_command(self, device_id: str, cmd: str, timeout: float = 120) -> dict:
        return self._request("POST", f"/api/devices/{device_id}/shell",
                             body={"cmd": cmd}, timeout=timeout) or {}

    # -- files -------------------------------------------------------------- #
    def files_list(self, device_id: str, path: str = "") -> dict:
        return self._request("GET", f"/api/devices/{device_id}/files",
                             params={"path": path}, timeout=40) or {}

    def files_mkdir(self, device_id: str, path: str) -> dict:
        return self._request("POST", f"/api/devices/{device_id}/files/mkdir",
                             body={"path": path}) or {}

    def files_delete(self, device_id: str, path: str) -> dict:
        return self._request("POST", f"/api/devices/{device_id}/files/delete",
                             body={"path": path}, timeout=60) or {}

    def file_download(self, device_id: str, path: str) -> tuple[bytes, str]:
        payload, headers = self._request(
            "GET", f"/api/devices/{device_id}/files/download",
            params={"path": path}, timeout=180, raw_response=True)
        name = _filename_from_disposition(headers.get("Content-Disposition", ""))
        return payload, name or os.path.basename(path.replace("\\", "/")) or "download"

    def file_upload(self, device_id: str, remote_dir: str, local_path: str) -> dict:
        """Multipart upload of one local file into `remote_dir` on the device."""
        name = os.path.basename(local_path)
        with open(local_path, "rb") as fh:
            content = fh.read()
        boundary = uuid.uuid4().hex
        ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
        body = b"".join([
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="file"; filename="{name}"\r\n'.encode(),
            f"Content-Type: {ctype}\r\n\r\n".encode(),
            content,
            f"\r\n--{boundary}--\r\n".encode(),
        ])
        return self._request("POST", f"/api/devices/{device_id}/files/upload",
                             params={"path": remote_dir}, raw_body=body,
                             content_type=f"multipart/form-data; boundary={boundary}",
                             timeout=300) or {}

    # -- console updates ---------------------------------------------------- #
    def console_release(self) -> dict:
        return self._request("GET", "/api/console-release", timeout=15) or {}

    # -- websockets --------------------------------------------------------- #
    def ws_url(self, path: str, params: dict | None = None) -> str:
        """WebSocket URL with the bearer token attached.

        The token rides in the query string because not every WebSocket client
        (or proxy) forwards an Authorization header on the upgrade -- the server
        accepts either form."""
        parts = urllib.parse.urlsplit(self.server_url)
        scheme = "wss" if parts.scheme == "https" else "ws"
        query = dict(params or {})
        if self.token:
            query["token"] = self.token
        return urllib.parse.urlunsplit((scheme, parts.netloc, path,
                                        urllib.parse.urlencode(query), ""))

    def ws_ssl_context(self):
        """SSL context for `websockets.connect` (None for plain ws://)."""
        return self._ssl_context() if self.server_url.startswith("https") else None

    def ws_pin(self) -> str:
        return self.fingerprint


def _detail(exc: urllib.error.HTTPError) -> str:
    try:
        payload = json.loads(exc.read() or b"{}")
        detail = payload.get("detail") or payload.get("error")
        if isinstance(detail, list) and detail:
            detail = detail[0].get("msg", "")
        if detail:
            return str(detail)
    except Exception:
        pass
    return {401: "Not signed in", 403: "Access denied", 404: "Not found",
            409: "Device offline", 504: "The device did not respond"
            }.get(exc.code, f"Server error ({exc.code})")


def _reason(reason) -> str:
    """Turn urllib's nested exceptions into something a technician can act on."""
    text = str(reason)
    if isinstance(reason, ssl.SSLCertVerificationError):
        return ("The server's TLS certificate is not trusted. If it is self-signed, "
                "tick 'Trust this server's certificate' and try again.")
    if isinstance(reason, ssl.SSLError):
        return f"TLS error: {text}"
    if "getaddrinfo" in text or "Name or service not known" in text:
        return "That server name could not be resolved -- check the address."
    if "refused" in text.lower():
        return "The server refused the connection -- check the address and port."
    if "timed out" in text.lower():
        return "The server did not respond in time."
    return text


def _filename_from_disposition(value: str) -> str:
    for part in value.split(";"):
        part = part.strip()
        if part.lower().startswith("filename="):
            return part[9:].strip('"')
    return ""
