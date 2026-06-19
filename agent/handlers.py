"""Remote-control handlers: shell, power, files. Cross-platform (Windows + Linux)."""
from __future__ import annotations

import asyncio
import base64
import os
import platform
import subprocess

IS_WIN = platform.system() == "Windows"


async def run_command(cmd: str, timeout: float = 60) -> dict:
    """Run a single shell command, returning combined output + exit code."""
    if IS_WIN:
        argv = ["powershell", "-NoProfile", "-Command", cmd]
    else:
        argv = ["/bin/sh", "-c", cmd]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {"output": out.decode(errors="replace"), "code": proc.returncode}
    except asyncio.TimeoutError:
        return {"output": "(timed out)", "code": 124}
    except Exception as exc:
        return {"output": f"error: {exc}", "code": 1}


async def run_script(content: str, shell: str = "shell", timeout: float = 120,
                     env: dict | None = None, files: list | None = None) -> dict:
    """Run a script in a temp working directory.

    ``env`` values are exported as environment variables (policy variables) and
    ``files`` ([{name, b64}]) are written alongside the script so it can use them.
    """
    import shutil
    import tempfile
    workdir = tempfile.mkdtemp(prefix="rmm-")
    suffix = ".ps1" if shell == "powershell" else (".bat" if (IS_WIN and shell == "cmd") else ".sh")
    script_path = os.path.join(workdir, "script" + suffix)
    try:
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(content)
        for item in (files or []):
            name = os.path.basename(item.get("name") or "")
            if not name:
                continue
            with open(os.path.join(workdir, name), "wb") as f:
                f.write(base64.b64decode(item.get("b64") or ""))
        run_env = dict(os.environ)
        for k, v in (env or {}).items():
            run_env[str(k)] = str(v)
        if shell == "powershell":
            argv = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script_path]
        elif IS_WIN:
            argv = ["cmd", "/c", script_path]
        else:
            os.chmod(script_path, 0o700)
            argv = ["/bin/sh", script_path]
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            cwd=workdir, env=run_env,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {"output": out.decode(errors="replace"), "code": proc.returncode}
    except asyncio.TimeoutError:
        return {"output": "(timed out)", "code": 124}
    except Exception as exc:
        return {"output": f"error: {exc}", "code": 1}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _active_session_id() -> int | None:
    """Id of the interactive console session (the logged-in user), or None."""
    import ctypes
    sid = ctypes.windll.kernel32.WTSGetActiveConsoleSessionId()
    return None if sid in (0xFFFFFFFF, 0) else sid


def _run_in_active_session(cmdline: str) -> bool:
    """Launch a command inside the interactive user's session.

    The agent runs as SYSTEM in session 0, where ``LockWorkStation`` and a logoff
    have no effect on the user's desktop. This grabs the active console session's
    user token and starts the process there via ``CreateProcessAsUserW``."""
    import ctypes
    from ctypes import wintypes

    sid = _active_session_id()
    if sid is None:
        return False
    k32, wts, adv, env_api = (ctypes.windll.kernel32, ctypes.windll.wtsapi32,
                              ctypes.windll.advapi32, ctypes.windll.userenv)
    hTok = wintypes.HANDLE()
    if not wts.WTSQueryUserToken(sid, ctypes.byref(hTok)):
        return False
    try:
        hDup = wintypes.HANDLE()
        # TokenPrimary=1, SecurityImpersonation=2, TOKEN_ALL_ACCESS
        if not adv.DuplicateTokenEx(hTok, 0xF01FF, None, 2, 1, ctypes.byref(hDup)):
            return False
        try:
            env = ctypes.c_void_p()
            if not env_api.CreateEnvironmentBlock(ctypes.byref(env), hDup, False):
                env = None

            class STARTUPINFO(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                            ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                            ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                            ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                            ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                            ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                            ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                            ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                            ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]

            class PROCESS_INFORMATION(ctypes.Structure):
                _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                            ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

            si = STARTUPINFO()
            si.cb = ctypes.sizeof(si)
            si.lpDesktop = "winsta0\\default"
            pi = PROCESS_INFORMATION()
            # CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW
            flags = 0x00000400 | 0x08000000
            ok = adv.CreateProcessAsUserW(hDup, None, ctypes.c_wchar_p(cmdline), None, None,
                                          False, flags, env, None, ctypes.byref(si),
                                          ctypes.byref(pi))
            if ok:
                k32.CloseHandle(pi.hProcess)
                k32.CloseHandle(pi.hThread)
            if env:
                env_api.DestroyEnvironmentBlock(env)
            return bool(ok)
        finally:
            k32.CloseHandle(hDup)
    finally:
        k32.CloseHandle(hTok)


def power_action(action: str) -> dict:
    """Perform a power/session action for the host OS."""
    try:
        if IS_WIN:
            # Lock/logoff must hit the interactive session, not the SYSTEM session 0.
            if action == "lock":
                if _run_in_active_session("rundll32.exe user32.dll,LockWorkStation"):
                    return {"ok": True, "action": action}
                subprocess.Popen(["rundll32.exe", "user32.dll,LockWorkStation"])
                return {"ok": True, "action": action}
            if action == "logoff":
                sid = _active_session_id()
                if sid is not None:
                    subprocess.Popen(["logoff", str(sid)])
                else:
                    subprocess.Popen(["shutdown", "/l"])
                return {"ok": True, "action": action}
            cmds = {
                "reboot": ["shutdown", "/r", "/t", "5"],
                "shutdown": ["shutdown", "/s", "/t", "5"],
            }
        else:
            cmds = {
                "reboot": ["shutdown", "-r", "now"],
                "shutdown": ["shutdown", "-h", "now"],
                "logoff": ["pkill", "-KILL", "-u", os.environ.get("USER", "")],
                "lock": ["loginctl", "lock-sessions"],
            }
        if action not in cmds:
            return {"ok": False, "error": f"unknown action {action}"}
        subprocess.Popen(cmds[action])
        return {"ok": True, "action": action}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def file_get(path: str, max_bytes: int = 25 * 1024 * 1024) -> dict:
    try:
        size = os.path.getsize(path)
        if size > max_bytes:
            return {"ok": False, "error": "file too large"}
        with open(path, "rb") as f:
            data = f.read()
        return {"ok": True, "name": os.path.basename(path),
                "data": base64.b64encode(data).decode()}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def file_put(path: str, b64: str) -> dict:
    try:
        with open(path, "wb") as f:
            f.write(base64.b64decode(b64))
        return {"ok": True, "path": path}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _drives() -> list[dict]:
    """Top-level roots to browse: drive letters on Windows, '/' on Linux."""
    out = []
    if IS_WIN:
        import psutil
        for p in psutil.disk_partitions(all=False):
            mp = p.mountpoint
            entry = {"name": mp, "path": mp, "is_dir": True, "size": None, "modified": None}
            try:
                u = __import__("psutil").disk_usage(mp)
                entry["size"] = u.total
                entry["used"] = u.used
                entry["percent"] = u.percent
            except Exception:
                pass
            out.append(entry)
    else:
        out.append({"name": "/", "path": "/", "is_dir": True, "size": None, "modified": None})
    return out


def file_list(path: str) -> dict:
    """List a directory. An empty path returns the drive/root list."""
    try:
        if not path:
            return {"ok": True, "path": "", "parent": None, "entries": _drives(), "roots": True}
        if not os.path.isdir(path):
            return {"ok": False, "error": "Not a directory"}
        entries = []
        with os.scandir(path) as it:
            for e in it:
                try:
                    st = e.stat(follow_symlinks=False)
                    is_dir = e.is_dir(follow_symlinks=False)
                    entries.append({
                        "name": e.name, "path": e.path, "is_dir": is_dir,
                        "size": None if is_dir else st.st_size,
                        "modified": st.st_mtime,
                    })
                except OSError:
                    continue
        entries.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
        parent = os.path.dirname(path.rstrip("\\/")) or (None if IS_WIN else "/")
        # On Windows, a drive root (C:\) has no meaningful parent → drive list.
        if IS_WIN and len(path.rstrip("\\/")) <= 2:
            parent = ""
        return {"ok": True, "path": path, "parent": parent, "entries": entries}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def dir_size(path: str, time_budget: float = 15.0) -> dict:
    """Sum the size of a folder tree (bounded by a time budget)."""
    import time
    total, files, start, truncated = 0, 0, time.time(), False
    try:
        for root, _dirs, names in os.walk(path):
            for n in names:
                try:
                    total += os.path.getsize(os.path.join(root, n))
                    files += 1
                except OSError:
                    pass
            if time.time() - start > time_budget:
                truncated = True
                break
        return {"ok": True, "path": path, "size": total, "files": files, "truncated": truncated}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def file_delete(path: str) -> dict:
    import shutil
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
        return {"ok": True, "path": path}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def file_mkdir(path: str) -> dict:
    try:
        os.makedirs(path, exist_ok=True)
        return {"ok": True, "path": path}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
