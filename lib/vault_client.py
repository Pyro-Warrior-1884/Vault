#!/usr/bin/env python3
"""CLI-side helper for the vault.

Bash is the user-facing layer.  This program is the only component that talks
to the daemon socket.  Secrets are read from stdin (never argv/env) and sent
as a single JSON request over the 0600 UNIX socket.  Secret values are never
printed to stdout except when explicitly requested by the copy path, and never
written to disk.
"""
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time

from common import (
    SOCKET_PATH, PID_PATH, TOKEN_PATH, DB_PATH,
    ensure_vault_dir, restrict, SOCKET_TIMEOUT,
    FORMAT_VERSION, KDF_ALG, KDF_TIME_COST, KDF_MEMORY_COST,
    KDF_PARALLELISM, KDF_HASH_LEN, ENC_ALG, WRAP_ALG,
)
import crypto_vault as cv
import db_vault as db


def _die(code: str) -> "None":
    sys.stdout.write("error:" + code + "\n")
    sys.exit(1)


def _read_secret_line() -> str:
    line = sys.stdin.readline()
    if line == "":
        return ""
    return line.rstrip("\n")


def _token() -> str:
    try:
        with open(TOKEN_PATH) as f:
            return f.read().strip()
    except OSError:
        return ""


def _connect(retries: int = 20, delay: float = 0.1) -> socket.socket:
    last = None
    for _ in range(retries):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(SOCKET_TIMEOUT)
            s.connect(SOCKET_PATH)
            return s
        except OSError as e:
            last = e
            try:
                s.close()
            except Exception:
                pass
            time.sleep(delay)
    raise last or OSError("cannot connect")


def _request(msg: dict, retries: int = 20, delay: float = 0.1) -> dict:
    msg.setdefault("token", _token())
    s = _connect(retries=retries, delay=delay)
    try:
        s.sendall((json.dumps(msg) + "\n").encode("utf-8"))
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    if not buf:
        return {"ok": False, "error": "no_response"}
    return json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))


# ---- commands ---------------------------------------------------------
def cmd_init() -> None:
    if db.is_initialized() and os.path.exists(DB_PATH):
        _die("already_initialized")
    password = _read_secret_line()
    password2 = _read_secret_line()
    if not password or password != password2:
        _die("password_mismatch")
    ensure_vault_dir()
    salt = cv.generate_salt(16)
    dek = cv.generate_dek(32)
    derived = cv.derive_key(
        password, salt,
        time_cost=KDF_TIME_COST, memory_cost=KDF_MEMORY_COST, hash_len=KDF_HASH_LEN,
    )
    wrapped = cv.wrap_dek(dek, derived)
    db.init_db({
        "format_version": str(FORMAT_VERSION),
        "kdf_alg": KDF_ALG,
        "kdf_time_cost": str(KDF_TIME_COST),
        "kdf_memory_cost": str(KDF_MEMORY_COST),
        "kdf_parallelism": str(KDF_PARALLELISM),
        "kdf_hash_len": str(KDF_HASH_LEN),
        "salt": cv.b64e(salt),
        "enc_alg": ENC_ALG,
        "wrap_alg": WRAP_ALG,
        "wrapped_dek": cv.b64e(wrapped),
    })
    sys.stdout.write("ok\n")


def cmd_start() -> None:
    """Start the daemon detached, then report readiness."""
    if os.path.exists(SOCKET_PATH):
        sys.stdout.write("ok\n")
        return
    python = shutil.which("python3") or sys.executable
    daemon = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vaultd.py")
    env = dict(os.environ)
    stderr_target = subprocess.DEVNULL
    if os.environ.get("VAULT_DEBUG"):
        stderr_target = open(os.path.join(os.path.dirname(SOCKET_PATH), "vaultd.log"), "ab")
    with open(os.devnull, "rb") as devnull:
        subprocess.Popen(
            [python, daemon],
            stdin=devnull,
            stdout=subprocess.DEVNULL,
            stderr=stderr_target,
            start_new_session=True,
            env=env,
        )
    deadline = time.time() + 5
    while time.time() < deadline:
        if os.path.exists(SOCKET_PATH):
            sys.stdout.write("ok\n")
            return
        time.sleep(0.05)
    _die("daemon_failed")


def cmd_unlock() -> None:
    if not db.is_initialized():
        _die("not_initialized")
    password = _read_secret_line()
    resp = _request({"cmd": "unlock", "master_password": password})
    if not resp.get("ok"):
        _die("invalid_password")
    sys.stdout.write("ok\n")


def cmd_lock() -> None:
    try:
        resp = _request({"cmd": "lock"})
    except OSError:
        _cleanup_state()
        sys.stdout.write("already\n")
        return
    if not resp.get("ok"):
        # daemon reachable but session already gone
        _cleanup_state()
        sys.stdout.write("already\n")
        return
    # give the daemon a moment to exit and remove its files
    deadline = time.time() + 2
    while time.time() < deadline and os.path.exists(SOCKET_PATH):
        time.sleep(0.05)
    _cleanup_state()
    sys.stdout.write("locked\n")


def _cleanup_state() -> None:
    for p in (SOCKET_PATH, PID_PATH, TOKEN_PATH):
        try:
            os.unlink(p)
        except OSError:
            pass


def cmd_status() -> None:
    if not os.path.exists(SOCKET_PATH):
        sys.stdout.write("locked\n")
        return
    try:
        resp = _request({"cmd": "status"}, retries=2, delay=0.05)
    except OSError:
        sys.stdout.write("locked\n")
        return
    if resp.get("ok") and resp.get("unlocked"):
        sys.stdout.write("unlocked\n")
    else:
        sys.stdout.write("locked\n")


def cmd_list() -> None:
    resp = _request({"cmd": "list_sources"})
    if not resp.get("ok"):
        _die(resp.get("error", "error"))
    for s in resp.get("sources", []):
        sys.stdout.write(s + "\n")


def cmd_preview(source: str) -> None:
    resp = _request({"cmd": "preview", "source": source})
    if not resp.get("ok"):
        _die(resp.get("error", "error"))
    sys.stdout.write("Source: {}\n".format(resp.get("source", source)))
    sys.stdout.write("Username: {}\n".format(resp.get("username", "")))
    sys.stdout.write("Password: {}\n".format("********" if resp.get("has_password") else ""))


def cmd_current(source: str) -> None:
    resp = _request({"cmd": "current", "source": source})
    if not resp.get("ok"):
        _die(resp.get("error", "error"))
    sys.stdout.write(resp.get("username", "") + "\n")


def _clipboard(value: str) -> None:
    tool = shutil.which("termux-clipboard-set")
    if not tool:
        _die("no_clipboard")
    try:
        p = subprocess.Popen([tool], stdin=subprocess.PIPE)
        p.communicate(input=value.encode("utf-8"))
        if p.returncode != 0:
            _die("clipboard_failed")
    except OSError:
        _die("clipboard_failed")


def cmd_copy(source: str) -> None:
    resp = _request({"cmd": "get", "source": source})
    if not resp.get("ok"):
        _die(resp.get("error", "error"))
    _clipboard(resp.get("username", ""))
    _clipboard(resp.get("password", ""))
    sys.stdout.write("copied\n")


def cmd_add() -> None:
    source = _read_secret_line()
    username = _read_secret_line()
    password = _read_secret_line()
    if not source.strip():
        _die("empty_source")
    resp = _request({
        "cmd": "add_secret",
        "source": source,
        "username": username,
        "password": password,
    })
    if not resp.get("ok"):
        _die(resp.get("error", "error"))
    sys.stdout.write("ok\n")


def cmd_update() -> None:
    source = _read_secret_line()
    username = _read_secret_line()
    password = _read_secret_line()
    resp = _request({
        "cmd": "update_secret",
        "source": source,
        "username": username,
        "password": password,
    })
    if not resp.get("ok"):
        _die(resp.get("error", "error"))
    sys.stdout.write("ok\n")


def cmd_delete(source: str) -> None:
    resp = _request({"cmd": "delete_secret", "source": source})
    if not resp.get("ok"):
        _die(resp.get("error", "error"))
    sys.stdout.write("ok\n")


def main() -> None:
    if len(sys.argv) < 2:
        _die("usage")
    cmd = sys.argv[1]
    args = sys.argv[2:]
    dispatch = {
        "init": lambda: cmd_init(),
        "start": lambda: cmd_start(),
        "unlock": lambda: cmd_unlock(),
        "lock": lambda: cmd_lock(),
        "status": lambda: cmd_status(),
        "list": lambda: cmd_list(),
        "add": lambda: cmd_add(),
        "update": lambda: cmd_update(),
    }
    if cmd in dispatch:
        dispatch[cmd]()
        return
    if cmd == "preview" and args:
        cmd_preview(args[0])
    elif cmd == "current" and args:
        cmd_current(args[0])
    elif cmd == "copy" and args:
        cmd_copy(args[0])
    elif cmd == "delete" and args:
        cmd_delete(args[0])
    else:
        _die("usage")


if __name__ == "__main__":
    try:
        main()
    except cv.CryptoError:
        _die("crypto")
    except BrokenPipeError:
        pass
    except SystemExit:
        raise
    except Exception:
        if os.environ.get("VAULT_DEBUG"):
            raise
        _die("internal")
