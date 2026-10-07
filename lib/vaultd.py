#!/usr/bin/env python3
"""Unlocked-session daemon.

Holds the plaintext DEK in memory only, and accepts newline-delimited JSON
requests over a 0600 UNIX socket.  Every request after unlock must carry the
random session token written to TOKEN_PATH (0600) at unlock time.

The DEK is never written to disk.  Killing this process (or rebooting) locks
the vault.
"""
import hmac
import json
import os
import signal
import socket
import sys

from common import (
    SOCKET_PATH, PID_PATH, TOKEN_PATH, ensure_vault_dir, restrict,
)
import crypto_vault as cv
import db_vault as db


TOKEN_BYTES = 32


class VaultDaemon:
    def __init__(self):
        self.dek = None
        self.token = None
        self.running = True

    # ---- key handling -------------------------------------------------
    def load_dek(self, master_password: str) -> None:
        meta = db.get_metadata()
        salt = cv.b64d(meta["salt"])
        wrapped = cv.b64d(meta["wrapped_dek"])
        derived = cv.derive_key(
            master_password,
            salt,
            time_cost=int(meta.get("kdf_time_cost", 4)),
            memory_cost=int(meta.get("kdf_memory_cost", 64 * 1024 * 1024)),
            hash_len=int(meta.get("kdf_hash_len", 32)),
        )
        dek = cv.unwrap_dek(wrapped, derived)
        if len(dek) != 32:
            raise cv.CryptoError("bad dek")
        self.dek = dek

    def encrypt_payload(self, username: str, password: str) -> bytes:
        payload = json.dumps(
            {"username": username or "", "password": password or ""},
            ensure_ascii=False,
        )
        return cv.encrypt(payload.encode("utf-8"), self.dek)

    def decrypt_payload(self, source: str) -> dict:
        ep = db.get_secret_payload(source)
        if ep is None:
            raise KeyError("not_found")
        pt = cv.decrypt(ep, self.dek)
        data = json.loads(pt.decode("utf-8"))
        return {
            "username": data.get("username", ""),
            "password": data.get("password", ""),
        }

    # ---- request dispatch --------------------------------------------
    def handle(self, msg: dict) -> dict:
        cmd = msg.get("cmd")

        if cmd == "ping":
            return {"ok": True, "unlocked": self.dek is not None}

        if cmd == "unlock":
            self.load_dek(msg.get("master_password", ""))
            self.token = cv.b64e(cv.generate_dek(TOKEN_BYTES))
            with open(TOKEN_PATH, "w") as f:
                f.write(self.token)
            restrict(TOKEN_PATH)
            return {"ok": True}

        # locking is never sensitive and is always allowed: it only reduces
        # access.  This also guarantees an idle/failed-unlock daemon exits.
        if cmd == "lock":
            self.dek = None
            self.token = None
            _safe_unlink(TOKEN_PATH)
            return {"ok": True, "shutdown": True}

        # every other command requires an authenticated unlocked session
        supplied = msg.get("token") or ""
        if self.dek is None:
            return {"ok": False, "error": "locked"}
        if not self.token or not hmac.compare_digest(supplied, self.token):
            return {"ok": False, "error": "unauthorized"}

        try:
            if cmd == "status":
                return {"ok": True, "unlocked": True}

            if cmd == "list_sources":
                return {"ok": True, "sources": db.list_sources()}

            if cmd == "export":
                secrets = []
                for source in db.list_sources():
                    d = self.decrypt_payload(source)
                    secrets.append({
                        "source": source,
                        "username": d["username"],
                        "password": d["password"],
                    })
                return {"ok": True, "secrets": secrets}

            if cmd == "import_plan":
                secrets = msg.get("secrets")
                if not isinstance(secrets, list):
                    return {"ok": False, "error": "bad_request"}
                existing = set(db.list_sources())
                conflicts = set()
                for item in secrets:
                    if not isinstance(item, dict):
                        return {"ok": False, "error": "bad_request"}
                    source = db.normalize_source(item.get("source", ""))
                    if source in existing:
                        conflicts.add(source)
                return {"ok": True, "total": len(secrets), "conflicts": sorted(conflicts)}

            if cmd == "import":
                secrets = msg.get("secrets")
                mode = msg.get("mode")
                if not isinstance(secrets, list) or mode not in ("overwrite", "skip"):
                    return {"ok": False, "error": "bad_request"}
                for item in secrets:
                    if (
                        not isinstance(item, dict)
                        or not isinstance(item.get("source"), str)
                        or not item["source"].strip()
                        or not isinstance(item.get("username"), str)
                        or not isinstance(item.get("password"), str)
                    ):
                        return {"ok": False, "error": "bad_request"}
                added = updated = skipped = 0
                for item in secrets:
                    source = db.normalize_source(item["source"])
                    payload = self.encrypt_payload(item["username"], item["password"])
                    if db.add_secret(source, payload):
                        added += 1
                    elif mode == "overwrite" and db.update_secret(source, payload):
                        updated += 1
                    else:
                        skipped += 1
                return {"ok": True, "added": added, "updated": updated, "skipped": skipped}

            if cmd == "preview":
                try:
                    d = self.decrypt_payload(msg.get("source", ""))
                    return {
                        "ok": True,
                        "source": db.normalize_source(msg.get("source", "")),
                        "username": d["username"],
                        "has_password": bool(d["password"]),
                    }
                except (KeyError, cv.CryptoError):
                    return {"ok": False, "error": "not_found"}

            if cmd == "current":
                try:
                    d = self.decrypt_payload(msg.get("source", ""))
                    return {"ok": True, "username": d["username"]}
                except (KeyError, cv.CryptoError):
                    return {"ok": False, "error": "not_found"}

            if cmd == "get":
                try:
                    d = self.decrypt_payload(msg.get("source", ""))
                    return {"ok": True, "username": d["username"], "password": d["password"]}
                except (KeyError, cv.CryptoError):
                    return {"ok": False, "error": "not_found"}

            if cmd == "add_secret":
                ok = db.add_secret(
                    msg.get("source", ""),
                    self.encrypt_payload(msg.get("username", ""), msg.get("password", "")),
                )
                return {"ok": True} if ok else {"ok": False, "error": "duplicate"}

            if cmd == "update_secret":
                source = msg.get("source", "")
                try:
                    current = self.decrypt_payload(source)
                except (KeyError, cv.CryptoError):
                    return {"ok": False, "error": "not_found"}
                new_un = msg.get("username", "")
                new_pw = msg.get("password", "")
                final_un = new_un if new_un != "" else current["username"]
                final_pw = new_pw if new_pw != "" else current["password"]
                ok = db.update_secret(source, self.encrypt_payload(final_un, final_pw))
                return {"ok": True} if ok else {"ok": False, "error": "not_found"}

            if cmd == "delete_secret":
                ok = db.delete_secret(msg.get("source", ""))
                return {"ok": True} if ok else {"ok": False, "error": "not_found"}

            return {"ok": False, "error": "unknown_command"}
        except cv.CryptoError:
            return {"ok": False, "error": "crypto"}
        except Exception:
            return {"ok": False, "error": "internal"}

    # ---- server loop --------------------------------------------------
    def serve(self) -> None:
        ensure_vault_dir()
        _safe_unlink(SOCKET_PATH)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(SOCKET_PATH)
        restrict(SOCKET_PATH)
        try:
            os.chmod(SOCKET_PATH, 0o600)
        except OSError:
            pass
        with open(PID_PATH, "w") as f:
            f.write(str(os.getpid()))
        restrict(PID_PATH)
        srv.listen(8)

        def stop(_signum, _frame):
            self.running = False
            try:
                srv.close()
            except OSError:
                pass

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)

        while self.running:
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            try:
                self._serve_conn(conn)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

        self.dek = None
        self.token = None
        _safe_unlink(SOCKET_PATH)
        _safe_unlink(PID_PATH)
        _safe_unlink(TOKEN_PATH)

    def _serve_conn(self, conn) -> None:
        try:
            conn.settimeout(10)
            buf = b""
            while b"\n" not in buf and len(buf) < 1 << 20:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
            if not buf:
                return
            msg = json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))
            resp = self.handle(msg)
            if resp.get("shutdown"):
                self.dek = None
                self.token = None
                self.running = False
            conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
        except Exception:
            try:
                conn.sendall(b'{"ok": false, "error": "internal"}\n')
            except OSError:
                pass


def _safe_unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def main():
    daemon = VaultDaemon()
    daemon.serve()


if __name__ == "__main__":
    main()
