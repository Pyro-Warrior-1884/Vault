import sqlite3
from typing import List, Optional

import common
from common import ensure_vault_dir, restrict


SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL UNIQUE,
    encrypted_payload BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_secrets_source ON secrets(source);
"""


def _connect():
    conn = sqlite3.connect(common.DB_PATH, isolation_level=None)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(metadata: dict) -> None:
    ensure_vault_dir()
    conn = _connect()
    try:
        conn.executescript(SCHEMA)
        for k, v in metadata.items():
            conn.execute(
                "INSERT OR REPLACE INTO vault_metadata (key, value) VALUES (?, ?)",
                (k, str(v)),
            )
    finally:
        conn.close()
    restrict(common.DB_PATH)


def is_initialized() -> bool:
    try:
        conn = _connect()
        try:
            cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}
        finally:
            conn.close()
        return {"vault_metadata", "secrets"} <= tables
    except sqlite3.Error:
        return False


def get_metadata() -> dict:
    conn = _connect()
    try:
        cur = conn.execute("SELECT key, value FROM vault_metadata")
        return {k: v for k, v in cur.fetchall()}
    finally:
        conn.close()


def normalize_source(source: str) -> str:
    return (source or "").strip().lower()


def add_secret(source: str, encrypted_payload: bytes) -> bool:
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO secrets (source, encrypted_payload) VALUES (?, ?)",
            (normalize_source(source), sqlite3.Binary(encrypted_payload)),
        )
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def update_secret(source: str, encrypted_payload: bytes) -> bool:
    conn = _connect()
    try:
        cur = conn.execute(
            "UPDATE secrets SET encrypted_payload=?, updated_at=CURRENT_TIMESTAMP WHERE source=?",
            (sqlite3.Binary(encrypted_payload), normalize_source(source)),
        )
        return cur.rowcount > 0
    finally:
        conn.close()


def get_secret_payload(source: str) -> Optional[bytes]:
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT encrypted_payload FROM secrets WHERE source=?",
            (normalize_source(source),),
        )
        row = cur.fetchone()
        return bytes(row[0]) if row else None
    finally:
        conn.close()


def delete_secret(source: str) -> bool:
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM secrets WHERE source=?", (normalize_source(source),))
        return cur.rowcount > 0
    finally:
        conn.close()


def list_sources() -> List[str]:
    conn = _connect()
    try:
        cur = conn.execute("SELECT source FROM secrets ORDER BY source")
        return [r[0] for r in cur.fetchall()]
    finally:
        conn.close()
