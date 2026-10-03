import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import common
import crypto_vault as cv
import db_vault as db


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(common, "VAULT_DIR", str(tmp_path))
    monkeypatch.setattr(common, "DB_PATH", str(tmp_path / "vault.db"))
    yield tmp_path


def _meta():
    salt = cv.generate_salt(16)
    dek = cv.generate_dek(32)
    derived = cv.derive_key("pw", salt, time_cost=2, memory_cost=32 * 1024 * 1024, hash_len=32)
    return {
        "format_version": "1",
        "kdf_alg": "argon2id",
        "salt": cv.b64e(salt),
        "wrapped_dek": cv.b64e(cv.wrap_dek(dek, derived)),
        "enc_alg": "xchacha20poly1305",
    }, dek


def test_schema_metadata_and_permissions(isolated):
    meta, _ = _meta()
    db.init_db(meta)
    assert db.is_initialized()
    assert db.get_metadata()["format_version"] == "1"
    mode = os.stat(common.DB_PATH).st_mode & 0o777
    assert mode == 0o600


def test_add_get_case_insensitive_duplicate_delete(isolated):
    meta, dek = _meta()
    db.init_db(meta)
    ep = cv.encrypt(b'{"username":"u","password":"p"}', dek)
    assert db.add_secret("GitHub", ep)
    assert not db.add_secret("github", ep)
    assert db.get_secret_payload("GITHUB") == ep
    assert db.get_secret_payload("github") == ep
    assert db.list_sources() == ["github"]


def test_update_changes_payload(isolated):
    meta, dek = _meta()
    db.init_db(meta)
    ep1 = cv.encrypt(b'{"username":"u","password":"p"}', dek)
    db.add_secret("github", ep1)
    ep2 = cv.encrypt(b'{"username":"u2","password":"p2"}', dek)
    assert db.update_secret("GitHub", ep2)
    assert db.get_secret_payload("github") == ep2
    assert db.get_secret_payload("github") != ep1


def test_delete_and_missing(isolated):
    meta, dek = _meta()
    db.init_db(meta)
    db.add_secret("github", cv.encrypt(b"{}", dek))
    assert db.delete_secret("GITHUB")
    assert not db.delete_secret("github")
    assert db.get_secret_payload("github") is None


def test_corrupt_database_handled(isolated):
    with open(common.DB_PATH, "wb") as f:
        f.write(b"this is not a sqlite database at all")
    assert db.is_initialized() is False


def test_plaintext_not_stored(isolated):
    meta, dek = _meta()
    db.init_db(meta)
    db.add_secret("github", cv.encrypt(b'{"username":"alice","password":"hunter2"}', dek))
    raw = open(common.DB_PATH, "rb").read()
    assert b"hunter2" not in raw
    assert b"alice" not in raw
