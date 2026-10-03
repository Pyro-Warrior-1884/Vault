import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import crypto_vault as cv


def test_encrypt_decrypt_roundtrip():
    dek = cv.generate_dek(32)
    pt = b"hello world"
    ct = cv.encrypt(pt, dek)
    assert ct != pt
    assert cv.decrypt(ct, dek) == pt


def test_wrong_key_fails():
    dek1 = cv.generate_dek(32)
    dek2 = cv.generate_dek(32)
    ct = cv.encrypt(b"secret", dek1)
    try:
        cv.decrypt(ct, dek2)
        assert False, "decryption with wrong key should fail"
    except cv.CryptoError:
        pass


def test_tamper_detected():
    dek = cv.generate_dek(32)
    ct = bytearray(cv.encrypt(b"secret", dek))
    ct[24] ^= 0xFF
    try:
        cv.decrypt(bytes(ct), dek)
        assert False, "tampered ciphertext should fail"
    except cv.CryptoError:
        pass


def test_truncated_ciphertext_fails():
    dek = cv.generate_dek(32)
    try:
        cv.decrypt(b"short", dek)
        assert False, "short ciphertext should fail"
    except cv.CryptoError:
        pass


def test_nonces_different_same_plaintext():
    dek = cv.generate_dek(32)
    pt = b"same"
    ct1 = cv.encrypt(pt, dek)
    ct2 = cv.encrypt(pt, dek)
    assert ct1 != ct2


def test_ciphertext_does_not_contain_plaintext():
    dek = cv.generate_dek(32)
    pt = b"SUPER-SECRET-VALUE"
    ct = cv.encrypt(pt, dek)
    assert pt not in ct


def test_wrap_unwrap_roundtrip():
    salt = cv.generate_salt(16)
    derived = cv.derive_key("pw", salt, time_cost=2, memory_cost=32 * 1024 * 1024, hash_len=32)
    dek = cv.generate_dek(32)
    wrapped = cv.wrap_dek(dek, derived)
    assert wrapped != dek
    assert cv.unwrap_dek(wrapped, derived) == dek


def test_wrong_password_cannot_unwrap():
    salt = cv.generate_salt(16)
    k1 = cv.derive_key("right", salt, time_cost=2, memory_cost=32 * 1024 * 1024, hash_len=32)
    k2 = cv.derive_key("wrong", salt, time_cost=2, memory_cost=32 * 1024 * 1024, hash_len=32)
    dek = cv.generate_dek(32)
    wrapped = cv.wrap_dek(dek, k1)
    try:
        cv.unwrap_dek(wrapped, k2)
        assert False, "wrong password should not unwrap DEK"
    except cv.CryptoError:
        pass


def test_derive_key_is_deterministic():
    salt = cv.generate_salt(16)
    a = cv.derive_key("pw", salt, time_cost=2, memory_cost=32 * 1024 * 1024, hash_len=32)
    b = cv.derive_key("pw", salt, time_cost=2, memory_cost=32 * 1024 * 1024, hash_len=32)
    assert a == b
