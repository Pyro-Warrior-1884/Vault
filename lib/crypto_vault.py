import base64

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
)
from nacl.pwhash.argon2id import kdf as argon2id_kdf
from nacl.utils import random as nacl_random


class CryptoError(Exception):
    pass


def generate_salt(length: int = 32) -> bytes:
    return nacl_random(length)


def generate_dek(length: int = 32) -> bytes:
    return nacl_random(length)


def derive_key(master_password: str, salt: bytes, *,
               time_cost: int = 4,
               memory_cost: int = 65536 * 1024,
               parallelism: int = 2,
               hash_len: int = 32) -> bytes:
    if not master_password:
        raise CryptoError("empty master password")
    out = argon2id_kdf(
        size=hash_len,
        password=master_password.encode("utf-8"),
        salt=salt,
        opslimit=time_cost,
        memlimit=memory_cost,
    )
    return out


def encrypt(plaintext: bytes, dek: bytes) -> bytes:
    if len(dek) < 32:
        raise CryptoError("invalid dek length")
    nonce = nacl_random(24)
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext,
        aad=b"",
        nonce=nonce,
        key=dek,
    )
    return nonce + ct


def decrypt(ciphertext: bytes, dek: bytes) -> bytes:
    if len(dek) < 32:
        raise CryptoError("invalid dek length")
    if len(ciphertext) < 24:
        raise CryptoError("invalid ciphertext")
    nonce = ciphertext[:24]
    ct = ciphertext[24:]
    try:
        pt = crypto_aead_xchacha20poly1305_ietf_decrypt(
            ct,
            aad=b"",
            nonce=nonce,
            key=dek,
        )
        return pt
    except Exception as e:
        raise CryptoError("decryption/authentication failed") from e


def wrap_dek(dek: bytes, derived_key: bytes) -> bytes:
    return encrypt(dek, derived_key)


def unwrap_dek(wrapped: bytes, derived_key: bytes) -> bytes:
    return decrypt(wrapped, derived_key)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))
