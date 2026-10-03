import os
import stat

VAULT_DIR = os.path.abspath(os.path.expanduser(os.environ.get("VAULT_DIR", "~/.vault")))
DB_PATH = os.path.join(VAULT_DIR, "vault.db")
SOCKET_PATH = os.path.join(VAULT_DIR, "vault.sock")
PID_PATH = os.path.join(VAULT_DIR, "vaultd.pid")
TOKEN_PATH = os.path.join(VAULT_DIR, "session.token")

FORMAT_VERSION = 1
KDF_ALG = "argon2id"
# Benchmarked on this device: ops=4 / 64 MiB ~= 0.35 s.
KDF_TIME_COST = 4
KDF_MEMORY_COST = 64 * 1024 * 1024  # bytes
KDF_PARALLELISM = 2  # informational; PyNaCl/libsodium fixes lanes
KDF_HASH_LEN = 32
ENC_ALG = "xchacha20poly1305"
WRAP_ALG = "xchacha20poly1305"

SOCKET_TIMEOUT = 8.0


def ensure_vault_dir():
    os.makedirs(VAULT_DIR, exist_ok=True)
    try:
        os.chmod(VAULT_DIR, stat.S_IRWXU)
    except OSError:
        pass
    return VAULT_DIR


def restrict(path):
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
