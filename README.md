# vault — Local Secret Manager for Termux

A small, offline, encrypted credential manager for Termux/Android.

`vault` stores **Source / Username / Password** records in a local SQLite
database. Secret material is encrypted with XChaCha20-Poly1305 under a random
data key, which is itself wrapped by an Argon2id-derived key from your master
password. The database is treated as hostile storage: an attacker who copies
`vault.db` sees only metadata and ciphertext.

- Local, offline, no network, no telemetry.
- Bash CLI front-end + Python crypto/SQLite back-end.
- `fzf` interactive picker, Termux clipboard integration.
- Versioned crypto format designed for future migration.

---

## 1. Requirements

- Termux (Android)
- `python` (3.10+), `python-pynacl`, `sqlite`, `fzf`, `termux-api`
- The **Termux:API** app installed (required for `termux-clipboard-set`)

```bash
pkg install python python-pynacl sqlite fzf termux-api
```

> `python-pynacl` provides libsodium bindings used for Argon2id and
> XChaCha20-Poly1305. We deliberately do **not** implement crypto ourselves.

---

## 2. Install

```bash
# from the project directory
bash install.sh
```

This installs the launcher to `$PREFIX/bin/vault` and the implementation to
`$PREFIX/share/vault/`. It never touches `~/.vault`, so upgrades preserve your
data. Missing dependencies are reported.

Verify:

```bash
vault help
```

### Run without installing

```bash
bash bin/vault help
```

(Use `bash bin/vault ...`; the repo scripts use `#!/usr/bin/env bash`, which
does not exist on Termux. `install.sh` rewrites shebangs to absolute paths.)

### Uninstall

```bash
bash install.sh --uninstall          # keeps ~/.vault
bash install.sh --uninstall --purge  # also deletes ~/.vault
```

---

## 3. Quick start

```bash
vault init       # create the vault (asks for a master password twice)
vault unlock     # derive key and open an unlocked session
vault add        # prompts: Source, Username, Password
vault show       # fzf picker, copies username then password
vault show github
vault edit github
vault delete github
vault lock
```

---

## 4. Commands

| Command | Needs unlock | Description |
| --- | --- | --- |
| `vault help` | no | Show usage. |
| `vault init` | no | Create the vault (salt, DEK, metadata, schema). |
| `vault unlock` | no | Prompt for master password, open a session. |
| `vault lock` | no | Close the session and clear key material. |
| `vault status` | no | Print `Vault is locked.` / `Vault is unlocked.` |
| `vault add` | yes | Add a Source/Username/Password record. |
| `vault show` | yes | `fzf` picker; decrypt and copy credentials. |
| `vault show <name>` | yes | Case-insensitive exact lookup and copy. |
| `vault edit` | yes | `fzf` picker; edit username/password. |
| `vault edit <name>` | yes | Edit username/password for a record. |
| `vault delete` | yes | `fzf` picker; delete with confirmation. |
| `vault delete <name>` | yes | Delete a record with confirmation. |

Notes:

- Passwords are **never** accepted as command-line arguments and never echoed.
- On `add`, a duplicate source prompts before overwriting (never silent).
- On `edit`, leaving a field empty keeps the existing value; leaving both empty
  prints `No changes made.` and writes nothing.
- `show` copies the **username**, then the **password**, so the password ends up
  in the clipboard last. Credentials are never printed to the terminal.
- Source names are normalized to lowercase for storage/lookup, so
  `vault show GitHub` and `vault show github` are the same record.

Example session:

```text
$ vault unlock
Master password:
✓ Vault unlocked

$ vault show github
✓ Credentials copied successfully

$ vault edit github
Editing: github
Current Username: pyro
New Username [leave empty to keep]:
New Password [leave empty to keep]:
✓ Secret 'github' updated
```

---

## 5. Encryption architecture

```
                 MASTER PASSWORD
                        │
                        ▼
                 Argon2id (salt)
                        │
                        ▼
             Password-Derived Key (32B)
                        │
                        ▼
              Encrypted DEK  (wrapped, base64 in metadata)
                        │
                        ▼
                       DEK (32B random)
                        │
                        ▼
         XChaCha20-Poly1305 over {"username","password"}
                        │
                        ▼
                    SQLite (BLOB)
```

- **KDF:** Argon2id via libsodium, 16-byte random salt, `opslimit=4`,
  `memlimit=64 MiB`, 32-byte output. Benchmarked at ~0.35 s on the test
  aarch64 device. Salt and parameters are stored in `vault_metadata`.
- **DEK:** 32 random bytes generated at `init`, independent of the password.
  Secret payloads are encrypted with the DEK.
- **Wrapping:** the DEK is encrypted with the password-derived key using
  XChaCha20-Poly1305 and stored base64 in metadata. Changing the master password
  later only requires re-wrapping the DEK, not re-encrypting every secret.
- **AEAD:** every payload uses XChaCha20-Poly1305 with a **fresh 24-byte random
  nonce**. Stored form is `nonce || ciphertext || tag`. The tag is verified
  before any plaintext is accepted; failures are treated as corruption/tampering.
- **Versioning:** `format_version = 1`, plus `kdf_alg`, `kdf_*`, `enc_alg`,
  `wrap_alg` so future migrations are possible.

---

## 6. Database schema

`~/.vault/vault.db` (mode `0600`):

```sql
CREATE TABLE vault_metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE secrets (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    source            TEXT NOT NULL UNIQUE,
    encrypted_payload BLOB NOT NULL,          -- nonce || ciphertext || tag
    created_at        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_secrets_source ON secrets(source);
```

- `source` is intentionally plaintext metadata (needed for search/display). It
  is **not** treated as a secret; usernames and passwords never appear in clear.
- All queries are parameterized.
- `vault_metadata` stores `format_version`, `kdf_*`, `salt`, `enc_alg`,
  `wrap_alg`, `wrapped_dek`.

---

## 7. Unlocked session model

The DEK must live somewhere while you work, but it must never touch disk. This
is handled by a short-lived daemon:

- `vault unlock` starts `vaultd` detached. It listens on `~/.vault/vault.sock`
  (mode `0600`) and holds the plaintext DEK **in memory only**.
- On successful unlock it writes a random **session token** to
  `~/.vault/session.token` (mode `0600`). Every subsequent request must present
  the token (constant-time compared).
- `vault lock` tells the daemon to clear the DEK and exit, then removes the
  socket/PID/token files.
- The daemon dies on reboot or crash; state never persists. Any command needing
  secrets fails closed with `Vault is locked. Run: vault unlock`.
- The Bash layer never sees or stores the DEK; it only talks to the daemon
  through `lib/vault_client.py`, sending secrets via **stdin** (never argv/env).

---

## 8. File layout

Repository:

```
vault/
├── bin/vault              # Bash CLI (orchestration)
├── lib/
│   ├── common.py          # paths, KDF constants, permissions
│   ├── crypto_vault.py    # Argon2id, XChaCha20-Poly1305, DEK wrapping
│   ├── db_vault.py        # SQLite schema + parameterized CRUD
│   ├── vaultd.py          # unlocked-session daemon
│   └── vault_client.py    # CLI ↔ daemon client (secret-safe I/O)
├── tests/                 # pytest suite
├── README.md
└── install.sh
```

Runtime:

```
~/.vault/
├── vault.db               # encrypted data + metadata (0600)
├── vault.sock             # session socket while unlocked (0600, transient)
├── vaultd.pid             # daemon pid (0600, transient)
└── session.token          # session token (0600, transient)
```

---

## 9. Security model / threat model

**Assumption: the database is hostile storage.** An attacker who obtains
`vault.db` can read source names, timestamps, KDF parameters, salt, and
ciphertext — but cannot recover usernames/passwords without the master password.

Protected:

- Master password is never stored anywhere.
- Usernames/passwords are stored only as AEAD ciphertext.
- The plaintext DEK is never written to disk.
- Wrong password / wrong key / tampered or truncated ciphertext all fail closed.
- Fresh nonce per encryption (no reuse).
- Secrets never appear in `argv`, environment variables, shell history, or logs.
- No network calls, no telemetry, no cloud.

Limitations you should understand:

- **Clipboard:** `show`/`copy` leaves credentials on the Android clipboard, which
  other apps may read. There is no auto-clear in V1. Treat the clipboard as
  semi-public and clear it manually when done.
- **Same-UID access:** on Termux all your processes share a UID, so a malicious
  script running as you could read the session token while unlocked. The token
  and socket permissions protect against other Android apps, not against
  code you run yourself while unlocked.
- **Unlock window:** while unlocked, the DEK is in the daemon's RAM. Lock when
  finished, especially on a shared/untrusted device.
- **Weak master password:** Argon2id slows guessing but cannot save a trivial
  password. Use a strong passphrase.
- **`ps`/history:** the design avoids passing secrets as arguments, but do not
  paste passwords into command lines or scripts yourself.
- **Backups:** `vault.db` is safe to copy (it is encrypted), but without the
  master password it is useless. There is no key escrow — lose the master
  password and the data is unrecoverable.

---

## 10. Testing

```bash
python3 -m pytest tests/ -q
```

The suite (28 tests) covers:

- **Crypto** (`tests/test_crypto.py`): round-trip; wrong key fails; tampered and
  truncated ciphertext fail; different nonces produce different ciphertext for
  the same plaintext; ciphertext does not contain plaintext; DEK wrap/unwrap;
  wrong password cannot unwrap; KDF determinism.
- **Database** (`tests/test_database.py`): schema + metadata + `0600` perms;
  add/get/delete; case-insensitive lookup; duplicate rejection; update changes
  ciphertext; missing records; corrupt DB handled; no plaintext stored.
- **CLI** (`tests/test_cli.py`): init; locked-state enforcement; wrong master
  password; unlock/lock/status (idempotent lock); add/show/edit/delete;
  edit-both-empty no-op; delete of nonexistent; duplicate prompt; `fzf` flows;
  and explicit security checks (no plaintext in the DB, no tracebacks, DEK not
  on disk).

Tests use generated dummy credentials only.

Set `VAULT_DEBUG=1` to surface Python tracebacks and a daemon log for
troubleshooting (still never prints secret contents).

---

## 11. Known limitations

- Clipboard is not auto-cleared.
- UNIX socket paths are limited to ~108 bytes, so keep `VAULT_DIR` short
  (the default `~/.vault` is fine).
- `edit` cannot rename a source or set a field to an empty string (empty means
  "keep"). Renaming is planned.
- The `fzf` preview shows the password masked as `********` rather than a
  ciphertext fingerprint. (A truncated ciphertext hash could be added later.)
- Single user, local only; no sync/backup/export yet.

---

## 12. Future improvements

`vault generate`, `vault search`, `vault edit` (rename), `vault change-password`,
`vault backup` / `restore`, `vault export` / `import`, `vault history`,
clipboard auto-clear/timeout, and biometric unlock via Termux:API.

The schema and versioned crypto format were designed so these can be added
without breaking existing vaults.

---

## 13. Troubleshooting

- `bad interpreter: /usr/bin/env: no such file or directory` — run scripts with
  `bash <script>`, or run `install.sh` (which writes absolute shebangs for the
  installed copies).
- Clipboard not working — install the **Termux:API** app and the `termux-api`
  package; `termux-clipboard-set` must be on `PATH`.
- `OSError: AF_UNIX path too long` — use a shorter `VAULT_DIR`.
- `Vault is not initialized. Run: vault init` — expected on a fresh install.
- `✗ Invalid master password` — the password or the wrapped DEK did not verify;
  the message is intentionally generic.
