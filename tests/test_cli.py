import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB = os.path.join(ROOT, "lib")
VAULT = os.path.join(ROOT, "bin", "vault")

MASTER = "correct horse battery staple"


@pytest.fixture
def env(tmp_path):
    # UNIX socket paths are limited to ~108 bytes, and pytest's tmp_path is
    # too long for that, so use a short dedicated temp dir.
    short = tempfile.mkdtemp(prefix="vt-", dir=tempfile.gettempdir())
    vault_dir = os.path.join(short, "v")
    os.mkdir(vault_dir)
    mock = os.path.join(short, "b")
    os.mkdir(mock)
    clip = os.path.join(short, "clip.txt")

    clip_tool = os.path.join(mock, "termux-clipboard-set")
    with open(clip_tool, "w") as f:
        f.write(
            "#!/data/data/com.termux/files/usr/bin/bash\n"
            "cat > {}\n".format(clip)
        )
    os.chmod(clip_tool, 0o755)

    fzf = os.path.join(mock, "fzf")
    with open(fzf, "w") as f:
        f.write(
            "#!/data/data/com.termux/files/usr/bin/bash\n"
            "cat > /dev/null\n"
            'printf "%s\\n" "$FZF_CHOICE"\n'
        )
    os.chmod(fzf, 0o755)

    sms_log = os.path.join(short, "sms.txt")
    sms_tool = os.path.join(mock, "termux-sms-send")
    with open(sms_tool, "w") as f:
        f.write(
            "#!/data/data/com.termux/files/usr/bin/bash\n"
            "printf '%s\\n' \"$@\" > {}\n".format(sms_log)
        )
    os.chmod(sms_tool, 0o755)

    phone = os.path.join(short, "phone")

    e = dict(os.environ)
    e["VAULT_DIR"] = vault_dir
    e["PATH"] = mock + os.pathsep + e["PATH"]
    e["FZF_CHOICE"] = "github"
    e["PHONE"] = phone
    e["PHONENO"] = "15550001111"
    e["PYTHONPATH"] = LIB + os.pathsep + e.get("PYTHONPATH", "")
    ctx = {
        "env": e,
        "vault_dir": vault_dir,
        "clip": clip,
        "tmp": short,
        "phone": phone,
        "sms_log": sms_log,
    }
    yield ctx
    subprocess.run(["bash", VAULT, "lock"], capture_output=True, text=True, env=e, timeout=30)
    shutil.rmtree(short, ignore_errors=True)


def run(env, args, stdin="", choice=None):
    e = dict(env["env"])
    if choice is not None:
        e["FZF_CHOICE"] = choice
    return subprocess.run(
        ["bash", VAULT] + args,
        input=stdin,
        capture_output=True,
        text=True,
        env=e,
        timeout=60,
    )


def init(env):
    return run(env, ["init"], stdin=MASTER + "\n" + MASTER + "\n")


def unlock(env):
    return run(env, ["unlock"], stdin=MASTER + "\n")


def add(env, source, user, pw):
    return run(env, ["add"], stdin="{}\n{}\n{}\n".format(source, user, pw))


def db_bytes(env):
    with open(os.path.join(env["vault_dir"], "vault.db"), "rb") as f:
        return f.read()


def test_init_creates_db_with_restrictive_perms(env):
    r = init(env)
    assert r.returncode == 0, r.stderr + r.stdout
    db = os.path.join(env["vault_dir"], "vault.db")
    assert os.path.exists(db)
    assert (os.stat(db).st_mode & 0o777) == 0o600


def test_requires_initialization(env):
    r = run(env, ["status"])
    assert r.returncode != 0
    assert "not initialized" in r.stdout


def test_locked_blocks_secret_commands(env):
    init(env)
    r = run(env, ["show", "github"])
    assert r.returncode != 0
    assert "locked" in r.stdout.lower()


def test_wrong_master_password(env):
    init(env)
    r = run(env, ["unlock"], stdin="wrong password\n")
    assert r.returncode != 0
    assert "Invalid master password" in r.stdout


def test_unlock_lock_status(env):
    init(env)
    assert "unlocked" in unlock(env).stdout.lower()
    assert "unlocked" in run(env, ["status"]).stdout
    r = run(env, ["lock"])
    assert "locked" in r.stdout.lower()
    r2 = run(env, ["lock"])
    assert "already locked" in r2.stdout.lower()
    assert "locked" in run(env, ["status"]).stdout


def test_add_show_edit_delete(env):
    init(env)
    unlock(env)
    r = add(env, "GitHub", "alice", "hunter2")
    assert "added" in r.stdout

    # show named copies password last
    r = run(env, ["show", "github"])
    assert "Credentials copied" in r.stdout
    assert open(env["clip"]).read() == "hunter2"

    # case-insensitive edit, username-only change keeps password
    r = run(env, ["edit", "GITHUB"], stdin="alice2\n\n")
    assert "updated" in r.stdout
    r = run(env, ["show", "github"])
    assert open(env["clip"]).read() == "hunter2"

    # delete with confirmation
    r = run(env, ["delete", "github"], stdin="y\n")
    assert "deleted" in r.stdout
    assert run(env, ["show", "github"]).returncode != 0


def test_edit_both_empty_is_noop(env):
    init(env)
    unlock(env)
    add(env, "github", "alice", "hunter2")
    r = run(env, ["edit", "github"], stdin="\n\n")
    assert "No changes made" in r.stdout


def test_delete_nonexistent(env):
    init(env)
    unlock(env)
    r = run(env, ["delete", "nope"], stdin="y\n")
    assert r.returncode != 0
    assert "No such source found" in r.stdout


def test_duplicate_source_prompts_and_aborts(env):
    init(env)
    unlock(env)
    add(env, "github", "alice", "hunter2")
    r = run(env, ["add"], stdin="github\nbob\nnewpw\nn\n")
    assert "already exists" in r.stdout
    assert "Aborted" in r.stdout
    # original password preserved
    run(env, ["show", "github"])
    assert open(env["clip"]).read() == "hunter2"


def test_fzf_show_and_delete(env):
    init(env)
    unlock(env)
    add(env, "github", "alice", "hunter2")
    r = run(env, ["show"], choice="github")
    assert "Credentials copied" in r.stdout
    assert open(env["clip"]).read() == "hunter2"
    r = run(env, ["delete"], stdin="y\n", choice="github")
    assert "deleted" in r.stdout


# ---- backup ---------------------------------------------------------------
def backup_file(env):
    return os.path.join(env["phone"], "Personal", "Training_Routine.json")


def test_backup_creates_json_and_sends_sms(env):
    init(env)
    unlock(env)
    add(env, "GitHub", "alice", "hunter2")
    add(env, "gitlab", "bob", "secret99")
    r = run(env, ["backup"])
    assert r.returncode == 0, r.stderr + r.stdout
    assert "Backup saved" in r.stdout
    path = backup_file(env)
    assert os.path.exists(path)
    with open(path) as f:
        data = json.load(f)
    assert data["count"] == 2
    assert re.fullmatch(r"\d{2}/\d{2}/\d{4} \d{2}:\d{2} (AM|PM)", data["exported_at"])
    by_src = {s["source"]: s for s in data["secrets"]}
    assert by_src["github"]["username"] == "alice"
    assert by_src["github"]["password"] == "hunter2"
    assert by_src["gitlab"]["username"] == "bob"
    assert by_src["gitlab"]["password"] == "secret99"
    assert "sms_failed" not in r.stdout
    sms = open(env["sms_log"]).read().splitlines()
    assert "-n" in sms
    assert "15550001111" in sms
    assert "Vault backup complete" in sms


def test_backup_requires_unlock(env):
    init(env)
    r = run(env, ["backup"])
    assert r.returncode != 0
    assert "locked" in r.stdout.lower()
    assert not os.path.exists(backup_file(env))


def test_backup_overwrites_silently(env):
    init(env)
    unlock(env)
    add(env, "github", "alice", "hunter2")
    assert run(env, ["backup"]).returncode == 0
    r = run(env, ["edit", "github"], stdin="alice\nnewpass\n")
    assert "updated" in r.stdout
    r = run(env, ["backup"])
    assert r.returncode == 0, r.stderr + r.stdout
    with open(backup_file(env)) as f:
        data = json.load(f)
    assert data["count"] == 1
    assert data["secrets"][0]["password"] == "newpass"


# ---- restore --------------------------------------------------------------
def test_restore_roundtrip(env):
    init(env)
    unlock(env)
    add(env, "GitHub", "alice", "hunter2")
    add(env, "gitlab", "bob", "secret99")
    assert run(env, ["backup"]).returncode == 0
    assert run(env, ["delete", "github"], stdin="y\n").returncode == 0
    assert run(env, ["delete", "gitlab"], stdin="y\n").returncode == 0
    r = run(env, ["restore"])
    assert r.returncode == 0, r.stderr + r.stdout
    assert "Restore complete: 2 added, 0 updated, 0 skipped" in r.stdout
    run(env, ["show", "github"])
    assert open(env["clip"]).read() == "hunter2"
    run(env, ["show", "gitlab"])
    assert open(env["clip"]).read() == "secret99"


def test_restore_requires_unlock(env):
    init(env)
    r = run(env, ["restore"])
    assert r.returncode != 0
    assert "locked" in r.stdout.lower()


def test_restore_missing_file(env):
    init(env)
    unlock(env)
    r = run(env, ["restore"])
    assert r.returncode != 0
    assert "No backup found" in r.stdout
    assert "Traceback" not in r.stderr


def test_restore_invalid_json(env):
    init(env)
    unlock(env)
    os.makedirs(os.path.dirname(backup_file(env)), exist_ok=True)
    with open(backup_file(env), "w") as f:
        f.write("{not json")
    r = run(env, ["restore"])
    assert r.returncode != 0
    assert "invalid" in r.stdout.lower()
    assert "Traceback" not in r.stderr


def test_restore_conflict_declined(env):
    init(env)
    unlock(env)
    add(env, "github", "alice", "hunter2")
    add(env, "gitlab", "bob", "secret99")
    assert run(env, ["backup"]).returncode == 0
    r = run(env, ["edit", "github"], stdin="alice\nnewpass\n")
    assert "updated" in r.stdout
    assert run(env, ["delete", "gitlab"], stdin="y\n").returncode == 0
    add(env, "twitter", "carol", "pw3")
    r = run(env, ["restore"], stdin="n\n")
    assert r.returncode == 0, r.stderr + r.stdout
    assert "Already in vault: github" in r.stdout
    assert "Restore complete: 1 added, 0 updated, 1 skipped" in r.stdout
    run(env, ["show", "github"])
    assert open(env["clip"]).read() == "newpass"
    run(env, ["show", "gitlab"])
    assert open(env["clip"]).read() == "secret99"
    run(env, ["show", "twitter"])
    assert open(env["clip"]).read() == "pw3"


def test_restore_conflict_accepted(env):
    init(env)
    unlock(env)
    add(env, "github", "alice", "hunter2")
    assert run(env, ["backup"]).returncode == 0
    r = run(env, ["edit", "github"], stdin="alice\nnewpass\n")
    assert "updated" in r.stdout
    r = run(env, ["restore"], stdin="y\n")
    assert r.returncode == 0, r.stderr + r.stdout
    assert "Already in vault: github" in r.stdout
    assert "Restore complete: 0 added, 1 updated, 0 skipped" in r.stdout
    run(env, ["show", "github"])
    assert open(env["clip"]).read() == "hunter2"


def test_restore_empty_backup(env):
    init(env)
    unlock(env)
    assert run(env, ["backup"]).returncode == 0
    r = run(env, ["restore"])
    assert r.returncode == 0, r.stderr + r.stdout
    assert "Backup contains no secrets." in r.stdout


# ---- security assertions -------------------------------------------------
def test_sqlite_never_contains_plaintext(env):
    init(env)
    unlock(env)
    add(env, "github", "alice", "hunter2-SUPER-SECRET")
    raw = db_bytes(env)
    assert b"hunter2-SUPER-SECRET" not in raw
    assert b"alice" not in raw
    assert MASTER.encode() not in raw


def test_no_traceback_on_bad_input(env):
    init(env)
    unlock(env)
    # empty source should be rejected without a traceback
    r = run(env, ["add"], stdin="\n\n\n")
    assert "Traceback" not in r.stdout
    assert "Traceback" not in r.stderr


def test_dek_not_written_to_disk(env):
    init(env)
    unlock(env)
    add(env, "github", "alice", "hunter2")
    # no decrypted key material should exist anywhere in the vault dir
    for root, _dirs, files in os.walk(env["vault_dir"]):
        for name in files:
            path = os.path.join(root, name)
            if not os.path.isfile(path):
                continue
            with open(path, "rb") as f:
                assert b"hunter2" not in f.read()
