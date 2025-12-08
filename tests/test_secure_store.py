# tests/test_secure_store.py
import os
import json
import tempfile
from pathlib import Path
import pytest
from cryptography.fernet import Fernet
from unittest.mock import patch

from core.secure_store import (
    encrypt_and_write,
    decrypt_and_read,
    read_and_decrypt,
    encryption_available,
    _atomic_write_bytes,
    _atomic_write_text,
    _load_or_create_keys,
    FERNET_KEYS,
    FERNET_INSTANCES,
)

SAMPLE = {"hello": "world", "_meta": {"fetched": "2025"}}


# -------------------------------------------------------------
# FIXTURE: Clean environment for every test
# -------------------------------------------------------------
@pytest.fixture
def clean_secure_store():
    keys_file = Path(__file__).resolve().parent.parent / "data" / "fernet-keys.json"

    # Reset global state
    FERNET_KEYS.clear()
    FERNET_INSTANCES.clear()

    # Reset loader cache
    _load_or_create_keys.cache_clear()

    # Remove key file
    if keys_file.exists():
        keys_file.unlink()

    yield

    # Cleanup again
    FERNET_KEYS.clear()
    FERNET_INSTANCES.clear()
    _load_or_create_keys.cache_clear()

    if keys_file.exists():
        keys_file.unlink()


# -------------------------------------------------------------
# ATOMIC WRITE TESTS
# -------------------------------------------------------------
def test_atomic_write_bytes(clean_secure_store):
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "x.bin")
        _atomic_write_bytes(p, b"abc")
        assert open(p, "rb").read() == b"abc"


def test_atomic_write_text(clean_secure_store):
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "x.json")
        _atomic_write_text(p, '{"a":1}')
        assert open(p).read() == '{"a":1}'


# -------------------------------------------------------------
# KEY GENERATION + ENCRYPT/DECRYPT
# -------------------------------------------------------------
def test_encrypt_and_write_generates_key(clean_secure_store):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "snap.json.enc")

        out = encrypt_and_write(SAMPLE, path)

        assert out.endswith(".enc")
        assert os.path.exists(out)

        # Key file must exist
        keyfile = Path(__file__).resolve().parent.parent / "data" / "fernet-keys.json"
        assert keyfile.exists()

        dec = decrypt_and_read(path)
        assert dec == SAMPLE


def test_encrypt_and_write_reuses_existing_key(clean_secure_store):
    with tempfile.TemporaryDirectory() as tmp:
        p1 = os.path.join(tmp, "a.json")
        p2 = os.path.join(tmp, "b.json")

        encrypt_and_write(SAMPLE, p1)
        encrypt_and_write({"x": 1}, p2)

        assert decrypt_and_read(p1) == SAMPLE
        assert decrypt_and_read(p2)["x"] == 1


# -------------------------------------------------------------
# DECRYPT BEHAVIOR
# -------------------------------------------------------------
def test_decrypt_prefers_encrypted_if_exists(clean_secure_store):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "data.json")

        fake_key = Fernet.generate_key()
        fake_f = Fernet(fake_key)

        # Correct patch: mutate the list, don't replace it
        with patch("core.secure_store._load_or_create_keys", return_value=[fake_key]):
            FERNET_INSTANCES.clear()
            FERNET_INSTANCES.append(fake_f)

            encrypt_and_write({"ok": True}, path)

        assert os.path.exists(path + ".enc")
        assert decrypt_and_read(path) == {"ok": True}


def test_decrypt_falls_back_to_plaintext(clean_secure_store):
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "plain.json")

        with open(p, "w", encoding="utf-8") as fh:
            json.dump(SAMPLE, fh)

        assert decrypt_and_read(p) == SAMPLE


def test_decrypt_tries_both_paths(clean_secure_store):
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "snap.json")
        encp = base + ".enc"

        key = Fernet.generate_key()
        f = Fernet(key)

        token = f.encrypt(json.dumps(SAMPLE).encode())
        with open(encp, "wb") as fh:
            fh.write(token)

        with patch("core.secure_store.FERNET_INSTANCES", [f]):
            with patch("core.secure_store._load_or_create_keys", return_value=[key]):
                dec = decrypt_and_read(base)
                assert dec == SAMPLE


# -------------------------------------------------------------
# PLAINTEXT FALLBACK WHEN NO KEY
# -------------------------------------------------------------
def test_plaintext_fallback_when_no_key(clean_secure_store):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "fallback.json")

        # no key returned
        with patch("core.secure_store._load_or_create_keys", return_value=[]):
            with patch("core.secure_store.FERNET_INSTANCES", []):
                out = encrypt_and_write(SAMPLE, path)
                assert out == path  # plaintext
                assert os.path.exists(path)

        assert decrypt_and_read(path) == SAMPLE


# -------------------------------------------------------------
# CORRUPTED KEY FILE → regeneration
# -------------------------------------------------------------
def test_corrupted_key_file_regenerated(clean_secure_store):
    keyfile = Path(__file__).resolve().parent.parent / "data" / "fernet-keys.json"
    keyfile.parent.mkdir(exist_ok=True)
    keyfile.write_text("{ BAD JSON [[[")  # corrupt

    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "test.json")
        encrypt_and_write(SAMPLE, p)

    assert keyfile.exists()
    data = json.loads(keyfile.read_text())
    assert "keys" in data
    assert len(data["keys"]) >= 1


# -------------------------------------------------------------
# MISC
# -------------------------------------------------------------
def test_read_and_decrypt_alias(clean_secure_store):
    assert read_and_decrypt is decrypt_and_read


def test_encryption_available(clean_secure_store):
    # True case
    with patch("core.secure_store._load_or_create_keys", return_value=[Fernet.generate_key()]):
        with patch("core.secure_store.FERNET_INSTANCES", [Fernet(Fernet.generate_key())]):
            assert encryption_available() is True

    # False case
    with patch("core.secure_store._load_or_create_keys", return_value=[]):
        with patch("core.secure_store.FERNET_INSTANCES", []):
            assert encryption_available() is False
