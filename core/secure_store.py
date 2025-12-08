# core/secure_store.py
import os
import json
import time
import base64
import logging
from pathlib import Path
from datetime import datetime, timedelta
from functools import lru_cache

try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    Fernet = None
    InvalidToken = Exception  # fallback

from core import config

logger = logging.getLogger("secure_store")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

# Paths
BASE_DIR = Path(config.DATA_DIR)
KEYS_FILE = BASE_DIR / "fernet-keys.json"
KEY_ROTATE_DAYS = 90

# Atomic write helpers
def _atomic_write_bytes(path: str, data: bytes, max_retries: int = 3):
    for attempt in range(1, max_retries + 1):
        try:
            tmp = path + ".tmp"
            with open(tmp, "wb") as fh:
                fh.write(data)
            os.replace(tmp, path)
            return
        except Exception as e:
            logger.warning("atomic write bytes failed attempt %d for %s: %s", attempt, path, e)
            time.sleep(0.25 * attempt)
    raise IOError(f"Failed to write bytes to {path} after {max_retries} attempts")

def _atomic_write_text(path: str, text: str, max_retries: int = 3):
    for attempt in range(1, max_retries + 1):
        try:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(text)
            os.replace(tmp, path)
            return
        except Exception as e:
            logger.warning("atomic write text failed attempt %d for %s: %s", attempt, path, e)
            time.sleep(0.25 * attempt)
    raise IOError(f"Failed to write text to {path} after {max_retries} attempts")

# Key management
def _load_or_create_keys():
    """
    Return list of byte keys (newest last). Strategy:
     - Respect config.FERNET_KEY or env IAM_XRAY_FERNET_KEY
     - Otherwise use KEYS_FILE if present
     - Otherwise generate & persist a new key
    """
    keys = []

    # 1) config/env override
    try:
        cfg = getattr(config, "FERNET_KEY", None)
        if cfg:
            if isinstance(cfg, str):
                keys.append(cfg.encode())
            else:
                keys.append(cfg)
    except Exception:
        pass

    envk = os.getenv("IAM_XRAY_FERNET_KEY")
    if envk:
        keys.append(envk.encode())

    # 2) on-disk keys file
    try:
        if KEYS_FILE.exists():
            raw = json.loads(KEYS_FILE.read_text(encoding="utf-8"))
            file_keys = raw.get("keys", []) or []
            for k in file_keys:
                if isinstance(k, str):
                    keys.append(k.encode())
    except Exception as e:
        logger.debug("Failed to read keys file: %s", e)
        # keep going

    # 3) generate if none
    if not keys:
        if Fernet is None:
            logger.warning("cryptography.Fernet not available; cannot generate Fernet key.")
            return []
        try:
            new_k = Fernet.generate_key()
            keys = [new_k]
            KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
            json.dump({"keys": [new_k.decode()], "created_at": datetime.utcnow().isoformat()}, KEYS_FILE.open("w", encoding="utf-8"), indent=2)
            logger.info("Generated new Fernet key and saved to %s", str(KEYS_FILE))
        except Exception as e:
            logger.error("Failed to generate/persist Fernet key: %s", e)
            return []

    # normalize bytes
    normalized = []
    for k in keys:
        if isinstance(k, str):
            normalized.append(k.encode())
        elif isinstance(k, bytes):
            normalized.append(k)
    return normalized

# Initialize instances (newest last)
FERNET_KEYS = _load_or_create_keys()
PRIMARY_KEY = FERNET_KEYS[-1] if FERNET_KEYS else None
FERNET_INSTANCES = []
if Fernet and FERNET_KEYS:
    try:
        FERNET_INSTANCES = [Fernet(k) for k in FERNET_KEYS]
    except Exception:
        FERNET_INSTANCES = []

# Public API
def encrypt_and_write(obj, path: str, max_retries: int = 3):
    """
    Encrypts `obj` and writes to disk. If path doesn't end with .enc, we write to path + '.enc'.
    Returns the final path that was written.
    """
    if not path:
        raise ValueError("path required")

    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    target_path = path if path.endswith(".enc") else path + ".enc"

    if not FERNET_INSTANCES:
        # fallback to plaintext write
        logger.warning("No fernet keys available; writing plaintext JSON to %s", target_path.replace(".enc", ""))
        fallback = path if not path.endswith(".enc") else path[:-4]
        _atomic_write_text(fallback, json.dumps(obj, indent=2, default=str), max_retries=max_retries)
        return fallback

    try:
        raw = json.dumps(obj, indent=2, default=str).encode("utf-8")
        enc = FERNET_INSTANCES[-1].encrypt(raw)
        _atomic_write_bytes(target_path, enc, max_retries=max_retries)
        logger.info("Encrypted snapshot written to %s", target_path)
        return target_path
    except Exception as e:
        logger.error("encrypt_and_write failed: %s", e)
        raise

def decrypt_and_read(path: str, max_retries: int = 3):
    """
    Decrypts and returns parsed JSON. Tries path and path + '.enc' if needed.
    If decryption fails, tries plaintext JSON decode.
    """
    if not path:
        raise ValueError("path required")
    tried = [path]
    if not path.endswith(".enc"):
        tried.append(path + ".enc")
    last_err = None

    for p in tried:
        if not os.path.exists(p):
            continue
        # read bytes
        try:
            with open(p, "rb") as fh:
                raw = fh.read()
        except Exception as e:
            last_err = e
            logger.warning("Failed to read %s: %s", p, e)
            continue

        # if we have fernet instances, try to decrypt using each (newest-first)
        if FERNET_INSTANCES:
            for f in reversed(FERNET_INSTANCES):
                try:
                    dec = f.decrypt(raw)
                    return json.loads(dec.decode("utf-8"))
                except InvalidToken:
                    # wrong key, try next
                    continue
                except Exception as e:
                    last_err = e
                    logger.debug("Decrypt attempt failed: %s", e)
                    continue
        # try plaintext decode as a fallback
        try:
            text = raw.decode("utf-8")
            return json.loads(text)
        except Exception as e:
            last_err = e
            logger.debug("Plaintext decode failed for %s: %s", p, e)
            continue

    if last_err:
        raise last_err
    return None

# alias for backwards-compat
read_and_decrypt = decrypt_and_read
