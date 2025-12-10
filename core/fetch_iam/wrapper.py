"""
IAM X-Ray — Unified Fetch Wrapper (v1.0 Enterprise Sync)

This file now acts as the HIGH-LEVEL WRAPPER around the new enterprise
engine located in core/fetch_iam/engine.py.

Responsibilities of this wrapper:
---------------------------------
✓ Snapshot load (.json or .enc)
✓ Snapshot caching + TTL logic
✓ Snapshot diff engine (your existing robust implementation)
✓ secure_store integration (encrypt/decrypt)
✓ Write snapshot safely
✓ Multi-region orchestrator wrapper
✓ Backward-compatible public API for main.py and UI

NOT responsible for:
--------------------
x Fetching IAM users/roles/policies  (moved to enterprise engine)
x Trust policy parsing                (moved to trust_policy.py)
x Policy expansion                    (moved to iam_policies.py)
x Action→resource mapping             (moved to resolver.py)
x Resource inventory fetch            (moved to resource_fetch.py)
"""
import os
import json
import logging
import warnings
from datetime import datetime, timezone
from copy import deepcopy
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, NoRegionError

from core import secure_store
from core import config
from core.cleanup import purge_old_snapshots

# 🚀 NEW ENTERPRISE ENGINE
from core.fetch_iam.engine import orchestrate_fetch
from core.fetch_iam import metadata as meta_mod


logger = logging.getLogger("fetch_iam")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)


# -----------------------------------------------------------------------------
#                           Snapshot Read Utilities
# -----------------------------------------------------------------------------
def _plaintext_read(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
            return json.loads(raw) if raw else None
    except Exception:
        return None


def load_snapshot(path):
    """
    Graceful loader:
    - If path.json missing but path.json.enc exists → load encrypted version
    - Returns None when snapshot not found
    """
    if not path:
        return None

    candidates = []
    if os.path.exists(path):
        candidates.append(path)
    if os.path.exists(path + ".enc"):
        candidates.append(path + ".enc")

    if not candidates:
        return None

    last_err = None
    for p in candidates:
        # Try decrypt
        try:
            if hasattr(secure_store, "decrypt_and_read"):
                return secure_store.decrypt_and_read(p)
            if hasattr(secure_store, "read_and_decrypt"):
                return secure_store.read_and_decrypt(p)
        except Exception as e:
            last_err = e

        # Try plaintext
        try:
            res = _plaintext_read(p)
            if res:
                return res
        except Exception as e:
            last_err = e

    if last_err:
        logger.warning(f"Failed to load snapshot: {last_err}")
    return None


# -----------------------------------------------------------------------------
#                               Diff Utilities
# -----------------------------------------------------------------------------
def _ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def _index_by(items, key):
    out = {}
    for it in items or []:
        k = it.get(key)
        if k:
            out[k] = it
    return out


def _shallow_equal(a, b):
    try:
        return json.dumps(a, sort_keys=True, default=str) == json.dumps(b, sort_keys=True, default=str)
    except Exception:
        return False


def _compute_entity_diff(prev_list, new_list, key):
    prev = _index_by(prev_list, key)
    new = _index_by(new_list, key)

    added = sorted([k for k in new.keys() - prev.keys()])
    removed = sorted([k for k in prev.keys() - new.keys()])
    modified = []
    modified_details = {}

    for k in new.keys() & prev.keys():
        if not _shallow_equal(prev[k], new[k]):
            modified.append(k)
            diff_keys = []
            for field in set(prev[k].keys()) | set(new[k].keys()):
                if prev[k].get(field) != new[k].get(field):
                    diff_keys.append(field)
            modified_details[k] = diff_keys

    return {
        "added": added,
        "removed": removed,
        "modified": sorted(modified),
        "modified_details": modified_details,
    }


def _apply_change_flags(snapshot, diff):
    for entity, key in [
        ("users", "UserName"),
        ("groups", "GroupName"),
        ("roles", "RoleName"),
        ("policies", "PolicyName"),
    ]:
        for name in diff[entity]["added"]:
            x = next((u for u in snapshot.get(entity, []) if u.get(key) == name), None)
            if x:
                x["_changed"] = "added"

        for name in diff[entity]["modified"]:
            x = next((u for u in snapshot.get(entity, []) if u.get(key) == name), None)
            if x:
                x["_changed"] = "modified"


# -----------------------------------------------------------------------------
#                           Public API: fetch_iam_data
# -----------------------------------------------------------------------------
def fetch_iam_data(
    session=None,
    profile_name=None,
    out_path=None,
    fast_mode=True,
    force_fetch=False,
    encrypt=False,
    multi_region=False,
    regions=None,
    progress_callback=None,
    cache_ttl=None,
    **kwargs
):
    """
    High-level wrapper around enterprise fetch engine.

    Steps:
    -------
    1) Resolve path
    2) Cache check (FAST mode)
    3) Call enterprise orchestrate_fetch()
    4) Apply diff engine
    5) Save snapshot (plaintext or encrypted)
    6) Cleanup old snapshots
    """

    if kwargs:
        warnings.warn(f"Ignoring unsupported parameters: {list(kwargs.keys())}")

    # Snapshot path resolution
    out_path = out_path or getattr(
        config, "SNAPSHOT_PATH",
        os.path.join(getattr(config, "DATA_DIR", "data"), "iam_snapshot.json")
    )
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    # TTL setting
    try:
        default_ttl = getattr(config, "CACHE_TTL", 3600)
    except Exception:
        default_ttl = 3600
    cache_ttl = cache_ttl or default_ttl

    # FAST CACHE SHORTCUT
    if fast_mode and not force_fetch:
        cached = load_snapshot(out_path)
        if cached:
            logger.info("FAST MODE: Returning cached snapshot.")
            return cached

    # Session creation
    if isinstance(session, boto3.Session):
        session_obj = session
    else:
        try:
            session_obj = boto3.Session(profile_name=profile_name)
        except Exception as e:
            raise RuntimeError(f"Failed to create boto3 session: {e}")

    # Region handling
    if multi_region:
        regions = regions or getattr(config, "DEFAULT_REGIONS", ["us-east-1"])
        mr_flag = True
    else:
        regions = regions or [getattr(config, "AWS_REGION", "us-east-1")]
        mr_flag = False

    # Load previous snapshot for diff logic
    prev_snapshot = load_snapshot(out_path)

    # -------------------------------------------------------------------------
    #                       ✨ CALL ENTERPRISE FETCH ENGINE ✨
    # -------------------------------------------------------------------------
    combined = orchestrate_fetch(
        session=session_obj,
        profile_name=profile_name,
        regions=regions,
        fast_mode=fast_mode,
        multi_region=mr_flag,
        progress_callback=progress_callback
    )

    # -------------------------------------------------------------------------
    #                       Apply Diff to Combined Snapshot
    # -------------------------------------------------------------------------
    if prev_snapshot:
        # Single-region mode diff
        if not mr_flag:
            prev = prev_snapshot
            new = combined

            diff = {
                "users": _compute_entity_diff(prev.get("users", []), new.get("users", []), "UserName"),
                "groups": _compute_entity_diff(prev.get("groups", []), new.get("groups", []), "GroupName"),
                "roles": _compute_entity_diff(prev.get("roles", []), new.get("roles", []), "RoleName"),
                "policies": _compute_entity_diff(prev.get("policies", []), new.get("policies", []), "PolicyName"),
            }
            _apply_change_flags(combined, diff)
            combined["_meta"]["diff"] = diff

    # -------------------------------------------------------------------------
    #                          Persist Snapshot
    # -------------------------------------------------------------------------
    try:
        if encrypt and hasattr(secure_store, "encrypt_and_write"):
            secure_store.encrypt_and_write(combined, out_path)
            logger.info(f"Encrypted snapshot saved to {out_path}.enc")
        else:
            tmp = out_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(combined, fh, indent=2, default=str)
            os.replace(tmp, out_path)
            logger.info(f"Snapshot written: {out_path}")
    except Exception as e:
        logger.error(f"Failed to write snapshot: {e}")

    # Cleanup old snapshots
    try:
        purge_old_snapshots(getattr(config, "KEEP_DAYS", 30))
    except Exception:
        pass

    return combined


if __name__ == "__main__":
    print("Run main.py UI instead.")
