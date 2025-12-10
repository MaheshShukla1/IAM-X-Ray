# core/cleanup.py
import os
import shutil
import time
from datetime import datetime, timedelta,timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import streamlit as st

from core import config   # MUST match folder structure

# -------------------------------------------------------------------
# CONSTANTS
# -------------------------------------------------------------------
DATA_DIR = config.DATA_DIR
SNAPSHOT_DIR = os.path.join(DATA_DIR, "snapshots")
CURRENT_SNAPSHOT_NAME = os.path.basename(config.SNAPSHOT_PATH)



def _auth_file():
    return os.path.join(DATA_DIR, "auth.json")

def _lock_file():
    return os.path.join(DATA_DIR, "setup.lock")

def _remember_file():
    return os.path.join(DATA_DIR, "iamxray_remember.json")

# -------------------------------------------------------------------
# SNAPSHOT LISTING
# -------------------------------------------------------------------
def _list_snapshot_files():
    """
    Find snapshot files in:
    - data/snapshots/
    - data/snapshots/backup/** (recursive)
    Includes:
    - *.json
    - *.json.enc
    - *.enc
    """
    if not os.path.exists(SNAPSHOT_DIR):
        os.makedirs(SNAPSHOT_DIR, exist_ok=True)
        return []

    files = []

    # MAIN snapshot folder
    for f in Path(SNAPSHOT_DIR).glob("*"):
        name = f.name
        if name.endswith((".json", ".json.enc", ".enc")):
            files.append(f)

    # RECURSIVE in backup folder
    backup_root = Path(SNAPSHOT_DIR) / "backup"
    if backup_root.exists():
        for f in backup_root.rglob("*"):
            if f.is_file() and f.name.endswith((".json", ".json.enc", ".enc")):
                files.append(f)

    return files


# -------------------------------------------------------------------
# GROUP FILES BY STEM
# -------------------------------------------------------------------
def _group_snapshot_files(files):
    """
    Example:
        - abc.json
        - abc.json.enc
        - abc.enc

    All belong to stem "abc"
    """
    groups = {}
    for p in files:
        name = p.name
        stem = name
        if name.endswith(".json.enc"):
            stem = name[: -len(".json.enc")]
        elif name.endswith(".json"):
            stem = name[: -len(".json")]
        elif name.endswith(".enc"):
            stem = name[: -len(".enc")]
        groups.setdefault(stem, []).append(p)
    return groups


# -------------------------------------------------------------------
# PURGE OLD SNAPSHOTS
# -------------------------------------------------------------------
def purge_old_snapshots(keep_days=None):
    """
    Rules:
    ✓ Always BACKUP before deleting (except files already inside backup/)
    ✓ Do NOT delete current active snapshot
    ✓ If plaintext+encrypted exist → delete older one only
    ✓ Single old file → delete if older than cutoff
    """
    if keep_days is None:
        keep_days = getattr(config, "KEEP_DAYS", 30)

    files = _list_snapshot_files()
    total_files = len(files)
    removed = 0
    backed_up = 0

    cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)

    if keep_days == 0:
       cutoff = datetime.min.replace(tzinfo=timezone.utc)

    backup_dir = os.path.join(SNAPSHOT_DIR, "backup")
    os.makedirs(backup_dir, exist_ok=True)

    groups = _group_snapshot_files(files)

    for stem, paths in groups.items():

        # Skip current snapshot
        if any(CURRENT_SNAPSHOT_NAME in str(p) for p in paths):
            continue

        # MULTIPLE VARIANTS (json + enc)
        if len(paths) > 1:
            try:
                paths_sorted = sorted(paths, key=lambda p: p.stat().st_mtime)
            except Exception:
                continue

            oldest = paths_sorted[0]

            try:
                mtime = datetime.fromtimestamp(oldest.stat().st_mtime, timezone.utc)
            except Exception:
                continue

            if mtime < cutoff:
                name = oldest.name

                # FIX #3 — Skip backup inside backup/
                if "backup" not in str(oldest.parent):
                    try:
                        shutil.copy2(str(oldest), os.path.join(backup_dir, name + ".bak"))
                        backed_up += 1
                    except Exception as e:
                        st.warning(f"Backup failed for {name}: {e}")

                # DELETE
                try:
                    os.remove(str(oldest))
                    removed += 1
                except Exception as e:
                    st.warning(f"Could not delete {name}: {e}")

            continue

        # SINGLE FILE
        p = paths[0]
        name = p.name

        # Skip active
        if CURRENT_SNAPSHOT_NAME in str(p):
            continue

        try:
            mtime = datetime.fromtimestamp(p.stat().st_mtime, timezone.utc)
        except Exception:
            continue

        if mtime >= cutoff:
            continue

        # FIX #3 — Skip creating backup if already in backup/
        if "backup" not in str(p.parent):
            try:
                shutil.copy2(str(p), os.path.join(backup_dir, name + ".bak"))
                backed_up += 1
            except Exception as e:
                st.warning(f"Backup failed for {name}: {e}")

        # DELETE
        try:
            os.remove(str(p))
            removed += 1
        except Exception as e:
            st.warning(f"Could not delete {name}: {e}")

    return removed, total_files



# -------------------------------------------------------------------
# PURGE IN BACKGROUND
# -------------------------------------------------------------------
def run_purge_in_background(keep_days=None):
    progress = st.progress(0.0)

    with ThreadPoolExecutor() as exe:
        future = exe.submit(purge_old_snapshots, keep_days)
        total_steps = 30

        for i in range(total_steps):
            time.sleep(0.05)
            progress.progress((i + 1) / total_steps)

        result = future.result()

    progress.progress(1.0)
    return result


# -------------------------------------------------------------------
# FULL APP RESET
# -------------------------------------------------------------------
def reset_app():
    """
    Full App Reset
    - Backup all app state files into: data/snapshots/backup/reset-<timestamp>/
    - Removes:
        auth.json
        setup.lock
        iamxray_remember.json
        snapshots/*
    - Preserves Demo snapshot
    """

    # Unified backup root (inside snapshots/backup)
    backup_root = os.path.join(SNAPSHOT_DIR, "backup")
    os.makedirs(backup_root, exist_ok=True)

    # Timestamped backup folder
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup_folder = os.path.join(backup_root, f"reset-{timestamp}")
    os.makedirs(backup_folder, exist_ok=True)

    def _backup_and_delete(path):
        if os.path.exists(path):
            try:
                shutil.copy2(path, os.path.join(backup_folder, os.path.basename(path)))
            except Exception:
                pass
            try:
                os.remove(path)
            except Exception:
                pass

    # Backup + delete app state
    _backup_and_delete(_auth_file())
    _backup_and_delete(_lock_file())
    _backup_and_delete(_remember_file())

    # Backup + delete snapshot files
    if os.path.exists(SNAPSHOT_DIR):
        for f in Path(SNAPSHOT_DIR).glob("*"):
            # Do not delete backups themselves
            if "backup" in str(f):
                continue

            try:
                shutil.copy2(str(f), os.path.join(backup_folder, f.name))
            except Exception:
                pass
            try:
                os.remove(str(f))
            except:
                pass

    return backup_folder


# -------------------------------------------------------------------
# UI — RESET APP
# -------------------------------------------------------------------
def ui_reset_app_button():
    st.subheader("🧨 Reset App (Full Wipe)")
    st.write(
        "This will backup and remove **local app state**:\n"
        "- auth.json\n"
        "- setup.lock\n"
        "- snapshots/\n"
        "- iamxray_remember.json\n\n"
        "**Demo snapshot is preserved.**"
    )

    confirm = st.checkbox("I understand this will wipe local data and create a backup.")
    if confirm:
        if st.button("Confirm Full Reset"):
            with st.spinner("Resetting app..."):
                backup_path = reset_app()

            st.success(f"App reset completed.\nBackup stored at:\n`{backup_path}`")

            # ⭐ Force clean reload so new empty state loads
            st.session_state.clear()
            try:
                st.experimental_rerun()
            except:
                st.rerun()

# -------------------------------------------------------------------
# UI — PURGE SNAPSHOTS
# -------------------------------------------------------------------
def ui_purge_button():
    st.subheader("🧹 Cleanup Snapshots")
    st.write(
        f"Deletes snapshots older than **{getattr(config, 'KEEP_DAYS', 30)} days**.\n"
        f"Backups will be saved under: `data/snapshots/backup`."
    )

    confirm = st.checkbox("I understand old snapshots will be permanently deleted.")
    if confirm:
        if st.button("Confirm Purge Now"):
            with st.spinner("Cleaning snapshots..."):
                removed, total = run_purge_in_background(
                    getattr(config, "KEEP_DAYS", 30)
                )

            if total == 0:
                st.info("No snapshot files found.")
            else:
                st.success(
                    f"Purged **{removed}** of **{total}** snapshot files.\n"
                    f"Backups stored in: `data/snapshots/backup`"
                )

