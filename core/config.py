# core/config.py
import os

# --- dotenv (safe optional) ---
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass


# --- Streamlit Safe Import ---
try:
    import streamlit as st
except Exception:
    st = None


# --- Secrets Loader ---
def _load_secrets():
    if st and hasattr(st, "secrets"):
        try:
            return dict(st.secrets)
        except Exception:
            return {}
    return {}

SECRETS = _load_secrets()
IS_CLOUD = bool(SECRETS)


def _secret(*keys, default=None):
    node = SECRETS
    try:
        for k in keys:
            node = node[k]
        return node
    except Exception:
        return default


# DIRECTORIES
DATA_DIR = (
    _secret("APP", "DATA_DIR")
    or os.getenv("IAM_XRAY_DATA_DIR")
    or "data"
)
os.makedirs(DATA_DIR, exist_ok=True)

SNAPSHOT_PATH = (
    _secret("APP", "SNAPSHOT_PATH")
    or os.getenv("IAM_XRAY_SNAPSHOT_PATH")
    or os.path.join(DATA_DIR, "iam_snapshot.json")
)

SNAPSHOT_DIR = os.path.join(DATA_DIR, "snapshots")
os.makedirs(SNAPSHOT_DIR, exist_ok=True)


# REGION
AWS_REGION = (
    _secret("AWS", "REGION")
    or _secret("APP", "AWS_REGION")
    or os.getenv("AWS_REGION")
    or "us-east-1"
)

DEFAULT_REGIONS = os.getenv("DEFAULT_REGIONS", "us-east-1,us-west-2").split(",")


# INT PARSER
def _int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


# CACHE
CACHE_TTL = _secret("APP", "CACHE_TTL") or _int("CACHE_TTL", 3600)
KEEP_DAYS = _secret("APP", "KEEP_DAYS") or _int("KEEP_DAYS", 30)


# FERNET KEY
FERNET_KEY = (
    _secret("APP", "FERNET_KEY")
    or _secret("FERNET_KEY")
    or os.getenv("IAM_XRAY_FERNET_KEY")
)

if not FERNET_KEY:
    if not IS_CLOUD:
        print("⚠ Using insecure dev FERNET_KEY")
    FERNET_KEY = "0" * 32


# EMAIL
EMAIL_ALERT_THRESHOLD = (
    _secret("APP", "EMAIL_ALERT_THRESHOLD")
    or _int("EMAIL_ALERT_THRESHOLD", 5)
)


# STREAMLIT RERUN WRAPPER
def rerun():
    try:
        import streamlit as st_mod

        if hasattr(st_mod, "rerun") and callable(st_mod.rerun):
            st_mod.rerun()

        elif hasattr(st_mod, "experimental_rerun") and callable(st_mod.experimental_rerun):
            st_mod.experimental_rerun()

    except Exception:
        pass
