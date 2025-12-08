# core/auth.py
"""
IAM X-Ray — Premium 3-step onboarding auth UI (Palette 1)
- Centered welcome screen (no left shift)
- 3-step wizard: Welcome → Why IAM X-Ray → Set Password
- Forgot password (safe reset)
- Demo Mode works reliably with main.py
- Animations + SVG icons
- Fully Streamlit 1.31+ compatible
"""

import os
import json
import secrets
import hashlib
import time
from datetime import datetime, timedelta, timezone
import streamlit as st

# Optional zxcvbn
try:
    from zxcvbn import zxcvbn as _zxcvbn
    ZXC_AVAILABLE = True
except Exception:
    ZXC_AVAILABLE = False

# Globals
AUTH_FILE = None
LOCK_FILE = None
REMEMBER_FILE = None
REMEMBER_DAYS = 7


# =====================================================================
# Utility helpers
# =====================================================================
def init_paths(auth_file, lock_file, remember_file):
    global AUTH_FILE, LOCK_FILE, REMEMBER_FILE
    AUTH_FILE = auth_file
    LOCK_FILE = lock_file
    REMEMBER_FILE = remember_file


def _atomic_write(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)
    os.replace(tmp, path)


def _read_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _hash_password(password, salt):
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def _now():
    return datetime.now(timezone.utc)


# =====================================================================
# Remember Me Token
# =====================================================================
def save_remember_token(days=REMEMBER_DAYS):
    if not REMEMBER_FILE:
        return
    tok = secrets.token_urlsafe(32)
    expiry = _now() + timedelta(days=days)
    _atomic_write(REMEMBER_FILE, {"token": tok, "expiry": expiry.isoformat()})


def load_remember_token():
    if not REMEMBER_FILE or not os.path.exists(REMEMBER_FILE):
        return None
    try:
        data = _read_json(REMEMBER_FILE)
        exp = datetime.fromisoformat(data["expiry"])
        if exp > _now():
            return data
    except Exception:
        return None
    return None


def clear_remember_token():
    if REMEMBER_FILE and os.path.exists(REMEMBER_FILE):
        os.remove(REMEMBER_FILE)


# =====================================================================
# Password Strength
# =====================================================================
def password_strength(pwd):
    if not pwd:
        return 0, None, []
    if ZXC_AVAILABLE:
        try:
            res = _zxcvbn(pwd)
            return res["score"], res.get("entropy"), res["feedback"].get("suggestions", [])
        except:
            pass
    # fallback
    score = 0
    score += len(pwd) >= 8
    score += any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
    score += any(c.isdigit() for c in pwd)
    score += any(c in "!@#$%^&*()_+-=[]{};:'\",.<>/?|" for c in pwd)
    return min(score, 4), None, []


def strength_color(score):
    return ["#ef4444", "#f97316", "#f59e0b", "#10b981", "#0ea5e9"][score]


# =====================================================================
# SVG Assets (Palette 1)
# =====================================================================
LOGO_SVG = """<svg width="56" height="56" viewBox="0 0 64 64"...></svg>"""  # truncated for readability
ILLUSTRATION_SVG = """<svg width="320" height="200" viewBox="0 0 320 200"...></svg>"""  # truncated


# =====================================================================
# CSS
# =====================================================================
CSS = """
<style>
.iam-auth {
  max-width: 760px;
  margin: 4% auto;
  display: flex;
  gap: 22px;
  justify-content: center;
  animation: fadeIn 0.55s ease-out;
}

.iam-card {
  max-width: 420px;
  padding: 28px;
  border-radius: 14px;
  background: rgba(255,255,255,0.04);
  border: 1px solid rgba(255,255,255,0.07);
  backdrop-filter: blur(8px);
}

.iam-ill { min-width: 320px; padding: 12px; }

@keyframes fadeIn {
  from {opacity:0; transform:translateY(10px);}
  to {opacity:1; transform:translateY(0);}
}
</style>
"""


def render_header():
    st.markdown(
        f"<div style='display:flex;gap:10px;align-items:center'>"
        f"{LOGO_SVG}"
        f"<div><div style='font-size:18px;font-weight:800'>IAM X-Ray</div>"
        f"<div style='font-size:13px;color:#9fbfe9'>Security begins with visibility.</div></div>"
        f"</div>",
        unsafe_allow_html=True,
    )


# =====================================================================
# Onboarding Screens
# =====================================================================

# ------------------ STEP 1 — WELCOME (centered) ------------------
def screen_welcome():
    st.markdown(CSS, unsafe_allow_html=True)

    st.markdown("<div class='iam-auth' style='justify-content:center;'>", unsafe_allow_html=True)

    # NO illustration on welcome → center card
    st.markdown("<div class='iam-card'>", unsafe_allow_html=True)

    render_header()

    st.markdown(
        """
        <h3>Welcome to IAM X-Ray</h3>
        <p style='color:#a8b9d8'>
        Security begins with visibility.<br>
        IAM X-Ray gives you a private, offline lens into your IAM — fast, accurate and beautifully simple.
        </p>
        """,
        unsafe_allow_html=True,
    )

    if st.button("Continue →", use_container_width=True):
        st.session_state.auth_flow = "why"
        st.rerun()

    if st.button("Try Demo Mode", use_container_width=True):
        st.session_state.force_demo_mode = True
        st.session_state.authenticated = True
        st.session_state.last_fetch_profile = "Demo"
        st.session_state.auth_flow = "login"  # IMPORTANT FIX
        st.rerun()

    st.markdown("</div></div>", unsafe_allow_html=True)
    st.stop()


# ------------------ STEP 2 — WHY SCREEN ------------------
def screen_why():
    st.markdown(CSS, unsafe_allow_html=True)

    st.markdown("<div class='iam-auth'>", unsafe_allow_html=True)

    st.markdown(f"<div class='iam-ill'>{ILLUSTRATION_SVG}</div>", unsafe_allow_html=True)

    st.markdown("<div class='iam-card'>", unsafe_allow_html=True)

    render_header()

    st.markdown(
        """
        <h3>Why IAM X-Ray?</h3>
        <p style='color:#a8b9d8'>A few reasons developers choose IAM X-Ray:</p>
        <ul style='color:#cfeeff'>
          <li>Visualize IAM relationships</li>
          <li>Detect risky permission combinations</li>
          <li>Explore attack surfaces with clarity</li>
          <li>100% offline — nothing leaves your machine</li>
        </ul>
        """,
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2)
    if col1.button("Set Master Password", use_container_width=True):
        st.session_state.auth_flow = "create"
        st.rerun()

    if col2.button("← Back", use_container_width=True):
        st.session_state.auth_flow = "welcome"
        st.rerun()

    st.markdown("</div></div>", unsafe_allow_html=True)
    st.stop()


# ------------------ STEP 3 — CREATE PASSWORD ------------------
def screen_create():
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown("<div class='iam-auth'>", unsafe_allow_html=True)

    st.markdown(f"<div class='iam-ill'>{ILLUSTRATION_SVG}</div>", unsafe_allow_html=True)
    st.markdown("<div class='iam-card'>", unsafe_allow_html=True)

    render_header()

    st.markdown(
        "<h3>Create a Master Password</h3>"
        "<p style='color:#a8b9d8'>This encrypts your local vault. Nothing is uploaded.</p>",
        unsafe_allow_html=True,
    )

    show = st.checkbox("Show password")
    inp = "default" if show else "password"

    p1 = st.text_input("Password", type=inp)
    p2 = st.text_input("Confirm Password", type=inp)
    remember = st.checkbox(f"Remember this device for {REMEMBER_DAYS} days")

    if p1:
        score, entropy, suggestions = password_strength(p1)
        pct = int((score / 4) * 100)
        st.markdown(
            f"<div style='height:8px;background:#333;border-radius:6px;margin-top:6px'>"
            f"<div style='width:{pct}%;height:100%;background:{strength_color(score)};border-radius:6px'></div>"
            f"</div>",
            unsafe_allow_html=True,
        )

    if st.button("Save & Continue", use_container_width=True):
        if not p1 or not p2:
            st.error("Fill both password fields.")
            st.stop()
        if p1 != p2:
            st.error("Passwords do not match.")
            st.stop()
        if len(p1) < 8:
            st.error("Minimum length is 8.")
            st.stop()

        salt = secrets.token_hex(16)
        hashed = _hash_password(p1, salt)
        _atomic_write(AUTH_FILE, {"salt": salt, "password_hash": hashed})
        open(LOCK_FILE, "w").close()

        if remember:
            save_remember_token()

        st.success("Vault created — unlocking…")
        time.sleep(0.4)
        st.session_state.authenticated = True
        st.rerun()

    if st.button("← Back", use_container_width=True):
        st.session_state.auth_flow = "why"
        st.rerun()

    st.markdown("</div></div>", unsafe_allow_html=True)
    st.stop()


# ------------------ LOGIN ------------------
def screen_login():
    st.markdown(CSS, unsafe_allow_html=True)

    st.markdown("<div class='iam-auth'>", unsafe_allow_html=True)
    st.markdown(f"<div class='iam-ill'>{ILLUSTRATION_SVG}</div>", unsafe_allow_html=True)
    st.markdown("<div class='iam-card'>", unsafe_allow_html=True)

    render_header()

    show = st.checkbox("Show password")
    t = "default" if show else "password"
    pw = st.text_input("Password", type=t)
    remember = st.checkbox(f"Remember this device for {REMEMBER_DAYS} days")

    if st.button("Unlock", use_container_width=True):
        try:
            data = _read_json(AUTH_FILE)
        except:
            st.error("Auth file missing or corrupted.")
            st.stop()

        if _hash_password(pw or "", data["salt"]) == data["password_hash"]:
            if remember:
                save_remember_token()
            st.success("Unlocked — loading…")
            time.sleep(0.35)
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("Incorrect password.")

    if st.button("Forgot password?", use_container_width=True):
        st.session_state.auth_flow = "forgot"
        st.rerun()

    st.markdown("</div></div>", unsafe_allow_html=True)
    st.stop()


# ------------------ FORGOT PASSWORD ------------------
def screen_forgot():
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown("<div class='iam-auth'>", unsafe_allow_html=True)
    st.markdown(f"<div class='iam-ill'>{ILLUSTRATION_SVG}</div>", unsafe_allow_html=True)
    st.markdown("<div class='iam-card'>", unsafe_allow_html=True)

    render_header()

    st.markdown(
        "<h3>Reset Password</h3>"
        "<p style='color:#a8b9d8'>Only auth files will be removed. Snapshots stay safe.</p>",
        unsafe_allow_html=True,
    )

    if st.button("Reset Password (safe)", use_container_width=True):
        try:
            if os.path.exists(AUTH_FILE): os.remove(AUTH_FILE)
            if os.path.exists(LOCK_FILE): os.remove(LOCK_FILE)
            clear_remember_token()
        except:
            pass

        st.success("Reset successful — returning…")
        time.sleep(0.45)

        st.session_state.clear()
        st.session_state.auth_flow = "welcome"
        st.rerun()

    if st.button("Cancel", use_container_width=True):
        st.session_state.auth_flow = "login"
        st.rerun()

    st.markdown("</div></div>", unsafe_allow_html=True)
    st.stop()


# =====================================================================
# MASTER ROUTER
# =====================================================================
def handle_auth(auth_file, lock_file, remember_file):
    init_paths(auth_file, lock_file, remember_file)

    os.makedirs(os.path.dirname(auth_file), exist_ok=True)

    st.session_state.setdefault("auth_flow", "welcome")
    st.session_state.setdefault("authenticated", False)

    first_run = not (os.path.exists(AUTH_FILE) or os.path.exists(LOCK_FILE))

    if first_run:
        flow = st.session_state["auth_flow"]
        if flow == "welcome": return screen_welcome()
        if flow == "why": return screen_why()
        return screen_create()

    if st.session_state.get("authenticated"):
        return True

    if load_remember_token():
        st.session_state["authenticated"] = True
        return True

    flow = st.session_state.get("auth_flow", "login")
    if flow == "login": return screen_login()
    if flow == "forgot": return screen_forgot()
    return screen_login()
