# core/auth.py
"""
IAM X-Ray — Ultra-Minimal Onboarding (Final Version, Fixed Demo Mode Bug)
- Welcome → Create Password → Login
- Demo Mode works only for the onboarding session
- Demo Mode automatically resets after real login
- Zero UI leakage into main.py
"""

import os
import json
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
import streamlit as st

# Optional password strength
try:
    from zxcvbn import zxcvbn as _zxcvbn
    ZXC_AVAILABLE = True
except Exception:
    ZXC_AVAILABLE = False

# Global paths (injected by handle_auth)
AUTH_FILE = None
LOCK_FILE = None
REMEMBER_FILE = None
REMEMBER_DAYS = 7


# -------------------------------------------------------
# Helpers
# -------------------------------------------------------
def init_paths(auth_file, lock_file, remember_file):
    global AUTH_FILE, LOCK_FILE, REMEMBER_FILE
    AUTH_FILE = auth_file
    LOCK_FILE = lock_file
    REMEMBER_FILE = remember_file


def _atomic_write(path, obj):
    tmp = path + ".tmp"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)
    os.replace(tmp, path)


def _read_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _hash_password(password, salt):
    return hashlib.sha256((salt + password).encode()).hexdigest()


def _now():
    return datetime.now(timezone.utc)


# -------------------------------------------------------
# Remember-me token
# -------------------------------------------------------
def save_remember_token(days=REMEMBER_DAYS):
    if not REMEMBER_FILE:
        return
    tok = secrets.token_urlsafe(32)
    exp = _now() + timedelta(days=days)
    _atomic_write(REMEMBER_FILE, {"token": tok, "expiry": exp.isoformat()})


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
        try:
            os.remove(REMEMBER_FILE)
        except:
            pass


# -------------------------------------------------------
# Password strength meter
# -------------------------------------------------------
def password_strength(pwd):
    if not pwd:
        return 0
    if ZXC_AVAILABLE:
        try:
            return _zxcvbn(pwd)["score"]
        except:
            pass
    score = 0
    score += len(pwd) >= 8
    score += any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
    score += any(c.isdigit() for c in pwd)
    score += any(c in "!@#$%^&*()_+-=[]{};:'\",.<>/?|" for c in pwd)
    return min(score, 4)


def strength_color(score):
    return ["#ef4444", "#f97316", "#f59e0b", "#10b981", "#0ea5e9"][score]


# -------------------------------------------------------
# CSS + Logo
# -------------------------------------------------------
LOGO_SVG = """
<svg width="38" height="38" viewBox="0 0 24 24" fill="none"
     xmlns="http://www.w3.org/2000/svg"
     style="vertical-align:middle;margin-right:10px;">
  <rect x="2" y="3" width="20" height="18" rx="3" fill="#0ea5e9"/>
  <path d="M7 9h10M7 13h6" stroke="white" stroke-width="1.5" stroke-linecap="round"/>
</svg>
"""

CSS = """
<style>
.auth-wrapper { display:flex; justify-content:center; margin-top:6%; }
.auth-card {
    width:420px; max-width:95%;
    padding:24px 26px;
    border-radius:14px;
    background:rgba(255,255,255,0.03);
    border:1px solid rgba(255,255,255,0.05);
    box-shadow:0 8px 26px rgba(0,0,0,0.45);
}
.auth-header { display:flex; align-items:center; gap:10px; }
.auth-title  { font-size:20px;font-weight:800;margin:0;padding:0; }
.auth-sub    { color:#9fbfe9;font-size:13px;margin-top:2px; }
.small-muted { font-size:13px; color:#a0aec0; }
.strength-bar{ height:8px;background:#222;border-radius:6px;margin-top:6px;overflow:hidden }
.strength-fill{ height:100%;border-radius:6px; }
</style>
"""


# -------------------------------------------------------
# Screens
# -------------------------------------------------------
def _center():
    st.markdown(CSS, unsafe_allow_html=True)
    colL, colC, colR = st.columns([1, 0.9, 1])
    return colC


# ---------------------- WELCOME -------------------------
def welcome_screen():
    c = _center()
    with c:
        st.markdown("<div class='auth-card'>", unsafe_allow_html=True)

        st.markdown(
            f"<div class='auth-header'>{LOGO_SVG}"
            "<div><div class='auth-title'>IAM X-Ray</div>"
            "<div class='auth-sub'>Security begins with visibility</div></div></div>",
            unsafe_allow_html=True,
        )

        st.markdown(
            "<p class='small-muted'>Visualize IAM relationships, detect risky permissions, explore attack surfaces — all offline.</p>",
            unsafe_allow_html=True,
        )

        col1, col2 = st.columns(2)

        if col1.button("Create Master Password", use_container_width=True):
            st.session_state.auth_step = "create"
            st.rerun()

        if col2.button("Try Demo Mode", use_container_width=True):
            st.session_state.force_demo_mode = True
            st.session_state.demo_session = True  # <-- NEW FIX
            st.session_state.authenticated = True
            st.session_state.last_fetch_profile = "Demo"
            st.session_state.auth_step = "done"
            st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)


# ---------------- CREATE PASSWORD ------------------------
def create_password_screen():
    c = _center()
    with c:
        st.markdown("<div class='auth-card'>", unsafe_allow_html=True)

        st.markdown(
            f"<div class='auth-header'>{LOGO_SVG}"
            "<div><div class='auth-title'>Create Master Password</div>"
            "<div class='auth-sub'>Encrypts your local vault.</div></div></div>",
            unsafe_allow_html=True,
        )

        show = st.checkbox("Show password")
        t = "default" if show else "password"

        p1 = st.text_input("Password", type=t, placeholder="At least 8 characters")
        p2 = st.text_input("Confirm Password", type=t, placeholder="Re-enter password")
        remember = st.checkbox(f"Remember this device for {REMEMBER_DAYS} days")

        if p1:
            score = password_strength(p1)
            pct = int((score / 4) * 100)
            st.markdown(
                f"<div class='strength-bar'><div class='strength-fill' style='width:{pct}%;background:{strength_color(score)}'></div></div>",
                unsafe_allow_html=True,
            )

        col1, col2 = st.columns(2)
        if col1.button("Save & Unlock", use_container_width=True):
            if not p1 or not p2:
                st.error("Both password fields required.")
                return
            if p1 != p2:
                st.error("Passwords do not match.")
                return
            if len(p1) < 8:
                st.error("Password too short.")
                return

            salt = secrets.token_hex(16)
            hashed = _hash_password(p1, salt)
            _atomic_write(AUTH_FILE, {"salt": salt, "password_hash": hashed})
            open(LOCK_FILE, "w").close()

            if remember:
                save_remember_token()

            st.session_state.authenticated = True
            st.session_state.auth_step = "done"
            st.session_state.force_demo_mode = False
            st.rerun()

        if col2.button("← Back", use_container_width=True):
            st.session_state.auth_step = "welcome"
            st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)


# ----------------------- LOGIN ---------------------------
def login_screen():
    c = _center()
    with c:
        st.markdown("<div class='auth-card'>", unsafe_allow_html=True)

        st.markdown(
            f"<div class='auth-header'>{LOGO_SVG}"
            "<div><div class='auth-title'>Unlock</div>"
            "<div class='auth-sub'>Enter your master password</div></div></div>",
            unsafe_allow_html=True,
        )

        show = st.checkbox("Show password")
        t = "default" if show else "password"
        pw = st.text_input("Password", type=t)
        remember = st.checkbox(f"Remember this device for {REMEMBER_DAYS} days")

        col1, col2 = st.columns(2)

        if col1.button("Unlock", use_container_width=True):
            try:
                data = _read_json(AUTH_FILE)
            except:
                st.error("Auth file missing. Create password again.")
                return

            if _hash_password(pw or "", data["salt"]) == data["password_hash"]:

                if remember:
                    save_remember_token()

                st.session_state.authenticated = True
                st.session_state.auth_step = "done"
                st.session_state.force_demo_mode = False  # <-- IMPORTANT FIX
                st.rerun()
            else:
                st.error("Incorrect password.")

        if col2.button("Forgot password?", use_container_width=True):
            try:
                if os.path.exists(AUTH_FILE): os.remove(AUTH_FILE)
                if os.path.exists(LOCK_FILE): os.remove(LOCK_FILE)
                clear_remember_token()
            except:
                pass

            st.info("Password reset. Create a new one.")
            st.session_state.auth_step = "create"
            st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)


# -------------------------------------------------------
# PUBLIC — handle_auth()
# -------------------------------------------------------
def handle_auth(auth_file, lock_file, remember_file):
    init_paths(auth_file, lock_file, remember_file)

    os.makedirs(os.path.dirname(auth_file), exist_ok=True)

    st.session_state.setdefault("auth_step", "welcome")
    st.session_state.setdefault("authenticated", False)
    st.session_state.setdefault("force_demo_mode", False)
    st.session_state.setdefault("demo_session", False)

    # Auto-login if remember token found
    if load_remember_token():
        st.session_state.authenticated = True
        st.session_state.auth_step = "done"

    # ------------------------------
    # FIX BLOCK: RESET DEMO MODE
    # ------------------------------
    if st.session_state.get("authenticated"):

        # If authenticated normally, clear demo
        if not st.session_state.get("demo_session"):
            st.session_state.force_demo_mode = False

        # If demo session ended (entered the UI)
        if st.session_state.get("demo_session") and st.session_state.auth_step == "done":
            st.session_state.force_demo_mode = False

    # Return early if fully authenticated
    if st.session_state.get("authenticated") and st.session_state.get("auth_step") == "done":
        return True

    # ------------------------------
    # ROUTING
    # ------------------------------
    first_run = not (os.path.exists(AUTH_FILE) or os.path.exists(LOCK_FILE))

    if first_run:
        if st.session_state.auth_step not in ("welcome", "create"):
            st.session_state.auth_step = "welcome"
    else:
        if st.session_state.auth_step not in ("login", "create", "welcome"):
            st.session_state.auth_step = "login"

    step = st.session_state.auth_step

    if step == "welcome":
        welcome_screen()
        return False

    if step == "create":
        create_password_screen()
        return False

    if step == "login":
        login_screen()
        return False

    return st.session_state.get("authenticated", False)
