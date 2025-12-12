# main.py
"""
IAM X-Ray — Optimized main.py (Stable Beta) — v1.0.0
Tooltips: Option A — Inline tooltip icon next to labels using only HTML title attributes.
"""
import sys
import os
import json
import time
import tempfile
from datetime import datetime, timezone
import configparser

import streamlit as st
import pandas as pd
import streamlit.components.v1 as components


# ---------------------------------------------------
# STREAMLIT PAGE CONFIG — MUST BE FIRST
# (before writing anything to the page)
# ---------------------------------------------------
st.set_page_config(
    page_title="IAM X-Ray — Stable Beta",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ---------------------------------------------------
# PATH FIX — allow importing core/*
# ---------------------------------------------------
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


# ---------------------------------------------------
# CORE IMPORTS
# ---------------------------------------------------
from core import config
from core.auth import handle_auth   # Authentication first

# ---------------------------------------------------
# PATHS
# ---------------------------------------------------
DATA_DIR   = getattr(config, "DATA_DIR", "data")
AUTH_FILE  = os.path.join(DATA_DIR, "auth.json")
LOCK_FILE  = os.path.join(DATA_DIR, "setup.lock")
REMEMBER_PATH = os.path.join(DATA_DIR, "iamxray_remember.json")

os.makedirs(DATA_DIR, exist_ok=True)


# ---------------------------------------------------
# AUTH BLOCK (must run immediately)
# ---------------------------------------------------
auth_ok = handle_auth(AUTH_FILE, LOCK_FILE, REMEMBER_PATH)

if not auth_ok:
    st.stop()     # Prevent ANY part of the main UI from rendering


# ---------------------------------------------------
# IMPORTS THAT REQUIRE AUTHENTICATION
# (engine, graph builder, cleanup, etc.)
# ---------------------------------------------------
try:
    from core.fetch_iam import fetch_iam_data
except Exception:
    from core.fetch_iam.wrapper import fetch_iam_data

from core.cleanup import ui_purge_button, ui_reset_app_button
from core.versions import VERSION
from core.fetch_iam.wrapper import list_available_aws_profiles


# small CSS for info-dot used in many places
st.markdown(
    """<style>
      .metric-card{background:rgba(40,40,80,0.75);padding:12px;border-radius:10px;text-align:center;border:1px solid #333}
      .info-dot{font-weight:700;color:#94a3b8;margin-left:6px;cursor:help}
      .small-muted{color:#9aa4bf;font-size:13px}
      .chain-controls {display:flex;gap:8px;align-items:center}
      .table-box {padding: 12px; border-radius: 10px; border: 1px solid #2f3241; background: rgba(255,255,255,0.02); margin-top: 20px;}
      .risk-badge { background: #ef4444; color: white; padding: 2px 8px; border-radius: 6px; font-weight: 700; }
      .risk-badge-low { background: #475569; color: white; padding: 2px 8px; border-radius: 6px; font-weight: 700; }
    </style>""",
    unsafe_allow_html=True,
)

# Helper: render inline label with tooltip
def ui_label(text: str, tooltip: str):
    """Render a label followed by an inline info icon using title tooltip (multi-line allowed via &#10;)."""
    safe = (text or "")
    tip = (tooltip or "").replace('"', "&quot;")
    html = f"{safe} <span class='info-dot' title=\"{tip}\">&#9432;</span>"
    st.markdown(html, unsafe_allow_html=True)

# === Paths (single source of truth) ===
DATA_DIR = getattr(config, "DATA_DIR", "data")
SNAPSHOT_PATH = getattr(config, "SNAPSHOT_PATH", os.path.join(DATA_DIR, "iam_snapshot.json"))
DEMO_PATH = os.path.join(DATA_DIR, "sample_snapshot.json")
REMEMBER_PATH = os.path.join(DATA_DIR, "iamxray_remember.json")
AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
LOCK_FILE = os.path.join(DATA_DIR, "setup.lock")
os.makedirs(DATA_DIR, exist_ok=True)

# === Session defaults ===
st.session_state.setdefault("theme", "dark")
st.session_state.setdefault("authenticated", False)
st.session_state.setdefault("search_query", "")
st.session_state.setdefault("debounce_ts", 0)
st.session_state.setdefault("last_fetch_profile", "Demo")
st.session_state.setdefault("scroll_to_graph", False)

# === License banner (light) ===
LICENSEE = os.getenv("LICENSEE", "")
if LICENSEE:
    st.markdown(
        '<div style="position:fixed;right:20px;bottom:12px;background:rgba(0,0,0,0.45);padding:6px 12px;border-radius:6px;color:white;font-size:12px;z-index:9999">Licensed to: <b>{}</b></div>'.format(
            LICENSEE
        ),
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        '<div style="position:fixed;right:20px;bottom:12px;opacity:0.25;color:black;font-size:12px">IAM X-Ray • beta</div>',
        unsafe_allow_html=True,
    )

# === Preflight: demo snapshot (lightweight) ===
def _atomic_write(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, default=str)
    os.replace(tmp, path)

def ensure_demo_snapshot():
    if os.path.exists(DEMO_PATH):
        return
    demo = {
        "_meta": {
            "fetched_at": datetime.now(timezone.utc).isoformat() + "Z",
            "fast_mode": True,
            "counts": {"users": 1, "roles": 1, "policies": 1},
            "regions": [{"_meta": {"region": "us-east-1"}}],
        },
        "users": [
            {
                "UserName": "demo-user",
                "Arn": "arn:aws:iam::123:user/demo-user",
                "IsRisky": False,
                "AttachedPolicies": [{"PolicyName": "DemoPolicy"}],
                "Groups": [],
            }
        ],
        "roles": [],
        "groups": [],
        "policies": [
            {
                "PolicyName": "DemoPolicy",
                "RiskScore": 1,
                "IsRisky": False,
                "Arn": "arn:aws:iam::123:policy/DemoPolicy",
                "Document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject"],
                            "Resource": ["arn:aws:s3:::demo-bucket/*"],
                        }
                    ]
                },
            }
        ],
    }
    _atomic_write(DEMO_PATH, demo)

ensure_demo_snapshot()

# # === AUTH HANDOFF (delegated) ===
# auth_ok = handle_auth(AUTH_FILE, LOCK_FILE, REMEMBER_PATH)
# if not auth_ok:
#     st.stop()

# === Helpers: lazy imports and caching ===
@st.cache_data(show_spinner=False)
def load_snapshot_cached(path, mtime=None):
    """
    Cache snapshot per file modification time (mtime is provided by caller).
    FIX 2: Always prefer core.fetch_iam.load_snapshot for loading snapshots (encrypted/plaintext fallback).
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    try:
        from core.fetch_iam import load_snapshot as lb
    except Exception:
        # last-resort fallback to legacy loader if present
        try:
            from core.graph_builder import load_snapshot as lb
        except Exception:
            raise RuntimeError("No snapshot loader available")
    snap = lb(path)
    if not isinstance(snap, dict):
        raise ValueError("snapshot not dict")
    return snap

@st.cache_data(show_spinner=False)
def build_graph_cached(snapshot_fingerprint, show_risky, highlight, highlight_color="#ffeb3b", highlight_duration=1800):
    """
    Cached wrapper that builds the full HTML and meta by calling build_iam_graph.
    Normalizes return values so callers get (nx_graph, html_str, meta_dict) regardless of graph_builder API shape.
    """
    from core.graph_builder import build_iam_graph

    # choose snapshot path from active selection (we pass active_snapshot globally)
    try:
        snap = load_snapshot_cached(active_snapshot, os.path.getmtime(active_snapshot) if os.path.exists(active_snapshot) else None)
    except Exception:
        snap = load_snapshot_cached(DEMO_PATH, os.path.getmtime(DEMO_PATH) if os.path.exists(DEMO_PATH) else None)

    res = build_iam_graph(snap, show_only_risky=show_risky, highlight_node=highlight, highlight_color=highlight_color, highlight_duration=highlight_duration)

    # Normalize different possible return signatures:
    # - New API: (nx_graph, html_str, meta_dict)
    # - Old API (legacy we observed): (G_final, html_str, None, export_bytes, meta_dict)
    if isinstance(res, (tuple, list)):
        if len(res) == 3:
            nx_graph, html_str, meta = res
        elif len(res) == 5:
            nx_graph, html_str, _, export_bytes, meta = res
            # try attach export_bytes into meta for callers expecting it
            if isinstance(meta, dict):
                meta = dict(meta)  # shallow copy
                meta.setdefault("raw_export_bytes", export_bytes)
        else:
            # fallback: best-effort mapping
            try:
                nx_graph = res[0]
                html_str = res[1] if len(res) > 1 else ""
                meta = res[-1] if len(res) > 0 else {}
            except Exception:
                nx_graph, html_str, meta = None, "", {}
    else:
        nx_graph, html_str, meta = None, "", {}

    if meta is None:
        meta = {}
    return nx_graph, html_str, meta

@st.cache_data(show_spinner=False)
def filter_resources_cached(snapshot_fingerprint, min_risk, show_risky, keep_key, mode):
    real_path = DEMO_PATH if mode == "Demo" else SNAPSHOT_PATH
    snap = load_snapshot_cached(real_path, os.path.getmtime(real_path) if os.path.exists(real_path) else None)
    users = snap.get("users", []) or []
    groups = snap.get("groups", []) or []
    roles = snap.get("roles", []) or []
    policies = snap.get("policies", []) or []

    # Use tolerant accessors for risk fields (FIX 4)
    def user_risk_ok(u):
        try:
            return int(u.get("RiskScore") or u.get("UserRiskScore") or 0)
        except Exception:
            return 0

    def user_is_risky(u):
        return bool(u.get("IsRisky") or u.get("UserIsRisky") or False)

    def role_risk_ok(r):
        try:
            return int(r.get("AssumePolicyRiskScore") or r.get("RiskScore") or r.get("AssumeRisk") or 0)
        except Exception:
            return 0

    def role_is_risky(r):
        return bool(r.get("IsRisky") or r.get("IsRiskyTrust") or False)

    def policy_risk_ok(p):
        try:
            return int(p.get("RiskScore") or 0)
        except Exception:
            return 0

    def policy_is_risky(p):
        return bool(p.get("IsRisky") or False)

    if min_risk > 0:
        users = [u for u in users if user_risk_ok(u) >= min_risk]
        roles = [r for r in roles if role_risk_ok(r) >= min_risk]
        policies = [p for p in policies if policy_risk_ok(p) >= min_risk]

    if show_risky:
        users = [u for u in users if user_is_risky(u)]
        roles = [r for r in roles if role_is_risky(r)]
        policies = [p for p in policies if policy_is_risky(p)]

    if keep_key:
        try:
            keep_set = set(json.loads(keep_key))
        except Exception:
            keep_set = set()
        if keep_set:
            users = [u for u in users if u.get("UserName") in keep_set]
            groups = [g for g in groups if g.get("GroupName") in keep_set]
            roles = [r for r in roles if r.get("RoleName") in keep_set]
            policies = [p for p in policies if p.get("PolicyName") in keep_set]

    return {
        "users": users,
        "groups": groups,
        "roles": roles,
        "policies": policies,
        "_meta": snap.get("_meta", {}),
    }

# Helper to compute snapshot fingerprint
def snapshot_fingerprint(path):
    try:
        stt = os.path.getmtime(path)
        sz = os.path.getsize(path)
        return f"{path}:{int(stt)}:{sz}"
    except Exception:
        return path

# Sidebar UI (controls) — FIXED: non-empty labels + unique keys to avoid Streamlit warnings/errors
with st.sidebar:
    # === BRAND LOGO (top-left) ===
    try:
        logo_path = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
        st.image(logo_path, width=140)
        st.markdown("<br>", unsafe_allow_html=True)
    except Exception as e:
        st.write(f"Logo load error: {e}")

    st.markdown("## Controls", unsafe_allow_html=True)

    # ------------------------------
    # Auth Mode Selector
    # ------------------------------
    ui_label(
        "Auth Mode",
        "Choose data source:\n"
        "Demo = local sample snapshot\n"
        "AWS Profile = read ~/.aws/credentials\n"
        "Env Keys = paste temporary credentials"
    )

    # user-facing mode (widget)
    ui_mode = st.selectbox(
        " ",
        ["Demo", "AWS Profile", "Env Keys"],
        key="auth_mode",
        label_visibility="collapsed",
    )

    # effective mode (safe, we never modify session_state)
    effective_mode = ui_mode
    selected_profile = None
    env = None

    # discover AWS profiles
    profiles = list_available_aws_profiles()

    # ------------------------------
    # CASE 1 → AWS PROFILE MODE
    # ------------------------------
    if ui_mode == "AWS Profile":

        ui_label(
            "AWS Profile",
            "Detected profiles from ~/.aws/credentials.\n"
            "Works in Docker if ~/.aws is mounted correctly."
        )

        if not profiles:
            # fallback WITHOUT touching st.session_state
            st.warning(
                "⚠ No AWS profiles found.\n"
                "Switched to Demo Mode.\n\n"
                "Fix: Mount ~/.aws:\n"
                "- Windows:  ${USERPROFILE}/.aws:/home/iamx/.aws:ro\n"
                "- Linux/Mac: ~/.aws:/home/iamx/.aws:ro"
            )
            effective_mode = "Demo"

        else:
            selected_profile = st.selectbox(
                " ",
                profiles,
                key="profile_select",
                label_visibility="collapsed",
            )

    # ------------------------------
    # CASE 2 → ENV KEYS MODE
    # ------------------------------
    elif ui_mode == "Env Keys":

        ui_label(
            "Env Keys",
            "Paste AWS_ACCESS_KEY_ID / SECRET_ACCESS_KEY.\n"
            "Optional: AWS_SESSION_TOKEN for STS."
        )

        ak = st.text_input(
            " ",
            placeholder="AWS_ACCESS_KEY_ID",
            key="env_ak",
            type="password",
            label_visibility="collapsed",
        )

        sk = st.text_input(
            " ",
            placeholder="AWS_SECRET_ACCESS_KEY",
            key="env_sk",
            type="password",
            label_visibility="collapsed",
        )

        tok = st.text_input(
            " ",
            placeholder="AWS_SESSION_TOKEN (optional)",
            key="env_tok",
            type="password",
            label_visibility="collapsed",
        )

        region = st.text_input(
            " ",
            "us-east-1",
            placeholder="AWS_REGION",
            key="env_region",
            label_visibility="collapsed",
        )

        if ak and sk:
            env = {
                "aws_access_key_id": ak,
                "aws_secret_access_key": sk,
                "aws_session_token": tok,
                "region_name": region,
            }

    # ------------------------------
    # CASE 3 → DEMO MODE
    # ------------------------------
    else:
        effective_mode = "Demo"

    # ------------------------------

    # ------------------------------
    st.markdown("---")

    # Fetch Options header
    st.markdown("### Fetch Options", unsafe_allow_html=True)
    ui_label("Fast (use cache)", "When enabled, uses cached snapshot if found and not expired.&#10;Good for quick iteration.")
    fast_mode = st.checkbox(" ", value=True, key="opt_fast", label_visibility="collapsed")

    ui_label("Force Live", "Ignore cache and fetch fresh live IAM snapshot from AWS.&#10;May take longer and require network access.")
    force_fetch = st.checkbox(" ", value=False, key="opt_force", label_visibility="collapsed")

    ui_label("Encrypt Snapshot", "Encrypt the stored snapshot file on disk (if supported by fetch engine).")
    encrypt = st.checkbox(" ", value=False, key="opt_encrypt", label_visibility="collapsed")

    ui_label("TTL (minutes)", "Cache TTL in minutes — cached snapshots younger than this are reused.")
    ttl_mins = st.number_input(" ", 1, 1440, 60, key="opt_ttl", label_visibility="collapsed")

    ui_label("Retention Days", "How many days to keep collected snapshots before eligible for purge.")
    keep_days = st.number_input(" ", 1, 365, 30, key="opt_keepdays", label_visibility="collapsed")

    ui_label("Fetch Latest Snapshot", "Click to run the fetch engine and persist an updated snapshot.")
    fetch_btn = st.button("Fetch Latest Snapshot", key="btn_fetch")

    st.write("---")
    st.subheader("Filter")
    ui_label("Show Only Risky", "Filter view to only show principals/policies flagged as risky.")
    show_risky = st.checkbox(" ", False, key="filter_risky", label_visibility="collapsed")

    ui_label("Changes Only", "Try to detect recent changes and limit display to changed principals.&#10;Relies on compute_keep_set_from_diff.")
    show_changes = st.checkbox(" ", False, key="filter_changes", label_visibility="collapsed")

    ui_label("Min Risk Score", "Slider to filter entries by minimum RiskScore value.")
    min_risk = st.slider(" ", 0, 10, 0, key="filter_minrisk", label_visibility="collapsed")

    st.write("---")
    st.caption("Housekeeping")
    # Purge / Reset tooltips
    try:
        # ui_purge_button likely renders its own control — show a nearby tooltip line for clarity
        st.markdown("<div style='display:flex;gap:8px;align-items:center;'>", unsafe_allow_html=True)
        st.markdown("<div style='flex:1'>", unsafe_allow_html=True)
        ui_label("Purge snapshots", "Deletes old snapshots according to retention policy. Use with caution.")
        st.markdown("</div>", unsafe_allow_html=True)
        ui_purge_button()
    except Exception:
        st.button("Purge snapshots (not available)", disabled=True, key="btn_purge_disabled")

    try:
        st.markdown("<div style='display:flex;gap:8px;align-items:center;'>", unsafe_allow_html=True)
        st.markdown("<div style='flex:1'>", unsafe_allow_html=True)
        ui_label("Reset app", "Reset application state and session — does not delete snapshots.")
        st.markdown("</div>", unsafe_allow_html=True)
        ui_reset_app_button()
    except Exception:
        st.button("Reset app (not available)", disabled=True, key="btn_reset_disabled")
        
mode = effective_mode
# Fetch handler
active_snapshot = DEMO_PATH if mode == "Demo" else SNAPSHOT_PATH

if fetch_btn:
    fetch_box = st.empty()
    prog = st.progress(0)

    try:
        fetch_box.info("Fetching IAM data…")

        # handle env keys
        if mode == "Env Keys" and env:
            os.environ["AWS_ACCESS_KEY_ID"] = env["aws_access_key_id"]
            os.environ["AWS_SECRET_ACCESS_KEY"] = env["aws_secret_access_key"]
            if env.get("aws_session_token"):
                os.environ["AWS_SESSION_TOKEN"] = env["aws_session_token"]
            if env.get("region_name"):
                os.environ["AWS_REGION"] = env["region_name"]

        # progress callback for engine
        def _cb(frac):
            try:
                frac = min(max(float(frac), 0.0), 1.0)
            except:
                frac = 0
            prog.progress(frac)

        # run engine
        fetch_iam_data(
            session=None,
            profile_name=(selected_profile if effective_mode == "AWS Profile" else None),
            out_path=SNAPSHOT_PATH,
            fast_mode=fast_mode,
            force_fetch=force_fetch,
            encrypt=encrypt,
            multi_region=False,
            cache_ttl=ttl_mins * 60,
            progress_callback=_cb,
        )

        prog.progress(1.0)
        fetch_box.success("Snapshot updated!")
        st.session_state.last_fetch_profile = (selected_profile or ("Env Keys" if mode == "Env Keys" else "Demo"))
        st.session_state.scroll_to_graph = True
        fetch_box.empty()
        st.rerun()

    except Exception as e:
        fetch_box.error(f"Fetch failed: {e}")
        prog.progress(0)

# Ensure snapshot file exists
if not os.path.exists(active_snapshot):
    st.warning("No snapshot found — run Fetch or switch to Demo")
    st.stop()

snap_fp = snapshot_fingerprint(active_snapshot)

# If user requested "changes only" compute keep set
keep_key = None
if show_changes:
    try:
        from core.graph_builder import compute_keep_set_from_diff
        snap_for_diff = load_snapshot_cached(active_snapshot, os.path.getmtime(active_snapshot))
        keep_set = compute_keep_set_from_diff(snap_for_diff) or set()
        keep_key = json.dumps(list(keep_set))
    except Exception:
        keep_key = None

# Load filtered resources
filtered = filter_resources_cached(snap_fp, min_risk, show_risky, keep_key, mode)
users = filtered["users"]
groups = filtered["groups"]
roles = filtered["roles"]
policies = filtered["policies"]
meta = filtered["_meta"] or {}

# counts
u_count = len(users)
g_count = len(groups)
r_count = len(roles)
p_count = len(policies)
ru = len([u for u in users if (u.get("IsRisky") or u.get("UserIsRisky") or False)])
rg = len([g for g in groups if (g.get("IsRisky") or False)])
rr = len([r for r in roles if (r.get("IsRisky") or False)])
rp = len([p for p in policies if (p.get("IsRisky") or False)])

# Tabs (Permission Chains removed)
tabs = st.tabs(["Graph View", "Table View"])

# Graph View
with tabs[0]:
    # title with tooltip (use ui_label for search, a simple markdown for title + inline icon)
    st.markdown(
        "### 🕸 Interactive IAM Attack Graph <span class='small-muted'>&nbsp;<span class='info-dot' title=\"Interactive attack graph rendered from the latest snapshot.&#10;Hover nodes to see details.&#10;Use the search box to highlight nodes/actions.\">&#9432;</span></span>",
        unsafe_allow_html=True,
    )

    # non-empty label to avoid Streamlit accessibility warnings
    ui_label("Search entity or permission", "Search across users, roles, policies, and actions. Examples: 's3:PutObject' or 'alice'.")
    search = st.text_input(" ", value=st.session_state.get("search_query", ""), placeholder="ex: s3:PutObject or alice", key="search_input", label_visibility="collapsed")
    now = int(time.time() * 1000)
    if (now - st.session_state["debounce_ts"]) > 300:
        st.session_state["search_query"] = search
    st.session_state["debounce_ts"] = now
    highlight = st.session_state["search_query"]

    graph_cache_key = f"{snap_fp}:risky={show_risky}:hl={highlight}"
    try:
        # FIX 3: build_graph_cached returns normalized (nx_graph, html_str, meta)
        G, graph_html, graph_meta = build_graph_cached(graph_cache_key, show_risky, highlight)
    except Exception as e:
        st.error(f"Graph build error: {e}")
        st.stop()

    # prepare export bytes if available in meta
    export_bytes = None
    if isinstance(graph_meta, dict):
        # try multiple possible keys to be robust
        export_bytes = graph_meta.get("raw_export_bytes") or graph_meta.get("raw_graph_bytes") or None
        # if meta contains path to raw export, try to load it
        raw_path = graph_meta.get("raw_export_path") or graph_meta.get("raw_export_file") or graph_meta.get("raw_export")
        if not export_bytes and raw_path and isinstance(raw_path, str) and os.path.exists(raw_path):
            try:
                with open(raw_path, "rb") as fh:
                    export_bytes = fh.read()
            except Exception:
                export_bytes = None

    if graph_html:
        components.html(graph_html, height=900, scrolling=False)

        # export button area with tooltip
        if export_bytes:
            st.markdown("<div style='display:flex;gap:8px;align-items:center'>", unsafe_allow_html=True)
            st.markdown("<div style='flex:1'>", unsafe_allow_html=True)
            st.markdown('<span class="info-dot" title="Download a compact JSON export of the rendered graph.&#10;Useful for offline analysis.">&#9432;</span>', unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)
            st.download_button("Download Graph JSON", export_bytes, "iam_graph.json", key="dl_graph_json")
            st.markdown("</div>", unsafe_allow_html=True)

        raw_export_path = os.path.join(tempfile.gettempdir(), "iam_xray_graph.raw.json")
        try:
            if os.path.exists(raw_export_path):
                with open(raw_export_path, "rb") as rf:
                    raw_bytes = rf.read()
                st.markdown('<span class="info-dot" title="Raw (uncollapsed) graph JSON export. Larger, includes low-level nodes.">&#9432;</span>', unsafe_allow_html=True)
                st.download_button("Download Raw (uncollapsed) Graph JSON", raw_bytes, "iam_graph.raw.json", key="dl_graph_raw")
        except Exception:
            pass

    # small explanation about highlight semantics (tooltip)
    st.markdown(
        "<div style='margin-top:8px'><small class='small-muted'>Tip: enter a node or action to highlight matching nodes. <span class='info-dot' title=\"Highlight matches in the graph.&#10;Exact matches or partial substrings will be used.\">&#9432;</span></small></div>",
        unsafe_allow_html=True,
    )

# ============================================================
# TABLE VIEW  — CLEAN, STYLED, NO AGGRID (Option B) with tooltips
# ============================================================
with tabs[1]:
    st.markdown("## 🟦 Current Active IAM Resources (Simple View)", unsafe_allow_html=True)

    fetched_at = meta.get("fetched_at", "—")
    fast_status = "FAST (cache)" if meta.get("fast_mode") else "LIVE (fresh)"

    # Region resolution
    region_used = None
    try:
        regions_meta = meta.get("regions") or []
        if regions_meta:
            first = regions_meta[0] or {}
            region_used = (
                first.get("_meta", {}).get("region")
                or first.get("_meta", {}).get("Region")
                or first.get("region")
            )
        if not region_used:
            region_used = meta.get("region") or "us-east-1"
    except Exception:
        region_used = meta.get("region") or "us-east-1"

    if isinstance(region_used, dict):
        region_used = region_used.get("name") or region_used.get("Region") or "us-east-1"

    # ================= Header metrics (tooltips included inline) =================
    c1, c2, c3 = st.columns(3)
    # profile card with tooltip
    profile_used = ("Demo" if mode == "Demo" else (selected_profile or st.session_state.get("last_fetch_profile", "Demo")))
    c1.markdown(
        (
            "<div class='metric-card'>"
            "<div style='color:#94a3b8'>AWS Profile <span class='info-dot' title=\"Selected credential profile used to fetch the snapshot.&#10;Demo uses sample data.\">&#9432;</span></div>"
            "<div style='font-weight:900;color:#38bdf8'>{profile}</div></div>"
        ).format(profile=profile_used),
        unsafe_allow_html=True,
    )

    # region card with tooltip
    c2.markdown(
        (
            "<div class='metric-card'>"
            "<div style='color:#94a3b8'>Region <span class='info-dot' title=\"Detected region from snapshot metadata.&#10;If missing, defaults to us-east-1.\">&#9432;</span></div>"
            "<div style='font-weight:900;color:#34d399'>{region}</div></div>"
        ).format(region=region_used),
        unsafe_allow_html=True,
    )

    # fetch mode card with tooltip
    c3.markdown(
        (
            "<div class='metric-card'>"
            "<div style='color:#94a3b8'>Fetch Mode <span class='info-dot' title=\"Indicates whether snapshot was served from cache or fetched live.\">&#9432;</span></div>"
            "<div style='font-weight:900;color:#f97316'>{fast}</div></div>"
        ).format(fast=fast_status),
        unsafe_allow_html=True,
    )

    st.markdown("<br>", unsafe_allow_html=True)

    a, b, c, d = st.columns(4)
    a.markdown(
        ("<div class='metric-card'>Total Users <span class='info-dot' title=\"Number of user principals in the current filtered snapshot.\">&#9432;</span>"
         "<div style='font-weight:900'>{count}</div></div>").format(count=u_count),
        unsafe_allow_html=True,
    )
    b.markdown(
        ("<div class='metric-card'>Total Groups <span class='info-dot' title=\"Number of groups in the snapshot.\">&#9432;</span>"
         "<div style='font-weight:900'>{count}</div></div>").format(count=g_count),
        unsafe_allow_html=True,
    )
    c.markdown(
        ("<div class='metric-card'>Total Roles <span class='info-dot' title=\"Number of roles in the snapshot.\">&#9432;</span>"
         "<div style='font-weight:900'>{count}</div></div>").format(count=r_count),
        unsafe_allow_html=True,
    )
    d.markdown(
        ("<div class='metric-card'>Total Policies <span class='info-dot' title=\"Number of policies in the snapshot.\">&#9432;</span>"
         "<div style='font-weight:900'>{count}</div></div>").format(count=p_count),
        unsafe_allow_html=True,
    )

    st.markdown("<br><h4>🔥 Risk Summary <span class='info-dot' title=\"Summary counts of principals/policies flagged risky by the analyzer.\">&#9432;</span></h4>", unsafe_allow_html=True)
    r1, r2, r3, r4 = st.columns(4)
    r1.markdown(("<div class='metric-card'>Risky Users <div style='color:#ef4444;font-weight:900'>{}</div></div>").format(ru), unsafe_allow_html=True)
    r2.markdown(("<div class='metric-card'>Risky Groups <div style='color:#ef4444;font-weight:900'>{}</div></div>").format(rg), unsafe_allow_html=True)
    r3.markdown(("<div class='metric-card'>Risky Roles <div style='color:#ef4444;font-weight:900'>{}</div></div>").format(rr), unsafe_allow_html=True)
    r4.markdown(("<div class='metric-card'>Risky Policies <div style='color:#ef4444;font-weight:900'>{}</div></div>").format(rp), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(
        (
            "<div style='padding:10px;border-radius:8px;border:1px solid #333;background:rgba(255,255,255,0.02)'>"
            "<small>Snapshot Fetched: <span class='info-dot' title=\"Timestamp when snapshot was collected. If blank, loader could not find metadata.\">&#9432;</span></small> <b>{fetched_at}</b></div>"
        ).format(fetched_at=fetched_at),
        unsafe_allow_html=True,
    )

    st.markdown("---")

    # Styled DataFrame helper (simple — we output HTML tables)
    def styled_df(html_table):
        st.markdown(html_table, unsafe_allow_html=True)

    # =========================================
    # USERS TABLE (with heading tooltip & column notes)
    # =========================================
    st.markdown(
        "### 👤 Users <span class='small-muted'>(graph shows relationships) <span class='info-dot' title=\"Columns: UserName = IAM username; Arn = full ARN; Groups = groups user is a member of; Policies = attached policies; RiskScore = computed risk (0-10).&#10;Risk badge color: red >=5, muted <5.&#10;IsRisky indicates the analyzer flagged the principal.\">&#9432;</span></span>",
        unsafe_allow_html=True,
    )

    user_rows = []
    for u in users:
        risk_score = u.get("RiskScore") or u.get("UserRiskScore") or 0
        user_rows.append(
            {
                "UserName": u.get("UserName", ""),
                "Arn": u.get("Arn", ""),
                "Groups": ", ".join(u.get("Groups", [])) if isinstance(u.get("Groups", []), list) else "",
                "Policies": ", ".join(p.get("PolicyName") if isinstance(p, dict) else str(p) for p in u.get("AttachedPolicies", [])),
                "RiskScore": risk_score,
                "IsRisky": bool(u.get("IsRisky") or u.get("UserIsRisky") or False),
            }
        )

    df_users = pd.DataFrame(user_rows)

    if not df_users.empty:
        df_users["RiskScore"] = df_users["RiskScore"].apply(lambda r: "<span class='risk-badge'>{}</span>".format(r) if r >= 5 else "<span class='risk-badge-low'>{}</span>".format(r))
        st.markdown("<div class='table-box'>", unsafe_allow_html=True)
        styled_df(df_users.to_html(escape=False, index=False))
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info("No Users Found.")

    # =========================================
    # ROLES TABLE (with heading tooltip)
    # =========================================
    st.markdown("### 🎭 Roles <span class='info-dot' title=\"Columns: RoleName, Arn, Policies (attached), RiskScore.&#10;AssumePolicyRiskScore shows how risky the role's trust/assume policy is.\">&#9432;</span>", unsafe_allow_html=True)

    role_rows = []
    for r in roles:
        risk_score = r.get("AssumePolicyRiskScore") or r.get("TrustPolicyRiskScore") or r.get("RiskScore") or 0
        role_rows.append(
            {
                "RoleName": r.get("RoleName", ""),
                "Arn": r.get("Arn", ""),
                "Policies": ", ".join(p.get("PolicyName") if isinstance(p, dict) else str(p) for p in r.get("AttachedPolicies", [])),
                "RiskScore": risk_score,
                "IsRisky": bool(r.get("IsRisky") or False),
            }
        )

    df_roles = pd.DataFrame(role_rows)

    if not df_roles.empty:
        df_roles["RiskScore"] = df_roles["RiskScore"].apply(lambda r: "<span class='risk-badge'>{}</span>".format(r) if r >= 5 else "<span class='risk-badge-low'>{}</span>".format(r))
        st.markdown("<div class='table-box'>", unsafe_allow_html=True)
        styled_df(df_roles.to_html(escape=False, index=False))
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info("No Roles Found.")

    # =========================================
    # POLICIES TABLE (with heading tooltip)
    # =========================================
    st.markdown("### 📘 Policies <span class='info-dot' title=\"Columns: PolicyName, Arn, RiskScore.&#10;Actions column omitted in compact view; use graph export for full statements.\">&#9432;</span>", unsafe_allow_html=True)

    pol_rows = []
    for p in policies:
        risk_score = p.get("RiskScore") or p.get("score") or 0
        pol_rows.append({"PolicyName": p.get("PolicyName", ""), "Arn": p.get("Arn", ""), "RiskScore": risk_score, "IsRisky": bool(p.get("IsRisky") or False)})

    df_pol = pd.DataFrame(pol_rows)

    if not df_pol.empty:
        df_pol["RiskScore"] = df_pol["RiskScore"].apply(lambda r: "<span class='risk-badge'>{}</span>".format(r) if r >= 5 else "<span class='risk-badge-low'>{}</span>".format(r))
        st.markdown("<div class='table-box'>", unsafe_allow_html=True)
        styled_df(df_pol.to_html(escape=False, index=False))
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info("No Policies Found.")

# Footer
st.caption("IAM X-Ray — Stable Beta Build • Graph + Table synced • Non-technical friendly overview.")
st.caption("IAM X-Ray — v{} • Stable Beta".format(VERSION))

