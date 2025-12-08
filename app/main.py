#app/main.py
"""
IAM X-Ray — Optimized main.py (Stable Beta)
- Smaller, faster, modular
- Lazy-load heavy modules
- Caches snapshot / graph / filtered tables
- Auth delegated to core.auth.handle_auth(auth_file, lock_file, remember_file)
- Compatible with core.fetch_iam, core.graph_builder, core.cleanup, core.config, core.versions
"""

import sys
import os
import json
import time

import configparser
from datetime import datetime, timezone, timedelta
import streamlit as st
import streamlit.components.v1 as components
import pandas as pd

# PATHS & import fixes
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core import config
from core.fetch_iam import fetch_iam_data
# graph functions will be lazy-imported where needed
from core import cleanup
from core.cleanup import ui_purge_button, ui_reset_app_button
from core.versions import VERSION
from core.auth import handle_auth  # expects (auth_file, lock_file, remember_path)

# === Basic page config & CSS ===
st.set_page_config(page_title="IAM X-Ray — Stable Beta", layout="wide", initial_sidebar_state="expanded")
st.markdown(
    """<style>
      .metric-card{background:rgba(40,40,80,0.75);padding:12px;border-radius:10px;text-align:center;border:1px solid #333}
      .info-dot{font-weight:700;color:#94a3b8;margin-left:6px;cursor:help}.small-muted{color:#9aa4bf;font-size:13px}
    </style>""",
    unsafe_allow_html=True,
)

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
# If other modules set this to force demo, respect it.
# st.session_state.force_demo_mode may be set by auth module.

# === License banner (light) ===
LICENSEE = os.getenv("LICENSEE", "")
if LICENSEE:
    st.markdown(f"""<div style="position:fixed;right:20px;bottom:12px;background:rgba(0,0,0,0.45);padding:6px 12px;border-radius:6px;color:white;font-size:12px;z-index:9999">Licensed to: <b>{LICENSEE}</b></div>""", unsafe_allow_html=True)
else:
    st.markdown("""<div style="position:fixed;right:20px;bottom:12px;opacity:0.25;color:black;font-size:12px">IAM X-Ray • beta</div>""", unsafe_allow_html=True)

# === Preflight: demo snapshot (lightweight) ===
def _atomic_write(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, default=str)
    os.replace(tmp, path)

def ensure_demo_snapshot():
    if os.path.exists(DEMO_PATH): return
    demo = {
        "_meta": {"fetched_at": datetime.now(timezone.utc).isoformat() + "Z", "fast_mode": True, "counts": {"users": 1, "roles": 1, "policies": 1}},
        "users": [{"UserName": "demo-user", "Arn": "arn:aws:iam::123:user/demo-user", "IsRisky": False, "AttachedPolicies": [{"PolicyName": "DemoPolicy"}]}],
        "roles": [], "groups": [], "policies": [{"PolicyName": "DemoPolicy", "RiskScore": 1, "IsRisky": False, "Arn": "arn:aws:iam::123:policy/DemoPolicy"}]
    }
    _atomic_write(DEMO_PATH, demo)

ensure_demo_snapshot()

# === AUTH HANDOFF (delegated) ===
# handle_auth will display onboarding/login UI and set st.session_state.authenticated appropriately.
auth_ok = handle_auth(AUTH_FILE, LOCK_FILE, REMEMBER_PATH)
if not auth_ok:
    st.stop()

# If auth triggered demo forcing, honor it
def _select_mode_with_force(defaults=("Demo","AWS Profile","Env Keys")):
    if st.session_state.get("force_demo_mode"):
        return "Demo"
    return st.selectbox("Auth Mode", list(defaults), help="Choose Demo for sample data, or AWS Profile / Env Keys for live fetch.")
# We'll call this inside sidebar (below) to keep layout stable.

# === Helpers: lazy imports and caching ===
@st.cache_data(show_spinner=False)
def load_snapshot_cached(path, mtime=None):
    """
    Cache snapshot per file modification time (mtime is provided by caller).
    Using st.cache_data to store JSON/dict snapshot.
    """
    from pathlib import Path
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    # We call an existing load_snapshot if provided by core.graph_builder or fetch_iam.
    try:
        from core.graph_builder import load_snapshot as lb
    except Exception:
        from core.fetch_iam import load_snapshot as lb
    snap = lb(path)
    if not isinstance(snap, dict):
        raise ValueError("snapshot not dict")
    return snap

@st.cache_data(show_spinner=False)
def compute_keep_set_cached(serialized_meta):
    # simple pass-through wrapper: compute_keep_set_from_diff expects snapshot; we pass serialized_meta as JSON str
    try:
        from core.graph_builder import compute_keep_set_from_diff
    except Exception:
        # fallback: no diff available
        return set()
    # serialized_meta is actually the snapshot dict dumped to string; to avoid large keys, we accept a fingerprint string.
    # In our usage below we'll pass snapshot JSON string to this function only when show_changes True.
    # But compute_keep_set_from_diff needs the snapshot dict — so caller will call it directly when needed.
    return set()

# Graph builder cache keyed by (snapshot fingerprint, show_only_risky, highlight)
@st.cache_data(show_spinner=False)
def build_graph_cached(snapshot_fingerprint, show_only_risky, highlight, highlight_color="#ffeb3b", highlight_duration=1800):
    # lazily import heavy graph builder
    from core.graph_builder import build_iam_graph
    # caller must provide actual snapshot object via file; we will load it again inside build_iam_graph call by reading snapshot path in main flow.
    # But to ensure caching works, snapshot_fingerprint should change whenever snapshot changes.
    # We will load snapshot from SNAPSHOT_PATH here (safe because function is cached by fingerprint).
    try:
        snap = load_snapshot_cached(SNAPSHOT_PATH, os.path.getmtime(SNAPSHOT_PATH) if os.path.exists(SNAPSHOT_PATH) else None)
    except Exception:
        snap = load_snapshot_cached(DEMO_PATH, os.path.getmtime(DEMO_PATH))
    # build_iam_graph returns (G, graph_html, clicked, export_bytes, empty_state)
    return build_iam_graph(snap, show_only_risky=show_only_risky, highlight_node=highlight, highlight_color=highlight_color, highlight_duration=highlight_duration)

# Filter resources cached by (snapshot_fingerprint, min_risk, show_risky, keep_key)
@st.cache_data(show_spinner=False)
def filter_resources_cached(snapshot_fingerprint, min_risk, show_risky, keep_key, mode):
    # pick correct snapshot file
    real_path = DEMO_PATH if mode == "Demo" else SNAPSHOT_PATH

    # load cached snapshot
    snap = load_snapshot_cached(real_path, os.path.getmtime(real_path))

    users = snap.get("users", []) or []
    groups = snap.get("groups", []) or []
    roles = snap.get("roles", []) or []
    policies = snap.get("policies", []) or []

    # --- RISK FILTERS ---
    if min_risk > 0:
        users = [u for u in users if (u.get("RiskScore") or 0) >= min_risk]
        roles = [r for r in roles if (r.get("AssumePolicyRiskScore") or 0) >= min_risk]
        policies = [p for p in policies if (p.get("RiskScore") or 0) >= min_risk]

    if show_risky:
        users = [u for u in users if u.get("IsRisky")]
        roles = [r for r in roles if r.get("IsRisky")]
        policies = [p for p in policies if p.get("IsRisky")]

    # --- KEEP (CHANGES ONLY) ---
    if keep_key:
        try:
            keep_set = set(json.loads(keep_key))
        except:
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
        "_meta": snap.get("_meta", {})
    }


# === Sidebar UI (controls) ===
with st.sidebar:
    st.header("Controls")

    # Auth Mode selection but allow force_demo_mode from auth to override
    if st.session_state.get("force_demo_mode"):
        mode = "Demo"
        st.markdown("**Auth Mode:** Demo (forced by onboarding)")
    else:
        mode = st.selectbox("Auth Mode", ["Demo", "AWS Profile", "Env Keys"], help="Choose Demo for sample data, AWS Profile to use ~/.aws/credentials, or Env Keys to paste temporary keys.")
    # list profiles (cheap)
    def list_profiles():
        creds = os.path.expanduser("~/.aws/credentials")
        if not os.path.exists(creds):
            return []
        cp = configparser.ConfigParser()
        cp.read(creds)
        return cp.sections()
    profiles = list_profiles()

    selected_profile = None
    env = None
    if mode == "AWS Profile":
        selected_profile = st.selectbox("AWS Profile", ["default"] + profiles, help="Select profile from ~/.aws/credentials")
    elif mode == "Env Keys":
        ak = st.text_input("AWS_ACCESS_KEY_ID", type="password", help="Paste access key. Only stored in environment during fetch.")
        sk = st.text_input("AWS_SECRET_ACCESS_KEY", type="password", help="Paste secret key. Only stored in environment during fetch.")
        tok = st.text_input("AWS_SESSION_TOKEN (optional)", type="password", help="Optional session token.")
        region = st.text_input("AWS_REGION", "us-east-1", help="Region for lookups.")
        if ak and sk:
            env = {"aws_access_key_id": ak, "aws_secret_access_key": sk, "aws_session_token": tok, "region_name": region}

    st.write("---")
    st.subheader("Fetch Options")
    fast_mode = st.checkbox("Fast (use cache)", value=True, help="Use cached snapshot if available.")
    force_fetch = st.checkbox("Force Live", value=False, help="Ignore cache and do a live fetch.")
    encrypt = st.checkbox("Encrypt Snapshot", value=False, help="Encrypt snapshot if configured.")
    ttl_mins = st.number_input("Cache TTL (minutes)", 1, 1440, 60, help="Cached snapshot TTL.")
    keep_days = st.number_input("Retention Days", 1, 365, 30, help="How many days to keep old snapshots.")

    fetch_btn = st.button("Fetch Latest Snapshot", help="Start fetching IAM data from AWS using selected auth mode.")

    st.write("---")
    st.subheader("Filter")
    show_risky = st.checkbox("Show Only Risky", False, help="Show only resources flagged as risky by the analyzer.")
    show_changes = st.checkbox("Changes Only", False, help="Show only resources changed since last snapshot.")
    min_risk = st.slider("Min Risk Score", 0, 10, 0, help="Filter out resources with risk score below this threshold.")

    st.write("---")
    st.caption("Housekeeping")
    # use cleanup utilities if available
    try:
        ui_purge_button()
    except Exception:
        st.button("Purge snapshots (not available)", disabled=True)
    try:
        ui_reset_app_button()
    except Exception:
        st.button("Reset app (not available)", disabled=True)

# === Fetch handler ===
active_snapshot = DEMO_PATH if mode == "Demo" else SNAPSHOT_PATH

if fetch_btn:
    # placeholder prevents stale messages after rerun
    fetch_box = st.empty()
    try:
        fetch_box.info("Fetching IAM data…")

        # set env if Env Keys
        if mode == "Env Keys" and env:
            os.environ["AWS_ACCESS_KEY_ID"] = env["aws_access_key_id"]
            os.environ["AWS_SECRET_ACCESS_KEY"] = env["aws_secret_access_key"]
            if env.get("aws_session_token"):
                os.environ["AWS_SESSION_TOKEN"] = env["aws_session_token"]
            if env.get("region_name"):
                os.environ["AWS_REGION"] = env["region_name"]

        fetch_iam_data(
            session=None,
            profile_name=(selected_profile if mode == "AWS Profile" else None),
            out_path=SNAPSHOT_PATH,
            fast_mode=fast_mode,
            force_fetch=force_fetch,
            encrypt=encrypt,
            multi_region=False,
            cache_ttl=ttl_mins * 60
        )

        fetch_box.success("Snapshot updated!")

        st.session_state.last_fetch_profile = (
            selected_profile or 
            ("Env Keys" if mode=="Env Keys" else "Demo")
        )
        st.session_state.scroll_to_graph = True

        # CLEAR messages cleanly
        fetch_box.empty()

        # force clean UI refresh
        st.rerun()

    except Exception as e:
        fetch_box.error(f"Fetch failed: {e}")


# === Ensure snapshot file exists ===
if not os.path.exists(active_snapshot):
    st.warning("No snapshot found — run Fetch or switch to Demo")
    st.stop()

# compute fingerprint for caching: combine file mtime + size
def snapshot_fingerprint(path):
    try:
        stt = os.path.getmtime(path)
        sz = os.path.getsize(path)
        return f"{path}:{int(stt)}:{sz}"
    except Exception:
        return path

snap_fp = snapshot_fingerprint(active_snapshot)

# If user requested "changes only" we must compute keep set via compute_keep_set_from_diff (lazy import)
keep_key = None
if show_changes:
    try:
        from core.graph_builder import compute_keep_set_from_diff
        snap_for_diff = load_snapshot_cached(active_snapshot, os.path.getmtime(active_snapshot))
        keep_set = compute_keep_set_from_diff(snap_for_diff) or set()
        # cache key must be JSON-serializable
        keep_key = json.dumps(list(keep_set))
    except Exception:
        keep_key = None

# Load filtered resources (cached)
filtered = filter_resources_cached(snap_fp, min_risk, show_risky, keep_key, mode)
users = filtered["users"]
groups = filtered["groups"]
roles = filtered["roles"]
policies = filtered["policies"]
meta = filtered["_meta"] or {}

# counts
u_count = len(users); g_count = len(groups); r_count = len(roles); p_count = len(policies)
ru = len([u for u in users if u.get("IsRisky")])
rg = len([g for g in groups if g.get("IsRisky")])
rr = len([r for r in roles if r.get("IsRisky")])
rp = len([p for p in policies if p.get("IsRisky")])

# === Tabs: GRAPH & TABLE (lazy heavy imports inside blocks) ===
tabs = st.tabs(["Graph View", "Table View"])

# Graph View
with tabs[0]:
    st.markdown("### 🕸 Interactive IAM Attack Graph <span class='small-muted'>Hover the info icon for quick help</span>", unsafe_allow_html=True)
    st.markdown("<div style='margin-bottom:8px;'>Graph shows resources and trust edges. <span class='info-dot' title='Click nodes to inspect. Use the search box to highlight nodes or permissions.'>ⓘ</span></div>", unsafe_allow_html=True)

    # search box with debounce
    search = st.text_input("Search entity or permission", value=st.session_state.get("search_query",""), placeholder="ex: s3:PutObject or alice", help="Type a username, role, or permission.")
    now = int(time.time() * 1000)
    if (now - st.session_state["debounce_ts"]) > 300:
        st.session_state["search_query"] = search
    st.session_state["debounce_ts"] = now
    highlight = st.session_state["search_query"]

    # Build graph lazily and cached by snapshot fingerprint + show_risky + highlight
    graph_cache_key = f"{snap_fp}:risky={show_risky}:hl={highlight}"
    try:
        G, graph_html, clicked, export_bytes, empty_state = build_graph_cached(graph_cache_key, show_risky, highlight)
    except Exception as e:
        st.error(f"Graph build error: {e}")
        st.stop()

    if graph_html:
        components.html(graph_html, height=900, scrolling=False)
        if export_bytes:
            st.download_button("Download Graph JSON", export_bytes, "iam_graph.json", help="Download raw graph JSON for offline inspection")

# Table View
with tabs[1]:
    st.markdown("## 🟦 Current Active IAM Resources (Simple View)")
    fetched_at = meta.get("fetched_at", "—")
    fast_status = "FAST (cache)" if meta.get("fast_mode") else "LIVE (fresh)"
    region_used = meta.get("region") or (meta.get("regions", ["us-east-1"])[0] if meta.get("regions") else "us-east-1")
    if isinstance(region_used, dict):
        region_used = region_used.get("name") or region_used.get("Region") or "us-east-1"

    # top metrics row
    c1, c2, c3 = st.columns(3)
    profile_used = ("Demo" if mode=="Demo" else (selected_profile or st.session_state.get("last_fetch_profile","Demo")))
    c1.markdown(f"<div class='metric-card'><div style='color:#94a3b8'>AWS Profile <span class='info-dot' title='Profile used for the last fetch.'>ⓘ</span></div><div style='font-weight:900;color:#38bdf8'>{profile_used}</div></div>", unsafe_allow_html=True)
    c2.markdown(f"<div class='metric-card'><div style='color:#94a3b8'>Region <span class='info-dot' title='Region from snapshot metadata.'>ⓘ</span></div><div style='font-weight:900;color:#34d399'>{region_used}</div></div>", unsafe_allow_html=True)
    c3.markdown(f"<div class='metric-card'><div style='color:#94a3b8'>Fetch Mode <span class='info-dot' title='Snapshot source: cache or live.'>ⓘ</span></div><div style='font-weight:900;color:#f97316'>{fast_status}</div></div>", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    a,b,c,d = st.columns(4)
    a.markdown(f"<div class='metric-card'><div>Total Users</div><b>{u_count}</b></div>", unsafe_allow_html=True)
    b.markdown(f"<div class='metric-card'><div>Total Groups</div><b>{g_count}</b></div>", unsafe_allow_html=True)
    c.markdown(f"<div class='metric-card'><div>Total Roles</div><b>{r_count}</b></div>", unsafe_allow_html=True)
    d.markdown(f"<div class='metric-card'><div>Total Policies</div><b>{p_count}</b></div>", unsafe_allow_html=True)

    st.markdown("<br><h4>🔥 Risk Summary <span class='info-dot' title='Counts of risky resources.'>ⓘ</span></h4>", unsafe_allow_html=True)
    r1,r2,r3,r4 = st.columns(4)
    r1.markdown(f"<div class='metric-card'><div>Risky Users</div><b style='color:#ef4444'>{ru}</b></div>", unsafe_allow_html=True)
    r2.markdown(f"<div class='metric-card'><div>Risky Groups</div><b style='color:#ef4444'>{rg}</b></div>", unsafe_allow_html=True)
    r3.markdown(f"<div class='metric-card'><div>Risky Roles</div><b style='color:#ef4444'>{rr}</b></div>", unsafe_allow_html=True)
    r4.markdown(f"<div class='metric-card'><div>Risky Policies</div><b style='color:#ef4444'>{rp}</b></div>", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(f"<div style='padding:10px;border-radius:8px;border:1px solid #333;background:rgba(255,255,255,0.02)'><small style='color:#aaa'>Snapshot Fetched:</small> <b title='Snapshot timestamp'>{fetched_at}</b></div>", unsafe_allow_html=True)
    st.markdown("---")

    # Build dataframes (cheap)
    user_df = pd.DataFrame([{
        "UserName": u.get("UserName"),
        "Arn": u.get("Arn"),
        "Groups": ", ".join(u.get("Groups", [])) if isinstance(u.get("Groups", []), list) else str(u.get("Groups","")),
        "AttachedPolicies": ", ".join([p.get("PolicyName") if isinstance(p, dict) else p for p in u.get("AttachedPolicies", [])]) if u.get("AttachedPolicies") else "",
        "RiskScore": u.get("RiskScore") or 0,
        "IsRisky": bool(u.get("IsRisky"))
    } for u in users]) if users else pd.DataFrame()

    role_df = pd.DataFrame([{
        "RoleName": r.get("RoleName"),
        "Arn": r.get("Arn"),
        "AttachedPolicies": ", ".join([p.get("PolicyName") if isinstance(p, dict) else p for p in r.get("AttachedPolicies", [])]) if r.get("AttachedPolicies") else "",
        "AssumePolicyRiskScore": r.get("AssumePolicyRiskScore") or r.get("RiskScore") or 0,
        "IsRisky": bool(r.get("IsRisky"))
    } for r in roles]) if roles else pd.DataFrame()

    pol_df = pd.DataFrame([{
        "PolicyName": p.get("PolicyName"),
        "Arn": p.get("Arn"),
        "RiskScore": p.get("RiskScore") or 0,
        "IsRisky": bool(p.get("IsRisky")),
        "Actions": ", ".join(p.get("Actions", []) or p.get("AllowedActions", [])) if (p.get("Actions") or p.get("AllowedActions")) else ""
    } for p in policies]) if policies else pd.DataFrame()

    # Lazy-load AgGrid and render (only when tab visible)
    try:
        from st_aggrid import AgGrid, GridOptionsBuilder, JsCode
        if user_df.empty:
            st.info("No Users Found.")
        else:
            gb = GridOptionsBuilder.from_dataframe(user_df)
            gb.configure_pagination(paginationAutoPageSize=False, paginationPageSize=25)
            gb.configure_side_bar()
            gb.configure_default_column(filter=True, sortable=True, resizable=True)
            gb.configure_column("IsRisky", header_name="Risky", cellStyle=JsCode("params => params.value ? {'backgroundColor':'#ffe6e6','color':'#900'} : null"), width=90)
            gb.configure_column("RiskScore", header_name="Risk Score", width=120)
            AgGrid(user_df, gridOptions=gb.build(), height=320, allow_unsafe_jscode=True)

        st.markdown("---")

        if role_df.empty:
            st.info("No Roles Found.")
        else:
            gb = GridOptionsBuilder.from_dataframe(role_df)
            gb.configure_default_column(filter=True, sortable=True, resizable=True)
            gb.configure_column("IsRisky", header_name="Risky", cellStyle=JsCode("params => params.value ? {'backgroundColor':'#ffe6e6','color':'#900'} : null"), width=90)
            AgGrid(role_df, gridOptions=gb.build(), height=260, allow_unsafe_jscode=True)

        st.markdown("---")

        if pol_df.empty:
            st.info("No Policies Found.")
        else:
            gb = GridOptionsBuilder.from_dataframe(pol_df)
            gb.configure_default_column(filter=True, sortable=True, resizable=True)
            gb.configure_column("IsRisky", header_name="Risky", cellStyle=JsCode("params => params.value ? {'backgroundColor':'#ffe6e6','color':'#900'} : null"), width=90)
            gb.configure_column("RiskScore", header_name="Risk Score", width=120)
            AgGrid(pol_df, gridOptions=gb.build(), height=320, allow_unsafe_jscode=True)

    except Exception:
        # Fall back to simple tables if AgGrid missing or errored
        if user_df.empty:
            st.info("No Users Found.")
        else:
            st.dataframe(user_df)
        st.markdown("---")
        if role_df.empty:
            st.info("No Roles Found.")
        else:
            st.dataframe(role_df)
        st.markdown("---")
        if pol_df.empty:
            st.info("No Policies Found.")
        else:
            st.dataframe(pol_df)

# Footer
st.caption("IAM X-Ray — Stable Beta Build • Graph + Table synced • Non-technical friendly overview.")
st.caption(f"IAM X-Ray — v{VERSION} • Stable Beta")
