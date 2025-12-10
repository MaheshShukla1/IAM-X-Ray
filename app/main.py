# #app/main.py
# """
# IAM X-Ray — Optimized main.py (Stable Beta)
# - Smaller, faster, modular
# - Lazy-load heavy modules
# - Caches snapshot / graph / filtered tables
# - Auth delegated to core.auth.handle_auth(auth_file, lock_file, remember_file)
# - Compatible with core.fetch_iam, core.graph_builder, core.cleanup, core.config, core.versions
# """

# import sys
# import os
# import json
# import time

# import configparser
# from datetime import datetime, timezone, timedelta
# import streamlit as st
# import streamlit.components.v1 as components
# import pandas as pd

# # PATHS & import fixes
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
# from core import config
# from core.fetch_iam import fetch_iam_data
# # graph functions will be lazy-imported where needed
# from core import cleanup
# from core.cleanup import ui_purge_button, ui_reset_app_button
# from core.versions import VERSION
# from core.auth import handle_auth  # expects (auth_file, lock_file, remember_path)

# # === Basic page config & CSS ===
# st.set_page_config(page_title="IAM X-Ray — Stable Beta", layout="wide", initial_sidebar_state="expanded")
# st.markdown(
#     """<style>
#       .metric-card{background:rgba(40,40,80,0.75);padding:12px;border-radius:10px;text-align:center;border:1px solid #333}
#       .info-dot{font-weight:700;color:#94a3b8;margin-left:6px;cursor:help}.small-muted{color:#9aa4bf;font-size:13px}
#     </style>""",
#     unsafe_allow_html=True,
# )

# # === Paths (single source of truth) ===
# DATA_DIR = getattr(config, "DATA_DIR", "data")
# SNAPSHOT_PATH = getattr(config, "SNAPSHOT_PATH", os.path.join(DATA_DIR, "iam_snapshot.json"))
# DEMO_PATH = os.path.join(DATA_DIR, "sample_snapshot.json")
# REMEMBER_PATH = os.path.join(DATA_DIR, "iamxray_remember.json")
# AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
# LOCK_FILE = os.path.join(DATA_DIR, "setup.lock")
# os.makedirs(DATA_DIR, exist_ok=True)

# # === Session defaults ===
# st.session_state.setdefault("theme", "dark")
# st.session_state.setdefault("authenticated", False)
# st.session_state.setdefault("search_query", "")
# st.session_state.setdefault("debounce_ts", 0)
# st.session_state.setdefault("last_fetch_profile", "Demo")
# st.session_state.setdefault("scroll_to_graph", False)
# # If other modules set this to force demo, respect it.
# # st.session_state.force_demo_mode may be set by auth module.

# # === License banner (light) ===
# LICENSEE = os.getenv("LICENSEE", "")
# if LICENSEE:
#     st.markdown(f"""<div style="position:fixed;right:20px;bottom:12px;background:rgba(0,0,0,0.45);padding:6px 12px;border-radius:6px;color:white;font-size:12px;z-index:9999">Licensed to: <b>{LICENSEE}</b></div>""", unsafe_allow_html=True)
# else:
#     st.markdown("""<div style="position:fixed;right:20px;bottom:12px;opacity:0.25;color:black;font-size:12px">IAM X-Ray • beta</div>""", unsafe_allow_html=True)

# # === Preflight: demo snapshot (lightweight) ===
# def _atomic_write(path, obj):
#     tmp = path + ".tmp"
#     with open(tmp, "w", encoding="utf-8") as fh:
#         json.dump(obj, fh, indent=2, default=str)
#     os.replace(tmp, path)

# def ensure_demo_snapshot():
#     if os.path.exists(DEMO_PATH): return
#     demo = {
#         "_meta": {"fetched_at": datetime.now(timezone.utc).isoformat() + "Z", "fast_mode": True, "counts": {"users": 1, "roles": 1, "policies": 1}},
#         "users": [{"UserName": "demo-user", "Arn": "arn:aws:iam::123:user/demo-user", "IsRisky": False, "AttachedPolicies": [{"PolicyName": "DemoPolicy"}]}],
#         "roles": [], "groups": [], "policies": [{"PolicyName": "DemoPolicy", "RiskScore": 1, "IsRisky": False, "Arn": "arn:aws:iam::123:policy/DemoPolicy"}]
#     }
#     _atomic_write(DEMO_PATH, demo)

# ensure_demo_snapshot()

# # === AUTH HANDOFF (delegated) ===
# # handle_auth will display onboarding/login UI and set st.session_state.authenticated appropriately.
# auth_ok = handle_auth(AUTH_FILE, LOCK_FILE, REMEMBER_PATH)
# if not auth_ok:
#     st.stop()

# # If auth triggered demo forcing, honor it
# def _select_mode_with_force(defaults=("Demo","AWS Profile","Env Keys")):
#     if st.session_state.get("force_demo_mode"):
#         return "Demo"
#     return st.selectbox("Auth Mode", list(defaults), help="Choose Demo for sample data, or AWS Profile / Env Keys for live fetch.")
# # We'll call this inside sidebar (below) to keep layout stable.

# # === Helpers: lazy imports and caching ===
# @st.cache_data(show_spinner=False)
# def load_snapshot_cached(path, mtime=None):
#     """
#     Cache snapshot per file modification time (mtime is provided by caller).
#     Using st.cache_data to store JSON/dict snapshot.
#     """
#     from pathlib import Path
#     if not os.path.exists(path):
#         raise FileNotFoundError(path)
#     # We call an existing load_snapshot if provided by core.graph_builder or fetch_iam.
#     try:
#         from core.graph_builder import load_snapshot as lb
#     except Exception:
#         from core.fetch_iam import load_snapshot as lb
#     snap = lb(path)
#     if not isinstance(snap, dict):
#         raise ValueError("snapshot not dict")
#     return snap

# @st.cache_data(show_spinner=False)
# def compute_keep_set_cached(serialized_meta):
#     # simple pass-through wrapper: compute_keep_set_from_diff expects snapshot; we pass serialized_meta as JSON str
#     try:
#         from core.graph_builder import compute_keep_set_from_diff
#     except Exception:
#         # fallback: no diff available
#         return set()
#     # serialized_meta is actually the snapshot dict dumped to string; to avoid large keys, we accept a fingerprint string.
#     # In our usage below we'll pass snapshot JSON string to this function only when show_changes True.
#     # But compute_keep_set_from_diff needs the snapshot dict — so caller will call it directly when needed.
#     return set()

# # Graph builder cache keyed by (snapshot fingerprint, show_only_risky, highlight)
# @st.cache_data(show_spinner=False)
# def build_graph_cached(snapshot_fingerprint, show_only_risky, highlight, highlight_color="#ffeb3b", highlight_duration=1800):
#     # lazily import heavy graph builder
#     from core.graph_builder import build_iam_graph
#     # caller must provide actual snapshot object via file; we will load it again inside build_iam_graph call by reading snapshot path in main flow.
#     # But to ensure caching works, snapshot_fingerprint should change whenever snapshot changes.
#     # We will load snapshot from SNAPSHOT_PATH here (safe because function is cached by fingerprint).
#     try:
#         snap = load_snapshot_cached(SNAPSHOT_PATH, os.path.getmtime(SNAPSHOT_PATH) if os.path.exists(SNAPSHOT_PATH) else None)
#     except Exception:
#         snap = load_snapshot_cached(DEMO_PATH, os.path.getmtime(DEMO_PATH))
#     # build_iam_graph returns (G, graph_html, clicked, export_bytes, empty_state)
#     return build_iam_graph(snap, show_only_risky=show_only_risky, highlight_node=highlight, highlight_color=highlight_color, highlight_duration=highlight_duration)

# # Filter resources cached by (snapshot_fingerprint, min_risk, show_risky, keep_key)
# @st.cache_data(show_spinner=False)
# def filter_resources_cached(snapshot_fingerprint, min_risk, show_risky, keep_key, mode):
#     # pick correct snapshot file
#     real_path = DEMO_PATH if mode == "Demo" else SNAPSHOT_PATH

#     # load cached snapshot
#     snap = load_snapshot_cached(real_path, os.path.getmtime(real_path))

#     users = snap.get("users", []) or []
#     groups = snap.get("groups", []) or []
#     roles = snap.get("roles", []) or []
#     policies = snap.get("policies", []) or []

#     # --- RISK FILTERS ---
#     if min_risk > 0:
#         users = [u for u in users if (u.get("RiskScore") or 0) >= min_risk]
#         roles = [r for r in roles if (r.get("AssumePolicyRiskScore") or 0) >= min_risk]
#         policies = [p for p in policies if (p.get("RiskScore") or 0) >= min_risk]

#     if show_risky:
#         users = [u for u in users if u.get("IsRisky")]
#         roles = [r for r in roles if r.get("IsRisky")]
#         policies = [p for p in policies if p.get("IsRisky")]

#     # --- KEEP (CHANGES ONLY) ---
#     if keep_key:
#         try:
#             keep_set = set(json.loads(keep_key))
#         except:
#             keep_set = set()

#         if keep_set:
#             users = [u for u in users if u.get("UserName") in keep_set]
#             groups = [g for g in groups if g.get("GroupName") in keep_set]
#             roles = [r for r in roles if r.get("RoleName") in keep_set]
#             policies = [p for p in policies if p.get("PolicyName") in keep_set]

#     return {
#         "users": users,
#         "groups": groups,
#         "roles": roles,
#         "policies": policies,
#         "_meta": snap.get("_meta", {})
#     }


# # === Sidebar UI (controls) ===
# with st.sidebar:
#     st.header("Controls")

#     # Auth Mode selection but allow force_demo_mode from auth to override
#     if st.session_state.get("force_demo_mode"):
#         mode = "Demo"
#         st.markdown("**Auth Mode:** Demo (forced by onboarding)")
#     else:
#         mode = st.selectbox("Auth Mode", ["Demo", "AWS Profile", "Env Keys"], help="Choose Demo for sample data, AWS Profile to use ~/.aws/credentials, or Env Keys to paste temporary keys.")
#     # list profiles (cheap)
#     def list_profiles():
#         creds = os.path.expanduser("~/.aws/credentials")
#         if not os.path.exists(creds):
#             return []
#         cp = configparser.ConfigParser()
#         cp.read(creds)
#         return cp.sections()
#     profiles = list_profiles()

#     selected_profile = None
#     env = None
#     if mode == "AWS Profile":
#         selected_profile = st.selectbox("AWS Profile", ["default"] + profiles, help="Select profile from ~/.aws/credentials")
#     elif mode == "Env Keys":
#         ak = st.text_input("AWS_ACCESS_KEY_ID", type="password", help="Paste access key. Only stored in environment during fetch.")
#         sk = st.text_input("AWS_SECRET_ACCESS_KEY", type="password", help="Paste secret key. Only stored in environment during fetch.")
#         tok = st.text_input("AWS_SESSION_TOKEN (optional)", type="password", help="Optional session token.")
#         region = st.text_input("AWS_REGION", "us-east-1", help="Region for lookups.")
#         if ak and sk:
#             env = {"aws_access_key_id": ak, "aws_secret_access_key": sk, "aws_session_token": tok, "region_name": region}

#     st.write("---")
#     st.subheader("Fetch Options")
#     fast_mode = st.checkbox("Fast (use cache)", value=True, help="Use cached snapshot if available.")
#     force_fetch = st.checkbox("Force Live", value=False, help="Ignore cache and do a live fetch.")
#     encrypt = st.checkbox("Encrypt Snapshot", value=False, help="Encrypt snapshot if configured.")
#     ttl_mins = st.number_input("Cache TTL (minutes)", 1, 1440, 60, help="Cached snapshot TTL.")
#     keep_days = st.number_input("Retention Days", 1, 365, 30, help="How many days to keep old snapshots.")

#     fetch_btn = st.button("Fetch Latest Snapshot", help="Start fetching IAM data from AWS using selected auth mode.")

#     st.write("---")
#     st.subheader("Filter")
#     show_risky = st.checkbox("Show Only Risky", False, help="Show only resources flagged as risky by the analyzer.")
#     show_changes = st.checkbox("Changes Only", False, help="Show only resources changed since last snapshot.")
#     min_risk = st.slider("Min Risk Score", 0, 10, 0, help="Filter out resources with risk score below this threshold.")

#     st.write("---")
#     st.caption("Housekeeping")
#     # use cleanup utilities if available
#     try:
#         ui_purge_button()
#     except Exception:
#         st.button("Purge snapshots (not available)", disabled=True)
#     try:
#         ui_reset_app_button()
#     except Exception:
#         st.button("Reset app (not available)", disabled=True)

# # === Fetch handler ===
# active_snapshot = DEMO_PATH if mode == "Demo" else SNAPSHOT_PATH

# if fetch_btn:
#     # placeholder prevents stale messages after rerun
#     fetch_box = st.empty()
#     try:
#         fetch_box.info("Fetching IAM data…")

#         # set env if Env Keys
#         if mode == "Env Keys" and env:
#             os.environ["AWS_ACCESS_KEY_ID"] = env["aws_access_key_id"]
#             os.environ["AWS_SECRET_ACCESS_KEY"] = env["aws_secret_access_key"]
#             if env.get("aws_session_token"):
#                 os.environ["AWS_SESSION_TOKEN"] = env["aws_session_token"]
#             if env.get("region_name"):
#                 os.environ["AWS_REGION"] = env["region_name"]

#         fetch_iam_data(
#             session=None,
#             profile_name=(selected_profile if mode == "AWS Profile" else None),
#             out_path=SNAPSHOT_PATH,
#             fast_mode=fast_mode,
#             force_fetch=force_fetch,
#             encrypt=encrypt,
#             multi_region=False,
#             cache_ttl=ttl_mins * 60
#         )

#         fetch_box.success("Snapshot updated!")

#         st.session_state.last_fetch_profile = (
#             selected_profile or 
#             ("Env Keys" if mode=="Env Keys" else "Demo")
#         )
#         st.session_state.scroll_to_graph = True

#         # CLEAR messages cleanly
#         fetch_box.empty()

#         # force clean UI refresh
#         st.rerun()

#     except Exception as e:
#         fetch_box.error(f"Fetch failed: {e}")


# # === Ensure snapshot file exists ===
# if not os.path.exists(active_snapshot):
#     st.warning("No snapshot found — run Fetch or switch to Demo")
#     st.stop()

# # compute fingerprint for caching: combine file mtime + size
# def snapshot_fingerprint(path):
#     try:
#         stt = os.path.getmtime(path)
#         sz = os.path.getsize(path)
#         return f"{path}:{int(stt)}:{sz}"
#     except Exception:
#         return path

# snap_fp = snapshot_fingerprint(active_snapshot)

# # If user requested "changes only" we must compute keep set via compute_keep_set_from_diff (lazy import)
# keep_key = None
# if show_changes:
#     try:
#         from core.graph_builder import compute_keep_set_from_diff
#         snap_for_diff = load_snapshot_cached(active_snapshot, os.path.getmtime(active_snapshot))
#         keep_set = compute_keep_set_from_diff(snap_for_diff) or set()
#         # cache key must be JSON-serializable
#         keep_key = json.dumps(list(keep_set))
#     except Exception:
#         keep_key = None

# # Load filtered resources (cached)
# filtered = filter_resources_cached(snap_fp, min_risk, show_risky, keep_key, mode)
# users = filtered["users"]
# groups = filtered["groups"]
# roles = filtered["roles"]
# policies = filtered["policies"]
# meta = filtered["_meta"] or {}

# # counts
# u_count = len(users); g_count = len(groups); r_count = len(roles); p_count = len(policies)
# ru = len([u for u in users if u.get("IsRisky")])
# rg = len([g for g in groups if g.get("IsRisky")])
# rr = len([r for r in roles if r.get("IsRisky")])
# rp = len([p for p in policies if p.get("IsRisky")])

# # === Tabs: GRAPH & TABLE (lazy heavy imports inside blocks) ===
# tabs = st.tabs(["Graph View", "Table View"])

# # Graph View
# with tabs[0]:
#     st.markdown("### 🕸 Interactive IAM Attack Graph <span class='small-muted'>Hover the info icon for quick help</span>", unsafe_allow_html=True)
#     st.markdown("<div style='margin-bottom:8px;'>Graph shows resources and trust edges. <span class='info-dot' title='Click nodes to inspect. Use the search box to highlight nodes or permissions.'>ⓘ</span></div>", unsafe_allow_html=True)

#     # search box with debounce
#     search = st.text_input("Search entity or permission", value=st.session_state.get("search_query",""), placeholder="ex: s3:PutObject or alice", help="Type a username, role, or permission.")
#     now = int(time.time() * 1000)
#     if (now - st.session_state["debounce_ts"]) > 300:
#         st.session_state["search_query"] = search
#     st.session_state["debounce_ts"] = now
#     highlight = st.session_state["search_query"]

#     # Build graph lazily and cached by snapshot fingerprint + show_risky + highlight
#     graph_cache_key = f"{snap_fp}:risky={show_risky}:hl={highlight}"
#     try:
#         G, graph_html, clicked, export_bytes, empty_state = build_graph_cached(graph_cache_key, show_risky, highlight)
#     except Exception as e:
#         st.error(f"Graph build error: {e}")
#         st.stop()

#     if graph_html:
#         components.html(graph_html, height=900, scrolling=False)
#         if export_bytes:
#             st.download_button("Download Graph JSON", export_bytes, "iam_graph.json", help="Download raw graph JSON for offline inspection")

# # Table View
# with tabs[1]:
#     st.markdown("## 🟦 Current Active IAM Resources (Simple View)")
#     fetched_at = meta.get("fetched_at", "—")
#     fast_status = "FAST (cache)" if meta.get("fast_mode") else "LIVE (fresh)"
#     region_used = meta.get("region") or (meta.get("regions", ["us-east-1"])[0] if meta.get("regions") else "us-east-1")
#     if isinstance(region_used, dict):
#         region_used = region_used.get("name") or region_used.get("Region") or "us-east-1"

#     # top metrics row
#     c1, c2, c3 = st.columns(3)
#     profile_used = ("Demo" if mode=="Demo" else (selected_profile or st.session_state.get("last_fetch_profile","Demo")))
#     c1.markdown(f"<div class='metric-card'><div style='color:#94a3b8'>AWS Profile <span class='info-dot' title='Profile used for the last fetch.'>ⓘ</span></div><div style='font-weight:900;color:#38bdf8'>{profile_used}</div></div>", unsafe_allow_html=True)
#     c2.markdown(f"<div class='metric-card'><div style='color:#94a3b8'>Region <span class='info-dot' title='Region from snapshot metadata.'>ⓘ</span></div><div style='font-weight:900;color:#34d399'>{region_used}</div></div>", unsafe_allow_html=True)
#     c3.markdown(f"<div class='metric-card'><div style='color:#94a3b8'>Fetch Mode <span class='info-dot' title='Snapshot source: cache or live.'>ⓘ</span></div><div style='font-weight:900;color:#f97316'>{fast_status}</div></div>", unsafe_allow_html=True)

#     st.markdown("<br>", unsafe_allow_html=True)
#     a,b,c,d = st.columns(4)
#     a.markdown(f"<div class='metric-card'><div>Total Users</div><b>{u_count}</b></div>", unsafe_allow_html=True)
#     b.markdown(f"<div class='metric-card'><div>Total Groups</div><b>{g_count}</b></div>", unsafe_allow_html=True)
#     c.markdown(f"<div class='metric-card'><div>Total Roles</div><b>{r_count}</b></div>", unsafe_allow_html=True)
#     d.markdown(f"<div class='metric-card'><div>Total Policies</div><b>{p_count}</b></div>", unsafe_allow_html=True)

#     st.markdown("<br><h4>🔥 Risk Summary <span class='info-dot' title='Counts of risky resources.'>ⓘ</span></h4>", unsafe_allow_html=True)
#     r1,r2,r3,r4 = st.columns(4)
#     r1.markdown(f"<div class='metric-card'><div>Risky Users</div><b style='color:#ef4444'>{ru}</b></div>", unsafe_allow_html=True)
#     r2.markdown(f"<div class='metric-card'><div>Risky Groups</div><b style='color:#ef4444'>{rg}</b></div>", unsafe_allow_html=True)
#     r3.markdown(f"<div class='metric-card'><div>Risky Roles</div><b style='color:#ef4444'>{rr}</b></div>", unsafe_allow_html=True)
#     r4.markdown(f"<div class='metric-card'><div>Risky Policies</div><b style='color:#ef4444'>{rp}</b></div>", unsafe_allow_html=True)

#     st.markdown("<br>", unsafe_allow_html=True)
#     st.markdown(f"<div style='padding:10px;border-radius:8px;border:1px solid #333;background:rgba(255,255,255,0.02)'><small style='color:#aaa'>Snapshot Fetched:</small> <b title='Snapshot timestamp'>{fetched_at}</b></div>", unsafe_allow_html=True)
#     st.markdown("---")

#     # Build dataframes (cheap)
#     user_df = pd.DataFrame([{
#         "UserName": u.get("UserName"),
#         "Arn": u.get("Arn"),
#         "Groups": ", ".join(u.get("Groups", [])) if isinstance(u.get("Groups", []), list) else str(u.get("Groups","")),
#         "AttachedPolicies": ", ".join([p.get("PolicyName") if isinstance(p, dict) else p for p in u.get("AttachedPolicies", [])]) if u.get("AttachedPolicies") else "",
#         "RiskScore": u.get("RiskScore") or 0,
#         "IsRisky": bool(u.get("IsRisky"))
#     } for u in users]) if users else pd.DataFrame()

#     role_df = pd.DataFrame([{
#         "RoleName": r.get("RoleName"),
#         "Arn": r.get("Arn"),
#         "AttachedPolicies": ", ".join([p.get("PolicyName") if isinstance(p, dict) else p for p in r.get("AttachedPolicies", [])]) if r.get("AttachedPolicies") else "",
#         "AssumePolicyRiskScore": r.get("AssumePolicyRiskScore") or r.get("RiskScore") or 0,
#         "IsRisky": bool(r.get("IsRisky"))
#     } for r in roles]) if roles else pd.DataFrame()

#     pol_df = pd.DataFrame([{
#         "PolicyName": p.get("PolicyName"),
#         "Arn": p.get("Arn"),
#         "RiskScore": p.get("RiskScore") or 0,
#         "IsRisky": bool(p.get("IsRisky")),
#         "Actions": ", ".join(p.get("Actions", []) or p.get("AllowedActions", [])) if (p.get("Actions") or p.get("AllowedActions")) else ""
#     } for p in policies]) if policies else pd.DataFrame()

#     # Lazy-load AgGrid and render (only when tab visible)
#     try:
#         from st_aggrid import AgGrid, GridOptionsBuilder, JsCode
#         if user_df.empty:
#             st.info("No Users Found.")
#         else:
#             gb = GridOptionsBuilder.from_dataframe(user_df)
#             gb.configure_pagination(paginationAutoPageSize=False, paginationPageSize=25)
#             gb.configure_side_bar()
#             gb.configure_default_column(filter=True, sortable=True, resizable=True)
#             gb.configure_column("IsRisky", header_name="Risky", cellStyle=JsCode("params => params.value ? {'backgroundColor':'#ffe6e6','color':'#900'} : null"), width=90)
#             gb.configure_column("RiskScore", header_name="Risk Score", width=120)
#             AgGrid(user_df, gridOptions=gb.build(), height=320, allow_unsafe_jscode=True)

#         st.markdown("---")

#         if role_df.empty:
#             st.info("No Roles Found.")
#         else:
#             gb = GridOptionsBuilder.from_dataframe(role_df)
#             gb.configure_default_column(filter=True, sortable=True, resizable=True)
#             gb.configure_column("IsRisky", header_name="Risky", cellStyle=JsCode("params => params.value ? {'backgroundColor':'#ffe6e6','color':'#900'} : null"), width=90)
#             AgGrid(role_df, gridOptions=gb.build(), height=260, allow_unsafe_jscode=True)

#         st.markdown("---")

#         if pol_df.empty:
#             st.info("No Policies Found.")
#         else:
#             gb = GridOptionsBuilder.from_dataframe(pol_df)
#             gb.configure_default_column(filter=True, sortable=True, resizable=True)
#             gb.configure_column("IsRisky", header_name="Risky", cellStyle=JsCode("params => params.value ? {'backgroundColor':'#ffe6e6','color':'#900'} : null"), width=90)
#             gb.configure_column("RiskScore", header_name="Risk Score", width=120)
#             AgGrid(pol_df, gridOptions=gb.build(), height=320, allow_unsafe_jscode=True)

#     except Exception:
#         # Fall back to simple tables if AgGrid missing or errored
#         if user_df.empty:
#             st.info("No Users Found.")
#         else:
#             st.dataframe(user_df)
#         st.markdown("---")
#         if role_df.empty:
#             st.info("No Roles Found.")
#         else:
#             st.dataframe(role_df)
#         st.markdown("---")
#         if pol_df.empty:
#             st.info("No Policies Found.")
#         else:
#             st.dataframe(pol_df)

# # Footer
# st.caption("IAM X-Ray — Stable Beta Build • Graph + Table synced • Non-technical friendly overview.")
# st.caption(f"IAM X-Ray — v{VERSION} • Stable Beta")



# # app/main.py
# """
# IAM X-Ray — Optimized main.py (Stable Beta)
# - Smaller, faster, modular
# - Lazy-load heavy modules
# - Caches snapshot / graph / filtered tables
# - Auth delegated to core.auth.handle_auth(auth_file, lock_file, remember_file)
# - Compatible with core.fetch_iam, core.graph_builder, core.cleanup, core.config, core.versions
# """

# import sys
# import os
# import json
# import time
# import tempfile

# import configparser
# from datetime import datetime, timezone, timedelta
# import streamlit as st
# import streamlit.components.v1 as components
# import pandas as pd

# # PATHS & import fixes
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# from core import config
# from core.fetch_iam import fetch_iam_data
# # graph functions will be lazy-imported where needed
# from core import cleanup
# from core.cleanup import ui_purge_button, ui_reset_app_button
# from core.versions import VERSION
# from core.auth import handle_auth  # expects (auth_file, lock_file, remember_path)

# # === Basic page config & CSS ===
# st.set_page_config(page_title="IAM X-Ray — Stable Beta", layout="wide", initial_sidebar_state="expanded")
# st.markdown(
#     """<style>
#       .metric-card{background:rgba(40,40,80,0.75);padding:12px;border-radius:10px;text-align:center;border:1px solid #333}
#       .info-dot{font-weight:700;color:#94a3b8;margin-left:6px;cursor:help}.small-muted{color:#9aa4bf;font-size:13px}
#     </style>""",
#     unsafe_allow_html=True,
# )

# # === Paths (single source of truth) ===
# DATA_DIR = getattr(config, "DATA_DIR", "data")
# SNAPSHOT_PATH = getattr(config, "SNAPSHOT_PATH", os.path.join(DATA_DIR, "iam_snapshot.json"))
# DEMO_PATH = os.path.join(DATA_DIR, "sample_snapshot.json")
# REMEMBER_PATH = os.path.join(DATA_DIR, "iamxray_remember.json")
# AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
# LOCK_FILE = os.path.join(DATA_DIR, "setup.lock")
# os.makedirs(DATA_DIR, exist_ok=True)

# # === Session defaults ===
# st.session_state.setdefault("theme", "dark")
# st.session_state.setdefault("authenticated", False)
# st.session_state.setdefault("search_query", "")
# st.session_state.setdefault("debounce_ts", 0)
# st.session_state.setdefault("last_fetch_profile", "Demo")
# st.session_state.setdefault("scroll_to_graph", False)
# # If other modules set this to force demo, respect it.
# # st.session_state.force_demo_mode may be set by auth module.

# # === License banner (light) ===
# LICENSEE = os.getenv("LICENSEE", "")
# if LICENSEE:
#     st.markdown(f"""<div style="position:fixed;right:20px;bottom:12px;background:rgba(0,0,0,0.45);padding:6px 12px;border-radius:6px;color:white;font-size:12px;z-index:9999">Licensed to: <b>{LICENSEE}</b></div>""", unsafe_allow_html=True)
# else:
#     st.markdown("""<div style="position:fixed;right:20px;bottom:12px;opacity:0.25;color:black;font-size:12px">IAM X-Ray • beta</div>""", unsafe_allow_html=True)

# # === Preflight: demo snapshot (lightweight) ===
# def _atomic_write(path, obj):
#     tmp = path + ".tmp"
#     with open(tmp, "w", encoding="utf-8") as fh:
#         json.dump(obj, fh, indent=2, default=str)
#     os.replace(tmp, path)

# def ensure_demo_snapshot():
#     if os.path.exists(DEMO_PATH): return
#     demo = {
#         "_meta": {"fetched_at": datetime.now(timezone.utc).isoformat() + "Z", "fast_mode": True, "counts": {"users": 1, "roles": 1, "policies": 1}},
#         "users": [{"UserName": "demo-user", "Arn": "arn:aws:iam::123:user/demo-user", "IsRisky": False, "AttachedPolicies": [{"PolicyName": "DemoPolicy"}]}],
#         "roles": [], "groups": [], "policies": [{"PolicyName": "DemoPolicy", "RiskScore": 1, "IsRisky": False, "Arn": "arn:aws:iam::123:policy/DemoPolicy"}]
#     }
#     _atomic_write(DEMO_PATH, demo)

# ensure_demo_snapshot()

# # === AUTH HANDOFF (delegated) ===
# # handle_auth will display onboarding/login UI and set st.session_state.authenticated appropriately.
# auth_ok = handle_auth(AUTH_FILE, LOCK_FILE, REMEMBER_PATH)
# if not auth_ok:
#     st.stop()

# # If auth triggered demo forcing, honor it
# def _select_mode_with_force(defaults=("Demo","AWS Profile","Env Keys")):
#     if st.session_state.get("force_demo_mode"):
#         return "Demo"
#     return st.selectbox("Auth Mode", list(defaults), help="Choose Demo for sample data, or AWS Profile / Env Keys for live fetch.")
# # We'll call this inside sidebar (below) to keep layout stable.

# # === Helpers: lazy imports and caching ===
# @st.cache_data(show_spinner=False)
# def load_snapshot_cached(path, mtime=None):
#     """
#     Cache snapshot per file modification time (mtime is provided by caller).
#     Using st.cache_data to store JSON/dict snapshot.
#     """
#     from pathlib import Path
#     if not os.path.exists(path):
#         raise FileNotFoundError(path)
#     # We call an existing load_snapshot if provided by core.graph_builder or fetch_iam.
#     try:
#         from core.graph_builder import load_snapshot as lb
#     except Exception:
#         from core.fetch_iam import load_snapshot as lb
#     snap = lb(path)
#     if not isinstance(snap, dict):
#         raise ValueError("snapshot not dict")
#     return snap

# @st.cache_data(show_spinner=False)
# def compute_keep_set_cached(serialized_meta):
#     # simple pass-through wrapper: compute_keep_set_from_diff expects snapshot; we pass serialized_meta as JSON str
#     try:
#         from core.graph_builder import compute_keep_set_from_diff
#     except Exception:
#         # fallback: no diff available
#         return set()
#     # serialized_meta is actually the snapshot dict dumped to string; to avoid large keys, we accept a fingerprint string.
#     # In our usage below we'll pass snapshot JSON string to this function only when show_changes True.
#     # But compute_keep_set_from_diff needs the snapshot dict — so caller will call it directly when needed.
#     return set()

# # Graph builder cache keyed by (snapshot fingerprint, show_only_risky, highlight)
# @st.cache_data(show_spinner=False)
# def build_graph_cached(snapshot_fingerprint, show_only_risky, highlight, highlight_color="#ffeb3b", highlight_duration=1800):
#     # lazily import heavy graph builder
#     from core.graph_builder import build_iam_graph
#     # caller must provide actual snapshot object via file; we will load it again inside build_iam_graph call by reading snapshot path in main flow.
#     # But to ensure caching works, snapshot_fingerprint should change whenever snapshot changes.
#     # We will load snapshot from SNAPSHOT_PATH here (safe because function is cached by fingerprint).
#     try:
#         snap = load_snapshot_cached(SNAPSHOT_PATH, os.path.getmtime(SNAPSHOT_PATH) if os.path.exists(SNAPSHOT_PATH) else None)
#     except Exception:
#         snap = load_snapshot_cached(DEMO_PATH, os.path.getmtime(DEMO_PATH))
#     # build_iam_graph returns (G, graph_html, clicked, export_bytes, meta)
#     return build_iam_graph(snap, show_only_risky=show_only_risky, highlight_node=highlight, highlight_color=highlight_color, highlight_duration=highlight_duration)

# # Filter resources cached by (snapshot_fingerprint, min_risk, show_risky, keep_key)
# @st.cache_data(show_spinner=False)
# def filter_resources_cached(snapshot_fingerprint, min_risk, show_risky, keep_key, mode):
#     # pick correct snapshot file
#     real_path = DEMO_PATH if mode == "Demo" else SNAPSHOT_PATH

#     # load cached snapshot
#     snap = load_snapshot_cached(real_path, os.path.getmtime(real_path))

#     users = snap.get("users", []) or []
#     groups = snap.get("groups", []) or []
#     roles = snap.get("roles", []) or []
#     policies = snap.get("policies", []) or []

#     # --- RISK FILTERS ---
#     if min_risk > 0:
#         users = [u for u in users if (u.get("RiskScore") or 0) >= min_risk]
#         roles = [r for r in roles if (r.get("AssumePolicyRiskScore") or 0) >= min_risk]
#         policies = [p for p in policies if (p.get("RiskScore") or 0) >= min_risk]

#     if show_risky:
#         users = [u for u in users if u.get("IsRisky")]
#         roles = [r for r in roles if r.get("IsRisky")]
#         policies = [p for p in policies if p.get("IsRisky")]

#     # --- KEEP (CHANGES ONLY) ---
#     if keep_key:
#         try:
#             keep_set = set(json.loads(keep_key))
#         except:
#             keep_set = set()

#         if keep_set:
#             users = [u for u in users if u.get("UserName") in keep_set]
#             groups = [g for g in groups if g.get("GroupName") in keep_set]
#             roles = [r for r in roles if r.get("RoleName") in keep_set]
#             policies = [p for p in policies if p.get("PolicyName") in keep_set]

#     return {
#         "users": users,
#         "groups": groups,
#         "roles": roles,
#         "policies": policies,
#         "_meta": snap.get("_meta", {})
#     }


# # === Sidebar UI (controls) ===
# with st.sidebar:
#     st.header("Controls")

#     # Auth Mode selection but allow force_demo_mode from auth to override
#     if st.session_state.get("force_demo_mode"):
#         mode = "Demo"
#         st.markdown("**Auth Mode:** Demo (forced by onboarding)")
#     else:
#         mode = st.selectbox("Auth Mode", ["Demo", "AWS Profile", "Env Keys"], help="Choose Demo for sample data, AWS Profile to use ~/.aws/credentials, or Env Keys to paste temporary keys.")
#     # list profiles (cheap)
#     def list_profiles():
#         creds = os.path.expanduser("~/.aws/credentials")
#         if not os.path.exists(creds):
#             return []
#         cp = configparser.ConfigParser()
#         cp.read(creds)
#         return cp.sections()
#     profiles = list_profiles()

#     selected_profile = None
#     env = None
#     if mode == "AWS Profile":
#         selected_profile = st.selectbox("AWS Profile", ["default"] + profiles, help="Select profile from ~/.aws/credentials")
#     elif mode == "Env Keys":
#         ak = st.text_input("AWS_ACCESS_KEY_ID", type="password", help="Paste access key. Only stored in environment during fetch.")
#         sk = st.text_input("AWS_SECRET_ACCESS_KEY", type="password", help="Paste secret key. Only stored in environment during fetch.")
#         tok = st.text_input("AWS_SESSION_TOKEN (optional)", type="password", help="Optional session token.")
#         region = st.text_input("AWS_REGION", "us-east-1", help="Region for lookups.")
#         if ak and sk:
#             env = {"aws_access_key_id": ak, "aws_secret_access_key": sk, "aws_session_token": tok, "region_name": region}

#     st.write("---")
#     st.subheader("Fetch Options")
#     fast_mode = st.checkbox("Fast (use cache)", value=True, help="Use cached snapshot if available.")
#     force_fetch = st.checkbox("Force Live", value=False, help="Ignore cache and do a live fetch.")
#     encrypt = st.checkbox("Encrypt Snapshot", value=False, help="Encrypt snapshot if configured.")
#     ttl_mins = st.number_input("Cache TTL (minutes)", 1, 1440, 60, help="Cached snapshot TTL.")
#     keep_days = st.number_input("Retention Days", 1, 365, 30, help="How many days to keep old snapshots.")

#     fetch_btn = st.button("Fetch Latest Snapshot", help="Start fetching IAM data from AWS using selected auth mode.")

#     st.write("---")
#     st.subheader("Filter")
#     show_risky = st.checkbox("Show Only Risky", False, help="Show only resources flagged as risky by the analyzer.")
#     show_changes = st.checkbox("Changes Only", False, help="Show only resources changed since last snapshot.")
#     min_risk = st.slider("Min Risk Score", 0, 10, 0, help="Filter out resources with risk score below this threshold.")

#     st.write("---")
#     st.caption("Housekeeping")
#     # use cleanup utilities if available
#     try:
#         ui_purge_button()
#     except Exception:
#         st.button("Purge snapshots (not available)", disabled=True)
#     try:
#         ui_reset_app_button()
#     except Exception:
#         st.button("Reset app (not available)", disabled=True)

# # === Fetch handler ===
# active_snapshot = DEMO_PATH if mode == "Demo" else SNAPSHOT_PATH

# if fetch_btn:
#     # placeholder prevents stale messages after rerun
#     fetch_box = st.empty()
#     try:
#         fetch_box.info("Fetching IAM data…")

#         # set env if Env Keys
#         if mode == "Env Keys" and env:
#             os.environ["AWS_ACCESS_KEY_ID"] = env["aws_access_key_id"]
#             os.environ["AWS_SECRET_ACCESS_KEY"] = env["aws_secret_access_key"]
#             if env.get("aws_session_token"):
#                 os.environ["AWS_SESSION_TOKEN"] = env["aws_session_token"]
#             if env.get("region_name"):
#                 os.environ["AWS_REGION"] = env["region_name"]

#         fetch_iam_data(
#             session=None,
#             profile_name=(selected_profile if mode == "AWS Profile" else None),
#             out_path=SNAPSHOT_PATH,
#             fast_mode=fast_mode,
#             force_fetch=force_fetch,
#             encrypt=encrypt,
#             multi_region=False,
#             cache_ttl=ttl_mins * 60
#         )

#         fetch_box.success("Snapshot updated!")

#         st.session_state.last_fetch_profile = (
#             selected_profile or 
#             ("Env Keys" if mode=="Env Keys" else "Demo")
#         )
#         st.session_state.scroll_to_graph = True

#         # CLEAR messages cleanly
#         fetch_box.empty()

#         # force clean UI refresh
#         st.rerun()

#     except Exception as e:
#         fetch_box.error(f"Fetch failed: {e}")


# # === Ensure snapshot file exists ===
# if not os.path.exists(active_snapshot):
#     st.warning("No snapshot found — run Fetch or switch to Demo")
#     st.stop()

# # compute fingerprint for caching: combine file mtime + size
# def snapshot_fingerprint(path):
#     try:
#         stt = os.path.getmtime(path)
#         sz = os.path.getsize(path)
#         return f"{path}:{int(stt)}:{sz}"
#     except Exception:
#         return path

# snap_fp = snapshot_fingerprint(active_snapshot)

# # If user requested "changes only" we must compute keep set via compute_keep_set_from_diff (lazy import)
# keep_key = None
# if show_changes:
#     try:
#         from core.graph_builder import compute_keep_set_from_diff
#         snap_for_diff = load_snapshot_cached(active_snapshot, os.path.getmtime(active_snapshot))
#         keep_set = compute_keep_set_from_diff(snap_for_diff) or set()
#         # cache key must be JSON-serializable
#         keep_key = json.dumps(list(keep_set))
#     except Exception:
#         keep_key = None

# # Load filtered resources (cached)
# filtered = filter_resources_cached(snap_fp, min_risk, show_risky, keep_key, mode)
# users = filtered["users"]
# groups = filtered["groups"]
# roles = filtered["roles"]
# policies = filtered["policies"]
# meta = filtered["_meta"] or {}

# # counts
# u_count = len(users); g_count = len(groups); r_count = len(roles); p_count = len(policies)
# ru = len([u for u in users if u.get("IsRisky")])
# rg = len([g for g in groups if g.get("IsRisky")])
# rr = len([r for r in roles if r.get("IsRisky")])
# rp = len([p for p in policies if p.get("IsRisky")])

# # === Tabs: GRAPH & TABLE (lazy heavy imports inside blocks) ===
# tabs = st.tabs(["Graph View", "Table View"])

# # Graph View
# with tabs[0]:
#     st.markdown("### 🕸 Interactive IAM Attack Graph <span class='small-muted'>Hover the info icon for quick help</span>", unsafe_allow_html=True)
#     st.markdown("<div style='margin-bottom:8px;'>Graph shows resources and trust edges. <span class='info-dot' title='Click nodes to inspect. Use the search box to highlight nodes or permissions.'>ⓘ</span></div>", unsafe_allow_html=True)

#     # search box with debounce
#     search = st.text_input("Search entity or permission", value=st.session_state.get("search_query",""), placeholder="ex: s3:PutObject or alice", help="Type a username, role, or permission.")
#     now = int(time.time() * 1000)
#     if (now - st.session_state["debounce_ts"]) > 300:
#         st.session_state["search_query"] = search
#     st.session_state["debounce_ts"] = now
#     highlight = st.session_state["search_query"]

#     # Build graph lazily and cached by snapshot fingerprint + show_risky + highlight
#     graph_cache_key = f"{snap_fp}:risky={show_risky}:hl={highlight}"
#     try:
#         G, graph_html, clicked, export_bytes, empty_state = build_graph_cached(graph_cache_key, show_risky, highlight)
#     except Exception as e:
#         st.error(f"Graph build error: {e}")
#         st.stop()

#     if graph_html:
#         components.html(graph_html, height=900, scrolling=False)
#         if export_bytes:
#             st.download_button("Download Graph JSON", export_bytes, "iam_graph.json", help="Download collapsed/focused graph JSON for offline inspection")

#         # NEW: try to offer the raw (uncollapsed) graph JSON that graph_builder exports to temp
#         raw_export_path = os.path.join(tempfile.gettempdir(), "iam_xray_graph.raw.json")
#         try:
#             if os.path.exists(raw_export_path):
#                 with open(raw_export_path, "rb") as rf:
#                     raw_bytes = rf.read()
#                 st.download_button("Download Raw (uncollapsed) Graph JSON", raw_bytes, "iam_graph.raw.json", help="Download raw uncollapsed graph JSON (full actions/policies).")
#         except Exception:
#             # non-fatal — don't block UI
#             pass

# # Table View
# with tabs[1]:
#     st.markdown("## 🟦 Current Active IAM Resources (Simple View)")
#     fetched_at = meta.get("fetched_at", "—")
#     fast_status = "FAST (cache)" if meta.get("fast_mode") else "LIVE (fresh)"
#     region_used = meta.get("region") or (meta.get("regions", ["us-east-1"])[0] if meta.get("regions") else "us-east-1")
#     if isinstance(region_used, dict):
#         region_used = region_used.get("name") or region_used.get("Region") or "us-east-1"

#     # top metrics row
#     c1, c2, c3 = st.columns(3)
#     profile_used = ("Demo" if mode=="Demo" else (selected_profile or st.session_state.get("last_fetch_profile","Demo")))
#     c1.markdown(f"<div class='metric-card'><div style='color:#94a3b8'>AWS Profile <span class='info-dot' title='Profile used for the last fetch.'>ⓘ</span></div><div style='font-weight:900;color:#38bdf8'>{profile_used}</div></div>", unsafe_allow_html=True)
#     c2.markdown(f"<div class='metric-card'><div style='color:#94a3b8'>Region <span class='info-dot' title='Region from snapshot metadata.'>ⓘ</span></div><div style='font-weight:900;color:#34d399'>{region_used}</div></div>", unsafe_allow_html=True)
#     c3.markdown(f"<div class='metric-card'><div style='color:#94a3b8'>Fetch Mode <span class='info-dot' title='Snapshot source: cache or live.'>ⓘ</span></div><div style='font-weight:900;color:#f97316'>{fast_status}</div></div>", unsafe_allow_html=True)

#     st.markdown("<br>", unsafe_allow_html=True)
#     a,b,c,d = st.columns(4)
#     a.markdown(f"<div class='metric-card'><div>Total Users</div><b>{u_count}</b></div>", unsafe_allow_html=True)
#     b.markdown(f"<div class='metric-card'><div>Total Groups</div><b>{g_count}</b></div>", unsafe_allow_html=True)
#     c.markdown(f"<div class='metric-card'><div>Total Roles</div><b>{r_count}</b></div>", unsafe_allow_html=True)
#     d.markdown(f"<div class='metric-card'><div>Total Policies</div><b>{p_count}</b></div>", unsafe_allow_html=True)

#     st.markdown("<br><h4>🔥 Risk Summary <span class='info-dot' title='Counts of risky resources.'>ⓘ</span></h4>", unsafe_allow_html=True)
#     r1,r2,r3,r4 = st.columns(4)
#     r1.markdown(f"<div class='metric-card'><div>Risky Users</div><b style='color:#ef4444'>{ru}</b></div>", unsafe_allow_html=True)
#     r2.markdown(f"<div class='metric-card'><div>Risky Groups</div><b style='color:#ef4444'>{rg}</b></div>", unsafe_allow_html=True)
#     r3.markdown(f"<div class='metric-card'><div>Risky Roles</div><b style='color:#ef4444'>{rr}</b></div>", unsafe_allow_html=True)
#     r4.markdown(f"<div class='metric-card'><div>Risky Policies</div><b style='color:#ef4444'>{rp}</b></div>", unsafe_allow_html=True)

#     st.markdown("<br>", unsafe_allow_html=True)
#     st.markdown(f"<div style='padding:10px;border-radius:8px;border:1px solid #333;background:rgba(255,255,255,0.02)'><small style='color:#aaa'>Snapshot Fetched:</small> <b title='Snapshot timestamp'>{fetched_at}</b></div>", unsafe_allow_html=True)
#     st.markdown("---")

#     # Build dataframes (cheap)
#     user_df = pd.DataFrame([{
#         "UserName": u.get("UserName"),
#         "Arn": u.get("Arn"),
#         "Groups": ", ".join(u.get("Groups", [])) if isinstance(u.get("Groups", []), list) else str(u.get("Groups","")),
#         "AttachedPolicies": ", ".join([p.get("PolicyName") if isinstance(p, dict) else p for p in u.get("AttachedPolicies", [])]) if u.get("AttachedPolicies") else "",
#         "RiskScore": u.get("RiskScore") or 0,
#         "IsRisky": bool(u.get("IsRisky"))
#     } for u in users]) if users else pd.DataFrame()

#     role_df = pd.DataFrame([{
#         "RoleName": r.get("RoleName"),
#         "Arn": r.get("Arn"),
#         "AttachedPolicies": ", ".join([p.get("PolicyName") if isinstance(p, dict) else p for p in r.get("AttachedPolicies", [])]) if r.get("AttachedPolicies") else "",
#         "AssumePolicyRiskScore": r.get("AssumePolicyRiskScore") or r.get("RiskScore") or 0,
#         "IsRisky": bool(r.get("IsRisky"))
#     } for r in roles]) if roles else pd.DataFrame()

#     pol_df = pd.DataFrame([{
#         "PolicyName": p.get("PolicyName"),
#         "Arn": p.get("Arn"),
#         "RiskScore": p.get("RiskScore") or 0,
#         "IsRisky": bool(p.get("IsRisky")),
#         "Actions": ", ".join(p.get("Actions", []) or p.get("AllowedActions", [])) if (p.get("Actions") or p.get("AllowedActions")) else ""
#     } for p in policies]) if policies else pd.DataFrame()

#     # Lazy-load AgGrid and render (only when tab visible)
#     try:
#         from st_aggrid import AgGrid, GridOptionsBuilder, JsCode
#         if user_df.empty:
#             st.info("No Users Found.")
#         else:
#             gb = GridOptionsBuilder.from_dataframe(user_df)
#             gb.configure_pagination(paginationAutoPageSize=False, paginationPageSize=25)
#             gb.configure_side_bar()
#             gb.configure_default_column(filter=True, sortable=True, resizable=True)
#             gb.configure_column("IsRisky", header_name="Risky", cellStyle=JsCode("params => params.value ? {'backgroundColor':'#ffe6e6','color':'#900'} : null"), width=90)
#             gb.configure_column("RiskScore", header_name="Risk Score", width=120)
#             AgGrid(user_df, gridOptions=gb.build(), height=320, allow_unsafe_jscode=True)

#         st.markdown("---")

#         if role_df.empty:
#             st.info("No Roles Found.")
#         else:
#             gb = GridOptionsBuilder.from_dataframe(role_df)
#             gb.configure_default_column(filter=True, sortable=True, resizable=True)
#             gb.configure_column("IsRisky", header_name="Risky", cellStyle=JsCode("params => params.value ? {'backgroundColor':'#ffe6e6','color':'#900'} : null"), width=90)
#             AgGrid(role_df, gridOptions=gb.build(), height=260, allow_unsafe_jscode=True)

#         st.markdown("---")

#         if pol_df.empty:
#             st.info("No Policies Found.")
#         else:
#             gb = GridOptionsBuilder.from_dataframe(pol_df)
#             gb.configure_default_column(filter=True, sortable=True, resizable=True)
#             gb.configure_column("IsRisky", header_name="Risky", cellStyle=JsCode("params => params.value ? {'backgroundColor':'#ffe6e6','color':'#900'} : null"), width=90)
#             gb.configure_column("RiskScore", header_name="Risk Score", width=120)
#             AgGrid(pol_df, gridOptions=gb.build(), height=320, allow_unsafe_jscode=True)

#     except Exception:
#         # Fall back to simple tables if AgGrid missing or errored
#         if user_df.empty:
#             st.info("No Users Found.")
#         else:
#             st.dataframe(user_df)
#         st.markdown("---")
#         if role_df.empty:
#             st.info("No Roles Found.")
#         else:
#             st.dataframe(role_df)
#         st.markdown("---")
#         if pol_df.empty:
#             st.info("No Policies Found.")
#         else:
#             st.dataframe(pol_df)

# # Footer
# st.caption("IAM X-Ray — Stable Beta Build • Graph + Table synced • Non-technical friendly overview.")
# st.caption(f"IAM X-Ray — v{VERSION} • Stable Beta")



# chatgpt old version


# # app/main.py
# """
# IAM X-Ray — Optimized main.py (Stable Beta)
# - Smaller, faster, modular
# - Lazy-load heavy modules
# - Caches snapshot / graph / filtered tables
# - Auth delegated to core.auth.handle_auth(auth_file, lock_file, remember_file)
# - Compatible with core.fetch_iam, core.graph_builder, core.cleanup, core.config, core.versions
# - NEW: Permission Chains panel using meta["permission_chains"] from graph_builder
# """

# import sys
# import os
# import json
# import time
# import tempfile
# from datetime import datetime, timezone, timedelta
# import configparser

# import streamlit as st
# import streamlit.components.v1 as components
# import pandas as pd

# # PATHS & import fixes
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# from core import config
# from core.fetch_iam.engine import fetch_iam_data
# from core import cleanup
# from core.cleanup import ui_purge_button, ui_reset_app_button
# from core.versions import VERSION
# from core.auth import handle_auth  # expects (auth_file, lock_file, remember_path)

# # === Basic page config & CSS ===
# st.set_page_config(page_title="IAM X-Ray — Stable Beta", layout="wide", initial_sidebar_state="expanded")
# st.markdown(
#     """<style>
#       .metric-card{background:rgba(40,40,80,0.75);padding:12px;border-radius:10px;text-align:center;border:1px solid #333}
#       .info-dot{font-weight:700;color:#94a3b8;margin-left:6px;cursor:help}.small-muted{color:#9aa4bf;font-size:13px}
#       .chain-item {padding:8px;margin:4px 0;border-radius:6px;background:#f3f4f6;border-left:4px solid #3b82f6;}
#       .chain-risky {border-left-color:#ef4444;background:#fef2f2;}
#       .chain-controls {display:flex;gap:8px;align-items:center}
#     </style>""",
#     unsafe_allow_html=True,
# )

# # === Paths (single source of truth) ===
# DATA_DIR = getattr(config, "DATA_DIR", "data")
# SNAPSHOT_PATH = getattr(config, "SNAPSHOT_PATH", os.path.join(DATA_DIR, "iam_snapshot.json"))
# DEMO_PATH = os.path.join(DATA_DIR, "sample_snapshot.json")
# REMEMBER_PATH = os.path.join(DATA_DIR, "iamxray_remember.json")
# AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
# LOCK_FILE = os.path.join(DATA_DIR, "setup.lock")
# os.makedirs(DATA_DIR, exist_ok=True)

# # === Session defaults ===
# st.session_state.setdefault("theme", "dark")
# st.session_state.setdefault("authenticated", False)
# st.session_state.setdefault("search_query", "")
# st.session_state.setdefault("debounce_ts", 0)
# st.session_state.setdefault("last_fetch_profile", "Demo")
# st.session_state.setdefault("scroll_to_graph", False)

# # === License banner (light) ===
# LICENSEE = os.getenv("LICENSEE", "")
# if LICENSEE:
#     st.markdown(f"""<div style="position:fixed;right:20px;bottom:12px;background:rgba(0,0,0,0.45);padding:6px 12px;border-radius:6px;color:white;font-size:12px;z-index:9999">Licensed to: <b>{LICENSEE}</b></div>""", unsafe_allow_html=True)
# else:
#     st.markdown("""<div style="position:fixed;right:20px;bottom:12px;opacity:0.25;color:black;font-size:12px">IAM X-Ray • beta</div>""", unsafe_allow_html=True)

# # === Preflight: demo snapshot (lightweight) ===
# def _atomic_write(path, obj):
#     tmp = path + ".tmp"
#     with open(tmp, "w", encoding="utf-8") as fh:
#         json.dump(obj, fh, indent=2, default=str)
#     os.replace(tmp, path)

# def ensure_demo_snapshot():
#     if os.path.exists(DEMO_PATH): return
#     demo = {
#         "_meta": {"fetched_at": datetime.now(timezone.utc).isoformat() + "Z", "fast_mode": True, "counts": {"users": 1, "roles": 1, "policies": 1}},
#         "users": [{"UserName": "demo-user", "Arn": "arn:aws:iam::123:user/demo-user", "IsRisky": False, "AttachedPolicies": [{"PolicyName": "DemoPolicy"}], "Groups": []}],
#         "roles": [], "groups": [], "policies": [{"PolicyName": "DemoPolicy", "RiskScore": 1, "IsRisky": False, "Arn": "arn:aws:iam::123:policy/DemoPolicy", "Document": {"Statement": [{"Effect": "Allow","Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::demo-bucket/*"]}]}}]
#     }
#     _atomic_write(DEMO_PATH, demo)

# ensure_demo_snapshot()

# # === AUTH HANDOFF (delegated) ===
# auth_ok = handle_auth(AUTH_FILE, LOCK_FILE, REMEMBER_PATH)
# if not auth_ok:
#     st.stop()

# # === Helpers: lazy imports and caching ===
# @st.cache_data(show_spinner=False)
# def load_snapshot_cached(path, mtime=None):
#     """
#     Cache snapshot per file modification time (mtime is provided by caller).
#     """
#     if not os.path.exists(path):
#         raise FileNotFoundError(path)
#     try:
#        from core.graph_builder import load_snapshot as lb
#     except Exception:
#        from core.fetch_iam import load_snapshot as lb
#     snap = lb(path)
#     if not isinstance(snap, dict):
#         raise ValueError("snapshot not dict")
#     return snap

# @st.cache_data(show_spinner=False)
# def build_graph_cached(snapshot_fingerprint, show_risky, highlight, highlight_color="#ffeb3b", highlight_duration=1800):
#     """
#     Cached wrapper that builds the full pyvis HTML and meta by calling build_iam_graph.
#     Keyed by a fingerprint that should change when snapshot changes.
#     """
#     from core.graph_builder import build_iam_graph
#     # choose snapshot path from active selection (we pass active_snapshot globally)
#     try:
#         snap = load_snapshot_cached(active_snapshot, os.path.getmtime(active_snapshot) if os.path.exists(active_snapshot) else None)
#     except Exception:
#         snap = load_snapshot_cached(DEMO_PATH, os.path.getmtime(DEMO_PATH) if os.path.exists(DEMO_PATH) else None)
#     return build_iam_graph(snap, show_only_risky=show_risky, highlight_node=highlight, highlight_color=highlight_color, highlight_duration=highlight_duration)

# @st.cache_data(show_spinner=False)
# def filter_resources_cached(snapshot_fingerprint, min_risk, show_risky, keep_key, mode):
#     real_path = DEMO_PATH if mode == "Demo" else SNAPSHOT_PATH
#     snap = load_snapshot_cached(real_path, os.path.getmtime(real_path) if os.path.exists(real_path) else None)
#     users = snap.get("users", []) or []
#     groups = snap.get("groups", []) or []
#     roles = snap.get("roles", []) or []
#     policies = snap.get("policies", []) or []

#     if min_risk > 0:
#         users = [u for u in users if (u.get("RiskScore") or 0) >= min_risk]
#         roles = [r for r in roles if (r.get("AssumePolicyRiskScore") or 0) >= min_risk]
#         policies = [p for p in policies if (p.get("RiskScore") or 0) >= min_risk]

#     if show_risky:
#         users = [u for u in users if u.get("IsRisky")]
#         roles = [r for r in roles if r.get("IsRisky")]
#         policies = [p for p in policies if p.get("IsRisky")]

#     if keep_key:
#         try:
#             keep_set = set(json.loads(keep_key))
#         except Exception:
#             keep_set = set()
#         if keep_set:
#             users = [u for u in users if u.get("UserName") in keep_set]
#             groups = [g for g in groups if g.get("GroupName") in keep_set]
#             roles = [r for r in roles if r.get("RoleName") in keep_set]
#             policies = [p for p in policies if p.get("PolicyName") in keep_set]

#     return {
#         "users": users,
#         "groups": groups,
#         "roles": roles,
#         "policies": policies,
#         "_meta": snap.get("_meta", {})
#     }

# # Helper to compute snapshot fingerprint
# def snapshot_fingerprint(path):
#     try:
#         stt = os.path.getmtime(path)
#         sz = os.path.getsize(path)
#         return f"{path}:{int(stt)}:{sz}"
#     except Exception:
#         return path

# # Sidebar UI (controls)
# with st.sidebar:
#     st.header("Controls")
#     if st.session_state.get("force_demo_mode"):
#         mode = "Demo"
#         st.markdown("**Auth Mode:** Demo (forced by onboarding)")
#     else:
#         mode = st.selectbox("Auth Mode", ["Demo", "AWS Profile", "Env Keys"], help="Choose Demo for sample data, AWS Profile to use ~/.aws/credentials, or Env Keys to paste temporary keys.")

#     def list_profiles():
#         creds = os.path.expanduser("~/.aws/credentials")
#         if not os.path.exists(creds):
#             return []
#         cp = configparser.ConfigParser()
#         cp.read(creds)
#         return cp.sections()
#     profiles = list_profiles()

#     selected_profile = None
#     env = None
#     if mode == "AWS Profile":
#         selected_profile = st.selectbox("AWS Profile", ["default"] + profiles, help="Select profile from ~/.aws/credentials")
#     elif mode == "Env Keys":
#         ak = st.text_input("AWS_ACCESS_KEY_ID", type="password")
#         sk = st.text_input("AWS_SECRET_ACCESS_KEY", type="password")
#         tok = st.text_input("AWS_SESSION_TOKEN (optional)", type="password")
#         region = st.text_input("AWS_REGION", "us-east-1")
#         if ak and sk:
#             env = {"aws_access_key_id": ak, "aws_secret_access_key": sk, "aws_session_token": tok, "region_name": region}

#     st.write("---")
#     st.subheader("Fetch Options")
#     fast_mode = st.checkbox("Fast (use cache)", value=True)
#     force_fetch = st.checkbox("Force Live", value=False)
#     encrypt = st.checkbox("Encrypt Snapshot", value=False)
#     ttl_mins = st.number_input("Cache TTL (minutes)", 1, 1440, 60)
#     keep_days = st.number_input("Retention Days", 1, 365, 30)

#     fetch_btn = st.button("Fetch Latest Snapshot")

#     st.write("---")
#     st.subheader("Filter")
#     show_risky = st.checkbox("Show Only Risky", False)
#     show_changes = st.checkbox("Changes Only", False)
#     min_risk = st.slider("Min Risk Score", 0, 10, 0)

#     st.write("---")
#     st.caption("Housekeeping")
#     try:
#         ui_purge_button()
#     except Exception:
#         st.button("Purge snapshots (not available)", disabled=True)
#     try:
#         ui_reset_app_button()
#     except Exception:
#         st.button("Reset app (not available)", disabled=True)

# # Fetch handler
# active_snapshot = DEMO_PATH if mode == "Demo" else SNAPSHOT_PATH

# if fetch_btn:
#     fetch_box = st.empty()
#     try:
#         fetch_box.info("Fetching IAM data…")
#         if mode == "Env Keys" and env:
#             os.environ["AWS_ACCESS_KEY_ID"] = env["aws_access_key_id"]
#             os.environ["AWS_SECRET_ACCESS_KEY"] = env["aws_secret_access_key"]
#             if env.get("aws_session_token"):
#                 os.environ["AWS_SESSION_TOKEN"] = env["aws_session_token"]
#             if env.get("region_name"):
#                 os.environ["AWS_REGION"] = env["region_name"]

#         fetch_iam_data(
#             session=None,
#             profile_name=(selected_profile if mode == "AWS Profile" else None),
#             out_path=SNAPSHOT_PATH,
#             fast_mode=fast_mode,
#             force_fetch=force_fetch,
#             encrypt=encrypt,
#             multi_region=False,
#             cache_ttl=ttl_mins * 60
#         )

#         fetch_box.success("Snapshot updated!")
#         st.session_state.last_fetch_profile = (selected_profile or ("Env Keys" if mode=="Env Keys" else "Demo"))
#         st.session_state.scroll_to_graph = True
#         fetch_box.empty()
#         st.rerun()
#     except Exception as e:
#         fetch_box.error(f"Fetch failed: {e}")

# # Ensure snapshot file exists
# if not os.path.exists(active_snapshot):
#     st.warning("No snapshot found — run Fetch or switch to Demo")
#     st.stop()

# snap_fp = snapshot_fingerprint(active_snapshot)

# # If user requested "changes only" compute keep set
# keep_key = None
# if show_changes:
#     try:
#         from core.graph_builder import compute_keep_set_from_diff
#         snap_for_diff = load_snapshot_cached(active_snapshot, os.path.getmtime(active_snapshot))
#         keep_set = compute_keep_set_from_diff(snap_for_diff) or set()
#         keep_key = json.dumps(list(keep_set))
#     except Exception:
#         keep_key = None

# # Load filtered resources
# filtered = filter_resources_cached(snap_fp, min_risk, show_risky, keep_key, mode)
# users = filtered["users"]
# groups = filtered["groups"]
# roles = filtered["roles"]
# policies = filtered["policies"]
# meta = filtered["_meta"] or {}

# # counts
# u_count = len(users); g_count = len(groups); r_count = len(roles); p_count = len(policies)
# ru = len([u for u in users if u.get("IsRisky")])
# rg = len([g for g in groups if g.get("IsRisky")])
# rr = len([r for r in roles if r.get("IsRisky")])
# rp = len([p for p in policies if p.get("IsRisky")])

# # Tabs
# tabs = st.tabs(["Graph View", "Table View", "Permission Chains"])

# # Graph View
# with tabs[0]:
#     st.markdown("### 🕸 Interactive IAM Attack Graph <span class='small-muted'>Hover the info icon for quick help</span>", unsafe_allow_html=True)
#     search = st.text_input("Search entity or permission", value=st.session_state.get("search_query",""), placeholder="ex: s3:PutObject or alice")
#     now = int(time.time() * 1000)
#     if (now - st.session_state["debounce_ts"]) > 300:
#         st.session_state["search_query"] = search
#     st.session_state["debounce_ts"] = now
#     highlight = st.session_state["search_query"]

#     graph_cache_key = f"{snap_fp}:risky={show_risky}:hl={highlight}"
#     try:
#         G, graph_html, clicked, export_bytes, graph_meta = build_graph_cached(graph_cache_key, show_risky, highlight)
#     except Exception as e:
#         st.error(f"Graph build error: {e}")
#         st.stop()

#     if graph_html:
#         components.html(graph_html, height=900, scrolling=False)
#         if export_bytes:
#             st.download_button("Download Graph JSON", export_bytes, "iam_graph.json")

#         raw_export_path = os.path.join(tempfile.gettempdir(), "iam_xray_graph.raw.json")
#         try:
#             if os.path.exists(raw_export_path):
#                 with open(raw_export_path, "rb") as rf:
#                     raw_bytes = rf.read()
#                 st.download_button("Download Raw (uncollapsed) Graph JSON", raw_bytes, "iam_graph.raw.json")
#         except Exception:
#             pass

# # Table View
# with tabs[1]:
#     st.markdown("## 🟦 Current Active IAM Resources (Simple View)")
#     fetched_at = meta.get("fetched_at", "—")
#     fast_status = "FAST (cache)" if meta.get("fast_mode") else "LIVE (fresh)"
#     region_used = meta.get("region") or (meta.get("regions", ["us-east-1"])[0] if meta.get("regions") else "us-east-1")
#     if isinstance(region_used, dict):
#         region_used = region_used.get("name") or region_used.get("Region") or "us-east-1"

#     c1, c2, c3 = st.columns(3)
#     profile_used = ("Demo" if mode=="Demo" else (selected_profile or st.session_state.get("last_fetch_profile","Demo")))
#     c1.markdown(f"<div class='metric-card'><div style='color:#94a3b8'>AWS Profile</div><div style='font-weight:900;color:#38bdf8'>{profile_used}</div></div>", unsafe_allow_html=True)
#     c2.markdown(f"<div class='metric-card'><div style='color:#94a3b8'>Region</div><div style='font-weight:900;color:#34d399'>{region_used}</div></div>", unsafe_allow_html=True)
#     c3.markdown(f"<div class='metric-card'><div style='color:#94a3b8'>Fetch Mode</div><div style='font-weight:900;color:#f97316'>{fast_status}</div></div>", unsafe_allow_html=True)

#     st.markdown("<br>", unsafe_allow_html=True)
#     a,b,c,d = st.columns(4)
#     a.markdown(f"<div class='metric-card'><div>Total Users</div><b>{u_count}</b></div>", unsafe_allow_html=True)
#     b.markdown(f"<div class='metric-card'><div>Total Groups</div><b>{g_count}</b></div>", unsafe_allow_html=True)
#     c.markdown(f"<div class='metric-card'><div>Total Roles</div><b>{r_count}</b></div>", unsafe_allow_html=True)
#     d.markdown(f"<div class='metric-card'><div>Total Policies</div><b>{p_count}</b></div>", unsafe_allow_html=True)

#     st.markdown("<br><h4>🔥 Risk Summary</h4>", unsafe_allow_html=True)
#     r1,r2,r3,r4 = st.columns(4)
#     r1.markdown(f"<div class='metric-card'><div>Risky Users</div><b style='color:#ef4444'>{ru}</b></div>", unsafe_allow_html=True)
#     r2.markdown(f"<div class='metric-card'><div>Risky Groups</div><b style='color:#ef4444'>{rg}</b></div>", unsafe_allow_html=True)
#     r3.markdown(f"<div class='metric-card'><div>Risky Roles</div><b style='color:#ef4444'>{rr}</b></div>", unsafe_allow_html=True)
#     r4.markdown(f"<div class='metric-card'><div>Risky Policies</div><b style='color:#ef4444'>{rp}</b></div>", unsafe_allow_html=True)

#     st.markdown("<br>", unsafe_allow_html=True)
#     st.markdown(f"<div style='padding:10px;border-radius:8px;border:1px solid #333;background:rgba(255,255,255,0.02)'><small>Snapshot Fetched:</small> <b>{fetched_at}</b></div>", unsafe_allow_html=True)
#     st.markdown("---")

#     user_df = pd.DataFrame([{
#         "UserName": u.get("UserName"),
#         "Arn": u.get("Arn"),
#         "Groups": ", ".join(u.get("Groups", [])) if isinstance(u.get("Groups", []), list) else str(u.get("Groups","")),
#         "AttachedPolicies": ", ".join([p.get("PolicyName") if isinstance(p, dict) else p for p in u.get("AttachedPolicies", [])]) if u.get("AttachedPolicies") else "",
#         "RiskScore": u.get("RiskScore") or 0,
#         "IsRisky": bool(u.get("IsRisky"))
#     } for u in users]) if users else pd.DataFrame()

#     role_df = pd.DataFrame([{
#         "RoleName": r.get("RoleName"),
#         "Arn": r.get("Arn"),
#         "AttachedPolicies": ", ".join([p.get("PolicyName") if isinstance(p, dict) else p for p in r.get("AttachedPolicies", [])]) if r.get("AttachedPolicies") else "",
#         "AssumePolicyRiskScore": r.get("AssumePolicyRiskScore") or r.get("RiskScore") or 0,
#         "IsRisky": bool(r.get("IsRisky"))
#     } for r in roles]) if roles else pd.DataFrame()

#     pol_df = pd.DataFrame([{
#         "PolicyName": p.get("PolicyName"),
#         "Arn": p.get("Arn"),
#         "RiskScore": p.get("RiskScore") or 0,
#         "IsRisky": bool(p.get("IsRisky")),
#         "Actions": ", ".join(p.get("Actions", []) or p.get("AllowedActions", [])) if (p.get("Actions") or p.get("AllowedActions")) else ""
#     } for p in policies]) if policies else pd.DataFrame()

#     # Attempt AgGrid if available
#     try:
#         from st_aggrid import AgGrid, GridOptionsBuilder, JsCode
#         if user_df.empty:
#             st.info("No Users Found.")
#         else:
#             gb = GridOptionsBuilder.from_dataframe(user_df)
#             gb.configure_pagination(paginationAutoPageSize=False, paginationPageSize=25)
#             gb.configure_side_bar()
#             gb.configure_default_column(filter=True, sortable=True, resizable=True)
#             gb.configure_column("IsRisky", header_name="Risky", cellStyle=JsCode("params => params.value ? {'backgroundColor':'#ffe6e6','color':'#900'} : null"), width=90)
#             gb.configure_column("RiskScore", header_name="Risk Score", width=120)
#             AgGrid(user_df, gridOptions=gb.build(), height=320, allow_unsafe_jscode=True)

#         st.markdown("---")

#         if role_df.empty:
#             st.info("No Roles Found.")
#         else:
#             gb = GridOptionsBuilder.from_dataframe(role_df)
#             gb.configure_default_column(filter=True, sortable=True, resizable=True)
#             gb.configure_column("IsRisky", header_name="Risky", cellStyle=JsCode("params => params.value ? {'backgroundColor':'#ffe6e6','color':'#900'} : null"), width=90)
#             AgGrid(role_df, gridOptions=gb.build(), height=260, allow_unsafe_jscode=True)

#         st.markdown("---")

#         if pol_df.empty:
#             st.info("No Policies Found.")
#         else:
#             gb = GridOptionsBuilder.from_dataframe(pol_df)
#             gb.configure_default_column(filter=True, sortable=True, resizable=True)
#             gb.configure_column("IsRisky", header_name="Risky", cellStyle=JsCode("params => params.value ? {'backgroundColor':'#ffe6e6','color':'#900'} : null"), width=90)
#             gb.configure_column("RiskScore", header_name="Risk Score", width=120)
#             AgGrid(pol_df, gridOptions=gb.build(), height=320, allow_unsafe_jscode=True)

#     except Exception:
#         if user_df.empty:
#             st.info("No Users Found.")
#         else:
#             st.dataframe(user_df)
#         st.markdown("---")
#         if role_df.empty:
#             st.info("No Roles Found.")
#         else:
#             st.dataframe(role_df)
#         st.markdown("---")
#         if pol_df.empty:
#             st.info("No Policies Found.")
#         else:
#             st.dataframe(pol_df)

# # Permission Chains Tab (enhanced)
# with tabs[2]:
#     st.markdown("### 🔗 Permission Chains <span class='small-muted'>Extracted paths from principals to actions</span>", unsafe_allow_html=True)
#     st.markdown("<div style='margin-bottom:8px;'>Shows sample chains like 'User Alice → Policy Admin → Action iam:PassRole'. <span class='info-dot' title='Chains from raw graph for full audit depth; limited to 50 for perf.'>ⓘ</span></div>", unsafe_allow_html=True)

#     graph_cache_key = f"{snap_fp}:risky={show_risky}:hl={highlight}"
#     try:
#         # fetch the meta only (cached)
#         _, _, _, _, graph_meta = build_graph_cached(graph_cache_key, show_risky, highlight)
#     except Exception as e:
#         st.error(f"Chains extraction error: {e}")
#         graph_meta = {}

#     chains = graph_meta.get("permission_chains", []) or []
#     who_can_full = graph_meta.get("who_can_do_full", {}) or {}

#     if not chains:
#         st.info("No permission chains found—try a larger snapshot or run a live fetch.")
#     else:
#         # left: list of chains; right: details + highlight panel
#         left_col, right_col = st.columns([1, 2])
#         with left_col:
#             st.markdown(f"**Sample chains ({len(chains)}):**")
#             # display rendered strings with clickable selection
#             selected_chain_idx = st.radio("Select chain to inspect", options=list(range(len(chains))), format_func=lambda i: chains[i]["render"])
#             st.caption("Select a chain to view details and highlight in graph.")

#         chain = chains[selected_chain_idx]
#         with right_col:
#             st.markdown("#### Chain Details")
#             st.markdown(f"**Rendered:** `{chain.get('render')}`")
#             st.markdown(f"**Risk Score:** `{chain.get('risk_score')}`")
#             if chain.get("notes"):
#                 st.markdown("**Notes:**")
#                 for n in chain.get("notes", []):
#                     st.markdown(f"- {n}")
#             if chain.get("resources"):
#                 st.markdown("**Resources (sample):**")
#                 for r in chain.get("resources", []):
#                     st.markdown(f"- `{r}`")
#             if chain.get("actions"):
#                 st.markdown("**Actions:**")
#                 for a in chain.get("actions", []):
#                     st.markdown(f"- `{a}`")

#             # Who-can panel (for the first action in chain)
#             action_for_lookup = chain.get("actions", [None])[0]
#             st.markdown("---")
#             st.markdown("**Who can perform the action?**")
#             if action_for_lookup:
#                 principals = who_can_full.get(action_for_lookup) or who_can_full.get(action_for_lookup.strip()) or []
#                 if principals:
#                     st.markdown(f"Found **{len(principals)}** principals (sample):")
#                     for p in principals[:20]:
#                         st.markdown(f"- `{p}`")
#                 else:
#                     st.markdown("No principals found in full mapping (action may be truncated or absent in sampled actions).")
#             else:
#                 st.markdown("No action available for this chain.")

#             st.markdown("---")
#             # Highlight chain button: renders a focused pyvis for this chain
#             if st.button("Highlight chain in focused graph"):
#                 # render subgraph HTML and show
#                 try:
#                     # render_subgraph_html uses caching below
#                     html = None
#                     try:
#                         html = render_chain_cached_html(snap_fp, active_snapshot, chain, show_risky)
#                     except NameError:
#                         # define cached renderer on demand (below)
#                         pass
#                     if not html:
#                         # fallback: define and call
#                         pass
#                 except Exception as e:
#                     st.error(f"Failed to render chain subgraph: {e}")

#             # Download chain JSON
#             st.download_button("Download Chain JSON", data=json.dumps(chain, indent=2, default=str), file_name=f"{chain.get('id','chain')}.json", help="Download chain metadata")

# # Define chain renderer after UI to allow caching decorated function to be declared in top-level
# # Caching: keyed by snapshot fingerprint + chain id
# @st.cache_data(show_spinner=False)
# def _render_chain_subgraph_html_cached(snap_fp_key: str, snapshot_path: str, chain_obj: dict, show_risky_flag: bool):
#     """
#     Build a focused pyvis HTML for the chain using core.graph_builder.build_graph + render_chain_subgraph.
#     Returns HTML string.
#     """
#     try:
#         from core.graph_builder import build_graph, render_chain_subgraph
#     except Exception as e:
#         raise RuntimeError(f"Graph builder functions not available: {e}")

#     # load snapshot
#     snap = load_snapshot_cached(snapshot_path, os.path.getmtime(snapshot_path) if os.path.exists(snapshot_path) else None)
#     # build raw graph (same trimming as main builder)
#     G_raw = build_graph(snap, show_only_risky=show_risky_flag)

#     # ensure chain_obj path nodes exist in G_raw; if some nodes missing perhaps because of sampling, still render what we have
#     sub_nx = render_chain_subgraph(G_raw, chain_obj, extra_hops=1, max_nodes=120)

#     # convert this small subgraph to pyvis HTML
#     try:
#         from pyvis.network import Network as PyNet
#     except Exception as e:
#         raise RuntimeError(f"pyvis not installed: {e}")

#     net = PyNet(height="600px", width="100%", directed=True, bgcolor="#ffffff", font_color="#111827")
#     net.set_options("""
#     {
#       "physics": {"enabled": true, "solver": "forceAtlas2Based", "stabilization": {"iterations": 150}},
#       "interaction": {"hover": true, "zoomView": true, "dragView": true}
#     }
#     """)

#     # small utility for colors
#     def _node_color(t, risky=False):
#         mapping = {
#             "user": "#3B82F6", "group": "#F59E0B", "role": "#10B981",
#             "policy": "#8b5cf6", "action": "#ef4444", "meta": "#94a3b8", "principal": "#9CA3AF"
#         }
#         if risky:
#             return "#ef4444"
#         return mapping.get(t, "#64748b")

#     # highlight nodes in chain_obj
#     chain_nodes = set(chain_obj.get("subgraph_path_nodes", []))

#     for n, a in sub_nx.nodes(data=True):
#         ntype = a.get("type", "unknown")
#         risky = bool(a.get("risky", False))
#         label = a.get("label") or n
#         size = 28 + (12 if n in chain_nodes else 0) + (8 if risky else 0)
#         shape = "dot"
#         if ntype == "action":
#             shape = "diamond"
#         elif ntype == "meta":
#             shape = "box"
#         title_lines = []
#         if ntype == "policy":
#             title_lines.append(f"Policy: {label}")
#         elif ntype == "user":
#             title_lines.append(f"User: {label}")
#         elif ntype == "role":
#             title_lines.append(f"Role: {label}")
#         elif ntype == "group":
#             title_lines.append(f"Group: {label}")
#         elif ntype == "action":
#             title_lines.append(f"Action: {a.get('meta',{}).get('action', label)}")
#         title = "<br>".join(title_lines) if title_lines else label
#         net.add_node(n, label=str(label), title=title, color=_node_color(ntype, risky), size=size, shape=shape, borderWidth=3 if n in chain_nodes else 1)

#     for u, v, d in sub_nx.edges(data=True):
#         rel = d.get("relation","")
#         lbl = rel if rel else ""
#         color = "#64748b"
#         dashes = False
#         if rel == "member":
#             color = "#3b82f6"
#         elif rel == "attached":
#             color = "#8b5cf6"
#         elif rel == "assumes":
#             color = "#10b981"
#             dashes = True
#         elif rel in ("CAN", "CANNOT"):
#             color = "#10b981" if rel=="CAN" else "#ef4444"
#         net.add_edge(u, v, label=lbl, color=color, dashes=dashes, width=2.5 if (u in chain_nodes or v in chain_nodes) else 1.8)

#     # generate HTML and return
#     tmpd = tempfile.mkdtemp(prefix="iamxray_chain_")
#     p = os.path.join(tmpd, "chain.html")
#     net.write_html(p)
#     with open(p, "r", encoding="utf-8") as fh:
#         html = fh.read()
#     # small injection of style for container
#     html = html.replace("<body>", "<body style='margin:0;background:#f8fafc'>", 1)
#     return html

# # wrapper that main code calls
# def render_chain_cached_html(snap_fp_key: str, snapshot_path: str, chain_obj: dict, show_risky_flag: bool):
#     return _render_chain_subgraph_html_cached(snap_fp_key, snapshot_path, chain_obj, show_risky_flag)

# # Footer
# st.caption("IAM X-Ray — Stable Beta Build • Graph + Table synced • Non-technical friendly overview.")
# st.caption(f"IAM X-Ray — v{VERSION} • Stable Beta")



# new chatgpt version

# # main.py
# """
# IAM X-Ray — Optimized main.py (Stable Beta)
# This version is synced with the enterprise fetch engine at core/fetch_iam/engine.py
# and the current graph_builder. It includes the 5 critical fixes requested:
# 1) import fetch_iam_data from core.fetch_iam.engine
# 2) always load snapshots with core.fetch_iam.load_snapshot
# 3) normalize build_iam_graph return values (compat with both old/new API)
# 4) use safe fallbacks for RiskScore/IsRisky fields
# 5) region metadata resolution fixed for new snapshot shape
# """

# import sys
# import os
# import json
# import time
# import tempfile
# from datetime import datetime, timezone
# import configparser

# import streamlit as st
# import streamlit.components.v1 as components
# import pandas as pd

# # PATHS & import fixes
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# from core import config
# # FIX 1: import enterprise fetch_iam_data from engine
# try:
#     from core.fetch_iam import fetch_iam_data
# except Exception:
#     # fallback if structure differs
#     from core.fetch_iam.wrapper import fetch_iam_data

# from core import cleanup
# from core.cleanup import ui_purge_button, ui_reset_app_button
# from core.versions import VERSION
# from core.auth import handle_auth  # expects (auth_file, lock_file, remember_path)

# # === Basic page config & CSS ===
# st.set_page_config(page_title="IAM X-Ray — Stable Beta", layout="wide", initial_sidebar_state="expanded")
# st.markdown(
#     """<style>
#       .metric-card{background:rgba(40,40,80,0.75);padding:12px;border-radius:10px;text-align:center;border:1px solid #333}
#       .info-dot{font-weight:700;color:#94a3b8;margin-left:6px;cursor:help}.small-muted{color:#9aa4bf;font-size:13px}
#       .chain-item {padding:8px;margin:4px 0;border-radius:6px;background:#f3f4f6;border-left:4px solid #3b82f6;}
#       .chain-risky {border-left-color:#ef4444;background:#fef2f2;}
#       .chain-controls {display:flex;gap:8px;align-items:center}
#     </style>""",
#     unsafe_allow_html=True,
# )

# # === Paths (single source of truth) ===
# DATA_DIR = getattr(config, "DATA_DIR", "data")
# SNAPSHOT_PATH = getattr(config, "SNAPSHOT_PATH", os.path.join(DATA_DIR, "iam_snapshot.json"))
# DEMO_PATH = os.path.join(DATA_DIR, "sample_snapshot.json")
# REMEMBER_PATH = os.path.join(DATA_DIR, "iamxray_remember.json")
# AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
# LOCK_FILE = os.path.join(DATA_DIR, "setup.lock")
# os.makedirs(DATA_DIR, exist_ok=True)

# # === Session defaults ===
# st.session_state.setdefault("theme", "dark")
# st.session_state.setdefault("authenticated", False)
# st.session_state.setdefault("search_query", "")
# st.session_state.setdefault("debounce_ts", 0)
# st.session_state.setdefault("last_fetch_profile", "Demo")
# st.session_state.setdefault("scroll_to_graph", False)

# # === License banner (light) ===
# LICENSEE = os.getenv("LICENSEE", "")
# if LICENSEE:
#     st.markdown(f"""<div style="position:fixed;right:20px;bottom:12px;background:rgba(0,0,0,0.45);padding:6px 12px;border-radius:6px;color:white;font-size:12px;z-index:9999">Licensed to: <b>{LICENSEE}</b></div>""", unsafe_allow_html=True)
# else:
#     st.markdown("""<div style="position:fixed;right:20px;bottom:12px;opacity:0.25;color:black;font-size:12px">IAM X-Ray • beta</div>""", unsafe_allow_html=True)

# # === Preflight: demo snapshot (lightweight) ===
# def _atomic_write(path, obj):
#     tmp = path + ".tmp"
#     with open(tmp, "w", encoding="utf-8") as fh:
#         json.dump(obj, fh, indent=2, default=str)
#     os.replace(tmp, path)

# def ensure_demo_snapshot():
#     if os.path.exists(DEMO_PATH): return
#     demo = {
#         "_meta": {"fetched_at": datetime.now(timezone.utc).isoformat() + "Z", "fast_mode": True, "counts": {"users": 1, "roles": 1, "policies": 1}, "regions": [{"_meta": {"region": "us-east-1"}}]},
#         "users": [{"UserName": "demo-user", "Arn": "arn:aws:iam::123:user/demo-user", "IsRisky": False, "AttachedPolicies": [{"PolicyName": "DemoPolicy"}], "Groups": []}],
#         "roles": [], "groups": [], "policies": [{"PolicyName": "DemoPolicy", "RiskScore": 1, "IsRisky": False, "Arn": "arn:aws:iam::123:policy/DemoPolicy", "Document": {"Statement": [{"Effect": "Allow","Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::demo-bucket/*"]}]}}]
#     }
#     _atomic_write(DEMO_PATH, demo)

# ensure_demo_snapshot()

# # === AUTH HANDOFF (delegated) ===
# auth_ok = handle_auth(AUTH_FILE, LOCK_FILE, REMEMBER_PATH)
# if not auth_ok:
#     st.stop()

# # === Helpers: lazy imports and caching ===

# @st.cache_data(show_spinner=False)
# def load_snapshot_cached(path, mtime=None):
#     """
#     Cache snapshot per file modification time (mtime is provided by caller).
#     FIX 2: Always prefer core.fetch_iam.load_snapshot for loading snapshots (encrypted/plaintext fallback).
#     """
#     if not os.path.exists(path):
#         raise FileNotFoundError(path)
#     try:
#         from core.fetch_iam import load_snapshot as lb
#     except Exception:
#         # last-resort fallback to legacy loader if present
#         try:
#             from core.graph_builder import load_snapshot as lb
#         except Exception:
#             raise RuntimeError("No snapshot loader available")
#     snap = lb(path)
#     if not isinstance(snap, dict):
#         raise ValueError("snapshot not dict")
#     return snap

# @st.cache_data(show_spinner=False)
# def build_graph_cached(snapshot_fingerprint, show_risky, highlight, highlight_color="#ffeb3b", highlight_duration=1800):
#     """
#     Cached wrapper that builds the full pyvis HTML and meta by calling build_iam_graph.
#     Normalizes return values so callers get (nx_graph, html_str, meta_dict) regardless of graph_builder API shape.
#     """
#     from core.graph_builder import build_iam_graph
#     # choose snapshot path from active selection (we pass active_snapshot globally)
#     try:
#         snap = load_snapshot_cached(active_snapshot, os.path.getmtime(active_snapshot) if os.path.exists(active_snapshot) else None)
#     except Exception:
#         snap = load_snapshot_cached(DEMO_PATH, os.path.getmtime(DEMO_PATH) if os.path.exists(DEMO_PATH) else None)

#     res = build_iam_graph(snap, show_only_risky=show_risky, highlight_node=highlight, highlight_color=highlight_color, highlight_duration=highlight_duration)

#     # Normalize different possible return signatures:
#     # - New API: (nx_graph, html_str, meta_dict)
#     # - Old API (legacy we observed): (G_final, html_str, None, export_bytes, meta_dict)
#     if isinstance(res, tuple) or isinstance(res, list):
#         if len(res) == 3:
#             nx_graph, html_str, meta = res
#         elif len(res) == 5:
#             nx_graph, html_str, _, export_bytes, meta = res
#             # try attach export_bytes into meta for callers expecting it
#             if isinstance(meta, dict):
#                 meta = dict(meta)  # shallow copy
#                 meta.setdefault("raw_export_bytes", export_bytes)
#         else:
#             # fallback: best-effort mapping
#             try:
#                 nx_graph = res[0]
#                 html_str = res[1] if len(res) > 1 else ""
#                 meta = res[-1] if len(res) > 0 else {}
#             except Exception:
#                 nx_graph, html_str, meta = None, "", {}
#     else:
#         nx_graph, html_str, meta = None, "", {}

#     if meta is None:
#         meta = {}
#     return nx_graph, html_str, meta

# @st.cache_data(show_spinner=False)
# def filter_resources_cached(snapshot_fingerprint, min_risk, show_risky, keep_key, mode):
#     real_path = DEMO_PATH if mode == "Demo" else SNAPSHOT_PATH
#     snap = load_snapshot_cached(real_path, os.path.getmtime(real_path) if os.path.exists(real_path) else None)
#     users = snap.get("users", []) or []
#     groups = snap.get("groups", []) or []
#     roles = snap.get("roles", []) or []
#     policies = snap.get("policies", []) or []

#     # Use tolerant accessors for risk fields (FIX 4)
#     def user_risk_ok(u):
#         return int(u.get("RiskScore") or u.get("UserRiskScore") or 0)
#     def user_is_risky(u):
#         return bool(u.get("IsRisky") or u.get("UserIsRisky") or False)

#     def role_risk_ok(r):
#         return int(r.get("AssumePolicyRiskScore") or r.get("RiskScore") or r.get("AssumeRisk") or 0)
#     def role_is_risky(r):
#         return bool(r.get("IsRisky") or r.get("IsRiskyTrust") or False)

#     def policy_risk_ok(p):
#         return int(p.get("RiskScore") or 0)
#     def policy_is_risky(p):
#         return bool(p.get("IsRisky") or False)

#     if min_risk > 0:
#         users = [u for u in users if user_risk_ok(u) >= min_risk]
#         roles = [r for r in roles if role_risk_ok(r) >= min_risk]
#         policies = [p for p in policies if policy_risk_ok(p) >= min_risk]

#     if show_risky:
#         users = [u for u in users if user_is_risky(u)]
#         roles = [r for r in roles if role_is_risky(r)]
#         policies = [p for p in policies if policy_is_risky(p)]

#     if keep_key:
#         try:
#             keep_set = set(json.loads(keep_key))
#         except Exception:
#             keep_set = set()
#         if keep_set:
#             users = [u for u in users if u.get("UserName") in keep_set]
#             groups = [g for g in groups if g.get("GroupName") in keep_set]
#             roles = [r for r in roles if r.get("RoleName") in keep_set]
#             policies = [p for p in policies if p.get("PolicyName") in keep_set]

#     return {
#         "users": users,
#         "groups": groups,
#         "roles": roles,
#         "policies": policies,
#         "_meta": snap.get("_meta", {})
#     }

# # Helper to compute snapshot fingerprint
# def snapshot_fingerprint(path):
#     try:
#         stt = os.path.getmtime(path)
#         sz = os.path.getsize(path)
#         return f"{path}:{int(stt)}:{sz}"
#     except Exception:
#         return path

# # Sidebar UI (controls)
# with st.sidebar:
#     st.header("Controls")
#     if st.session_state.get("force_demo_mode"):
#         mode = "Demo"
#         st.markdown("**Auth Mode:** Demo (forced by onboarding)")
#     else:
#         mode = st.selectbox("Auth Mode", ["Demo", "AWS Profile", "Env Keys"], help="Choose Demo for sample data, AWS Profile to use ~/.aws/credentials, or Env Keys to paste temporary keys.")

#     def list_profiles():
#         creds = os.path.expanduser("~/.aws/credentials")
#         if not os.path.exists(creds):
#             return []
#         cp = configparser.ConfigParser()
#         cp.read(creds)
#         return cp.sections()
#     profiles = list_profiles()

#     selected_profile = None
#     env = None
#     if mode == "AWS Profile":
#         selected_profile = st.selectbox("AWS Profile", ["default"] + profiles, help="Select profile from ~/.aws/credentials")
#     elif mode == "Env Keys":
#         ak = st.text_input("AWS_ACCESS_KEY_ID", type="password")
#         sk = st.text_input("AWS_SECRET_ACCESS_KEY", type="password")
#         tok = st.text_input("AWS_SESSION_TOKEN (optional)", type="password")
#         region = st.text_input("AWS_REGION", "us-east-1")
#         if ak and sk:
#             env = {"aws_access_key_id": ak, "aws_secret_access_key": sk, "aws_session_token": tok, "region_name": region}

#     st.write("---")
#     st.subheader("Fetch Options")
#     fast_mode = st.checkbox("Fast (use cache)", value=True)
#     force_fetch = st.checkbox("Force Live", value=False)
#     encrypt = st.checkbox("Encrypt Snapshot", value=False)
#     ttl_mins = st.number_input("Cache TTL (minutes)", 1, 1440, 60)
#     keep_days = st.number_input("Retention Days", 1, 365, 30)

#     fetch_btn = st.button("Fetch Latest Snapshot")

#     st.write("---")
#     st.subheader("Filter")
#     show_risky = st.checkbox("Show Only Risky", False)
#     show_changes = st.checkbox("Changes Only", False)
#     min_risk = st.slider("Min Risk Score", 0, 10, 0)

#     st.write("---")
#     st.caption("Housekeeping")
#     try:
#         ui_purge_button()
#     except Exception:
#         st.button("Purge snapshots (not available)", disabled=True)
#     try:
#         ui_reset_app_button()
#     except Exception:
#         st.button("Reset app (not available)", disabled=True)

# # Fetch handler
# active_snapshot = DEMO_PATH if mode == "Demo" else SNAPSHOT_PATH

# if fetch_btn:
#     fetch_box = st.empty()
#     prog = st.progress(0)

#     try:
#         fetch_box.info("Fetching IAM data…")

#         # handle env keys
#         if mode == "Env Keys" and env:
#             os.environ["AWS_ACCESS_KEY_ID"] = env["aws_access_key_id"]
#             os.environ["AWS_SECRET_ACCESS_KEY"] = env["aws_secret_access_key"]
#             if env.get("aws_session_token"):
#                 os.environ["AWS_SESSION_TOKEN"] = env["aws_session_token"]
#             if env.get("region_name"):
#                 os.environ["AWS_REGION"] = env["region_name"]

#         # progress callback for engine
#         def _cb(frac):
#             try:
#                 frac = min(max(float(frac), 0.0), 1.0)
#             except:
#                 frac = 0
#             prog.progress(frac)

#         # run engine
#         fetch_iam_data(
#             session=None,
#             profile_name=(selected_profile if mode == "AWS Profile" else None),
#             out_path=SNAPSHOT_PATH,
#             fast_mode=fast_mode,
#             force_fetch=force_fetch,
#             encrypt=encrypt,
#             multi_region=False,
#             cache_ttl=ttl_mins * 60,
#             progress_callback=_cb
#         )

#         prog.progress(1.0)
#         fetch_box.success("Snapshot updated!")
#         st.session_state.last_fetch_profile = (selected_profile or ("Env Keys" if mode=="Env Keys" else "Demo"))
#         st.session_state.scroll_to_graph = True
#         fetch_box.empty()
#         st.rerun()

#     except Exception as e:
#         fetch_box.error(f"Fetch failed: {e}")
#         prog.progress(0)

# # Ensure snapshot file exists
# if not os.path.exists(active_snapshot):
#     st.warning("No snapshot found — run Fetch or switch to Demo")
#     st.stop()

# snap_fp = snapshot_fingerprint(active_snapshot)

# # If user requested "changes only" compute keep set
# keep_key = None
# if show_changes:
#     try:
#         from core.graph_builder import compute_keep_set_from_diff
#         snap_for_diff = load_snapshot_cached(active_snapshot, os.path.getmtime(active_snapshot))
#         keep_set = compute_keep_set_from_diff(snap_for_diff) or set()
#         keep_key = json.dumps(list(keep_set))
#     except Exception:
#         keep_key = None

# # Load filtered resources
# filtered = filter_resources_cached(snap_fp, min_risk, show_risky, keep_key, mode)
# users = filtered["users"]
# groups = filtered["groups"]
# roles = filtered["roles"]
# policies = filtered["policies"]
# meta = filtered["_meta"] or {}

# # counts
# u_count = len(users); g_count = len(groups); r_count = len(roles); p_count = len(policies)
# ru = len([u for u in users if (u.get("IsRisky") or u.get("UserIsRisky") or False)])
# rg = len([g for g in groups if (g.get("IsRisky") or False)])
# rr = len([r for r in roles if (r.get("IsRisky") or False)])
# rp = len([p for p in policies if (p.get("IsRisky") or False)])

# # Tabs
# tabs = st.tabs(["Graph View", "Table View", "Permission Chains"])

# # Graph View
# with tabs[0]:
#     st.markdown("### 🕸 Interactive IAM Attack Graph <span class='small-muted'>Hover the info icon for quick help</span>", unsafe_allow_html=True)
#     search = st.text_input("Search entity or permission", value=st.session_state.get("search_query",""), placeholder="ex: s3:PutObject or alice")
#     now = int(time.time() * 1000)
#     if (now - st.session_state["debounce_ts"]) > 300:
#         st.session_state["search_query"] = search
#     st.session_state["debounce_ts"] = now
#     highlight = st.session_state["search_query"]

#     graph_cache_key = f"{snap_fp}:risky={show_risky}:hl={highlight}"
#     try:
#         # FIX 3: build_graph_cached returns normalized (nx_graph, html_str, meta)
#         G, graph_html, graph_meta = build_graph_cached(graph_cache_key, show_risky, highlight)
#     except Exception as e:
#         st.error(f"Graph build error: {e}")
#         st.stop()

#     # prepare export bytes if available in meta
#     export_bytes = None
#     if isinstance(graph_meta, dict):
#         # try multiple possible keys to be robust
#         export_bytes = graph_meta.get("raw_export_bytes") or graph_meta.get("raw_graph_bytes") or None
#         # if meta contains path to raw export, try to load it
#         raw_path = graph_meta.get("raw_export_path") or graph_meta.get("raw_export_file") or graph_meta.get("raw_export")
#         if not export_bytes and raw_path and isinstance(raw_path, str) and os.path.exists(raw_path):
#             try:
#                 with open(raw_path, "rb") as fh:
#                     export_bytes = fh.read()
#             except Exception:
#                 export_bytes = None

#     if graph_html:
#         components.html(graph_html, height=900, scrolling=False)
#         if export_bytes:
#             st.download_button("Download Graph JSON", export_bytes, "iam_graph.json")

#         raw_export_path = os.path.join(tempfile.gettempdir(), "iam_xray_graph.raw.json")
#         try:
#             if os.path.exists(raw_export_path):
#                 with open(raw_export_path, "rb") as rf:
#                     raw_bytes = rf.read()
#                 st.download_button("Download Raw (uncollapsed) Graph JSON", raw_bytes, "iam_graph.raw.json")
#         except Exception:
#             pass

# # Table View
# with tabs[1]:
#     st.markdown("## 🟦 Current Active IAM Resources (Simple View)")
#     fetched_at = meta.get("fetched_at", "—")
#     fast_status = "FAST (cache)" if meta.get("fast_mode") else "LIVE (fresh)"
#     # FIX 5: region detection from new snapshot shape
#     region_used = None
#     try:
#         regions_meta = meta.get("regions") or []
#         if regions_meta and isinstance(regions_meta, list):
#             first = regions_meta[0] or {}
#             region_used = first.get("_meta", {}).get("region") or first.get("_meta", {}).get("Region") or first.get("region")
#         if not region_used:
#             region_used = meta.get("region") or "us-east-1"
#     except Exception:
#         region_used = meta.get("region") or "us-east-1"
#     if isinstance(region_used, dict):
#         region_used = region_used.get("name") or region_used.get("Region") or "us-east-1"

#     c1, c2, c3 = st.columns(3)
#     profile_used = ("Demo" if mode=="Demo" else (selected_profile or st.session_state.get("last_fetch_profile","Demo")))
#     c1.markdown(f"<div class='metric-card'><div style='color:#94a3b8'>AWS Profile</div><div style='font-weight:900;color:#38bdf8'>{profile_used}</div></div>", unsafe_allow_html=True)
#     c2.markdown(f"<div class='metric-card'><div style='color:#94a3b8'>Region</div><div style='font-weight:900;color:#34d399'>{region_used}</div></div>", unsafe_allow_html=True)
#     c3.markdown(f"<div class='metric-card'><div style='color:#94a3b8'>Fetch Mode</div><div style='font-weight:900;color:#f97316'>{fast_status}</div></div>", unsafe_allow_html=True)

#     st.markdown("<br>", unsafe_allow_html=True)
#     a,b,c,d = st.columns(4)
#     a.markdown(f"<div class='metric-card'><div>Total Users</div><b>{u_count}</b></div>", unsafe_allow_html=True)
#     b.markdown(f"<div class='metric-card'><div>Total Groups</div><b>{g_count}</b></div>", unsafe_allow_html=True)
#     c.markdown(f"<div class='metric-card'><div>Total Roles</div><b>{r_count}</b></div>", unsafe_allow_html=True)
#     d.markdown(f"<div class='metric-card'><div>Total Policies</div><b>{p_count}</b></div>", unsafe_allow_html=True)

#     st.markdown("<br><h4>🔥 Risk Summary</h4>", unsafe_allow_html=True)
#     r1,r2,r3,r4 = st.columns(4)
#     r1.markdown(f"<div class='metric-card'><div>Risky Users</div><b style='color:#ef4444'>{ru}</b></div>", unsafe_allow_html=True)
#     r2.markdown(f"<div class='metric-card'><div>Risky Groups</div><b style='color:#ef4444'>{rg}</b></div>", unsafe_allow_html=True)
#     r3.markdown(f"<div class='metric-card'><div>Risky Roles</div><b style='color:#ef4444'>{rr}</b></div>", unsafe_allow_html=True)
#     r4.markdown(f"<div class='metric-card'><div>Risky Policies</div><b style='color:#ef4444'>{rp}</b></div>", unsafe_allow_html=True)

#     st.markdown("<br>", unsafe_allow_html=True)
#     st.markdown(f"<div style='padding:10px;border-radius:8px;border:1px solid #333;background:rgba(255,255,255,0.02)'><small>Snapshot Fetched:</small> <b>{fetched_at}</b></div>", unsafe_allow_html=True)
#     st.markdown("---")

#     # Use tolerant accessors for table fields (FIX 4)
#     def _user_risk(u):
#         return int(
#         u.get("RiskScore") or 
#         u.get("UserRiskScore") or 
#         u.get("PolicyRiskScore") or 
#         u.get("risk_score") or 0
#        )
       
#     def _get_user_is_risky(u):
#         return bool(u.get("IsRisky") or u.get("UserIsRisky") or False)
#     def _attached_policy_names(att_list):
#         out = []
#         if not att_list:
#             return ""
#         for p in att_list:
#             if isinstance(p, dict):
#                 out.append(p.get("PolicyName") or p.get("PolicyArn") or p.get("Arn") or str(p))
#             else:
#                 out.append(str(p))
#         return ", ".join(out)

#     user_df = pd.DataFrame([{
#        "UserName": u.get("UserName"),
#        "Arn": u.get("Arn"),
#        "Groups": ", ".join(u.get("Groups", [])) if isinstance(u.get("Groups", []), list) else str(u.get("Groups","")),
#        "AttachedPolicies": _attached_policy_names(u.get("AttachedPolicies", [])),
#        "RiskScore": u.get("RiskScore") or u.get("UserRiskScore") or u.get("risk_score") or 0,
#        "IsRisky": bool(u.get("IsRisky") or u.get("UserIsRisky") or u.get("is_risky") or False),
#     } for u in users]) if users else pd.DataFrame()

#     if not user_df.empty:
#         user_df.fillna("", inplace=True)


#     role_df = pd.DataFrame([{
#        "RoleName": r.get("RoleName"),
#        "Arn": r.get("Arn"),
#        "AttachedPolicies": _attached_policy_names(r.get("AttachedPolicies", [])),
#        "AssumePolicyRiskScore": (
#         r.get("AssumePolicyRiskScore") or
#         r.get("TrustPolicyRiskScore") or
#         r.get("RiskScore") or 
#         r.get("risk_score") or 0
#     ),
#        "IsRisky": bool(r.get("IsRisky") or r.get("is_risky") or False),
#     } for r in roles]) if roles else pd.DataFrame()

#     if not role_df.empty:
#         role_df.fillna("", inplace=True)



#     pol_df = pd.DataFrame([{
#        "PolicyName": p.get("PolicyName"),
#        "Arn": p.get("Arn"),
#        "RiskScore": p.get("RiskScore") or p.get("score") or p.get("risk_score") or 0,
#        "IsRisky": bool(p.get("IsRisky") or p.get("is_risky") or False),
#        "Actions": ", ".join(p.get("Actions", []) or p.get("AllowedActions", []) or []),
#     } for p in policies]) if policies else pd.DataFrame()

#     if not pol_df.empty:
#         pol_df.fillna("", inplace=True)


#     # Attempt AgGrid if available
#     try:
#         from st_aggrid import AgGrid, GridOptionsBuilder, JsCode
#         if user_df.empty:
#             st.info("No Users Found.")
#         else:
#             # gb = GridOptionsBuilder.from_dataframe(user_df)
#             # gb.configure_pagination(paginationAutoPageSize=False, paginationPageSize=25)
#             # gb.configure_side_bar()
#             # gb.configure_default_column(filter=True, sortable=True, resizable=True)
#             # gb.configure_column("IsRisky", header_name="Risky", cellStyle=JsCode("params => params.value ? {'backgroundColor':'#ffe6e6','color':'#900'} : null"), width=90)
#             # gb.configure_column("RiskScore", header_name="Risk Score", width=120)
#             # AgGrid(user_df, gridOptions=gb.build(), height=320, allow_unsafe_jscode=True)

#             gb = GridOptionsBuilder.from_dataframe(user_df)
#             gb.configure_pagination(paginationAutoPageSize=False, paginationPageSize=10)
#             gb.configure_side_bar()

#             gb.configure_default_column(
#                 filter=True,
#                 sortable=True,
#                 resizable=True,
#                 wrapText=True,      # auto wrap
#                 autoHeight=True,    # row auto-height
#                 tooltipField=True   # tooltips enabled
#             )

#             # Wider useful columns
#             gb.configure_column("Arn", width=420, tooltipField="Arn")
#             gb.configure_column("AttachedPolicies", width=260, tooltipField="AttachedPolicies")
#             gb.configure_column("Groups", width=180)

#             # Risk Styling
#             gb.configure_column(
#                 "IsRisky",
#                 header_name="Risky",
#                 width=90,
#                 cellStyle=JsCode(
#                     """function(params){
#                     if(params.value){
#                     return {'backgroundColor':'#ffe6e6','color':'#900','fontWeight':'bold'};
#                     }
#                     return {};
#                 }"""
#             )
#         )

#         # Auto layout for readability
#         gb.configure_grid_options(domLayout="normal")

#         AgGrid(user_df, gridOptions=gb.build(), height=380, allow_unsafe_jscode=True)


#         st.markdown("---")

#         if role_df.empty:
#             st.info("No Roles Found.")
#         else:
#             gb = GridOptionsBuilder.from_dataframe(role_df)
#             gb.configure_default_column(filter=True, sortable=True, resizable=True)
#             gb.configure_column("IsRisky", header_name="Risky", cellStyle=JsCode("params => params.value ? {'backgroundColor':'#ffe6e6','color':'#900'} : null"), width=90)
#             AgGrid(role_df, gridOptions=gb.build(), height=260, allow_unsafe_jscode=True)

#         st.markdown("---")

#         if pol_df.empty:
#             st.info("No Policies Found.")
#         else:
#             gb = GridOptionsBuilder.from_dataframe(pol_df)
#             gb.configure_default_column(filter=True, sortable=True, resizable=True)
#             gb.configure_column("IsRisky", header_name="Risky", cellStyle=JsCode("params => params.value ? {'backgroundColor':'#ffe6e6','color':'#900'} : null"), width=90)
#             gb.configure_column("RiskScore", header_name="Risk Score", width=120)
#             AgGrid(pol_df, gridOptions=gb.build(), height=320, allow_unsafe_jscode=True)

#     except Exception:
#         if user_df.empty:
#             st.info("No Users Found.")
#         else:
#             st.dataframe(user_df)
#         st.markdown("---")
#         if role_df.empty:
#             st.info("No Roles Found.")
#         else:
#             st.dataframe(role_df)
#         st.markdown("---")
#         if pol_df.empty:
#             st.info("No Policies Found.")
#         else:
#             st.dataframe(pol_df)

# # Permission Chains Tab (enhanced)
# with tabs[2]:
#     st.markdown("### 🔗 Permission Chains <span class='small-muted'>Extracted paths from principals to actions</span>", unsafe_allow_html=True)
#     st.markdown("<div style='margin-bottom:8px;'>Shows sample chains like 'User Alice → Policy Admin → Action iam:PassRole'. <span class='info-dot' title='Chains from raw graph for full audit depth; limited to 50 for perf.'>ⓘ</span></div>", unsafe_allow_html=True)

#     graph_cache_key = f"{snap_fp}:risky={show_risky}:hl={highlight}"
#     try:
#         _, _, graph_meta = build_graph_cached(graph_cache_key, show_risky, highlight)
#     except Exception as e:
#         st.error(f"Chains extraction error: {e}")
#         graph_meta = {}

#     # FIX — Permission chains must come from graph_meta (not table meta)
#     if isinstance(graph_meta, dict):
#        chains = graph_meta.get("permission_chains") or []
#     else:
#        chains = []
      
#     who_can_full = graph_meta.get("who_can_do_full") or {}

#     if not chains:
#         st.info("No permission chains found—try a larger snapshot or run a live fetch.")
#     else:
#         # left: list of chains; right: details + highlight panel
#         left_col, right_col = st.columns([1, 2])
#         with left_col:
#             st.markdown(f"**Sample chains ({len(chains)}):**")
#             # display rendered strings with clickable selection
#             selected_chain_idx = st.radio("Select chain to inspect", options=list(range(len(chains))), format_func=lambda i: chains[i]["render"])
#             st.caption("Select a chain to view details and highlight in graph.")

#         chain = chains[selected_chain_idx]
#         with right_col:
#             st.markdown("#### Chain Details")
#             st.markdown(f"**Rendered:** `{chain.get('render')}`")
#             st.markdown(f"**Risk Score:** `{chain.get('risk_score')}`")
#             if chain.get("notes"):
#                 st.markdown("**Notes:**")
#                 for n in chain.get("notes", []):
#                     st.markdown(f"- {n}")
#             if chain.get("resources"):
#                 st.markdown("**Resources (sample):**")
#                 for r in chain.get("resources", []):
#                     st.markdown(f"- `{r}`")
#             if chain.get("actions"):
#                 st.markdown("**Actions:**")
#                 for a in chain.get("actions", []):
#                     st.markdown(f"- `{a}`")

#             # Who-can panel (for the first action in chain)
#             action_for_lookup = chain.get("actions", [None])[0]
#             st.markdown("---")
#             st.markdown("**Who can perform the action?**")
#             if action_for_lookup:
#                 principals = who_can_full.get(action_for_lookup) or who_can_full.get(action_for_lookup.strip()) or []
#                 if principals:
#                     st.markdown(f"Found **{len(principals)}** principals (sample):")
#                     for p in principals[:20]:
#                         st.markdown(f"- `{p}`")
#                 else:
#                     st.markdown("No principals found in full mapping (action may be truncated or absent in sampled actions).")
#             else:
#                 st.markdown("No action available for this chain.")

#             st.markdown("---")
#             # Highlight chain button: renders a focused pyvis for this chain
#             if st.button("Highlight chain in focused graph"):
#                 try:
#                     html = render_chain_cached_html(snap_fp, active_snapshot, chain, show_risky)
#                     if html:
#                         components.html(html, height=640, scrolling=False)
#                 except Exception as e:
#                     st.error(f"Failed to render chain subgraph: {e}")

#             # Download chain JSON
#             st.download_button("Download Chain JSON", data=json.dumps(chain, indent=2, default=str), file_name=f"{chain.get('id','chain')}.json", help="Download chain metadata")

# # Define chain renderer after UI to allow caching decorated function to be declared in top-level
# # Caching: keyed by snapshot fingerprint + chain id
# @st.cache_data(show_spinner=False)
# def _render_chain_subgraph_html_cached(snap_fp_key: str, snapshot_path: str, chain_obj: dict, show_risky_flag: bool):
#     """
#     Build a focused pyvis HTML for the chain using core.graph_builder.build_graph + render_chain_subgraph.
#     Returns HTML string.
#     """
#     try:
#         from core.graph_builder import build_graph, render_chain_subgraph
#     except Exception as e:
#         raise RuntimeError(f"Graph builder functions not available: {e}")

#     # load snapshot
#     snap = load_snapshot_cached(snapshot_path, os.path.getmtime(snapshot_path) if os.path.exists(snapshot_path) else None)
#     # build raw graph (same trimming as main builder)
#     G_raw = build_graph(snap, show_only_risky=show_risky_flag)

#     # ensure chain_obj path nodes exist in G_raw; if some nodes missing perhaps because of sampling, still render what we have
#     sub_nx = render_chain_subgraph(G_raw, chain_obj, extra_hops=1, max_nodes=120)

#     # convert this small subgraph to pyvis HTML
#     try:
#         from pyvis.network import Network as PyNet
#     except Exception as e:
#         raise RuntimeError(f"pyvis not installed: {e}")

#     net = PyNet(height="600px", width="100%", directed=True, bgcolor="#ffffff", font_color="#111827")
#     net.set_options("""
#     {
#       "physics": {"enabled": true, "solver": "forceAtlas2Based", "stabilization": {"iterations": 150}},
#       "interaction": {"hover": true, "zoomView": true, "dragView": true}
#     }
#     """)

#     # small utility for colors
#     def _node_color(t, risky=False):
#         mapping = {
#             "user": "#3B82F6", "group": "#F59E0B", "role": "#10B981",
#             "policy": "#8b5cf6", "action": "#ef4444", "meta": "#94a3b8", "principal": "#9CA3AF"
#         }
#         if risky:
#             return "#ef4444"
#         return mapping.get(t, "#64748b")

#     # highlight nodes in chain_obj
#     chain_nodes = set(chain_obj.get("subgraph_path_nodes", []))

#     for n, a in sub_nx.nodes(data=True):
#         ntype = a.get("type", "unknown")
#         risky = bool(a.get("risky", False))
#         label = a.get("label") or n
#         size = 28 + (12 if n in chain_nodes else 0) + (8 if risky else 0)
#         shape = "dot"
#         if ntype == "action":
#             shape = "diamond"
#         elif ntype == "meta":
#             shape = "box"
#         title_lines = []
#         if ntype == "policy":
#             title_lines.append(f"Policy: {label}")
#         elif ntype == "user":
#             title_lines.append(f"User: {label}")
#         elif ntype == "role":
#             title_lines.append(f"Role: {label}")
#         elif ntype == "group":
#             title_lines.append(f"Group: {label}")
#         elif ntype == "action":
#             title_lines.append(f"Action: {a.get('meta',{}).get('action', label)}")
#         title = "<br>".join(title_lines) if title_lines else label
#         net.add_node(n, label=str(label), title=title, color=_node_color(ntype, risky), size=size, shape=shape, borderWidth=3 if n in chain_nodes else 1)

#     for u, v, d in sub_nx.edges(data=True):
#         rel = d.get("relation","")
#         lbl = rel if rel else ""
#         color = "#64748b"
#         dashes = False
#         if rel == "member":
#             color = "#3b82f6"
#         elif rel == "attached":
#             color = "#8b5cf6"
#         elif rel == "assumes":
#             color = "#10b981"
#             dashes = True
#         elif rel in ("CAN", "CANNOT"):
#             color = "#10b981" if rel=="CAN" else "#ef4444"
#         net.add_edge(u, v, label=lbl, color=color, dashes=dashes, width=2.5 if (u in chain_nodes or v in chain_nodes) else 1.8)

#     # generate HTML and return
#     tmpd = tempfile.mkdtemp(prefix="iamxray_chain_")
#     p = os.path.join(tmpd, "chain.html")
#     net.write_html(p)
#     with open(p, "r", encoding="utf-8") as fh:
#         html = fh.read()
#     # small injection of style for container
#     html = html.replace("<body>", "<body style='margin:0;background:#f8fafc'>", 1)
#     return html

# # wrapper that main code calls
# def render_chain_cached_html(snap_fp_key: str, snapshot_path: str, chain_obj: dict, show_risky_flag: bool):
#     return _render_chain_subgraph_html_cached(snap_fp_key, snapshot_path, chain_obj, show_risky_flag)

# # Footer
# st.caption("IAM X-Ray — Stable Beta Build • Graph + Table synced • Non-technical friendly overview.")
# st.caption(f"IAM X-Ray — v{VERSION} • Stable Beta")




# new version 1.2
# main.py
"""
IAM X-Ray — Optimized main.py (Stable Beta) — v1.2
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

    # --- Auth Mode
    ui_label(
        "Auth Mode",
        "Choose data source: Demo uses a local sample snapshot.&#10;AWS Profile reads ~/.aws/credentials.&#10;Env Keys allows temporary key paste.",
    )
    if st.session_state.get("force_demo_mode"):
        mode = "Demo"
        st.markdown("**Auth Mode:** Demo (forced by onboarding)", unsafe_allow_html=True)
    else:
        # label printed via ui_label; provide a non-empty internal label and collapse visibility
        mode = st.selectbox(
            " ",
            ["Demo", "AWS Profile", "Env Keys"],
            key="auth_mode",
            label_visibility="collapsed",
        )

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
        ui_label("AWS Profile", "Select a profile from your ~/.aws/credentials file.&#10;Profiles map to named credential sets.")
        selected_profile = st.selectbox(
            " ",
            ["default"] + profiles,
            key="profile_select",
            label_visibility="collapsed",
        )
    elif mode == "Env Keys":
        ui_label(
            "Env Keys",
            "Paste temporary AWS credentials. These are set into environment variables for the fetch run.&#10;They are not stored persistently.",
        )
        ak = st.text_input(" ", type="password", placeholder="AWS_ACCESS_KEY_ID", key="env_ak", label_visibility="collapsed")
        sk = st.text_input(" ", type="password", placeholder="AWS_SECRET_ACCESS_KEY", key="env_sk", label_visibility="collapsed")
        tok = st.text_input(" ", type="password", placeholder="AWS_SESSION_TOKEN (optional)", key="env_tok", label_visibility="collapsed")
        region = st.text_input(" ", "us-east-1", placeholder="AWS_REGION", key="env_region", label_visibility="collapsed")
        if ak and sk:
            env = {"aws_access_key_id": ak, "aws_secret_access_key": sk, "aws_session_token": tok, "region_name": region}

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
            profile_name=(selected_profile if mode == "AWS Profile" else None),
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



# # main.py
# """
# IAM X-Ray — Stable Beta (Cytoscape Edition)
# - Uses core.graph_builder.build_iam_graph (Option A: HTML only)
# - Removes permission chain tab fully
# - Removes PyVis + chain logic
# - Perfect search → focus → reset
# - Table view stable
# - Rich HTML tooltips (pure HTML, multi-line with &#10;)
# """

# import sys
# import os
# import json
# import time
# from datetime import datetime, timezone
# import configparser

# import streamlit as st
# import streamlit.components.v1 as components
# import pandas as pd

# # ---------------------------------------------------------
# # IMPORT PATH FIX (core/)
# # ---------------------------------------------------------
# APP_DIR = os.path.dirname(os.path.abspath(__file__))
# REPO_ROOT = os.path.dirname(APP_DIR)
# sys.path.insert(0, REPO_ROOT)

# # core imports
# from core import config
# from core.cleanup import ui_purge_button, ui_reset_app_button
# from core.versions import VERSION
# from core.auth import handle_auth

# # fetch_iam import (engine → wrapper fallback)
# try:
#     from core.fetch_iam import fetch_iam_data, load_snapshot as engine_load_snapshot
# except Exception:
#     try:
#         from core.fetch_iam.wrapper import fetch_iam_data
#         from core.fetch_iam.wrapper import load_snapshot as engine_load_snapshot
#     except Exception:
#         engine_load_snapshot = None

# # ---------------------------------------------------------
# # PAGE CONFIG + tooltip CSS
# # ---------------------------------------------------------
# st.set_page_config(page_title="IAM X-Ray — Stable Beta", layout="wide", initial_sidebar_state="expanded")
# st.markdown(
#     """
#     <style>
#     .metric-card{background:rgba(40,40,80,0.75);padding:12px;border-radius:10px;text-align:center;border:1px solid #333}
#     .info-dot{font-weight:700;color:#94a3b8;margin-left:8px;cursor:help}
#     .small-muted{color:#9aa4bf;font-size:13px}
#     .tooltip-inline{font-size:13px;color:#94a3b8;margin-left:8px}
#     .search-row{display:flex;gap:8px;align-items:center}
#     </style>
#     """,
#     unsafe_allow_html=True,
# )

# DATA_DIR = getattr(config, "DATA_DIR", "data")
# SNAPSHOT_PATH = getattr(config, "SNAPSHOT_PATH", os.path.join(DATA_DIR, "iam_snapshot.json"))
# DEMO_PATH = os.path.join(DATA_DIR, "sample_snapshot.json")
# AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
# LOCK_FILE = os.path.join(DATA_DIR, "setup.lock")
# os.makedirs(DATA_DIR, exist_ok=True)

# # ---------------------------------------------------------
# # DEFAULT SESSION KEYS
# # ---------------------------------------------------------
# st.session_state.setdefault("theme", "dark")
# st.session_state.setdefault("authenticated", False)
# st.session_state.setdefault("search_query", "")
# st.session_state.setdefault("debounce_ts", 0)
# st.session_state.setdefault("last_fetch_profile", "Demo")
# st.session_state.setdefault("scroll_to_graph", False)

# # ---------------------------------------------------------
# # HELPERS
# # ---------------------------------------------------------
# def _atomic_write(path, obj):
#     tmp = path + ".tmp"
#     with open(tmp, "w", encoding="utf-8") as fh:
#         json.dump(obj, fh, indent=2, default=str)
#     os.replace(tmp, path)


# def ensure_demo_snapshot():
#     if os.path.exists(DEMO_PATH):
#         return

#     demo = {
#         "_meta": {
#             "fetched_at": datetime.now(timezone.utc).isoformat() + "Z",
#             "fast_mode": True,
#             "counts": {"users": 1, "roles": 1, "policies": 1},
#             "regions": [{"_meta": {"region": "us-east-1"}}],
#         },
#         "users": [
#             {
#                 "UserName": "demo-user",
#                 "Arn": "arn:aws:iam::123:user/demo-user",
#                 "AttachedPolicies": [{"PolicyName": "DemoPolicy"}],
#                 "Groups": [],
#             }
#         ],
#         "roles": [],
#         "groups": [],
#         "policies": [
#             {
#                 "PolicyName": "DemoPolicy",
#                 "Arn": "arn:aws:iam::123:policy/DemoPolicy",
#                 "RiskScore": 1,
#                 "Document": {
#                     "Statement": [
#                         {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::demo/*"]}
#                     ]
#                 },
#             }
#         ],
#     }
#     _atomic_write(DEMO_PATH, demo)


# ensure_demo_snapshot()

# # ---------------------------------------------------------
# # AUTH
# # ---------------------------------------------------------
# auth_ok = handle_auth(AUTH_FILE, LOCK_FILE, None)
# if not auth_ok:
#     st.stop()

# # ---------------------------------------------------------
# # SNAPSHOT LOADER
# # ---------------------------------------------------------
# @st.cache_data(show_spinner=False)
# def load_snapshot_cached(path, mtime=None):
#     if not os.path.exists(path):
#         raise FileNotFoundError(path)

#     if engine_load_snapshot:
#         snap = engine_load_snapshot(path)
#     else:
#         # fallback to minimal loader inside graph_builder
#         from core.graph_builder import load_snapshot as fallback
#         snap = fallback(path)

#     if not isinstance(snap, dict):
#         raise ValueError("Invalid snapshot")
#     return snap


# # ---------------------------------------------------------
# # GRAPH BUILDER WRAPPER (Cytoscape HTML)
# # ---------------------------------------------------------
# @st.cache_data(show_spinner=False)
# def build_graph_cached(snapshot_fingerprint, show_risky, highlight, highlight_color="#ffeb3b"):
#     """
#     Calls build_iam_graph(snapshot) which returns:
#         (None, html_string, meta_dict)
#     """
#     from core.graph_builder import build_iam_graph

#     # load snapshot
#     try:
#         snap = load_snapshot_cached(active_snapshot, os.path.getmtime(active_snapshot))
#     except Exception:
#         snap = load_snapshot_cached(DEMO_PATH, os.path.getmtime(DEMO_PATH))

#     nx_graph, html, meta = build_iam_graph(
#         snap,
#         show_only_risky=show_risky,
#         highlight_node=highlight,
#         highlight_color=highlight_color,
#         highlight_duration=1800
#     )

#     if meta is None:
#         meta = {}

#     return nx_graph, html, meta


# # ---------------------------------------------------------
# # RESOURCE FILTERING (unchanged)
# # ---------------------------------------------------------
# @st.cache_data(show_spinner=False)
# def filter_resources_cached(snapshot_fp, min_risk, show_risky, mode):
#     path = DEMO_PATH if mode == "Demo" else SNAPSHOT_PATH
#     snap = load_snapshot_cached(path, os.path.getmtime(path) if os.path.exists(path) else None)

#     users = snap.get("users", [])
#     groups = snap.get("groups", [])
#     roles = snap.get("roles", [])
#     policies = snap.get("policies", [])

#     def safe_int(x):
#         try:
#             return int(x)
#         except Exception:
#             return 0

#     def is_risky(x):
#         return bool(x.get("IsRisky") or x.get("is_risky") or False)

#     # Risk rules
#     if min_risk > 0:
#         users = [u for u in users if safe_int(u.get("RiskScore") or u.get("UserRiskScore") or 0) >= min_risk]
#         roles = [r for r in roles if safe_int(r.get("AssumePolicyRiskScore") or r.get("RiskScore") or 0) >= min_risk]
#         policies = [p for p in policies if safe_int(p.get("RiskScore") or p.get("score") or 0) >= min_risk]

#     if show_risky:
#         users = [u for u in users if is_risky(u)]
#         roles = [r for r in roles if is_risky(r)]
#         policies = [p for p in policies if is_risky(p)]

#     return {
#         "users": users,
#         "groups": groups,
#         "roles": roles,
#         "policies": policies,
#         "_meta": snap.get("_meta", {}),
#     }


# def snapshot_fingerprint(path):
#     try:
#         stt = os.path.getmtime(path)
#         sz = os.path.getsize(path)
#         return f"{path}:{int(stt)}:{sz}"
#     except Exception:
#         return path


# # ---------------------------------------------------------
# # SIDEBAR
# # ---------------------------------------------------------
# with st.sidebar:
#     st.header("Controls")

#     # tooltip builder (NO backslashes allowed inside)
#     def t(txt):
#         return f'<span class="info-dot" title="{txt}">ⓘ</span>'

#     # Auth mode tooltip
#     tooltip_auth = (
#         "Choose Demo to use built-in sample data.&#10;"
#         "AWS Profile uses credentials from ~/.aws/credentials.&#10;"
#         "Env Keys uses raw keys (less safe)."
#     )

#     mode = "Demo" if st.session_state.get("force_demo_mode") else st.selectbox("Auth Mode", ["Demo","AWS Profile","Env Keys"])
#     st.markdown(
#         f'<div class="tooltip-inline">Auth Mode <span class="info-dot" title="{tooltip_auth}">ⓘ</span></div>',
#         unsafe_allow_html=True
#     )

#     # list profiles
#     def list_profiles():
#         creds = os.path.expanduser("~/.aws/credentials")
#         if not os.path.exists(creds):
#             return []
#         cp = configparser.ConfigParser()
#         cp.read(creds)
#         return cp.sections()

#     profiles = list_profiles()
#     selected_profile = None
#     env = None

#     # AWS Profile tooltip
#     profile_tip = (
#         "Select a profile from ~/.aws/credentials.&#10;"
#         "Used to fetch LIVE IAM data."
#     )

#     if mode == "AWS Profile":
#         selected_profile = st.selectbox("AWS Profile", ["default"] + profiles)
#         st.markdown(
#             f'<div class="tooltip-inline">Profile <span class="info-dot" title="{profile_tip}">ⓘ</span></div>',
#             unsafe_allow_html=True
#         )

#     # Env keys tooltip
#     env_tip = (
#         "Paste AWS credentials directly.&#10;"
#         "Avoid on shared machines.&#10;"
#         "You may optionally provide session token and region."
#     )

#     if mode == "Env Keys":
#         st.markdown(
#             f'<div class="tooltip-inline">Env Keys <span class="info-dot" title="{env_tip}">ⓘ</span></div>',
#             unsafe_allow_html=True
#         )
#         ak = st.text_input("AWS_ACCESS_KEY_ID", type="password")
#         sk = st.text_input("AWS_SECRET_ACCESS_KEY", type="password")
#         tok = st.text_input("AWS_SESSION_TOKEN (optional)", type="password")
#         region = st.text_input("AWS_REGION", "us-east-1")
#         if ak and sk:
#             env = {
#                 "aws_access_key_id": ak,
#                 "aws_secret_access_key": sk,
#                 "aws_session_token": tok,
#                 "region_name": region,
#             }

#     st.write("---")
#     st.subheader("Fetch Options")

#     fetch_tip = (
#         "Fast uses cached snapshot when available.&#10;"
#         "Force Live fetches IAM data fresh.&#10;"
#         "Encrypt stores snapshot encrypted on disk."
#     )

#     st.markdown(
#         f'<div class="tooltip-inline">Fetch Options <span class="info-dot" title="{fetch_tip}">ⓘ</span></div>',
#         unsafe_allow_html=True
#     )

#     fast_mode = st.checkbox("Fast (use cache)", True)
#     force_fetch = st.checkbox("Force Live", False)
#     encrypt = st.checkbox("Encrypt Snapshot", False)
#     ttl_mins = st.number_input("Cache TTL (minutes)", 1, 1440, 60)
#     fetch_btn = st.button("Fetch Latest Snapshot")

#     st.write("---")
#     st.subheader("Filter")

#     filter_tip = (
#         "Show Only Risky filters only entities flagged risky.&#10;"
#         "Min Risk Score filters by numerical risk severity."
#     )

#     st.markdown(
#         f'<div class="tooltip-inline">Filter <span class="info-dot" title="{filter_tip}">ⓘ</span></div>',
#         unsafe_allow_html=True
#     )

#     show_risky = st.checkbox("Show Only Risky", False)
#     min_risk = st.slider("Min Risk Score", 0, 10, 0)

#     st.write("---")

#     maintenance_tip = (
#         "Purge snapshots removes stored IAM snapshots.&#10;"
#         "Reset clears Streamlit session state."
#     )

#     st.markdown(
#         f'<div class="tooltip-inline">Maintenance <span class="info-dot" title="{maintenance_tip}">ⓘ</span></div>',
#         unsafe_allow_html=True
#     )

#     try:
#         ui_purge_button()
#     except Exception:
#         st.button("Purge snapshots (not available)", disabled=True)

#     try:
#         ui_reset_app_button()
#     except Exception:
#         st.button("Reset app (not available)", disabled=True)


# # ---------------------------------------------------------
# # SNAPSHOT HANDLE
# # ---------------------------------------------------------
# active_snapshot = DEMO_PATH if mode == "Demo" else SNAPSHOT_PATH

# if fetch_btn:
#     box = st.empty()
#     prog = st.progress(0)
#     try:
#         box.info("Fetching IAM data…")

#         if mode == "Env Keys" and env:
#             os.environ.update({
#                 "AWS_ACCESS_KEY_ID": env["aws_access_key_id"],
#                 "AWS_SECRET_ACCESS_KEY": env["aws_secret_access_key"],
#             })
#             if env.get("aws_session_token"):
#                 os.environ["AWS_SESSION_TOKEN"] = env["aws_session_token"]
#             if env.get("region_name"):
#                 os.environ["AWS_REGION"] = env["region_name"]

#         def _cb(frac):
#             prog.progress(min(max(float(frac), 0.0), 1.0))

#         fetch_iam_data(
#             session=None,
#             profile_name=(selected_profile if mode=="AWS Profile" else None),
#             out_path=SNAPSHOT_PATH,
#             fast_mode=fast_mode,
#             force_fetch=force_fetch,
#             encrypt=encrypt,
#             multi_region=False,
#             cache_ttl=ttl_mins * 60,
#             progress_callback=_cb,
#         )

#         prog.progress(1.0)
#         box.success("Snapshot updated!")
#         st.session_state.last_fetch_profile = selected_profile or "Demo"
#         st.session_state.scroll_to_graph = True
#         box.empty()
#         st.experimental_rerun()

#     except Exception as e:
#         box.error(f"Fetch failed: {e}")
#         prog.progress(0)

# if not os.path.exists(active_snapshot):
#     st.warning("No snapshot found — run Fetch or use Demo")
#     st.stop()

# snap_fp = snapshot_fingerprint(active_snapshot)

# # ---------------------------------------------------------
# # FILTERED SNAPSHOT
# # ---------------------------------------------------------
# filtered = filter_resources_cached(snap_fp, min_risk, show_risky, mode)
# users = filtered["users"]
# groups = filtered["groups"]
# roles = filtered["roles"]
# policies = filtered["policies"]
# meta = filtered.get("_meta", {}) or {}

# u_count = len(users)
# g_count = len(groups)
# r_count = len(roles)
# p_count = len(policies)

# # ---------------------------------------------------------
# # TABS (NO Permission Chain tab)
# # ---------------------------------------------------------
# tabs = st.tabs(["Graph View","Table View"])

# # =========================================================
# # GRAPH VIEW
# # =========================================================
# with tabs[0]:
#     st.markdown("### 🕸 Interactive IAM Graph <span class='small-muted'>(Cytoscape)</span>", unsafe_allow_html=True)
#     st.markdown('<div class="small-muted">Pan & zoom with mouse. Click nodes to inspect (console logs for now).</div>', unsafe_allow_html=True)

#     # inline search label + tooltip
#     st.markdown('<div style="display:flex;align-items:center;gap:8px;margin-top:8px"><b>Search</b><span class="info-dot" title="Search by exact node id or label (ex: demo-user).&#10;For actions use s3:GetObject, iam:PassRole etc.&#10;Press Search button to focus the matching node.">ⓘ</span></div>', unsafe_allow_html=True)
#     search = st.text_input("", value=st.session_state.get("search_query",""), placeholder="ex: s3:PutObject or demo-user")

#     now = int(time.time()*1000)
#     if now - st.session_state["debounce_ts"] > 300:
#         st.session_state["search_query"] = search
#     st.session_state["debounce_ts"] = now

#     highlight = ""

#     # 1️⃣ Build graph WITHOUT highlight (for search resolution)
#     key_nohl = f"{snap_fp}:risk={show_risky}:hl="
#     try:
#         G0, html0, meta0 = build_graph_cached(key_nohl, show_risky, "")
#     except Exception as e:
#         st.error(f"Graph build error: {e}")
#         st.stop()

#     # 2️⃣ Search resolution
#     if search and search.strip():
#         q = search.strip().lower()

#         # 2a — Try who-can-do map first (action search)
#         who = (meta0 or {}).get("who_can_do_full") or {}
#         if ":" in q:
#             for act, principals in who.items():
#                 if act.lower() == q:
#                     if principals:
#                         highlight = principals[0]
#                     break

#         # 2b — Node exact match
#         if not highlight and G0 is not None:
#             for nid, attrs in G0.nodes(data=True):
#                 lab = (attrs.get("label") or "").lower()
#                 if nid.lower() == q or lab == q:
#                     highlight = nid
#                     break

#         # 2c — Prefix / substring match
#         if not highlight and G0 is not None:
#             for nid, attrs in G0.nodes(data=True):
#                 lab = (attrs.get("label") or "").lower()
#                 if nid.lower().startswith(q) or lab.startswith(q) or (":" in q and q in lab):
#                     highlight = nid
#                     break

#     # 3️⃣ Build graph WITH highlight if needed
#     if highlight:
#         key_hl = f"{snap_fp}:risk={show_risky}:hl={highlight}"
#         G, graph_html, graph_meta = build_graph_cached(key_hl, show_risky, highlight)
#     else:
#         G, graph_html, graph_meta = G0, html0, meta0

#     # 4️⃣ Render graph
#     if graph_html:
#         components.html(graph_html, height=900, scrolling=False)

# # =========================================================
# # TABLE VIEW
# # =========================================================
# with tabs[1]:
#     st.markdown("## 🟦 Current IAM Resources")
#     st.markdown('<div class="small-muted">Table lists are simplified for readability; use graph to explore relationships.</div>', unsafe_allow_html=True)

#     fetched_at = meta.get("fetched_at") or "—"
#     region_used = "us-east-1"

#     try:
#         reg_meta = meta.get("regions") or []
#         if reg_meta:
#             region_used = reg_meta[0].get("_meta", {}).get("region") or "us-east-1"
#     except:
#         pass

#     # Stats cards with tooltips
#     def metric_html(title, value, tip):
#         return f"<div class='metric-card'><div style='color:#94a3b8'>{title} <span class='info-dot' title=\"{tip}\">ⓘ</span></div><div style='font-weight:900;color:#fff'>{value}</div></div>"

#     c1,c2,c3 = st.columns(3)
#     profile_used = ("Demo" if mode=="Demo" else (selected_profile or st.session_state.get("last_fetch_profile","Demo")))
#     c1.markdown(metric_html("AWS Profile", profile_used, "Which AWS profile or mode was used for the last fetch."), unsafe_allow_html=True)
#     c2.markdown(metric_html("Region", region_used, "The AWS region used (if detected)."), unsafe_allow_html=True)
#     c3.markdown(metric_html("Fetched", fetched_at, "When the snapshot was fetched (UTC)."), unsafe_allow_html=True)

#     st.markdown("<br>", unsafe_allow_html=True)

#     # Users table
#     st.markdown("### Users <span class='small-muted'>(click graph nodes to inspect details)</span>", unsafe_allow_html=True)
#     user_rows = []
#     for u in users:
#         user_rows.append({
#             "UserName": u.get("UserName",""),
#             "Arn": u.get("Arn",""),
#             "Groups": ", ".join(u.get("Groups",[])) if isinstance(u.get("Groups",[]), list) else str(u.get("Groups","")),
#             "Policies": ", ".join(
#                 p.get("PolicyName") if isinstance(p,dict) else str(p)
#                 for p in u.get("AttachedPolicies",[])
#             ),
#             "RiskScore": u.get("RiskScore") or u.get("UserRiskScore") or 0,
#         })
#     st.dataframe(pd.DataFrame(user_rows))

#     # Roles table
#     st.markdown("### Roles")
#     role_rows = []
#     for r in roles:
#         role_rows.append({
#             "RoleName": r.get("RoleName",""),
#             "Arn": r.get("Arn",""),
#             "Policies": ", ".join(
#                 p.get("PolicyName") if isinstance(p,dict) else str(p)
#                 for p in r.get("AttachedPolicies",[])
#             ),
#             "RiskScore": r.get("AssumePolicyRiskScore") or r.get("RiskScore") or 0,
#         })
#     st.dataframe(pd.DataFrame(role_rows))

#     # Policies table
#     st.markdown("### Policies")
#     pol_rows = []
#     for p in policies:
#         pol_rows.append({
#             "PolicyName": p.get("PolicyName",""),
#             "Arn": p.get("Arn",""),
#             "RiskScore": p.get("RiskScore") or p.get("score") or 0,
#         })
#     st.dataframe(pd.DataFrame(pol_rows))

# # ---------------------------------------------------------
# # FOOTER
# # ---------------------------------------------------------
# st.caption(f"IAM X-Ray — v{VERSION} • Cytoscape Edition • Clean & Stable")
