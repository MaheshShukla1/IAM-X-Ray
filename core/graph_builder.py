import networkx as nx
from pyvis.network import Network
import tempfile
import os
import logging
import re
import json
import difflib
from datetime import datetime, timedelta

from core import secure_store   # 🔑 new import for encrypted snapshot support

NODE_COLORS = {
    "user": "#3B82F6",     # Blue
    "group": "#F59E0B",    # Orange
    "role": "#10B981",     # Green
    "policy": "#6B7280",   # Gray
    "principal": "#9CA3AF" # Light Gray
}

# ================== NEW HELPERS ==================

def load_snapshot(path):
    """
    Load IAM snapshot - supports both encrypted and plaintext.
    """
    try:
        return secure_store.read_and_decrypt(path)
    except Exception:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

RISKY_PATTERNS = [
    r"\*",
    r"iam:PassRole",
    r"sts:AssumeRole",
    r"s3:\*",
    r"kms:\*",
    r"ec2:\*",
]

def analyze_policy_document(doc):
    """
    Scan a policy document and return risky findings (actions with wildcards or sensitive services).
    """
    findings = []
    if not isinstance(doc, dict):
        return findings

    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]

    for stmt in stmts:
        actions = stmt.get("Action") or stmt.get("NotAction")
        if not actions:
            continue
        if isinstance(actions, str):
            actions = [actions]
        for act in actions:
            for pat in RISKY_PATTERNS:
                if re.fullmatch(pat.replace("*", ".*"), act, flags=re.IGNORECASE):
                    findings.append({"action": act, "pattern": pat, "effect": stmt.get("Effect", "Allow")})
    return findings


def search_permissions(G, query):
    """
    Search who can perform a given action, or what a given entity can do.
    - If query looks like 'service:Action', return entities allowed.
    - If query matches a node name, return its permissions.
    - If no exact match, suggest close matches.
    """
    results = {}
    if not query:
        return results

    query_low = query.lower()
    is_regex = query.startswith("/")
    if is_regex:
        query = query[1:]
        query_low = query_low[1:]
        try:
            regex_pat = re.compile(query, re.IGNORECASE)
        except re.error:
            return {"error": "Invalid regex pattern"}

    # Case 1: Action search (e.g., s3:PutObject)
    if ":" in query_low:
        matches = []
        for n, attrs in G.nodes(data=True):
            if attrs.get("type") == "policy":
                doc = (attrs.get("meta") or {}).get("Document")
                if doc:
                    findings = analyze_policy_document(doc)
                    for f in findings:
                        act_low = f["action"].lower()
                        if (not is_regex and query_low == act_low) or (is_regex and regex_pat.search(act_low)):
                            matches.append(n)
        # Deep traversal: Find who has access via attached policies
        who_can_do = set()
        for m in matches:
            who_can_do.update(G.predecessors(m))
        results["action_search"] = {query: matches}
        results["who_can_do"] = list(who_can_do)
        return results

    # Case 2: Entity search
    target_node = None
    for node in G.nodes:
        if node.lower() == query_low:
            target_node = node
            break

    if target_node and target_node in G.nodes:
        attrs = G.nodes[target_node]
        node_type = attrs.get("type")
        if node_type == "policy":
            doc = (attrs.get("meta") or {}).get("Document")
            if doc:
                findings = analyze_policy_document(doc)
                results["entity_policies"] = findings if findings else [{"message": "✅ No risky actions"}]
        else:
            # For user/group/role/principal: find attached/outgoing policies and their findings
            attached_policies = [succ for succ in G.successors(target_node) if G.nodes[succ].get("type") == "policy"]
            entity_findings = {}
            for pname in attached_policies:
                doc = (G.nodes[pname].get("meta") or {}).get("Document")
                if doc:
                    findings = analyze_policy_document(doc)
                    entity_findings[pname] = findings if findings else [{"message": "✅ No risky actions"}]
            results["entity"] = dict(attrs)
            results["entity_attached_findings"] = entity_findings
    else:
        # No exact node → suggest fuzzy matches
        close_matches = difflib.get_close_matches(query, list(G.nodes), n=3, cutoff=0.8)
        if close_matches:
            results["fuzzy_matches"] = close_matches

    return results

# ================== EXISTING HELPERS (untouched) ==================

def _node_label(name, kind, risky=False, score=0):
    prefix = {
        "user": "👤 ",
        "group": "👥 ",
        "role": "🎭 ",
        "policy": "📜 ",
        "principal": "🔑 "
    }.get(kind, "")
    label = f"{prefix}{name}"
    if risky:
        label = f"🔥 {label}"
    if score and score > 0:
        label = f"{label} ({score})"
    return label

def _risk_color(score):
    if score is None:
        score = 0
    score = max(0, min(score, 10))
    r = int((score / 10) * 255)
    g = int(((10 - score) / 10) * 200)
    b = 60
    return f"rgb({r},{g},{b})"

def compute_keep_set_from_diff(snapshot):
    """Return set of entity names that are added/modified (for all entity types)."""
    d = (snapshot or {}).get("_meta", {}).get("diff", {}) or {}
    keep = set()
    for ent, key_name in [("users", "UserName"), ("groups", "GroupName"),
                          ("roles", "RoleName"), ("policies", "PolicyName")]:
        ent_diff = d.get(ent, {}) or {}
        for n in (ent_diff.get("added", []) or []) + (ent_diff.get("modified", []) or []):
            if n:
                keep.add(n)
    return keep

def build_adjacency(G):
    """Return {node: {incoming: [...], outgoing: [...]}}."""
    adj = {}
    for n in G.nodes:
        incoming = sorted([x for x in G.predecessors(n)]) if hasattr(G, "predecessors") else []
        outgoing = sorted([x for x in G.successors(n)]) if hasattr(G, "successors") else []
        adj[n] = {"incoming": incoming, "outgoing": outgoing}
    return adj

def export_graph_json(G, path="graph.json"):
    """Export NetworkX graph to JSON file."""
    data = {
        "nodes": [{"id": n, **attrs} for n, attrs in G.nodes(data=True)],
        "edges": [{"source": u, "target": v, **attrs} for u, v, attrs in G.edges(data=True)],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path


def build_graph(snapshot, show_only_risky=False):
    """
    Pure graph builder (no HTML). Returns a NetworkX.DiGraph.
    Mirrors build_iam_graph's node/edge logic.
    """
    G = nx.DiGraph()

    # Users
    for u in snapshot.get("users", []):
        name = u.get("UserName")
        if name:
            risky = bool(u.get("IsRisky"))
            G.add_node(name, type="user", risky=risky, meta=u)

    # Groups
    for g in snapshot.get("groups", []):
        gname = g.get("GroupName")
        if not gname:
            continue
        risky = bool(g.get("IsRisky"))
        G.add_node(gname, type="group", risky=risky, meta=g)

        for ap in g.get("AttachedPolicies", []) or []:
            pname = ap.get("PolicyName")
            if pname:
                if not G.has_node(pname):
                    G.add_node(pname, type="policy", risky=False, meta={})
                G.add_edge(gname, pname, relation="attached")

    # Roles
    for r in snapshot.get("roles", []):
        rname = r.get("RoleName")
        if not rname:
            continue
        role_risk = bool(r.get("AssumePolicyRisk"))
        role_score = r.get("AssumePolicyRiskScore") or 0
        G.add_node(rname, type="role", risky=role_risk, meta=r, risk_score=role_score)

        for ap in r.get("AttachedPolicies", []) or []:
            pname = ap.get("PolicyName")
            if pname:
                if not G.has_node(pname):
                    G.add_node(pname, type="policy", risky=False, meta={})
                G.add_edge(rname, pname, relation="attached")

        for pr in r.get("PrincipalsInfo") or []:
            short = pr["value"].split("/")[-1] if isinstance(pr.get("value"), str) and "/" in pr.get("value") else pr.get("value")
            node_name = f"PRINC:{short}"
            if not G.has_node(node_name):
                G.add_node(
                    node_name, type="principal", risky=False,
                    meta={"principal": pr.get("value"), "principal_type": pr.get("type")}
                )
            G.add_edge(node_name, rname, relation="assumes")

    # Policies
    for p in snapshot.get("policies", []):
        pname = p.get("PolicyName")
        if pname:
            is_risky = bool(p.get("IsRisky"))
            score = p.get("RiskScore") or 0
            G.add_node(pname, type="policy", risky=is_risky, meta=p, risk_score=score)

    # User → group/policy edges
    for u in snapshot.get("users", []):
        uname = u.get("UserName")
        for gname in u.get("Groups", []) or []:
            if G.has_node(gname):
                G.add_edge(uname, gname, relation="member")
        for ap in u.get("AttachedPolicies", []) or []:
            pname = ap.get("PolicyName")
            if pname:
                if not G.has_node(pname):
                    G.add_node(pname, type="policy", risky=False, meta={})
                G.add_edge(uname, pname, relation="attached")

    # Risky-only filter
    if show_only_risky:
        risky_nodes = {n for n, a in G.nodes(data=True) if a.get("risky")}
        neighbors = set()
        for rn in risky_nodes:
            neighbors.update(G.predecessors(rn))
            neighbors.update(G.successors(rn))
        keep = risky_nodes.union(neighbors)
        return G.subgraph(keep).copy()

    return G

# ---------- UI graph builder (PyVis HTML) ----------
def build_iam_graph(snapshot, show_only_risky=False, highlight_node=None,
                    highlight_color="#ffeb3b", highlight_duration=2200):
    """
    Build IAM graph.
    Returns: (G, html_str, clicked_node)
    """
    # build pure graph first
    G_full = build_graph(snapshot, show_only_risky=show_only_risky)
    G = G_full  # alias expected by callers

    # === PyVis Graph ===
    net = Network(height="760px", width="100%", notebook=False, directed=True)
    net.set_options("""
    {
      "physics": {"enabled": true, "solver": "repulsion",
        "repulsion": {"centralGravity": 0.2, "springLength": 180, "springConstant": 0.02},
        "stabilization": {"iterations": 1500, "updateInterval": 25}
      },
      "interaction": {"hover": true, "navigationButtons": true}
    }
    """)

    impact_score = snapshot.get("_meta", {}).get("diff", {}).get("impact_score")

    # nodes
    for node, attrs in G.nodes(data=True):
        ntype = attrs.get("type", "node")
        risky = attrs.get("risky", False)
        meta = attrs.get("meta", {})
        score = attrs.get("risk_score") or (meta.get("RiskScore") if isinstance(meta, dict) else 0) or 0

        change_flag = meta.get("_changed")
        change_details = ""
        if change_flag == "added":
            change_details = "➕ Added"
        elif change_flag == "modified":
            change_details = "🔄 Modified"

        # ---- tooltips with Findings count / TrustFindings count ----
        if ntype == "policy":
            findings = meta.get("Findings") or []
            findings_count = len(findings)
            unused_count = len([f for f in findings if f.get("code") == "UNUSED_ACTION"])
            tlines = [
                f"Policy: {meta.get('PolicyName')}",
                f"Arn: {meta.get('Arn')}",
                f"IsRisky: {meta.get('IsRisky')}",
                f"RiskScore: {meta.get('RiskScore')}",
                f"Findings: {findings_count}",
                f"Unused Actions: {unused_count}",
                change_details
            ] if findings else [
                f"Policy: {meta.get('PolicyName')}",
                f"Arn: {meta.get('Arn')}",
                f"IsRisky: {meta.get('IsRisky')}",
                f"RiskScore: {meta.get('RiskScore')}",
                f"Findings: 0 ✅ No risky actions",
                change_details
            ]
            # Add usage hints to tooltips
            slu = meta.get("ServiceLastUsed", {})
            services = slu.get("services", [])
            unused = [s.get("serviceNamespace") for s in services if s.get("lastAuthenticated") and (datetime.utcnow() - datetime.fromisoformat(s.get("lastAuthenticated").replace("Z", "+00:00"))).days > 90]
            if unused:
                tlines.append("Unused services: " + ", ".join(unused))
        elif ntype == "role":
            trust_find_count = len(meta.get("AssumePolicyFindings") or [])
            tlines = [
                f"Role: {meta.get('RoleName')}",
                f"Arn: {meta.get('Arn')}",
                f"AssumeRisk: {meta.get('AssumePolicyRisk')}",
                f"AssumeScore: {meta.get('AssumePolicyRiskScore')}",
                f"TrustFindings: {trust_find_count}",
                change_details
            ]
            # Add usage hints to tooltips
            slu = meta.get("ServiceLastUsed", {})
            services = slu.get("services", [])
            unused = [s.get("serviceNamespace") for s in services if s.get("lastAuthenticated") and (datetime.utcnow() - datetime.fromisoformat(s.get("lastAuthenticated").replace("Z", "+00:00"))).days > 90]
            if unused:
                tlines.append("Unused services: " + ", ".join(unused))
        elif ntype == "principal":
            tlines = [
                f"Principal: {meta.get('principal')}",
                f"Type: {meta.get('principal_type')}",
                change_details
            ]
        else:
            # user/group default
            tlines = [str(meta), change_details]
            # Add usage hints for user/group if available
            slu = meta.get("ServiceLastUsed", {})
            services = slu.get("services", [])
            unused = [s.get("serviceNamespace") for s in services if s.get("lastAuthenticated") and (datetime.utcnow() - datetime.fromisoformat(s.get("lastAuthenticated").replace("Z", "+00:00"))).days > 90]
            if unused:
                tlines.append("Unused services: " + ", ".join(unused))

        color = _risk_color(score) if score > 0 else NODE_COLORS.get(ntype, "#CCCCCC")
        if risky and not score:
            color = "#FF6B6B"

        size = 18 + (score * 2) if score else 18
        if node == highlight_node:
            size = max(size, 36)

        net.add_node(
            node,
            label=_node_label(node, ntype, risky, score),
            title="<br>".join([str(x) for x in tlines if x]),
            color=color,
            size=size
        )

    # edges (with severity color/thickness for enterprise feel)
    for u, v, ed in G.edges(data=True):
        rel = ed.get("relation", "")
        # Edge severity: color red if source or target risky, thickness based on scores
        u_attrs = G.nodes[u]
        v_attrs = G.nodes[v]
        u_risky = u_attrs.get("risky", False)
        v_risky = v_attrs.get("risky", False)
        u_score = u_attrs.get("risk_score", 0) or 0
        v_score = v_attrs.get("risk_score", 0) or 0
        edge_color = "#FF6B6B" if u_risky or v_risky else "#CCCCCC"
        # Gray if target policy has unused actions
        if v_attrs.get("type") == "policy":
            findings = v_attrs.get("meta", {}).get("Findings") or []
            unused_count = len([f for f in findings if f.get("code") == "UNUSED_ACTION"])
            if unused_count > 0:
                edge_color = "#CCCCCC"
        edge_width = 1 + int((u_score + v_score) / 5)  # Scale thickness (max ~5)
        if rel == "assumes":
            edge_width += 1  # Slightly thicker for assumes
        net.add_edge(u, v, title=rel, width=edge_width, color=edge_color)

    tmpdir = tempfile.mkdtemp(prefix="iamxray_")
    html_path = os.path.join(tmpdir, "iam_graph.html")
    net.write_html(html_path)

    with open(html_path, "r", encoding="utf-8") as f:
        html_str = f.read()

    # === Legend with toggle (color matched to NODE_COLORS) ===
    legend_html = f"""
<div id="iam_legend" style="position:fixed;top:10px;left:10px;background:#111;color:#fff;padding:8px;border-radius:8px;z-index:9999;font-size:13px;max-width:170px;">
  <div style="font-weight:700;margin-bottom:6px;">Legend</div>
  <div style="margin-bottom:3px;"><span style="display:inline-block;width:12px;height:12px;background:{NODE_COLORS['user']};border-radius:50%;margin-right:6px;"></span>👤 User</div>
  <div style="margin-bottom:3px;"><span style="display:inline-block;width:12px;height:12px;background:{NODE_COLORS['group']};border-radius:50%;margin-right:6px;"></span>👥 Group</div>
  <div style="margin-bottom:3px;"><span style="display:inline-block;width:12px;height:12px;background:{NODE_COLORS['role']};border-radius:50%;margin-right:6px;"></span>🎭 Role</div>
  <div style="margin-bottom:3px;"><span style="display:inline-block;width:12px;height:12px;background:{NODE_COLORS['policy']};border-radius:50%;margin-right:6px;"></span>📜 Policy</div>
  <div style="margin-bottom:3px;"><span style="display:inline-block;width:12px;height:12px;background:{NODE_COLORS['principal']};border-radius:50%;margin-right:6px;"></span>🔑 Principal</div>
  <div style="margin-top:6px;font-size:12px;color:#ddd;">
    <span style="display:inline-block;width:12px;height:12px;background:#FF6B6B;border-radius:50%;margin-right:6px;"></span>🔥 = risky
  </div>
  <button onclick="toggleLegend()" style="margin-top:5px;padding:2px 6px;font-size:11px;">Toggle</button>
</div>
<script>
function toggleLegend(){{
    var lg = document.getElementById('iam_legend');
    if(lg.style.display === 'none'){{ lg.style.display='block'; }}
    else {{ lg.style.display='none'; }}
}}
</script>
"""

    impact_overlay = ""
    if impact_score is not None:
        color = "#10B981" if impact_score <= 2 else ("#F59E0B" if impact_score <= 6 else "#EF4444")
        impact_overlay = f"<div id='iam_impact' style='position:fixed;top:10px;right:10px;background:{color};color:#fff;padding:6px 10px;border-radius:6px;z-index:9999;font-weight:700;'>Impact: {impact_score}</div>"

    # ---- Highlight JS with configurable color/duration ----
    # Use str.format with escaped braces to avoid f-string brace issues
    highlight_js = """
<script type="text/javascript">
function _getNodeColor(id) {{
    try {{
        const n = network.body.data.nodes.get(id);
        if(!n) return null;
        if(typeof n.color === 'string') return n.color;
        if(n.color && n.color.background) return n.color.background;
        return null;
    }} catch(e) {{ return null; }}
}}
function _updateNodeColors(updates) {{
    try {{ network.body.data.nodes.update(updates); }} catch(e) {{}}
}}
function highlightPath(nodeId) {{
    if(!nodeId) return;
    const connected = network.getConnectedNodes(nodeId) || [];
    const toHighlight = [nodeId].concat(connected);
    const original = {{}};
    toHighlight.forEach(id => {{ original[id] = _getNodeColor(id) || null; }});
    const upd = toHighlight.map(id => ({{id: id, color: {{background: '{COLOR}'}}}}));
    _updateNodeColors(upd);
    const connectedEdges = network.getConnectedEdges(nodeId) || [];
    const edgeUpdates = connectedEdges.map(eid => {{
        try {{
            const ed = network.body.data.edges.get(eid);
            if(ed) {{ return {{id: eid, width: (ed.width||1) + 3}}; }}
        }} catch(e){{}}
        return null;
    }}).filter(x=>x);
    try {{ network.body.data.edges.update(edgeUpdates); }} catch(e) {{}}
    setTimeout(()=> {{
        const restoreNodes = Object.keys(original).map(id => {{
            const orig = original[id];
            if(orig) return {{id: id, color: {{background: orig}}}};
            return {{id: id}};
        }});
        try {{ network.body.data.nodes.update(restoreNodes); }} catch(e){{}}
        try {{ network.redraw(); }} catch(e){{}}
    }}, {DURATION});
}}
network.on("click", function(params) {{
    if (params.nodes.length > 0) {{
        const clickedNode = params.nodes[0];
        try {{ highlightPath(clickedNode); }} catch(e) {{}}
        window.parent.postMessage({{type: "iam_node_click", node: clickedNode}}, "*");
        try {{ localStorage.setItem("iam_last_node", clickedNode); }} catch(e){{}}
    }}
}});
try {{
    const lastNode = localStorage.getItem("iam_last_node");
    if (lastNode) {{
        setTimeout(() => {{ try {{ highlightPath(lastNode); }} catch(e){{}} }}, 800);
    }}
}} catch(e){{}}
</script>
""".format(COLOR=highlight_color, DURATION=int(highlight_duration))

    # inject overlays + highlight script
    html_str = html_str.replace("<body>", "<body>" + legend_html + impact_overlay)
    html_str = re.sub(r"(</body>)", highlight_js + r"\\1", html_str, flags=re.IGNORECASE)

    clicked_node = None
    return G, html_str, clicked_node



# ================== EXTRA HELPERS ==================
def export_graph_json(G, path="graph.json"):
    """Export NetworkX graph to JSON file."""
    data = {
        "nodes": [{"id": n, **attrs} for n, attrs in G.nodes(data=True)],
        "edges": [{"source": u, "target": v, **attrs} for u, v, attrs in G.edges(data=True)],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path

def compute_keep_set_from_diff(snapshot):
    """
    Extract set of entities (names) that are added/modified in diff.
    """
    d = snapshot.get("_meta", {}).get("diff", {}) or {}
    keep = set()
    for ent, key_name in [("users", "UserName"), ("groups", "GroupName"), ("roles", "RoleName"), ("policies", "PolicyName")]:
        ent_diff = d.get(ent, {})
        for n in ent_diff.get("added", []) + ent_diff.get("modified", []):
            if n:
                keep.add(n)
    return keep

def build_adjacency(G, node):
    """
    Return predecessors and successors of a node.
    """
    preds = sorted([n for n in G.predecessors(node)]) if hasattr(G, "predecessors") else []
    succs = sorted([n for n in G.successors(node)]) if hasattr(G, "successors") else []
    return preds, succs