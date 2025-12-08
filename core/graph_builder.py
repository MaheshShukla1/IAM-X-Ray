# core/graph_builder.py
"""
Safe, trimmed IAM graph builder for IAM X-Ray v0.1.0-beta.

- Filters AWS-managed policies & service-linked roles early to avoid explosion.
- Caps default graph size via MAX_NODES and preserves changed/risky nodes from snapshot diff.
- Lightweight policy analysis for risk-highlighting.
- Maintains compatibility with previous API:
    build_graph(snapshot, show_only_risky=False) -> networkx.DiGraph
    build_iam_graph(snapshot, ...) -> (G, html_str, clicked_node, export_bytes)
    search_permissions(G, query) -> dict
"""
import os
import re
import json
import tempfile
import logging
import random # for potential sampling
from datetime import datetime, timedelta
import networkx as nx
from pyvis.network import Network
# Try to import secure_store (some versions provide decrypt_and_read)
from core import secure_store
logger = logging.getLogger("graph_builder")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)
# Colors used in UI
NODE_COLORS = {
    "user": "#3B82F6",
    "group": "#F59E0B",
    "role": "#10B981",
    "policy": "#6B7280",
    "principal": "#9CA3AF",
}
# Safety limits for beta
MAX_NODES = 200 # target cap for interactive graph
CLUSTER_THRESHOLD = 600 # not used aggressively in beta
MAX_ADDITIONAL_NODES = 500 # increased to handle more nodes without failure
# AWS-managed/service-linked detection
AWS_MANAGED_PREFIX = "arn:aws:iam::aws:policy/"
AWS_SERVICE_ROLE_PATTERNS = [r"AWSServiceRoleFor", r"^aws-service-role/"]
AWS_DEFAULT_ROLE_NAMES = ["OrganizationAccountAccessRole"]
# Risk patterns for light analyzer
RISKY_PATTERNS = [
    r"\*",
    r"iam:PassRole",
    r"sts:AssumeRole",
]
# ================= REAL WORLD DANGEROUS IAM ACTIONS (2025 EDITION) =================
DANGEROUS_ACTIONS = {
    # Privilege Escalation Goldmine
    "iam:CreatePolicy": "Creates a new IAM policy, potentially granting broad permissions.",
    "iam:CreatePolicyVersion": "Overwrites policy versions, allowing modification of existing permissions.",
    "iam:SetDefaultPolicyVersion": "Activates a specific policy version, possibly reverting to risky settings.",
    "iam:AttachUserPolicy": "Attaches policy to user, granting new permissions.",
    "iam:AttachGroupPolicy": "Attaches policy to group, affecting multiple users.",
    "iam:AttachRolePolicy": "Attaches policy to role, enabling service access.",
    "iam:PutUserPolicy": "Adds inline policy to user, customizing permissions.",
    "iam:PutGroupPolicy": "Adds inline policy to group, customizing group permissions.",
    "iam:PutRolePolicy": "Adds inline policy to role, customizing role permissions.",
    "iam:UpdateAssumeRolePolicy": "Modifies role trust policy, changing who can assume the role.",
    "iam:PassRole": "Passes role to services, potentially escalating privileges.",
    "sts:AssumeRole": "Assumes another role, switching identities with its permissions.",
    "iam:CreateAccessKey": "Creates long-term access keys, risking credential exposure.",
    "iam:CreateLoginProfile": "Sets console password, enabling console access.",
    # Full Control
    "ec2:RunInstances": "Launches new EC2 instances, potentially with attached roles.",
    "lambda:CreateFunction": "Creates new Lambda functions, executing code.",
    "lambda:InvokeFunction": "Triggers Lambda execution, running code.",
    "lambda:UpdateFunctionCode": "Updates Lambda code, modifying behavior.",
    # Data Exfil
    "s3:GetObject": "Downloads objects from S3, accessing data.",
    "s3:ListBucket": "Lists S3 bucket contents, discovering objects.",
    "secretsmanager:GetSecretValue": "Retrieves secrets, exposing sensitive data.",
    "ssm:GetParameter": "Retrieves SSM parameters, accessing configs.",
    # Wildcards
    "*": "Grants full access, equivalent to Administrator.",
    "s3:*": "Full S3 access, including delete and put.",
    "ec2:*": "Full EC2 control, including terminate.",
    # Add more common
    "ec2:TerminateInstances": "Permanently deletes EC2 instances.",
    "s3:DeleteObject": "Deletes S3 objects, causing data loss.",
    "iam:*": "Full IAM control, high escalation risk.",
}
# HIGH-RISK actions as set for fast lookup (lowercase)
HIGH_RISK_ACTIONS = set(act.lower() for act in [
    "iam:createpolicy", "iam:createpolicyversion", "iam:setdefaultpolicyversion",
    "iam:attachuserpolicy", "iam:attachgrouppolicy", "iam:attachrolepolicy",
    "iam:putuserpolicy", "iam:putgrouppolicy", "iam:putrolepolicy",
    "iam:updateassumerolepolicy", "iam:passrole", "sts:assumerole",
    "iam:createaccesskey", "iam:createloginprofile",
    # Add destructive
    "ec2:terminateinstances", "s3:deletebucket", "rds:deletedbinstance",
])
# MEDIUM-RISK patterns
MEDIUM_RISK_PATTERNS = [
    r"\*$", # ends with *
    r":\*$", # service:*
    r"^\*$", # *
]
# LOW-RISK examples (for classification)
LOW_RISK_ACTIONS = set(act.lower() for act in [
    "ec2:describeinstances", "s3:listbucket", "iam:listpolicies",
    "logs:describelogstreams", "cloudtrail:describetrails",
])
def load_snapshot(path):
    """
    Load IAM snapshot - supports encrypted (.enc) and plaintext (.json).
    Tries secure_store.decrypt_and_read or secure_store.read_and_decrypt if present.
    """
    if not path or not os.path.exists(path):
        raise FileNotFoundError(f"Snapshot not found: {path}")
    # prefer secure_store.decrypt_and_read
    try:
        if hasattr(secure_store, "decrypt_and_read"):
            return secure_store.decrypt_and_read(path)
        if hasattr(secure_store, "read_and_decrypt"):
            return secure_store.read_and_decrypt(path)
    except Exception as e:
        logger.debug(f"secure_store decrypt/read failed: {e}. Trying plaintext fallback.")
    # plaintext fallback
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
# ------------------- Lightweight policy analyzer ---------------------
def _ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]
def _lightweight_policy_findings(doc):
    """
    Minimal, fast checks:
      - action/resource wildcard
      - iam:PassRole, sts:AssumeRole
    Returns list of finding dicts.
    """
    findings = []
    if not isinstance(doc, dict):
        return findings
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for idx, stmt in enumerate(stmts):
        effect = stmt.get("Effect", "Allow").lower()
        actions = _ensure_list(stmt.get("Action") or stmt.get("NotAction"))
        resources = _ensure_list(stmt.get("Resource"))
        for a in actions:
            if not isinstance(a, str):
                continue
            al = a.lower()
            if al == "*" or "*" in al:
                findings.append({"code": "ACTION_WILDCARD", "message": f"Action wildcard: {a}", "effect": effect})
            if al in ("iam:passrole", "sts:assumerole"):
                findings.append({"code": "SENSITIVE_ACTION", "message": f"Sensitive action: {a}", "effect": effect})
        for r in resources:
            if isinstance(r, str) and r.strip() == "*":
                findings.append({"code": "RESOURCE_WILDCARD", "message": "Resource '*' used", "effect": effect})
    return findings
# ------------------- Helpers to detect AWS-managed/service roles ---------------------
def _is_aws_managed_policy(p):
    arn = (p or {}).get("Arn") or ""
    name = (p or {}).get("PolicyName") or ""
    if isinstance(arn, str) and arn.startswith(AWS_MANAGED_PREFIX):
        return True
    # also catch obvious patterns
    if isinstance(name, str) and (name.startswith("AWS") or "Amazon" in name):
        # conservative: only skip if clearly AWS-managed naming
        if "Managed" in name or "AWS" in name:
            return True
    return False
def _is_service_linked_role(r):
    name = (r or {}).get("RoleName") or ""
    if not name:
        return False
    for pat in AWS_SERVICE_ROLE_PATTERNS:
        if re.search(pat, name, flags=re.IGNORECASE):
            return True
    if name in AWS_DEFAULT_ROLE_NAMES:
        return True
    return False
# ------------------- Diff-based keep set ---------------------
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
# ------------------- Build adjacency helper ---------------------
def build_adjacency(G):
    """Return {node: {incoming: [...], outgoing: [...]}} for a networkx graph."""
    adj = {}
    for n in G.nodes:
        incoming = sorted([x for x in G.predecessors(n)]) if hasattr(G, "predecessors") else []
        outgoing = sorted([x for x in G.successors(n)]) if hasattr(G, "successors") else []
        adj[n] = {"incoming": incoming, "outgoing": outgoing}
    return adj
def export_graph_json(G, path="graph.json"):
    """Export a compact nodes/edges JSON for download/debug."""
    data = {
        "nodes": [{"id": n, **dict(G.nodes[n])} for n in G.nodes()],
        "edges": [{"source": u, "target": v, **(dict(e) if isinstance(e, dict) else {})} for u, v, e in G.edges(data=True)]
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path
# ------------------- Build trimmed graph (core fix) ---------------------
def build_graph(snapshot, show_only_risky=False):
    """
    Build a networkx DiGraph from snapshot with safety trimming:
      - Filter out AWS-managed policies and service-linked roles early.
      - Cap node count to MAX_NODES preserving changed/risky nodes if possible.
    Returns: nx.DiGraph
    """
    if not snapshot or not any(k in snapshot for k in ("users", "groups", "roles", "policies")):
        logger.warning("Invalid or empty snapshot data")
        return nx.DiGraph()
    # -- Pre-filter lists to remove heavy AWS-managed/service items --
    users = snapshot.get("users", []) or []
    groups = snapshot.get("groups", []) or []
    roles = snapshot.get("roles", []) or []
    policies = snapshot.get("policies", []) or []
    filtered_policies = []
    for p in policies:
        try:
            if _is_aws_managed_policy(p):
                continue
        except Exception:
            # if detection fails, keep policy to be safe
            filtered_policies.append(p)
            continue
        filtered_policies.append(p)
    filtered_roles = []
    for r in roles:
        try:
            if _is_service_linked_role(r):
                continue
        except Exception:
            filtered_roles.append(r)
            continue
        filtered_roles.append(r)
    # Quick counts
    total_entities = len(users) + len(groups) + len(filtered_roles) + len(filtered_policies)
    logger.info(f"Entities after AWS-managed/service-role filtering: users={len(users)}, groups={len(groups)}, roles={len(filtered_roles)}, policies={len(filtered_policies)} (total={total_entities})")
    # Decide keep set based on diff (prefer changed/risky)
    keep_set = compute_keep_set_from_diff(snapshot)
    # Build an ordered list of nodes (prefer keep_set and risky ones)
    # We'll create a set of node ids to include (strings: user names, group names, role names, policy names)
    node_candidates = []
    def add_candidate(name, t, score=0, risky=False):
        node_candidates.append({"id": name, "type": t, "score": score, "risky": risky})
    for p in filtered_policies:
        pname = p.get("PolicyName") or p.get("Arn")
        if not pname:
            continue
        is_risky = bool(p.get("IsRisky")) or bool(_lightweight_policy_findings(p.get("Document") or {}))
        add_candidate(pname, "policy", score=p.get("RiskScore") or 0, risky=is_risky)
    for r in filtered_roles:
        rname = r.get("RoleName") or r.get("Arn")
        if not rname:
            continue
        role_risk = bool(r.get("AssumePolicyRisk")) or bool(r.get("AssumePolicyFindings"))
        add_candidate(rname, "role", score=r.get("AssumePolicyRiskScore") or 0, risky=role_risk)
    for g in groups:
        gname = g.get("GroupName")
        if gname:
            add_candidate(gname, "group", risky=bool(g.get("IsRisky")))
    for u in users:
        uname = u.get("UserName")
        if uname:
            add_candidate(uname, "user", risky=bool(u.get("IsRisky")))
    # Sort candidates: keep ones from keep_set and risky first, then by score desc
    def candidate_sort_key(c):
        return (
            0 if c["id"] in keep_set else 1,
            0 if c["risky"] else 1,
            -int(c.get("score") or 0)
        )
    node_candidates_sorted = sorted(node_candidates, key=candidate_sort_key)
    # Trim to MAX_NODES
    chosen = node_candidates_sorted[:MAX_NODES]
    chosen_ids = {c["id"] for c in chosen}
    logger.info(f"Selected {len(chosen)} nodes (MAX_NODES={MAX_NODES}) for graph")
    # Build graph only from chosen nodes
    G = nx.DiGraph()
    # Add nodes (with meta) for chosen set
    # Helper to add node if in chosen_ids
    def add_node_if_chosen(id_name, kind, meta=None, risk_score=0, risky=False):
        if id_name in chosen_ids and not G.has_node(id_name):
            attrs = {"type": kind, "meta": meta or {}, "risk_score": risk_score, "risky": bool(risky)}
            G.add_node(id_name, **attrs)
    # Add policy nodes
    policy_map = { (p.get("PolicyName") or p.get("Arn")): p for p in filtered_policies if (p.get("PolicyName") or p.get("Arn")) }
    for pname, p in policy_map.items():
        is_risky = bool(p.get("IsRisky")) or bool(_lightweight_policy_findings(p.get("Document") or {}))
        add_node_if_chosen(pname, "policy", meta=p, risk_score=p.get("RiskScore") or 0, risky=is_risky)
    # Add role nodes and attachments
    role_map = { (r.get("RoleName") or r.get("Arn")): r for r in filtered_roles if (r.get("RoleName") or r.get("Arn")) }
    for rname, r in role_map.items():
        add_node_if_chosen(rname, "role", meta=r, risk_score=r.get("AssumePolicyRiskScore") or 0, risky=bool(r.get("AssumePolicyRisk")))
        for ap in (r.get("AttachedPolicies") or []):
            pname = ap.get("PolicyName")
            if pname:
                add_node_if_chosen(pname, "policy")
                if G.has_node(pname) and G.has_node(rname):
                    G.add_edge(rname, pname, relation="attached")
        for pr in (r.get("PrincipalsInfo") or []):
            short = (pr.get("value") or "").split("/")[-1]
            node_name = f"PRINC:{short}"
            add_node_if_chosen(node_name, "principal", meta=pr)
            if G.has_node(node_name) and G.has_node(rname):
                G.add_edge(node_name, rname, relation="assumes")
    # Add groups and their attached policies
    group_map = { g.get("GroupName"): g for g in groups if g.get("GroupName") }
    for gname, g in group_map.items():
        add_node_if_chosen(gname, "group", meta=g, risky=bool(g.get("IsRisky")))
        for ap in (g.get("AttachedPolicies") or []):
            pname = ap.get("PolicyName")
            if pname:
                add_node_if_chosen(pname, "policy")
                if G.has_node(gname) and G.has_node(pname):
                    G.add_edge(gname, pname, relation="attached")
    # Add users, membership and attached policies
    user_map = { u.get("UserName"): u for u in users if u.get("UserName") }
    for uname, u in user_map.items():
        add_node_if_chosen(uname, "user", meta=u, risky=bool(u.get("IsRisky")))
        for gname in (u.get("Groups") or []):
            if G.has_node(uname) and G.has_node(gname):
                G.add_edge(uname, gname, relation="member")
        for ap in (u.get("AttachedPolicies") or []):
            pname = ap.get("PolicyName")
            if pname:
                add_node_if_chosen(pname, "policy")
                if G.has_node(uname) and G.has_node(pname):
                    G.add_edge(uname, pname, relation="attached")
    # If show_only_risky option set, filter G down
    if show_only_risky:
        risky_nodes = [n for n, a in G.nodes(data=True) if a.get("risky")]
        H = G.subgraph(risky_nodes).copy()
        return H
    return G
# ------------------- Search (keeps compatibility with previous API) ---------------------
import difflib
def search_permissions(G, query):
    """
    Search who can perform a given action (lightweight), or return attached findings for an entity.
    Works with networkx DiGraph created by build_graph.
    """
    results = {}
    if not query:
        return results
    q_low = query.lower()
    is_regex = q_low.startswith("/")
    regex_pat = None
    if is_regex:
        try:
            regex_pat = re.compile(query[1:], re.IGNORECASE)
        except re.error:
            return {"error": "Invalid regex"}
    # If it looks like an action (contains ':') scan policy nodes
    if ":" in q_low:
        matches = []
        for n, attrs in G.nodes(data=True):
            if attrs.get("type") == "policy":
                doc = (attrs.get("meta") or {}).get("Document") or {}
                findings = _lightweight_policy_findings(doc)
                for f in findings:
                    msg = f.get("message", "").lower()
                    if (not is_regex and q_low in msg) or (is_regex and regex_pat.search(msg)):
                        matches.append(n)
                        break
        who_can_do = set()
        for m in matches:
            # predecessors are entities that reference the policy
            if hasattr(G, "predecessors"):
                try:
                    who_can_do.update(list(G.predecessors(m)))
                except Exception:
                    pass
        results["action_search"] = {query: matches}
        results["who_can_do"] = list(who_can_do)
        return results
    # Entity search
    # exact match
    target = None
    for n in G.nodes:
        if n.lower() == q_low:
            target = n
            break
    if target:
        attrs = G.nodes[target]
        if attrs.get("type") == "policy":
            doc = (attrs.get("meta") or {}).get("Document") or {}
            findings = _lightweight_policy_findings(doc)
            results["entity_policies"] = findings if findings else [{"message": "✅ No risky actions"}]
        else:
            attached = [s for s in G.successors(target) if G.nodes[s].get("type") == "policy"]
            entity_findings = {}
            for p in attached:
                doc = (G.nodes[p].get("meta") or {}).get("Document") or {}
                entity_findings[p] = _lightweight_policy_findings(doc) or [{"message": "✅ No risky actions"}]
            results["entity"] = dict(attrs)
            results["entity_attached_findings"] = entity_findings
        return results
    # fuzzy matches
    close = difflib.get_close_matches(query, list(G.nodes), n=3, cutoff=0.7)
    if close:
        results["fuzzy_matches"] = close
    return results
def build_iam_graph(snapshot, show_only_risky=False, highlight_node=None, highlight_color="#ffeb3b", highlight_duration=2200):
    """
    IAM X-Ray v1.0 — Beta
    """
    G = build_graph(snapshot, show_only_risky=show_only_risky)
    if len(G.nodes) == 0:
        empty_html = "<div style='text-align:center;padding:100px;font-size:24px;color:#666;'>No entities match current filters</div>"
        return nx.DiGraph(), empty_html, None, b"{}", {"reason": "no_matching_nodes"}
    net = Network(
        height="100vh",
        width="100%",
        directed=True,
        bgcolor="#ffffff",
        font_color="#1e293b"
    )
    net.set_options("""
    {
      "physics": {
        "enabled": true,
        "solver": "forceAtlas2Based",
        "forceAtlas2Based": {
          "gravitationalConstant": -80,
          "centralGravity": 0.01,
          "springLength": 220,
          "springConstant": 0.04,
          "damping": 0.9
        },
        "stabilization": {"iterations": 300}
      },
      "interaction": {
        "hover": true,
        "zoomView": true,
        "dragView": true,
        "navigationButtons": false
      },
      "edges": {
        "smooth": {"type": "cubicBezier", "roundness": 0.5},
        "arrows": {"to": {"enabled": true, "scaleFactor": 0.8}},
        "font": {"size": 12, "color": "#64748b"},
        "color": "#94a3b8",
        "width": 2
      }
    }
    """)
    # Node colors
    def get_node_color(ntype, risky=False):
        if risky: return "#dc2626"
        return {
            "user": "#3b82f6",
            "group": "#f59e0b",
            "role": "#10b981",
            "policy": "#8b5cf6",
            "principal": "#94a3b8"
        }.get(ntype, "#64748b")
    # Add main entities with AWS ICONS
    for node, attrs in G.nodes(data=True):
        ntype = attrs.get("type", "unknown")
        title = node
        risky = attrs.get("risky", False)
        if ntype == "policy":
            title = f"Policy: {node}<br>Risk Score: {attrs.get('risk_score', 0)}<br>Attached to: {', '.join(G.predecessors(node)) or 'None'}"
        elif ntype == "role":
            title = f"Role: {node}<br>Can be assumed by: {', '.join(G.predecessors(node)) or 'None'}<br>Policies: {', '.join(G.successors(node)) or 'None'}"
        elif ntype == "group":
            title = f"Group: {node}<br>Members: {', '.join(G.predecessors(node)) or 'None'}<br>Policies: {', '.join(G.successors(node)) or 'None'}"
        elif ntype == "user":
            title = f"User: {node}<br>Groups: {', '.join(G.successors(node)) or 'None'}<br>Policies: {', '.join([s for s in G.successors(node) if G.nodes[s]['type'] == 'policy']) or 'None'}"
        # AWS Console Style Icons
        icon = ""
        if ntype == "user":
            icon = "" # fa-user
        elif ntype == "group":
            icon = "" # fa-users
        elif ntype == "role":
            icon = "" # fa-user-shield
        elif ntype == "policy":
            icon = "" # fa-file-contract
        elif ntype == "principal":
            icon = "" # fa-cloud
        title_html = f"<b>{node}</b><br><small>{title}</small>"
        if risky:
            title_html = f"Warning: {title_html}"
        size = 50 if risky else 45
        if highlight_node and highlight_node.lower() in node.lower():
            size += 20
        net.add_node(
            node,
            label=f"{icon} {node}",
            title=title_html,
            color=get_node_color(ntype, risky),
            size=size,
            font={"size": 18, "face": "Amazon Ember, Arial", "color": "#1e293b"},
            shape="dot",
            borderWidth=4 if risky else 2,
            shadow=True
        )
    # Add edges
    for u, v, data in G.edges(data=True):
        rel = data.get("relation", "")
        label = ""
        color = "#64748b"
        dashes = False
        if rel == "member":
            label = "member of"
            color = "#3b82f6"
        elif rel == "attached":
            label = "has policy"
            color = "#8b5cf6"
        elif rel == "assumes":
            label = "can assume"
            color = "#10b981"
            dashes = True
        net.add_edge(u, v, label=label, color=color, dashes=dashes, width=2.5)
    # MAIN MAGIC: Professional Action Nodes
    action_counter = 0
    additional_nodes_count = 0
    for policy_node, attrs in G.nodes(data=True):
        if attrs.get("type") != "policy":
            continue
        doc = (attrs.get("meta") or {}).get("Document") or {}
        stmts = doc.get("Statement", [])
        if not isinstance(stmts, list):
            stmts = [stmts]
        for stmt in stmts:
        
            effect = stmt.get("Effect", "Allow")
            is_deny = effect == "Deny"
            actions = _ensure_list(stmt.get("Action") or stmt.get("NotAction"))
            resources = _ensure_list(stmt.get("Resource") or ["*"])
            # To reduce node count, if many actions, sample high-risk ones first
            high_risk_actions = [a for a in actions if a.lower() in HIGH_RISK_ACTIONS]
            other_actions = [a for a in actions if a not in high_risk_actions]
            sampled_actions = high_risk_actions + random.sample(other_actions, min(3, len(other_actions))) if len(other_actions) > 3 else other_actions
            for action in sampled_actions:
                if additional_nodes_count > MAX_ADDITIONAL_NODES:
                    logger.warning("Reached max additional nodes; skipping further actions")
                    break
                if not action:
                    continue
                action_original = action.strip()
                action_clean = action_original
                if action_clean == "*":
                    action_clean = "* (All Actions)"
                # Risk Detection using original action
                al = action_original.lower()
                risk_level = "low"
                risk_reason = ""
                outcome = DANGEROUS_ACTIONS.get(action_original, "Standard operation - no specific risk identified.")
                if al in HIGH_RISK_ACTIONS:
                    risk_level = "high"
                    risk_reason = "Privilege Escalation / Persistence Risk / Destructive"
                elif any(re.search(pat, al, re.IGNORECASE) for pat in MEDIUM_RISK_PATTERNS):
                    risk_level = "medium"
                    risk_reason = "Data read/write or broad access"
                elif al in LOW_RISK_ACTIONS:
                    risk_level = "low"
                    risk_reason = "Listing / describe / metadata"
                else:
                    # Default to low if not matched
                    risk_level = "low"
                    risk_reason = "Listing / describe / metadata"
                if is_deny:
                    risk_level = "deny"
                    risk_reason = "Explicit Deny"
                    outcome = "Action Denied: " + outcome
                # Skip low priority to reduce clutter and potential large graph issues
                if risk_level == "low":
                    continue
                # Smart Label
                if action_clean == "* (All Actions)":
                    short_label = "ALL ACTIONS"
                elif ":" in action_clean:
                    short_label = action_clean.split(":", 1)[1]
                    if short_label == "*":
                        short_label = action_clean.split(":")[0].upper() + ":*"
                else:
                    short_label = action_clean
                if len(short_label) > 20:
                    short_label = short_label[:17] + "..."
                # AWS-Style Colors
                if risk_level == "high":
                    node_color, border_color = "#dc2626", "#7f1d1d"
                    size, edge_width, edge_color = 38, 5, "#dc2626"
                elif risk_level == "medium":
                    node_color, border_color = "#f97316", "#c2410c"
                    size, edge_width, edge_color = 34, 4, "#f97316"
                elif risk_level == "deny":
                    node_color, border_color = "#ef4444", "#b91c1c"
                    size, edge_width, edge_color = 30, 3, "#ef4444"
                else:
                    node_color, border_color = "#6366f1", "#4338ca"
                    size, edge_width, edge_color = 28, 2, "#4f46e5"
                # Title with outcome
                title_text = f"<b style='font-size:16px'>{action_clean}</b><br>Priority: {risk_level.upper()}<br>Reason: {risk_reason}<br>Outcome: {outcome}"
                if "*" in ''.join(resources):
                    title_text += "<br>Resource: * (All Resources)"
                action_node = f"ACTION_{action_counter}_{action_clean.replace(':', '_').replace('*', 'STAR').replace(' ', '_')[:50]}"
                action_counter += 1
                additional_nodes_count += 1
                net.add_node(
                    action_node,
                    label=short_label,
                    title=title_text,
                    color={"background": node_color, "border": border_color},
                    shape="box",
                    size=size,
                    font={"size": 14, "color": "white", "face": "Amazon Ember, Arial", "strokeWidth": 3, "strokeColor": "#000"},
                    borderWidth=3,
                    shadow=True
                )
                edge_label = "denies" if is_deny else "allows"
                net.add_edge(policy_node, action_node, label=edge_label, color=edge_color, width=edge_width, dashes=(risk_level in ["high", "deny"]))
                for predecessor in G.predecessors(policy_node):
                    if G.nodes[predecessor].get("type") in ["user", "role", "group"]:
                        can_label = "CANNOT" if is_deny else "CAN"
                        net.add_edge(
                            predecessor, action_node,
                            label=can_label,
                            color=edge_color if risk_level != "low" else "#10b981",
                            width=edge_width if risk_level != "low" else 2,
                            font={"size": 14, "color": edge_color if risk_level != "low" else "#166534", "strokeWidth": 2},
                            dashes=(is_deny)
                        )
                # Add service node if applicable
                if ":" in action_original:
                    service = action_original.split(":")[0].upper()
                    service_node = f"SVC_{service}"
                    # Explicit check
                    if not any(n['id'] == service_node for n in net.nodes):
                        additional_nodes_count += 1
                        net.add_node(
                            service_node,
                            label=service,
                            title=f"AWS Service: {service}<br>Accessed via: {action_clean}",
                            color="#a5b4fc",
                            shape="diamond",
                            size=32,
                            font={"size": 16, "color": "#312e81"}
                        )
                    net.add_edge(action_node, service_node, label="in", color="#6366f1", width=2)
                # Add resource nodes (limit to 3 per action to prevent explosion)
                res_list = resources[:3]
                if len(resources) > 3:
                    res_list.append("and more...")
                for res in res_list:
                    if additional_nodes_count > MAX_ADDITIONAL_NODES:
                        break
                    if res == "and more...":
                        res_clean = "MULTIPLE RESOURCES"
                        res_title = "Multiple resources (truncated)"
                    else:
                        res_clean = res if res != "*" else "ALL RESOURCES (*)"
                        res_title = f"Resource: {res_clean}<br>Outcome if action performed: {outcome}"
                    res_node = f"RES_{action_counter}_{res_clean.replace(':', '_').replace('/', '_').replace('*', 'STAR')[:50]}"
                    action_counter += 1
                    additional_nodes_count += 1
                    # Explicit check
                    if not any(n['id'] == res_node for n in net.nodes):
                        net.add_node(
                            res_node,
                            label=res_clean.split('/')[-1] if '/' in res_clean else res_clean[:20] + '...' if len(res_clean) > 20 else res_clean,
                            title=res_title,
                            color="#6ee7b7" if not is_deny else "#fecaca",
                            shape="ellipse",
                            size=25,
                            font={"size": 12, "color": "#064e3b" if not is_deny else "#7f1d1d"}
                        )
                    res_edge_label = "on" if not is_deny else "denied on"
                    net.add_edge(action_node, res_node, label=res_edge_label, color="#34d399" if not is_deny else "#ef4444", width=2, dashes=is_deny)
    # Professional Legend + Font Awesome with full integrity
    legend_html = """
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" integrity="sha512-Avb2QiuDEEvB4bZJYdft2mNjVShBftLdPG8fj0V7irTLQ8Uo0qcPxh4Plq7G5tGm0rU+1SPhVotteLpBERwTkw==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <div style="position:fixed;top:15px;left:15px;background:#ffffff;padding:20px 25px;border-radius:12px;border:1px solid #e2e8f0;box-shadow:0 10px 30px rgba(0,0,0,0.1);z-index:9999;font-family:Amazon Ember,Arial,sans-serif">
      <h3 style="margin:0 0 12px;color:#0f172a;font-weight:bold">IAM X-Ray v1.0.0-beta</h3>
  
      <div style="font-size:14px;line-height:1.8;color:#475569">
        <div><span style="color:#dc2626;font-weight:bold">High Risk</span> — Escalation / Persistence / Destructive</div>
        <div><span style="color:#f97316;font-weight:bold">Medium Risk</span> — Data Read/Write / Broad Access</div>
        <div><span style="color:#6366f1;font-weight:bold">Low Risk</span> — List / Describe / Metadata</div>
        <div><span style="color:#ef4444;font-weight:bold">Deny</span> — Explicit Deny</div>
        <div><span style="color:#3b82f6">Blue</span> User • <span style="color:#f59e0b">Orange</span> Group</div>
        <div><span style="color:#10b981">Green</span> Role • <span style="color:#8b5cf6">Purple</span> Policy</div>
        <div><span style="color:#a5b4fc">Indigo</span> Service • <span style="color:#6ee7b7">Green</span> Resource</div>
      </div>
    </div>
    """
    tmpdir = tempfile.mkdtemp(prefix="iamxray_")
    html_path = os.path.join(tmpdir, "graph.html")
    try:
        net.write_html(html_path)
        with open(html_path, "r", encoding="utf-8") as f:
            html_str = f.read()
        # Inject legend & font awesome
        html_str = html_str.replace("<head>", "<head><meta charset='utf-8'>")
        html_str = html_str.replace("<body>", f"<body style='margin:0;background:#f8fafc'>{legend_html}")
    except Exception as e:
        logger.error(f"Failed to write or modify HTML: {e}")
        html_str = "<div style='text-align:center;padding:100px;font-size:24px;color:#666;'>Graph rendering failed - please try again or check logs</div>"
    export_path = os.path.join(tempfile.gettempdir(), "iam_xray_graph.json")
    export_graph_json(G, export_path)
    with open(export_path, "rb") as f:
        export_bytes = f.read()
    return G, html_str, None, export_bytes, None

