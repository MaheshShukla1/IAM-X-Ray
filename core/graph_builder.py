# core/graph_builder.py
"""
IAM X-Ray — Cytoscape-based Graph Builder (BloodHound-style layout)

Replaces PyVis with Cytoscape.js HTML output. Deterministic tiered layout
(Users → Groups → Roles → Policies → Actions → Services → Principals/Meta).
Keeps API compatibility: returns (G_final, html_str, None, export_bytes, meta)
"""

from __future__ import annotations
import os
import re
import json
import tempfile
import logging
import random
from datetime import datetime, timezone
from collections import deque
from typing import List, Dict, Tuple, Any, Optional, Set

import networkx as nx

# Try to import secure_store (may be optional)
try:
    from core import secure_store
except Exception:
    secure_store = None

logger = logging.getLogger("graph_builder")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

# -----------------------
# Constants & thresholds
# -----------------------
NODE_COLORS = {
    "user": "#3b82f6",       # blue
    "group": "#f59e0b",      # amber
    "role": "#10b981",       # green
    "policy": "#8b5cf6",     # violet
    "action": "#ef4444",     # red
    "service": "#0ea5e9",    # cyan
    "principal": "#6b7280",  # neutral grey
    "meta": "#64748b",
    "resource": "#0ea5e9",  # cyan
}


# Safety limits
MAX_NODES = 300
CLUSTER_THRESHOLD = 600
MAX_ADDITIONAL_NODES = 800
MAX_ACTIONS_GLOBAL = 800

# Collapse thresholds
USER_COLLAPSE_THRESHOLD = 40
GROUP_COLLAPSE_THRESHOLD = 25
ROLE_COLLAPSE_THRESHOLD = 40
POLICY_COLLAPSE_THRESHOLD = 50

# Chain extraction limits
MAX_CHAINS = 80
MAX_PRINCIPALS_SAMPLE = 120
MAX_ACTIONS_SAMPLE = 40

# AWS-managed/service-linked detection
AWS_MANAGED_PREFIX = "arn:aws:iam::aws:policy/"
AWS_SERVICE_ROLE_PATTERNS = [r"AWSServiceRoleFor", r"^aws-service-role/"]
AWS_DEFAULT_ROLE_NAMES = ["OrganizationAccountAccessRole"]

# Risk / dangerous actions (abbreviated)
DANGEROUS_ACTIONS = {
    "iam:CreatePolicy": "Creates a new IAM policy, potentially granting broad permissions.",
    "iam:PassRole": "Passes role to services, potentially escalating privileges.",
    "sts:AssumeRole": "Assumes another role, switching identities with its permissions.",
    "*": "Grants full access, equivalent to Administrator.",
}

HIGH_RISK_ACTIONS = set(act.lower() for act in [
    "iam:createpolicy", "iam:passrole", "sts:assumerole", "iam:createaccesskey",
])

MEDIUM_RISK_PATTERNS = [r"\*$", r":\*$", r"^\*$"]
LOW_RISK_ACTIONS = set(act.lower() for act in [
    "ec2:describeinstances", "s3:listbucket", "iam:listpolicies",
])

SERVICE_DISPLAY = {
    "s3": "S3 Actions",
    "iam": "IAM Actions",
    "ec2": "EC2 Actions",
    "lambda": "Lambda Actions",
    "secretsmanager": "SecretsManager Actions",
    "ssm": "SSM Actions",
    "sts": "STS Actions",
    "kms": "KMS Actions",
    "dynamodb": "DynamoDB Actions",
    "rds": "RDS Actions",
}

# -----------------------
# Utilities
# -----------------------
def _ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]

def _is_aws_managed_policy(p):
    arn = (p or {}).get("Arn") or ""
    name = (p or {}).get("PolicyName") or ""
    if isinstance(arn, str) and arn.startswith(AWS_MANAGED_PREFIX):
        return True
    if isinstance(name, str) and (name.startswith("AWS") or "Amazon" in name):
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

def compute_keep_set_from_diff(snapshot):
    keep = set()
    if not snapshot or not isinstance(snapshot, dict):
        return keep
    top_diff = (snapshot or {}).get("_meta", {}).get("diff", {}) or {}
    def _collect_from_diff(d):
        for ent, _ in [("users", "UserName"), ("groups", "GroupName"),
                       ("roles", "RoleName"), ("policies", "PolicyName")]:
            ent_diff = d.get(ent, {}) or {}
            for n in (ent_diff.get("added", []) or []) + (ent_diff.get("modified", []) or []):
                if n:
                    keep.add(n)
    if top_diff and any(k in top_diff for k in ("users", "groups", "roles", "policies")):
        _collect_from_diff(top_diff)
    regions = (snapshot or {}).get("_meta", {}).get("regions", []) or []
    for r in regions:
        rd = (r or {}).get("_meta", {}).get("diff", {}) or {}
        if rd:
            _collect_from_diff(rd)
    return keep

def build_adjacency(G):
    adj = {}
    for n in G.nodes:
        incoming = sorted([x for x in G.predecessors(n)]) if hasattr(G, "predecessors") else []
        outgoing = sorted([x for x in G.successors(n)]) if hasattr(G, "successors") else []
        adj[n] = {"incoming": incoming, "outgoing": outgoing}
    return adj

def export_graph_json(G, path="graph.json"):
    data = {
        "nodes": [{"id": n, **{k:v for k,v in dict(G.nodes[n]).items() if k != 'meta' or isinstance(v, (str,int,float,bool))}} for n in G.nodes()],
        "edges": [{"source": u, "target": v, **(dict(e) if isinstance(e, dict) else {})} for u, v, e in G.edges(data=True)]
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    except TypeError:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    return path

# -----------------------
# Snapshot loader
# -----------------------
def load_snapshot(path):
    if not path:
        raise FileNotFoundError("Snapshot path empty")
    candidates = []
    if os.path.exists(path):
        candidates.append(path)
    if os.path.exists(path + ".enc"):
        candidates.append(path + ".enc")
    if not candidates:
        raise FileNotFoundError(f"Snapshot not found: {path}")
    last_err = None
    for p in candidates:
        try:
            if secure_store and hasattr(secure_store, "decrypt_and_read"):
                return secure_store.decrypt_and_read(p)
            if secure_store and hasattr(secure_store, "read_and_decrypt"):
                return secure_store.read_and_decrypt(p)
        except Exception as e:
            last_err = e
            logger.debug(f"secure_store decrypt/read failed for {p}: {e}. Trying plaintext fallback.")
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            last_err = e
            logger.debug(f"plaintext read failed for {p}: {e}")
    raise FileNotFoundError(f"Failed to load snapshot: {last_err}")

# -----------------------
# Policy analyzer
# -----------------------
def _lightweight_policy_findings(doc):
    findings = []
    if not isinstance(doc, dict):
        return findings
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for stmt in stmts:
        try:
            effect = (stmt.get("Effect") or "Allow").lower()
        except Exception:
            effect = "allow"
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

# -----------------------
# Build raw graph (base)
# -----------------------
def build_graph(snapshot, show_only_risky=False):
    if not snapshot or not any(k in snapshot for k in ("users", "groups", "roles", "policies")):
        logger.warning("Invalid or empty snapshot data")
        return nx.DiGraph()

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

    keep_set = compute_keep_set_from_diff(snapshot)

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

    def candidate_sort_key(c):
        return (
            0 if c["id"] in keep_set else 1,
            0 if c["risky"] else 1,
            -int(c.get("score") or 0)
        )

    node_candidates_sorted = sorted(node_candidates, key=candidate_sort_key)
    chosen = node_candidates_sorted[:MAX_NODES]
    chosen_ids = {c["id"] for c in chosen}
    logger.info(f"Selected {len(chosen)} nodes (MAX_NODES={MAX_NODES}) for graph")

    G = nx.DiGraph()

    def add_node_if_chosen(id_name, kind, meta=None, risk_score=0, risky=False):
        if id_name in chosen_ids and not G.has_node(id_name):
            attrs = {"type": kind, "meta": meta or {}, "risk_score": risk_score, "risky": bool(risky)}
            attrs["label"] = id_name
            G.add_node(id_name, **attrs)

    policy_map = { (p.get("PolicyName") or p.get("Arn")): p for p in filtered_policies if (p.get("PolicyName") or p.get("Arn")) }
    for pname, p in policy_map.items():
        is_risky = bool(p.get("IsRisky")) or bool(_lightweight_policy_findings(p.get("Document") or {}))
        add_node_if_chosen(pname, "policy", meta=p, risk_score=p.get("RiskScore") or 0, risky=is_risky)

    role_map = { (r.get("RoleName") or r.get("Arn")): r for r in filtered_roles if (r.get("RoleName") or r.get("Arn")) }
    for rname, r in role_map.items():
        add_node_if_chosen(rname, "role", meta=r, risk_score=r.get("AssumePolicyRiskScore") or 0, risky=bool(r.get("IsRisky") or r.get("AssumePolicyRisk")))
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

    group_map = { g.get("GroupName"): g for g in groups if g.get("GroupName") }
    for gname, g in group_map.items():
        add_node_if_chosen(gname, "group", meta=g, risky=bool(g.get("IsRisky")))
        for ap in (g.get("AttachedPolicies") or []):
            pname = ap.get("PolicyName")
            if pname:
                add_node_if_chosen(pname, "policy")
                if G.has_node(gname) and G.has_node(pname):
                    G.add_edge(gname, pname, relation="attached")

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

    if show_only_risky:
        risky_nodes = [n for n, a in G.nodes(data=True) if a.get("risky")]
        return G.subgraph(risky_nodes).copy()

    return G

# -----------------------
# COLLAPSE LAYER (non-destructive)
# -----------------------
def collapse_graph(G):
    if G is None or len(G.nodes) == 0:
        return G
    H = G.copy()
    users = [n for n, a in H.nodes(data=True) if a.get("type") == "user"]
    groups = [n for n, a in H.nodes(data=True) if a.get("type") == "group"]
    roles = [n for n, a in H.nodes(data=True) if a.get("type") == "role"]
    policies = [n for n, a in H.nodes(data=True) if a.get("type") == "policy"]

    def add_meta(name, display_label, original_nodes):
        if not H.has_node(name):
            H.add_node(name, type="meta", meta={"label": display_label, "members": list(original_nodes)}, count=len(original_nodes), risky=any(H.nodes[n].get("risky") for n in original_nodes), label=display_label)
    if len(users) >= USER_COLLAPSE_THRESHOLD:
        add_meta("USERS", f"Users ({len(users)})", users)
        for u in users:
            for succ in list(H.successors(u)):
                if H.has_node(succ):
                    rel_data = H.get_edge_data(u, succ) or {}
                    H.add_edge("USERS", succ, **rel_data)
            for pred in list(H.predecessors(u)):
                rel_data = H.get_edge_data(pred, u) or {}
                H.add_edge(pred, "USERS", **rel_data)
        H.remove_nodes_from(users)
    if len(groups) >= GROUP_COLLAPSE_THRESHOLD:
        add_meta("GROUPS", f"Groups ({len(groups)})", groups)
        for g in groups:
            for succ in list(H.successors(g)):
                rel_data = H.get_edge_data(g, succ) or {}
                H.add_edge("GROUPS", succ, **rel_data)
            for pred in list(H.predecessors(g)):
                rel_data = H.get_edge_data(pred, g) or {}
                H.add_edge(pred, "GROUPS", **rel_data)
        H.remove_nodes_from(groups)
    if len(roles) >= ROLE_COLLAPSE_THRESHOLD:
        add_meta("ROLES", f"Roles ({len(roles)})", roles)
        for r in roles:
            for succ in list(H.successors(r)):
                rel_data = H.get_edge_data(r, succ) or {}
                H.add_edge("ROLES", succ, **rel_data)
            for pred in list(H.predecessors(r)):
                rel_data = H.get_edge_data(pred, r) or {}
                H.add_edge(pred, "ROLES", **rel_data)
        H.remove_nodes_from(roles)
    if len(policies) >= POLICY_COLLAPSE_THRESHOLD:
        add_meta("POLICIES", f"Policies ({len(policies)})", policies)
        for p in policies:
            for pred in list(H.predecessors(p)):
                rel_data = H.get_edge_data(pred, p) or {}
                H.add_edge(pred, "POLICIES", **rel_data)
            for succ in list(H.successors(p)):
                rel_data = H.get_edge_data(p, succ) or {}
                H.add_edge("POLICIES", succ, **rel_data)
        H.remove_nodes_from(policies)
    return H

# -----------------------
# Focus / apply_focus
# -----------------------
def apply_focus(G, focus):
    if not focus or focus not in G.nodes:
        return G
    keep = set([focus])
    for p in G.predecessors(focus):
        keep.add(p)
    for c in G.successors(focus):
        keep.add(c)
    for node in list(keep):
        for p in G.predecessors(node):
            keep.add(p)
        for s in G.successors(node):
            keep.add(s)
    for n, a in G.nodes(data=True):
        if a.get("type") == "meta":
            keep.add(n)
    return G.subgraph(keep).copy()

# -----------------------
# Search
# -----------------------
import difflib
def search_permissions(G, query):
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
            try:
                who_can_do.update(list(G.predecessors(m)))
            except Exception:
                pass
        results["action_search"] = {query: matches}
        results["who_can_do"] = list(who_can_do)
        return results
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
    close = difflib.get_close_matches(query, list(G.nodes), n=3, cutoff=0.7)
    if close:
        results["fuzzy_matches"] = close
    return results

# -----------------------
# Permission chain helpers (unchanged)
# -----------------------
def render_readable_chain(path: List[str], G: nx.DiGraph) -> str:
    parts = []
    for node_id in path:
        if node_id not in G:
            parts.append(f"{node_id} (Unknown)")
            continue
        data = G.nodes[node_id]
        node_type = data.get("type", "unknown")
        label = data.get("label", node_id.split(":")[-1] if ":" in node_id else node_id)
        type_map = {
            "user": "User",
            "group": "Group",
            "role": "Role",
            "policy": "Policy",
            "action": "Action",
            "principal": "Principal",
            "meta": "Meta Group",
            "service": "Service"
        }
        prefix = type_map.get(node_type, "Entity")
        if data.get("risky", False):
            prefix += " (Risky)"
        parts.append(f"{label} ({prefix})")
    return " → ".join(parts)

def build_permission_chains(G_raw: nx.DiGraph, max_chains: int = MAX_CHAINS) -> List[str]:
    if len(G_raw.nodes) == 0:
        return []
    chains = []
    principals = [(n, d) for n, d in G_raw.nodes(data=True) if d.get("type") in ["user", "group", "role", "principal"]]
    principals = sorted(principals, key=lambda x: (0 if x[1].get("risky") else 1))[:MAX_PRINCIPALS_SAMPLE]
    actions = [(n, d) for n, d in G_raw.nodes(data=True) if d.get("type") == "action"]
    actions = sorted(actions, key=lambda x: (0 if x[1].get("risky") else 1))[:MAX_ACTIONS_SAMPLE]
    for pnode, _ in principals:
        for anode, _ in actions:
            if nx.has_path(G_raw, pnode, anode):
                try:
                    path = nx.shortest_path(G_raw, pnode, anode)
                    if len(path) <= 7:
                        chains.append(render_readable_chain(path, G_raw))
                        if len(chains) >= max_chains:
                            break
                except Exception:
                    continue
        if len(chains) >= max_chains:
            break
    random.shuffle(chains)
    return chains[:max_chains]

def compute_who_can_do_full(G_raw: nx.DiGraph) -> Dict[str, List[str]]:
    who = {}
    action_nodes = [n for n, d in G_raw.nodes(data=True) if d.get("type") == "action"]
    if not action_nodes:
        return {}
    capped_actions = action_nodes[:MAX_ACTIONS_GLOBAL] if len(action_nodes) > MAX_ACTIONS_GLOBAL else action_nodes
    for act_node in capped_actions:
        found = set()
        q = deque([act_node])
        visited = {act_node}
        while q:
            cur = q.popleft()
            for pred in G_raw.predecessors(cur):
                if pred in visited:
                    continue
                visited.add(pred)
                dtype = G_raw.nodes[pred].get("type")
                if dtype in ("user", "group", "role", "principal", "meta"):
                    found.add(pred)
                q.append(pred)
        action_str = G_raw.nodes[act_node].get("meta", {}).get("action") or str(act_node)
        who[action_str] = sorted(found)
    return who

def extract_permission_chain_objects(G_raw: nx.DiGraph, who_map: Dict[str, List[str]], max_chains: int = MAX_CHAINS) -> List[Dict]:
    chains = []
    principals = [(n, d) for n, d in G_raw.nodes(data=True) if d.get("type") in ("user", "group", "role", "principal")]
    principals = sorted(principals, key=lambda x: (0 if x[1].get("risky") else 1))[:MAX_PRINCIPALS_SAMPLE]
    actions = [(n, d) for n, d in G_raw.nodes(data=True) if d.get("type") == "action"]
    actions = sorted(actions, key=lambda x: (0 if x[1].get("risky") else 1))[:MAX_ACTIONS_SAMPLE]
    count = 0
    for pnode, pdata in principals:
        for anode, adata in actions:
            if count >= max_chains:
                break
            try:
                if nx.has_path(G_raw, pnode, anode):
                    path = nx.shortest_path(G_raw, pnode, anode)
                    if 1 < len(path) <= 8:
                        action_str = G_raw.nodes[anode].get("meta", {}).get("action") or str(anode)
                        resources = set()
                        effect = "Allow"
                        notes = []
                        risk = 0
                        for node in path:
                            ndata = G_raw.nodes[node]
                            rscore = ndata.get("risk_score") or 0
                            try:
                                risk += int(rscore)
                            except Exception:
                                pass
                            if ndata.get("type") == "policy":
                                doc = (ndata.get("meta") or {}).get("Document") or {}
                                stmts = doc.get("Statement", [])
                                if isinstance(stmts, dict):
                                    stmts = [stmts]
                                for stmt in _ensure_list(stmts):
                                    for r in _ensure_list(stmt.get("Resource", [])):
                                        resources.add(r)
                                    if (stmt.get("Effect") or "").lower() == "deny":
                                        effect = "Deny"
                                        notes.append("Explicit Deny in policy")
                                    if stmt.get("NotAction") or stmt.get("NotResource"):
                                        notes.append("Policy uses NotAction/NotResource - manual review required")
                        risk = min(10, int(risk))
                        readable = render_readable_chain(path, G_raw)
                        chain_obj = {
                            "id": f"chain_{count:04d}",
                            "actors": [pnode],
                            "path": path,
                            "render": readable,
                            "actions": [action_str],
                            "resources": sorted(list(resources))[:8],
                            "effect": effect,
                            "risk_score": risk,
                            "notes": list(sorted(set(notes)))[:8],
                            "subgraph_path_nodes": path
                        }
                        chains.append(chain_obj)
                        count += 1
            except Exception:
                continue
        if count >= max_chains:
            break
    random.shuffle(chains)
    return chains

def render_chain_subgraph(G_raw: nx.DiGraph, chain_obj: Dict, extra_hops: int = 1, max_nodes: int = 120) -> nx.DiGraph:
    nodes = list(chain_obj.get("subgraph_path_nodes", []))
    keep: Set[str] = set(nodes)
    frontier = set(nodes)
    for _ in range(extra_hops):
        new_front = set()
        for n in frontier:
            try:
                for p in G_raw.predecessors(n):
                    if len(keep) >= max_nodes:
                        break
                    keep.add(p)
                    new_front.add(p)
                for s in G_raw.successors(n):
                    if len(keep) >= max_nodes:
                        break
                    keep.add(s)
                    new_front.add(s)
            except Exception:
                continue
        frontier = new_front
        if len(keep) >= max_nodes:
            break
    return G_raw.subgraph(keep).copy()

# -----------------------
# Helper: service helpers
# -----------------------
def _service_from_action(action_str: str) -> str:
    if not isinstance(action_str, str) or ":" not in action_str:
        return "other"
    svc = action_str.split(":", 1)[0].lower()
    return svc or "other"

def _service_meta_name(svc: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_]", "_", svc.upper())
    return f"ACTIONS_{safe}"

def _service_display_label(svc: str) -> str:
    return SERVICE_DISPLAY.get(svc, f"{svc.upper()} Actions")

def _build_cytoscape_html(nodes_meta: List[Dict], edges_meta: List[Dict], style_css: str = "") -> str:
    """
    nodes_meta: list of {id, label, x, y, type, risky, parent (optional), title_html, width, height, color}
    edges_meta: list of {source, target, label, color, dashes}
    Returns full HTML string embedding cytoscape and initial script.
    """
    # Cytoscape CDN (stable)
    cy_cdn = "https://unpkg.com/cytoscape@3.23.0/dist/cytoscape.min.js"

    # Minimal CSS for legend and page (overrideable via style_css param)
    if not style_css:
        style_css = """
        body { margin: 0; font-family: Inter, Roboto, Arial, sans-serif; background: #f8fafc; color:#0f172a; -webkit-font-smoothing:antialiased; }
        #cy { width:100%; height:100vh; display:block; }
        .iamx-legend {
            position: fixed;
            top: 12px;
            left: 12px;
            background: white;
            padding:12px 14px;
            border-radius:10px;
            border:1px solid #e6eef8;
            box-shadow:0 8px 24px rgba(15,23,42,0.06);
            z-index:9999;
            font-size:13px;
            max-width: 320px;
        }
        .iamx-legend b { display:block; margin-bottom:6px; font-size:14px; }
        .iamx-legend .row { margin-top:6px; }
        .iamx-legend .chips { margin-top:8px; font-size:12px; color:#374151; }
        """

    # JSON-encode nodes and edges arrays (safely)
    nodes_json = json.dumps(nodes_meta)
    edges_json = json.dumps(edges_meta)

    # Build HTML (use doubled braces where necessary because this is an f-string)
    html = f"""
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width,initial-scale=1" />
        <script src="{cy_cdn}"></script>
        <style>{style_css}</style>
      </head>
      <body>
        <div class="iamx-legend">
          <b>IAM X-Ray — Actions by Service</b>
          <div class="row"><span style="color:#dc2626;font-weight:600">High Risk</span> — Escalation / Destructive</div>
          <div class="row"><span style="color:#f97316;font-weight:600">Medium Risk</span> — Broad / data access</div>
          <div class="row"><span style="color:#10b981;font-weight:600">Assume</span> — Role trust</div>
          <div class="chips"><span style="color:#3b82f6">User</span> • <span style="color:#f59e0b">Group</span> • <span style="color:#10b981">Role</span> • <span style="color:#8b5cf6">Policy</span> • <span style="color:#ef4444">Action</span> • <span style="color:#0ea5e9">Resource</span></div>
        </div>

        <div id="cy"></div>

        <script>
          const nodes = {nodes_json};
          const edges = {edges_json};

          function makeElement(n) {{
            const data = {{ id: n.id, label: n.label, type: n.type }};
            if (n.parent) data.parent = n.parent;
            // pass through width/height/color/title_html for Cytoscape data()
            if (n.width) data.width = n.width;
            if (n.height) data.height = n.height;
            if (n.color) data.color = n.color;
            if (n.title_html) data.title_html = n.title_html;
            return {{ data: data, position: {{ x: n.x, y: n.y }}, classes: n.type + (n.risky ? ' risky' : ''), selectable: true }};
          }}

          function makeEdge(e) {{
            const data = {{ id: e.source + '___' + e.target, source: e.source, target: e.target, label: e.label || '' }};
            if (e.color) data.color = e.color;
            return {{ data: data, classes: e.label || '' }};
          }}

          const cy = cytoscape({{
            container: document.getElementById('cy'),
            elements: {{
              nodes: nodes.map(makeElement),
              edges: edges.map(makeEdge)
            }},
            style: [
              // base node
              {{ selector: 'node', style: {{
                  'label': 'data(label)',
                  'text-valign': 'center',
                  'text-halign': 'center',
                  'font-size': 12,
                  'text-wrap': 'wrap',
                  'width': 'data(width)',
                  'height': 'data(height)',
                  'background-color': 'data(color)',
                  'border-color': '#111827',
                  'border-width': 2,
                  'overlay-padding': 6,
                  'z-index': 1
              }} }},
              // risky highlight
              {{ selector: 'node.risky', style: {{
                  'border-color': '#dc2626',
                  'border-width': 6,
                  'background-color': '#fff5f5',
                  'shadow-blur': 18,
                  'shadow-color': '#dc2626',
                  'shadow-opacity': 0.28,
                  'shadow-offset-x': 0,
                  'shadow-offset-y': 2,
                  'z-index': 10
              }} }},
              // service: subtle rounded container
              {{ selector: 'node[type="service"]', style: {{
                  'shape': 'roundrectangle',
                  'background-opacity': 0.06,
                  'border-style': 'dashed',
                  'label': 'data(label)',
                  'font-size': 13,
                  'padding': 8
              }} }},
              // action: diamond (big)
              {{ selector: 'node[type="action"]', style: {{
                  'shape': 'diamond',
                  'font-size': 11,
                  'padding': 4
              }} }},
              // policy: ellipse
              {{ selector: 'node[type="policy"]', style: {{
                  'shape': 'ellipse',
                  'font-size': 12,
                  'padding': 6
              }} }},
              // resource: roundrectangle with soft bg
              {{ selector: 'node[type="resource"]', style: {{
                  'shape': 'roundrectangle',
                  'background-color': '#e0f2fe',
                  'background-opacity': 1,
                  'label': 'data(label)',
                  'font-size': 11,
                  'padding': 6
              }} }},
              // role/group: rectangle
              {{ selector: 'node[type="role"], node[type="group"]', style: {{
                  'shape': 'rectangle',
                  'font-size': 12,
                  'padding': 6
              }} }},
              // user/principal: rounded rectangle
              {{ selector: 'node[type="user"], node[type="principal"]', style: {{
                  'shape': 'roundrectangle',
                  'font-size': 11,
                  'padding': 6
              }} }},

              // EDGE STYLES — BloodHound-like (straight, triangle arrowheads)
              {{ selector: 'edge', style: {{
                  'curve-style': 'straight',
                  'target-arrow-shape': 'triangle',
                  'arrow-scale': 1.2,
                  'width': 2,
                  'line-color': 'data(color)',
                  'target-arrow-color': 'data(color)',
                  'label': 'data(label)',
                  'font-size': 10,
                  'text-rotation': 'autorotate',
                  'text-margin-y': -6
              }} }},

              // can assume dashed heavier
              {{ selector: 'edge[label = "can assume"]', style: {{
                  'line-style': 'dashed',
                  'width': 3,
                  'line-color': 'data(color)',
                  'target-arrow-color': 'data(color)'
              }} }},

              // explicit cannot = dashed red
              {{ selector: 'edge[ label = "CANNOT" ]', style: {{
                  'line-style': 'dashed',
                  'line-color': '#ef4444',
                  'target-arrow-color': '#ef4444'
              }} }},

              // explicit CAN = green
              {{ selector: 'edge[ label = "CAN" ]', style: {{
                  'line-color': '#10b981',
                  'target-arrow-color': '#10b981'
              }} }},

              // assume coloring override
              {{ selector: 'edge[ label = "can assume" ]', style: {{
                  'line-color': '#f59e0b',
                  'target-arrow-color': '#f59e0b'
              }} }}
            ],
            layout: {{ name: 'preset' }},
            userZoomingEnabled: true,
            userPanningEnabled: true,
            wheelSensitivity: 0.2
          }});

          // Auto fit + center with padding for nicer framing
          cy.ready(function() {{
            try {{
              cy.fit(cy.elements(), 100);
              cy.center();
            }} catch (e) {{
              // fallback: fit without margin
              try {{ cy.fit(cy.elements()); cy.center(); }} catch (e2) {{ }}
            }}
          }});

          // Simple tooltip: show title_html when node hovered (custom floating tooltip)
          (function() {{
            let tip = null;
            function makeTip() {{
              tip = document.createElement('div');
              tip.style.position = 'fixed';
              tip.style.pointerEvents = 'none';
              tip.style.background = 'rgba(15,23,42,0.95)';
              tip.style.color = '#fff';
              tip.style.padding = '8px 10px';
              tip.style.borderRadius = '6px';
              tip.style.fontSize = '12px';
              tip.style.maxWidth = '360px';
              tip.style.boxShadow = '0 6px 18px rgba(2,6,23,0.4)';
              tip.style.zIndex = 10000;
              tip.style.display = 'none';
              document.body.appendChild(tip);
            }}
            makeTip();
            cy.on('mouseover', 'node', function(evt) {{
              const n = evt.target;
              const html = n.data('title_html') || n.data('label') || '';
              tip.innerHTML = html.replace(/\\n/g, '<br/>');
              tip.style.display = 'block';
            }});
            cy.on('mouseout', 'node', function() {{
              tip.style.display = 'none';
            }});
            cy.on('mousemove', function(e) {{
              if (!tip) return;
              // position tooltip near pointer but avoid overflow
              const x = e.originalEvent.clientX + 12;
              const y = e.originalEvent.clientY + 12;
              tip.style.left = x + 'px';
              tip.style.top = y + 'px';
            }});
          }})();

          // click: set id to hash (helps integration)
          cy.on('tap', 'node', function(evt) {{
            const id = evt.target.id();
            try {{ window.location.hash = '#node=' + encodeURIComponent(id); }} catch (e) {{ }}
          }});

          // double-click: zoom to node
          cy.on('dblclick', 'node', function(evt) {{
            const n = evt.target;
            cy.animate({{ center: {{ eles: n }}, zoom: 1.6, duration: 420 }});
          }});

          // keyboard arrows to pan (optional small UX helper)
          document.addEventListener('keydown', function(e) {{
            const panStep = 40;
            if (e.key === 'ArrowLeft') cy.panBy({{ x: panStep, y: 0 }});
            if (e.key === 'ArrowRight') cy.panBy({{ x: -panStep, y: 0 }});
            if (e.key === 'ArrowUp') cy.panBy({{ x: 0, y: panStep }});
            if (e.key === 'ArrowDown') cy.panBy({{ x: 0, y: -panStep }});
          }});

        </script>
      </body>
    </html>
    """
    return html


# -----------------------
# Core: build_iam_graph (Cytoscape)
# -----------------------
def build_iam_graph(snapshot, show_only_risky=False, highlight_node=None, highlight_color="#ffeb3b", highlight_duration=2200):
    """
    Build graph, generate action/service nodes, resource nodes, extract chains,
    and emit Cytoscape HTML.
    Returns: (G_final, html_str, None, export_bytes, meta)
    """
    G_raw = build_graph(snapshot, show_only_risky=show_only_risky)
    if len(G_raw.nodes) == 0:
        empty_html = "<div style='text-align:center;padding:80px;font-size:20px;color:#666;'>No entities match current filters</div>"
        return nx.DiGraph(), empty_html, None, b"{}", {"reason": "no_matching_nodes"}

    # --- ACTION GENERATION ---
    who_can_do_sampled = {}
    action_counter = 0
    added_actions = 0
    policy_nodes = [n for n, d in G_raw.nodes(data=True) if d.get("type") == "policy"]
    random.shuffle(policy_nodes)
    created_service_nodes = set()

    for policy_node in policy_nodes:
        try:
            attrs = G_raw.nodes[policy_node]
            doc = (attrs.get("meta") or {}).get("Document") or {}
            stmts = doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
        except Exception:
            stmts = []

        for stmt in _ensure_list(stmts):
            effect = (stmt.get("Effect") or "Allow")
            is_deny = effect.lower() == "deny"

            actions = _ensure_list(stmt.get("Action") or stmt.get("NotAction"))
            if not actions:
                continue

            # Split high-risk vs others
            high_risk_actions = [a for a in actions if isinstance(a, str) and a.lower() in HIGH_RISK_ACTIONS]
            other_actions = [a for a in actions if isinstance(a, str) and a not in high_risk_actions]

            sampled_other = other_actions if len(other_actions) <= 3 else random.sample(other_actions, min(3, len(other_actions)))
            sampled = high_risk_actions + sampled_other

            for action in sampled:
                if not isinstance(action, str):
                    continue
                if added_actions >= MAX_ACTIONS_GLOBAL or added_actions >= MAX_ADDITIONAL_NODES:
                    break

                action_original = action.strip()
                safe_label = action_original.replace(":", "_").replace("*", "STAR").replace(" ", "_")[:140]
                action_node = f"ACTION_{action_counter}_{safe_label}"

                action_counter += 1
                added_actions += 1

                # Risk classification
                al = action_original.lower()
                if al in HIGH_RISK_ACTIONS:
                    risk_level = "high"
                elif any(re.search(pat, al, re.IGNORECASE) for pat in MEDIUM_RISK_PATTERNS):
                    risk_level = "medium"
                else:
                    risk_level = "low"

                # Create action node
                if not G_raw.has_node(action_node):
                    G_raw.add_node(
                        action_node,
                        type="action",
                        meta={"action": action_original},
                        risky=(risk_level == "high"),
                        label=action_original,
                    )

                # Policy -> Action edge
                rel = "denies" if is_deny else "allows"
                G_raw.add_edge(policy_node, action_node, relation=rel)

                # Principals -> Action edges (CAN / CANNOT)
                try:
                    preds = list(G_raw.predecessors(policy_node))
                except Exception:
                    preds = []

                for pred in preds:
                    pred_type = G_raw.nodes[pred].get("type")
                    if pred_type in ("user", "role", "group", "principal", "meta"):
                        can_label = "CANNOT" if is_deny else "CAN"
                        G_raw.add_edge(pred, action_node, relation=can_label)
                        who_can_do_sampled.setdefault(action_original, set()).add(pred)

                who_can_do_sampled.setdefault(action_original, set()).update(preds)

                # --- SERVICE NODE CREATION ---
                svc = _service_from_action(action_original)
                svc_meta = _service_meta_name(svc)
                svc_label = _service_display_label(svc)

                if not G_raw.has_node(svc_meta):
                    G_raw.add_node(
                        svc_meta,
                        type="service",
                        meta={"label": svc_label, "members": []},
                        label=svc_label
                    )
                    created_service_nodes.add(svc_meta)

                if not G_raw.has_edge(action_node, svc_meta):
                    G_raw.add_edge(action_node, svc_meta, relation="in_service")

                try:
                    svc_meta_obj = G_raw.nodes[svc_meta].setdefault("meta", {})
                    members = svc_meta_obj.get("members")
                    if members is None or not isinstance(members, list):
                        svc_meta_obj["members"] = [action_original]
                    else:
                        if action_original not in members:
                            members.append(action_original)
                except Exception:
                    logger.debug(f"Failed to append member to service meta {svc_meta}", exc_info=True)

                # -----------------------------
                # ⭐ PATCH 7 — RESOURCE NODES ⭐
                # -----------------------------
                resources = _ensure_list(stmt.get("Resource"))
                for res in resources:
                    try:
                        res_id = f"RES:{res}"
                        if not G_raw.has_node(res_id):
                            rlabel = res if len(res) <= 160 else res[:157] + "..."
                            G_raw.add_node(
                                res_id,
                                type="resource",
                                label=rlabel,
                                risky=False,
                                meta={"resource": res}
                            )
                        if not G_raw.has_edge(action_node, res_id):
                            G_raw.add_edge(action_node, res_id, relation="targets")
                    except Exception:
                        logger.debug(f"Failed to add resource node for {res}", exc_info=True)

            if added_actions >= MAX_ACTIONS_GLOBAL or added_actions >= MAX_ADDITIONAL_NODES:
                break

        if added_actions >= MAX_ACTIONS_GLOBAL or added_actions >= MAX_ADDITIONAL_NODES:
            break

    # Normalize sampled map
    who_can_do_serializable = {k: sorted(list(v)) for k, v in who_can_do_sampled.items()}

    # Full chain analysis
    who_can_do_full = compute_who_can_do_full(G_raw)
    who_can_do_full_normalized = {k.strip().lower(): v for k, v in who_can_do_full.items() if k}

    permission_chain_objs = extract_permission_chain_objects(G_raw, who_can_do_full)

    # Export raw graph
    try:
        raw_export_path = os.path.join(
            tempfile.gettempdir(),
            f"iam_xray_graph.raw.{int(datetime.utcnow().timestamp())}.json"
        )
        export_graph_json(G_raw, raw_export_path)
    except Exception:
        raw_export_path = None

    # Collapse and focus
    G_collapsed = collapse_graph(G_raw)
    G_final = apply_focus(G_collapsed, highlight_node) if highlight_node else G_collapsed

    # -----------------------
    # BUILD CYTOSCAPE NODES
    # -----------------------
    tier_order = ["user", "group", "role", "policy", "action", "service", "resource", "principal", "meta"]
    tier_to_x = {t: i * 110 for i, t in enumerate(tier_order)}
    y_spacing = 85

    nodes_by_tier = {t: [] for t in tier_order}
    for n, attrs in G_final.nodes(data=True):
        t = attrs.get("type", "meta")
        nodes_by_tier.setdefault(t, []).append((n, attrs))

    for t in nodes_by_tier:
        nodes_by_tier[t].sort(key=lambda x: (0 if x[1].get("risky") else 1, str(x[0]).lower()))

    nodes_meta = []

    for t_idx, t in enumerate(tier_order):
        col_x = tier_to_x.get(t, 0)
        items = nodes_by_tier.get(t, [])

        for i, (node_id, attrs) in enumerate(items):
            y = i * y_spacing + 80
            x = col_x + 80

            ntype = attrs.get("type")
            label = attrs.get("label") or node_id
            risky = bool(attrs.get("risky"))
            meta = attrs.get("meta") or {}

            # Node hover text
            title_lines = []
            if ntype == "policy":
                title_lines.append(f"Policy: {label}")
            elif ntype == "role":
                title_lines.append(f"Role: {label}")
            elif ntype == "group":
                title_lines.append(f"Group: {label}")
            elif ntype == "user":
                title_lines.append(f"User: {label}")
            elif ntype == "service":
                members = meta.get("members") or []
                sample = ", ".join(members[:12]) + ("..." if len(members) > 12 else "")
                title_lines.append(f"{meta.get('label', label)}")
                title_lines.append(f"Actions: {sample}")
            elif ntype == "action":
                title_lines.append(f"Action: {meta.get('action', label)}")
            elif ntype == "resource":
                title_lines.append(f"Resource: {meta.get('resource')}")

            title_html = "<br>".join(title_lines) if title_lines else label

            # BloodHound-like sizing
            if ntype == "service":
                members = meta.get("members", [])
                w, h = 200, max(140, len(members) * 12)
            elif ntype == "action":
                w, h = 95, 95
            elif ntype == "policy":
                w, h = 140, 70
            elif ntype == "resource":
                w, h = 180, 55
            elif ntype in ("user", "group", "role", "principal"):
                w, h = 130, 60
            else:
                w, h = 110, 50

            entry = {
                "id": node_id,
                "label": label,
                "x": x,
                "y": y,
                "type": ntype,
                "risky": risky,
                "title_html": title_html,
                "color": NODE_COLORS.get(ntype, "#64748b"),
                "width": w,
                "height": h
            }

            # Action belongs to service?
            if ntype == "action":
                for succ in G_final.successors(node_id):
                    if G_final.nodes[succ].get("type") == "service":
                        entry["parent"] = succ
                        break

            nodes_meta.append(entry)

    # -----------------------
    # BUILD CYTOSCAPE EDGES
    # -----------------------
    edges_meta = []
    for u, v, data in G_final.edges(data=True):
        rel = data.get("relation", "")
        label = ""
        color = "#94a3b8"

        if rel == "member":
            label = "member"; color = "#3b82f6"
        elif rel == "attached":
            label = "has policy"; color = "#8b5cf6"
        elif rel == "assumes":
            label = "can assume"; color = "#f59e0b"
        elif rel == "allows":
            label = "allows"; color = "#10b981"
        elif rel == "denies":
            label = "denies"; color = "#ef4444"
        elif rel == "CAN":
            label = "CAN"; color = "#10b981"
        elif rel == "CANNOT":
            label = "CANNOT"; color = "#ef4444"
        elif rel == "targets":
            label = "targets"; color = "#0ea5e9"

        edges_meta.append({
            "source": u,
            "target": v,
            "label": label,
            "color": color,
            "dashes": False
        })

    # Build HTML
    html_str = _build_cytoscape_html(nodes_meta, edges_meta)

    # Export collapsed graph bytes
    try:
        export_path = os.path.join(
            tempfile.gettempdir(),
            f"iam_xray_graph.collapsed.{int(datetime.utcnow().timestamp())}.json"
        )
        export_graph_json(G_final, export_path)
        with open(export_path, "rb") as f:
            export_bytes = f.read()
    except Exception:
        export_bytes = b"{}"

    meta = {
        "raw_node_count": len(G_raw.nodes),
        "collapsed_node_count": len(G_final.nodes),
        "who_can_do_sampled": who_can_do_serializable,
        "who_can_do_full": who_can_do_full,
        "who_can_do_full_normalized": who_can_do_full_normalized,
        "permission_chains": permission_chain_objs,
        "permission_chain_count": len(permission_chain_objs),
        "raw_export_path": raw_export_path
    }

    return G_final, html_str, None, export_bytes, meta


