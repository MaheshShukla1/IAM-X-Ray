# core/graph_builder.py
"""
IAM X-Ray — Consolidated Graph Builder (Final, Service-clustered Actions)

Design decisions:
- Option A: Show ALL actions under service clusters (S3, IAM, EC2, Lambda, STS, KMS, SecretsManager, SSM, DynamoDB, etc.)
- Action nodes remain visible (no global ACTIONS collapse). Each action node connects to a SERVICE meta-node (e.g., ACTIONS_S3).
- Policy -> Action -> Service cluster path makes graphs readable and avoids a single "ACTIONS" spaghetti node.
- Highly instrumented: who_can_do (sampled + full reverse-BFS), permission chain objects, chain subgraph renderer for highlight views.
- Performance caps and sampling ensure UI remains responsive for 200–800 actions.

Compatibility:
- Exposes: build_graph(snapshot, show_only_risky=False)
- Exposes: build_iam_graph(snapshot, show_only_risky=False, highlight_node=None, ...)
- Exposes: render_chain_subgraph and helpers used by app/main.py for chain highlighting
"""

from __future__ import annotations
import os
import re
import json
import tempfile
import logging
import random
from datetime import datetime
from collections import deque
from typing import List, Dict, Tuple, Any, Optional, Set

import networkx as nx
from pyvis.network import Network

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
    "user": "#0ea5a4",        # teal
    "group": "#f59e0b",       # amber
    "role": "#10b981",        # green
    "policy": "#7c3aed",      # purple
    "principal": "#9CA3AF",
    "meta": "#94a3b8",
    "action": "#ef4444",      # red (danger)
    "service": "#2563eb",     # stronger blue for service containers
    "resource": "#06b6d4",     # light cyan
}

# Safety limits
MAX_NODES = 300                 # pre-collapse selection cap for interactive graph
CLUSTER_THRESHOLD = 600
MAX_ADDITIONAL_NODES = 800      # cap for added action/resource nodes
MAX_ACTIONS_GLOBAL = 800        # upper bound for action generation

# Collapse thresholds (we keep actions visible, but still collapse large user/group/role/policy sets)
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

# Risk / dangerous actions
DANGEROUS_ACTIONS = {
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
    "ec2:RunInstances": "Launches new EC2 instances, potentially with attached roles.",
    "lambda:CreateFunction": "Creates new Lambda functions, executing code.",
    "lambda:InvokeFunction": "Triggers Lambda execution, running code.",
    "lambda:UpdateFunctionCode": "Updates Lambda code, modifying behavior.",
    "s3:GetObject": "Downloads objects from S3, accessing data.",
    "s3:ListBucket": "Lists S3 bucket contents, discovering objects.",
    "secretsmanager:GetSecretValue": "Retrieves secrets, exposing sensitive data.",
    "ssm:GetParameter": "Retrieves SSM parameters, accessing configs.",
    "*": "Grants full access, equivalent to Administrator.",
    "s3:*": "Full S3 access, including delete and put.",
    "ec2:*": "Full EC2 control, including terminate.",
    "ec2:TerminateInstances": "Permanently deletes EC2 instances.",
    "s3:DeleteObject": "Deletes S3 objects, causing data loss.",
    "iam:*": "Full IAM control, high escalation risk.",
}

HIGH_RISK_ACTIONS = set(act.lower() for act in [
    "iam:createpolicy", "iam:createpolicyversion", "iam:setdefaultpolicyversion",
    "iam:attachuserpolicy", "iam:attachgrouppolicy", "iam:attachrolepolicy",
    "iam:putuserpolicy", "iam:putgrouppolicy", "iam:putrolepolicy",
    "iam:updateassumerolepolicy", "iam:passrole", "sts:assumerole",
    "iam:createaccesskey", "iam:createloginprofile",
    "ec2:terminateinstances", "s3:deletebucket", "rds:deletedbinstance",
])

MEDIUM_RISK_PATTERNS = [
    r"\*$",
    r":\*$",
    r"^\*$",
]

LOW_RISK_ACTIONS = set(act.lower() for act in [
    "ec2:describeinstances", "s3:listbucket", "iam:listpolicies",
    "logs:describelogstreams", "cloudtrail:describetrails",
])

# Mapping service display labels (pretty labels requested)
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
    # fallback: use upper-case service
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

def compute_keep_set_from_diff(snapshot):
    """
    Build keep-set from snapshot diffs. Supports:
      - single-region snapshots with _meta.diff (old style)
      - multi-region snapshots where _meta.regions contains per-region snapshots
    """
    keep = set()
    if not snapshot or not isinstance(snapshot, dict):
        return keep

    # If top-level diff present (legacy/compat)
    top_diff = (snapshot or {}).get("_meta", {}).get("diff", {}) or {}
    def _collect_from_diff(d):
        for ent, key_name in [("users", "UserName"), ("groups", "GroupName"),
                              ("roles", "RoleName"), ("policies", "PolicyName")]:
            ent_diff = d.get(ent, {}) or {}
            for n in (ent_diff.get("added", []) or []) + (ent_diff.get("modified", []) or []):
                if n:
                    keep.add(n)

    if top_diff:
        # some engine versions store counts only under _meta.diff; ensure correct shape
        if any(k in top_diff for k in ("users", "groups", "roles", "policies")):
            _collect_from_diff(top_diff)
    # If multi-region snapshot with per-region diffs
    regions = (snapshot or {}).get("_meta", {}).get("regions", []) or []
    if regions and isinstance(regions, list):
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
        data = {
            "nodes": [{"id": n, **{k:v for k,v in dict(G.nodes[n]).items() if k != 'meta'}} for n in G.nodes()],
            "edges": [{"source": u, "target": v, **(dict(e) if isinstance(e, dict) else {})} for u, v, e in G.edges(data=True)]
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    return path

# -----------------------
# Snapshot loader
# -----------------------
def load_snapshot(path):
    """
    Load IAM snapshot - supports encrypted (.enc) and plaintext (.json).
    Accepts snapshots written by the enterprise engine (single-region or multi-region).
    """
    if not path:
        raise FileNotFoundError(f"Snapshot path empty")
    # prefer .enc if available
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
# Lightweight policy analyzer
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
    """
    Build a networkx DiGraph from snapshot with safety trimming.
    - Filters AWS managed & service-linked roles
    - Caps nodes to MAX_NODES preserving keep_set/risky nodes
    """
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

    total_entities = len(users) + len(groups) + len(filtered_roles) + len(filtered_policies)
    logger.info(f"Entities after AWS-managed/service-role filtering: users={len(users)}, groups={len(groups)}, roles={len(filtered_roles)}, policies={len(filtered_policies)} (total={total_entities})")

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
        H = G.subgraph(risky_nodes).copy()
        return H

    return G

# -----------------------
# COLLAPSE LAYER (non-destructive)
# -----------------------
def collapse_graph(G):
    """
    Non-destructive collapsing for users/groups/roles/policies only.
    Important: action nodes are NOT globally collapsed here because we display them
    under service clusters to retain readability.
    """
    if G is None or len(G.nodes) == 0:
        return G

    H = G.copy()

    users = [n for n, a in H.nodes(data=True) if a.get("type") == "user"]
    groups = [n for n, a in H.nodes(data=True) if a.get("type") == "group"]
    roles = [n for n, a in H.nodes(data=True) if a.get("type") == "role"]
    policies = [n for n, a in H.nodes(data=True) if a.get("type") == "policy"]
    # intentionally do NOT collect action nodes for global collapse

    def add_meta(name, display_label, original_nodes):
        if not H.has_node(name):
            H.add_node(name, type="meta", meta={"label": display_label, "members": list(original_nodes)}, count=len(original_nodes), risky=any(H.nodes[n].get("risky") for n in original_nodes), label=display_label)
            logger.debug(f"Added meta node {name} with {len(original_nodes)} members")

    # Collapse users
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

    # Collapse groups
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

    # Collapse roles
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

    # Collapse policies
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
    """
    Keep: focus, direct preds/succs, one-hop neighbors of those, meta nodes.
    """
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
    sub = G.subgraph(keep).copy()
    return sub

# -----------------------
# Search (compatibility)
# -----------------------
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

    # Action search: scan policies' Documents for findings (best-effort)
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

    # Entity search - exact match
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

# -----------------------
# Permission Chain Extractor & Renderer (improved)
# -----------------------
def render_readable_chain(path: List[str], G: nx.DiGraph) -> str:
    """
    Render path as human-readable sentence.
    """
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
    """
    Extract permission chains from raw graph: Principal → ... → Action.
    Use sampled principals and actions; returns rendered strings.
    """
    if len(G_raw.nodes) == 0:
        return []
    chains = []
    # Sample principals (risky first)
    principals = [(n, d) for n, d in G_raw.nodes(data=True) if d.get("type") in ["user", "group", "role", "principal"]]
    principals = sorted(principals, key=lambda x: (0 if x[1].get("risky") else 1))
    principals = principals[:MAX_PRINCIPALS_SAMPLE]
    # Sample actions (risky first)
    actions = [(n, d) for n, d in G_raw.nodes(data=True) if d.get("type") == "action"]
    actions = sorted(actions, key=lambda x: (0 if x[1].get("risky") else 1))
    actions = actions[:MAX_ACTIONS_SAMPLE]
    logger.info(f"Extracting chains: principals_sample={len(principals)} actions_sample={len(actions)}")
    for pnode, _ in principals:
        for anode, _ in actions:
            if nx.has_path(G_raw, pnode, anode):
                try:
                    path = nx.shortest_path(G_raw, pnode, anode)
                    if len(path) <= 7:
                        rendered = render_readable_chain(path, G_raw)
                        chains.append(rendered)
                        if len(chains) >= max_chains:
                            break
                except Exception:
                    continue
        if len(chains) >= max_chains:
            break
    random.shuffle(chains)
    logger.info(f"Extracted {len(chains)} permission chains (rendered strings)")
    return chains[:max_chains]

# -----------------------
# Compute full who_can_do mapping (reverse BFS)
# -----------------------
def compute_who_can_do_full(G_raw: nx.DiGraph) -> Dict[str, List[str]]:
    """
    For each action node, find all principals (user/group/role/principal/meta) that have a CAN path to it.
    Uses reverse BFS from each action node.
    Returns: action_string -> sorted list of principal node ids
    """
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
    if len(action_nodes) > len(capped_actions):
        logger.warning(f"compute_who_can_do_full truncated actions: {len(action_nodes)} -> {len(capped_actions)} (MAX_ACTIONS_GLOBAL)")
    return who

# -----------------------
# Extract detailed chain objects
# -----------------------
def extract_permission_chain_objects(G_raw: nx.DiGraph, who_map: Dict[str, List[str]], max_chains: int = MAX_CHAINS) -> List[Dict]:
    """
    Build chain objects prioritized by risky principals/actions.
    Each chain object contains: id, actors, path, render, actions, resources, effect, risk_score, notes, subgraph_path_nodes
    """
    chains = []
    principals = [(n, d) for n, d in G_raw.nodes(data=True) if d.get("type") in ("user", "group", "role", "principal")]
    principals = sorted(principals, key=lambda x: (0 if x[1].get("risky") else 1))
    principals = principals[:MAX_PRINCIPALS_SAMPLE]

    actions = [(n, d) for n, d in G_raw.nodes(data=True) if d.get("type") == "action"]
    actions = sorted(actions, key=lambda x: (0 if x[1].get("risky") else 1))
    actions = actions[:MAX_ACTIONS_SAMPLE]

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
    logger.info(f"Built {len(chains)} detailed chain objects")
    return chains

# -----------------------
# Render small chain subgraph for UI highlighting
# -----------------------
def render_chain_subgraph(G_raw: nx.DiGraph, chain_obj: Dict, extra_hops: int = 1, max_nodes: int = 120) -> nx.DiGraph:
    """
    Create a focused subgraph for the given chain object.
    Returns a networkx DiGraph ready for pyvis rendering.
    """
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
    sub = G_raw.subgraph(keep).copy()
    return sub

# -----------------------
# Helper: determine service from action string
# -----------------------
def _service_from_action(action_str: str) -> str:
    """
    Guess AWS service prefix from an action string like 's3:GetObject'.
    Returns lower-case service string or 'other'.
    """
    if not isinstance(action_str, str) or ":" not in action_str:
        return "other"
    svc = action_str.split(":", 1)[0].lower()
    return svc or "other"

def _service_meta_name(svc: str) -> str:
    """
    Return the internal meta node name for a service, e.g., ACTIONS_S3
    """
    safe = re.sub(r"[^A-Za-z0-9_]", "_", svc.upper())
    return f"ACTIONS_{safe}"

def _service_display_label(svc: str) -> str:
    """
    Pretty display label mapping requested by user (SERVICE_DISPLAY).
    """
    return SERVICE_DISPLAY.get(svc, f"{svc.upper()} Actions")

# -----------------------
# Core: build_iam_graph (wires everything, creates service clusters)
# -----------------------
def build_iam_graph(snapshot, show_only_risky=False, highlight_node=None, highlight_color="#ffeb3b", highlight_duration=2200):
    """
    Build raw graph, add action nodes grouped by service cluster, compute who_can_do maps,
    extract permission chains (detailed objects), apply collapse & focus, render pyvis HTML.
    Returns: (G_final, html_str, clicked_node(None), export_bytes, meta)
    """
    G_raw = build_graph(snapshot, show_only_risky=show_only_risky)

    if len(G_raw.nodes) == 0:
        empty_html = "<div style='text-align:center;padding:100px;font-size:24px;color:#666;'>No entities match current filters</div>"
        return nx.DiGraph(), empty_html, None, b"{}", {"reason": "no_matching_nodes"}

    # --- Step: generate ACTION nodes in G_raw (non-destructive augmentation)
    who_can_do_sampled = {}  # action_str -> set(entities)
    action_counter = 0
    added_actions = 0

    policy_nodes = [n for n, d in G_raw.nodes(data=True) if d.get("type") == "policy"]
    if len(policy_nodes) > 0:
        random.shuffle(policy_nodes)

    # Prepare service meta mapping to keep created service nodes
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
            is_deny = (effect or "Allow").lower() == "deny"
            actions = _ensure_list(stmt.get("Action") or stmt.get("NotAction"))
            if not actions:
                continue

            # prioritize high-risk actions first
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

                al = action_original.lower()
                risk_level = "low"
                if al in HIGH_RISK_ACTIONS:
                    risk_level = "high"
                elif any(re.search(pat, al, re.IGNORECASE) for pat in MEDIUM_RISK_PATTERNS):
                    risk_level = "medium"
                elif al in (a.lower() for a in LOW_RISK_ACTIONS):
                    risk_level = "low"

                # add action node (only if not exists)
                if not G_raw.has_node(action_node):
                    G_raw.add_node(action_node, type="action", meta={"action": action_original}, risky=(risk_level == "high"), label=action_original)

                # policy -> action
                rel = "denies" if is_deny else "allows"
                G_raw.add_edge(policy_node, action_node, relation=rel)

                # connect predecessors to action (CAN/CANNOT)
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

                # --- NEW: determine service and attach action -> service cluster
                svc = _service_from_action(action_original)
                svc_meta = _service_meta_name(svc)
                svc_label = _service_display_label(svc)

                # create service meta node if not exists
                if not G_raw.has_node(svc_meta):
                    # create as meta/service node so collapse keeps it visible
                    G_raw.add_node(svc_meta, type="service", meta={"label": svc_label, "members": []}, label=svc_label)
                    created_service_nodes.add(svc_meta)

                # link action -> service meta (we want action to point to service cluster)
                # Use relation "in_service"
                if not G_raw.has_edge(action_node, svc_meta):
                    G_raw.add_edge(action_node, svc_meta, relation="in_service")
                # keep membership record for tooltips / samples (robust)
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

            if added_actions >= MAX_ACTIONS_GLOBAL or added_actions >= MAX_ADDITIONAL_NODES:
                logger.warning("Reached action generation cap; truncating further actions")
                break
        if added_actions >= MAX_ACTIONS_GLOBAL or added_actions >= MAX_ADDITIONAL_NODES:
            break

    # Convert sampled who_can_do to lists
    who_can_do_serializable = {k: sorted(list(v)) for k, v in who_can_do_sampled.items()}

    # Compute full reverse-BFS who_can_do map (true full mapping)
    who_can_do_full = compute_who_can_do_full(G_raw)

    # Normalize keys for UI (main.py uses lowercase & stripped keys)
    who_can_do_full_normalized = {}
    for k, v in (who_can_do_full or {}).items():
        if not k:
            continue
    k_norm = k.strip().lower()
    who_can_do_full_normalized[k_norm] = v

    # Extract detailed chain objects
    permission_chain_objs = extract_permission_chain_objects(G_raw, who_can_do_full, max_chains=MAX_CHAINS)

    # Export raw uncollapsed graph for debugging (best-effort)
    try:
        raw_export_path = os.path.join(tempfile.gettempdir(), f"iam_xray_graph.raw.{int(datetime.utcnow().timestamp())}.json")
        export_graph_json(G_raw, raw_export_path)
    except Exception:
        raw_export_path = None

    # Apply collapse layer (users/groups/roles/policies). ACTION nodes and SERVICE meta nodes remain
    G_collapsed = collapse_graph(G_raw)

    # Apply focus if highlight_node provided
    G_final = apply_focus(G_collapsed, highlight_node) if highlight_node else G_collapsed

    # Build PyVis network
    net = Network(
        height="100vh",
        width="100%",
        directed=True,
        bgcolor="#ffffff",
        font_color="#0f172a"
    )
    net.set_options("""
    {
    "physics": {
        "enabled": true,
        "solver": "barnesHut",
        "barnesHut": {
        "gravitationalConstant": -26000,
        "centralGravity": 0.65,
        "springLength": 110,
        "springConstant": 0.08,
        "damping": 0.62,
        "avoidOverlap": 1
        },
        "stabilization": {
        "enabled": true,
        "iterations": 180
        }
    },
    "interaction": {
        "hover": true,
        "zoomView": true,
        "dragView": true,
        "navigationButtons": true
    },
    "edges": {
        "smooth": { "type": "dynamic" },
        "arrows": { "to": { "enabled": true, "scaleFactor": 0.9 } },
        "color": "#94a3b8",
        "width": 2
        }
    }
    """)

    
    # Node color helper (unchanged)
    def get_node_color(ntype, risky=False):
        if risky:
            return "#dc2626"
        return NODE_COLORS.get(ntype, "#64748b")
    # helper: mass by node type - larger mass pulls node to center with barnesHut
    MASS_BY_TYPE = {
        "service": 18.0,      # central anchor
        "action": 4.0,
        "policy": 3.5,
        "role": 2.8,
        "group": 2.0,
        "user": 1.5,
        "principal": 1.2,
        "meta": 5.5,
        "unknown": 1.0
    }

    # Gather nodes that are part of extracted chains (for visual emphasis)
    chain_node_set = set()
    for chain in permission_chain_objs:
        for n in chain.get("subgraph_path_nodes", []):
            chain_node_set.add(n)

    # Add nodes to PyVis with mass + improved sizing for BloodHound-ish layout
    for node, attrs in G_final.nodes(data=True):
        ntype = attrs.get("type", "unknown")
        risky = bool(attrs.get("risky", False))
        meta = attrs.get("meta", {}) or {}

        # Build tooltip/title (reuse your existing lines for readability)
        title_lines = []
        if ntype == "policy":
            title_lines.append(f"Policy: {node}")
            title_lines.append(f"Risk Score: {attrs.get('risk_score', 0)}")
            preds = list(G_final.predecessors(node))
            title_lines.append(f"Attached to: {', '.join(preds) if preds else 'None'}")
        elif ntype == "role":
            title_lines.append(f"Role: {node}")
            preds = list(G_final.predecessors(node))
            succs = list(G_final.successors(node))
            title_lines.append(f"Can be assumed by: {', '.join(preds) if preds else 'None'}")
            title_lines.append(f"Policies: {', '.join([s for s in succs if G_final.nodes[s].get('type') == 'policy']) or 'None'}")
        elif ntype == "group":
            title_lines.append(f"Group: {node}")
            preds = list(G_final.predecessors(node))
            succs = list(G_final.successors(node))
            title_lines.append(f"Members: {', '.join(preds) if preds else 'None'}")
            title_lines.append(f"Policies: {', '.join([s for s in succs if G_final.nodes[s].get('type') == 'policy']) or 'None'}")
        elif ntype == "user":
            title_lines.append(f"User: {node}")
            succs = list(G_final.successors(node))
            title_lines.append(f"Groups: {', '.join([s for s in succs if G_final.nodes[s].get('type') == 'group']) or 'None'}")
            title_lines.append(f"Policies: {', '.join([s for s in succs if G_final.nodes[s].get('type') == 'policy']) or 'None'}")
        elif ntype == "principal":
            title_lines.append(f"Principal: {node}")
            title_lines.append(meta.get("value", ""))
        elif ntype == "service":
            label = meta.get("label") or node
            members = meta.get("members") or []
            title_lines.append(f"{label}")
            sample = ", ".join(members[:12]) + (", ..." if len(members) > 12 else "")
            title_lines.append(f"Actions (sample {min(12, len(members))}/{len(members)}): {sample or 'None'}")
        elif ntype == "action":
            action_str = meta.get("action", node)
            title_lines.append(f"Action: {action_str}")
            can_by = who_can_do_serializable.get(action_str, []) or who_can_do_full.get(action_str, [])
            title_lines.append(f"Can be performed by (sample): {', '.join(can_by[:8]) if can_by else 'None'}")

        title_html = "<br>".join(title_lines) if title_lines else str(meta.get("label") or node)
        if risky:
            title_html = "⚠️ " + title_html

        # Size mapping tuned for visuals (service big center, action medium, principals smaller)
        if ntype == "service":
            base_size = 90 if risky else 72
        elif ntype == "action":
            base_size = 40 if risky else 32
        elif ntype == "policy":
            base_size = 54 if risky else 46
        elif ntype in ("role", "group"):
            base_size = 46 if risky else 38
        elif ntype in ("user", "principal"):
            base_size = 34 if risky else 28
        elif ntype == "meta":
            base_size = 60
        else:
            base_size = 36

        # emphasize chain nodes visually
        if node in chain_node_set:
            base_size = int(base_size * 1.25)

        # shape selection (service: box, action: diamond, policy: ellipse, others dot)
        if ntype == "service":
            shape = "box"
        elif ntype == "action":
            shape = "diamond"
        elif ntype == "policy":
            shape = "ellipse"
        else:
            shape = "dot"

        # mass influences barnesHut clustering (higher mass -> pulled to center)
        mass = float(MASS_BY_TYPE.get(ntype, MASS_BY_TYPE["unknown"]))
        if node in chain_node_set:
            mass = mass * 1.4

        net.add_node(
            node,
            label=str(attrs.get("label") or node),
            title=title_html,
            color=get_node_color(ntype, risky),
            size=base_size,
            shape=shape,
            borderWidth=4 if risky else 2,
            shadow=True,
            physics=True,
            mass=mass
        )

    # Add edges
    for u, v, data in G_final.edges(data=True):
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
        elif rel in ("allows", "denies"):
            label = rel
            color = "#dc2626" if rel == "denies" else "#10b981"
        elif rel in ("CAN", "CANNOT"):
            label = rel
            color = "#10b981" if rel == "CAN" else "#ef4444"
            dashes = (rel == "CANNOT")
        elif rel == "in_service":
            label = ""
            color = "#94a3b8"
        net.add_edge(u, v, label=label, color=color, dashes=dashes, width=2.5)

    # Legend HTML
    legend_html = """
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" />
    <div style="position:fixed;top:12px;left:12px;background:#ffffff;padding:12px 16px;border-radius:10px;border:1px solid #e6eef8;box-shadow:0 8px 24px rgba(15,23,42,0.06);z-index:9999;font-family:Arial,Helvetica,sans-serif">
      <div style="font-weight:700;color:#0f172a;margin-bottom:6px">IAM X-Ray — Actions by Service</div>
      <div style="font-size:12.5px;color:#374151;line-height:1.45">
        <div><span style="color:#dc2626;font-weight:600">High Risk</span> — Escalation / Destructive</div>
        <div><span style="color:#f97316;font-weight:600">Medium Risk</span> — Broad / data access</div>
        <div><span style="color:#10b981;font-weight:600">Assume</span> — Role trust</div>
        <div style="margin-top:6px"><span style="color:#3b82f6">User</span> • <span style="color:#f59e0b">Group</span> • <span style="color:#10b981">Role</span> • <span style="color:#8b5cf6">Policy</span> • <span style="color:#ef4444">Action</span></div>
      </div>
    </div>
    """

    # Write HTML to temp and inject legend
    tmpdir = tempfile.mkdtemp(prefix="iamxray_")
    html_path = os.path.join(tmpdir, "graph.html")
    try:
        net.write_html(html_path)
        with open(html_path, "r", encoding="utf-8") as f:
            html_str = f.read()
        html_str = html_str.replace("<head>", "<head><meta charset='utf-8'>", 1)
        html_str = html_str.replace("<body>", f"<body style='margin:0;background:#f8fafc'>{legend_html}", 1)
    except Exception as e:
        logger.error(f"Failed to write or modify HTML: {e}")
        html_str = "<div style='text-align:center;padding:100px;font-size:22px;color:#666;'>Graph rendering failed - check logs</div>"

    # Export collapsed graph JSON
    export_path = os.path.join(tempfile.gettempdir(), f"iam_xray_graph.collapsed.{int(datetime.utcnow().timestamp())}.json")
    try:
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
        "raw_export_path": raw_export_path
    }
    meta["permission_chains"] = permission_chain_objs
    meta["permission_chain_count"] = len(permission_chain_objs)

    return G_final, html_str, None, export_bytes, meta

