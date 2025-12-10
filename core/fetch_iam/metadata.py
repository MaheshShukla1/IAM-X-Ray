# core/fetch_iam/metadata.py
"""
IAM X-Ray — metadata utilities

Responsibilities:
- Build snapshot-level metadata and summary: counts, risk_summary, action_count, resource_count, service_stats, cross_account_links
- Keep metadata compact and useful for UI
"""

from __future__ import annotations
import logging
from typing import Dict, Any, List
from collections import Counter

logger = logging.getLogger("fetch_iam.metadata")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

def build_snapshot_metadata(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """
    Accepts combined snapshot (may be multi-region) and return meta summary dict.
    """
    meta = {}
    # counts
    try:
        if snapshot.get("_meta", {}).get("regions"):
            # multi-region aggregated
            users = 0; groups = 0; roles = 0; policies = 0
            for r in snapshot["_meta"]["regions"]:
                c = r.get("_meta", {}).get("counts", {})
                users += c.get("users", 0)
                groups += c.get("groups", 0)
                roles += c.get("roles", 0)
                policies += c.get("policies", 0)
            meta["counts"] = {"users": users, "groups": groups, "roles": roles, "policies": policies}
        else:
            meta["counts"] = {
                "users": len(snapshot.get("users", []) or []),
                "groups": len(snapshot.get("groups", []) or []),
                "roles": len(snapshot.get("roles", []) or []),
                "policies": len(snapshot.get("policies", []) or []),
            }
    except Exception:
        meta["counts"] = {"users": 0, "groups": 0, "roles": 0, "policies": 0}

    # risk summary (sum of policy risk score + role trust risk)
    try:
        pol_scores = sum(p.get("RiskScore", 0) for p in snapshot.get("policies", []) or [])
        role_scores = sum(r.get("AssumePolicyRiskScore", 0) for r in snapshot.get("roles", []) or [])
        meta["risk_summary"] = {"policy_risk_sum": pol_scores, "role_trust_risk_sum": role_scores}
    except Exception:
        meta["risk_summary"] = {"policy_risk_sum": 0, "role_trust_risk_sum": 0}

    # service stats (counts of discovered resources)
    try:
        svc = {}
        # if multi-region, sum resources maps
        if snapshot.get("_meta", {}).get("regions"):
            for r in snapshot["_meta"]["regions"]:
                rs = r.get("_resources", {}) or {}
                for k, v in rs.items():
                    svc[k] = svc.get(k, 0) + len(v or [])
        else:
            rs = snapshot.get("_resources", {}) or {}
            for k, v in rs.items():
                svc[k] = len(v or [])
        meta["service_stats"] = svc
    except Exception:
        meta["service_stats"] = {}

    # action_count & resource_count from resolver maps if present
    try:
        am = snapshot.get("_action_map") or {}
        ri = snapshot.get("_resource_index") or {}
        meta["action_count"] = len(am)
        meta["resource_count"] = len(ri)
    except Exception:
        meta["action_count"] = 0
        meta["resource_count"] = 0

    # cross-account links: inspect trust findings in roles for 'Cross-account'
    try:
        cross = []
        for r in snapshot.get("roles", []) or []:
            findings = r.get("TrustPolicyFindings", []) or []
            for f in findings:
                if "Cross-account" in f or "Cross-account trust" in f:
                    cross.append(r.get("RoleName"))
                    break
        meta["cross_account_links"] = sorted(list(set(cross)))
    except Exception:
        meta["cross_account_links"] = []

    return meta
