# core/fetch_iam/resolver.py
"""
IAM X-Ray — resolver module

Responsibilities:
- Analyze policy Documents and extract action -> resource mapping (best-effort)
- Provide small policy analyzer used by engine to enrich policy entries
- Does not attempt full AWS IAM policy language evaluation, instead:
    - Iterates statements, normalizes Actions, Resources, Effect
    - Builds simple mapping: action_str -> set(resources)
- Returns:
    - action_map: { action_str: { "resources": [...], "policies": [policy_name], "effects": ["Allow"/"Deny"] } }
    - resource_index: { resource_arn: [action_str, ...] }
"""

from __future__ import annotations
import logging
import json
import re
from typing import Dict, Any, List, Tuple, Set

logger = logging.getLogger("fetch_iam.resolver")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)
    
# Quick lookup when engine created action_index
def fast_principal_finder(action_index: dict, action: str):
    """
    Return list of policy names/principals for action using prebuilt action_index.
    action_index is expected to be {action: [policy_name, ...]}
    """
    if not action_index or not action:
        return []
    return action_index.get(action, [])

def _ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]

def normalize_action(a: str) -> str:
    if not isinstance(a, str):
        return str(a)
    return a.strip()

def analyze_policy_document(doc: Dict) -> Dict:
    """
    Light weight analysis used by engine to mark risk score/findings.
    Returns {is_risky, score, findings}
    """
    if not isinstance(doc, dict):
        return {"is_risky": False, "score": 0, "findings": []}
    stmts = _ensure_list(doc.get("Statement", []))
    score = 0
    findings = []
    for stmt in stmts:
        eff = (stmt.get("Effect") or "Allow").lower()
        actions = _ensure_list(stmt.get("Action") or stmt.get("NotAction") or [])
        resources = _ensure_list(stmt.get("Resource") or [])
        for a in actions:
            if not isinstance(a, str):
                continue
            al = a.lower()
            if al == "*" or "*" in al:
                findings.append("Action wildcard")
                score = max(score, 9)
            if "iam:passrole" in al or "sts:assumerole" in al:
                findings.append("Sensitive action present")
                score = max(score, 8)
        for r in resources:
            if isinstance(r, str) and r.strip() == "*":
                findings.append("Resource wildcard")
                score = max(score, 7)
    return {"is_risky": score >= 6, "score": min(10, score), "findings": list(dict.fromkeys(findings))}

def map_actions_to_resources(policies: List[Dict], resources: Dict[str, Any]) -> Tuple[Dict[str, Dict], Dict[str, List[str]]]:
    """
    Build a mapping of actions -> resources and inverse resource index.
    policies: list of policy dicts (with optional 'Document')
    returns (action_map, resource_index)
    """
    action_map: Dict[str, Dict] = {}
    resource_index: Dict[str, List[str]] = {}

    # helper to register
    def reg(action: str, res_list: List[str], policy_name: str, effect: str):
        a = normalize_action(action)
        if a not in action_map:
            action_map[a] = {"resources": set(), "policies": set(), "effects": set()}
        for r in res_list:
            action_map[a]["resources"].add(r)
            resource_index.setdefault(r, []).append(a)
        action_map[a]["policies"].add(policy_name)
        action_map[a]["effects"].add(effect)

    # iterate policies
    for p in policies or []:
        pname = p.get("PolicyName") or p.get("Arn") or "<unnamed>"
        doc = p.get("Document") or {}
        stmts = _ensure_list(doc.get("Statement", []))
        for stmt in stmts:
            try:
                effect = (stmt.get("Effect") or "Allow")
                actions = _ensure_list(stmt.get("Action") or stmt.get("NotAction") or [])
                resources_list = _ensure_list(stmt.get("Resource") or ["*"])
                # normalize resources to strings
                res_strings = [str(r) for r in resources_list if isinstance(r, (str, int))]
                if not res_strings:
                    res_strings = ["*"]
                for a in actions:
                    if isinstance(a, str):
                        # expand simple wildcard to preserve readability
                        reg(a, res_strings, pname, effect)
            except Exception:
                continue

    # convert sets to lists for JSON friendliness
    for k, v in list(action_map.items()):
        action_map[k] = {
            "resources": sorted(list(v["resources"])),
            "policies": sorted(list(v["policies"])),
            "effects": sorted(list(v["effects"]))
        }

    # dedupe resource_index entries
    for r, acts in list(resource_index.items()):
        resource_index[r] = sorted(list(set(acts)))

    return action_map, resource_index
