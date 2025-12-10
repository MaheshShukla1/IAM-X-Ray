# core/fetch_iam/trust_policy.py
"""
IAM X-Ray — trust_policy module (Module 4)

Responsibilities:
- Parse and normalize an IAM Role trust (AssumeRolePolicyDocument)
- Extract principal entries (Service, AWS accounts/roles, Federated providers, Wildcards)
- Detect ExternalId usage, Condition keys (aws:PrincipalOrgID, StringEquals, ArnEquals, etc.)
- Score trust risk with human-readable findings
- Provide small utilities to attach normalized PrincipalsInfo to Role snapshot entries

Public functions:
- parse_trust_policy(document) -> normalized dict
- extract_principals(document) -> List[Dict] (type, value, raw)
- analyze_trust_policy(document) -> Dict(score, findings, is_risky, details)
- normalize_role_entry(role_entry) -> role_entry augmented with PrincipalsInfo + TrustPolicyFindings + AssumePolicyRiskScore
"""

from __future__ import annotations
import json
import logging
import re
from typing import Any, Dict, List, Tuple, Optional

logger = logging.getLogger("fetch_iam.trust_policy")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

# Known condition keys that reduce risk when present with proper values
LOW_RISK_CONDITIONS = [
    "StringEquals",
    "StringLike",
    "ArnEquals",
    "ArnLike",
]

# Known federation types (common patterns)
FEDERATED_PATTERNS = [
    "cognito-identity.amazonaws.com",
    "accounts.google.com",
    "graph.facebook.com",
    "www.amazon.com",
    "oidc",
    "saml-provider",
]

# -----------------------
# Helpers
# -----------------------
def _ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]

def _is_aws_principal_value(v: str) -> bool:
    # crude check for arn or account id
    if not isinstance(v, str):
        return False
    if v.startswith("arn:aws:iam::"):
        return True
    if re.fullmatch(r"\d{12}", v):
        return True
    return False

def _normalize_value(val: Any) -> List[str]:
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v) for v in val]
    return [str(val)]

# -----------------------
# Parse / Extract principals
# -----------------------
def parse_trust_policy(document: Dict) -> Dict:
    """
    Normalize AssumeRolePolicyDocument into a standard dict:
    {
      "statements": [
         {"Effect":"Allow","Principal": {"AWS":[...],"Service":[...],"Federated":[...], "*":True/False}, "Action":[...], "Condition": {...}}
      ]
    }
    """
    if not isinstance(document, dict):
        return {"statements": []}

    stmts = _ensure_list(document.get("Statement") or document.get("statement") or [])
    out_stmts = []
    for s in stmts:
        try:
            effect = s.get("Effect", "Allow")
            principal = s.get("Principal", {})
            # normalize principal mapping to lists
            normalized_principal = {}
            if principal == "*" or principal == {"AWS": "*"} or principal == {"Service": "*"}:
                normalized_principal["*"] = True
            elif isinstance(principal, dict):
                for k, v in principal.items():
                    if v is None:
                        continue
                    normalized_principal[k] = _normalize_value(v)
            else:
                # string like "*"
                if isinstance(principal, str) and principal.strip() == "*":
                    normalized_principal["*"] = True
                else:
                    normalized_principal["AWS"] = _normalize_value(principal)
            action = _ensure_list(s.get("Action") or s.get("NotAction") or [])
            condition = s.get("Condition") or {}
            out_stmts.append({
                "Effect": effect,
                "Principal": normalized_principal,
                "Action": action,
                "Condition": condition
            })
        except Exception as e:
            logger.debug(f"parse_trust_policy: skipping malformed stmt: {e}")
            continue
    return {"statements": out_stmts}

def extract_principals(document: Dict) -> List[Dict]:
    """
    Return list of principals extracted from trust policy statements.
    Each principal dict:
    { "type": "Service"|"AWS"|"Federated"|"Wildcard"|"Unknown", "value": "...", "raw": <original> }
    """
    parsed = parse_trust_policy(document)
    principals = []
    for stmt in parsed.get("statements", []):
        pmap = stmt.get("Principal") or {}
        if pmap.get("*"):
            principals.append({"type": "Wildcard", "value": "*", "raw": "*"})
            continue
        for ptype, vals in pmap.items():
            if not vals:
                continue
            for v in vals:
                typ = "Unknown"
                if ptype.lower() == "service":
                    typ = "Service"
                elif ptype.lower() == "aws":
                    typ = "AWS"
                elif ptype.lower() in ("federated", "federation", "federate"):
                    typ = "Federated"
                else:
                    # sometimes keys misspelt or custom - guess
                    if any(fp in str(v).lower() for fp in FEDERATED_PATTERNS):
                        typ = "Federated"
                    elif _is_aws_principal_value(v):
                        typ = "AWS"
                    elif ":" in str(v) and "amazonaws.com" in v:
                        typ = "Service"
                principals.append({"type": typ, "value": v, "raw": {ptype: v}})
    # dedupe while preserving order
    seen = set()
    out = []
    for p in principals:
        key = (p["type"], p["value"])
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out

# -----------------------
# Analyze trust: detailed
# -----------------------
def analyze_trust_policy(document: Dict) -> Dict:
    """
    Analyze trust document and produce a risk score + findings.
    Returns:
      {
        "score": int (0..10),
        "is_risky": bool,
        "findings": [str...],
        "principals": [normalized principals],
        "conditions": summarized
      }
    Heuristics:
      - Wildcard principal without conditions -> score 10
      - Cross-account AWS principal without ExternalId or org condition -> score 8-9
      - Service principal (e.g., lambda.amazonaws.com) generally low risk unless combined with permissive conditions -> score 2-5
      - Federated providers flagged (score 5) unless conditions restrict issuer/audiences
      - Presence of Condition with aws:PrincipalOrgID, ExternalId, or specific ArnEquals reduces score
    """
    parsed = parse_trust_policy(document)
    findings = []
    score = 0
    principals = extract_principals(document)
    conditions_summary = []

    if not parsed.get("statements"):
        findings.append("No statements found in trust policy")
        return {"score": 0, "is_risky": False, "findings": findings, "principals": principals, "conditions": []}

    for stmt in parsed.get("statements", []):
        pmap = stmt.get("Principal") or {}
        cond = stmt.get("Condition") or {}
        # Wildcard principal
        if pmap.get("*"):
            # if there are no conditions or only benign ones -> critical
            if not cond:
                findings.append("Principal: * (any entity) allowed to assume role — no conditions")
                score = max(score, 10)
            else:
                findings.append("Principal: * allowed but conditions exist (inspect conditions)")
                score = max(score, 7)
                conditions_summary.append(cond)
            continue

        # For each principal type, reason about risk
        for ptype, vals in pmap.items():
            if not vals:
                continue
            for v in vals:
                # AWS principals (accounts/roles)
                if ptype.lower() == "aws":
                    # value could be arn:aws:iam::123456789012:root or arn:aws:iam::123:role/Name or account id
                    if isinstance(v, str) and v.strip() == "*":
                        findings.append("AWS principal wildcard in Principal AWS")
                        score = max(score, 9)
                    elif isinstance(v, str) and v.startswith("arn:aws:iam::"):
                        # cross-account if account id != local (we can't know local here)
                        # we mark cross-account risky unless ExternalId/PrincipalOrgID condition present
                        if not cond:
                            findings.append(f"Cross-account trust detected for principal {v} with no conditions")
                            score = max(score, 8)
                        else:
                            # check for ExternalId or aws:PrincipalOrgID
                            if not (("StringEquals" in cond and "sts:ExternalId" in json.dumps(cond["StringEquals"])) or
                                    ("StringEquals" in cond and "aws:PrincipalOrgID" in json.dumps(cond["StringEquals"])) or
                                    any(k in json.dumps(cond).lower() for k in ("externalid", "aws:principalorgid"))):
                                findings.append(f"Cross-account trust for {v} — conditions present but ExternalId/PrincipalOrgID not detected")
                                score = max(score, 7)
                            else:
                                findings.append(f"Cross-account trust for {v} with guarding conditions (ExternalId/PrincipalOrgID) present — lower risk")
                                score = max(score, 3)
                    else:
                        # account id string
                        if re.fullmatch(r"\d{12}", str(v)):
                            if not cond:
                                findings.append(f"Account {v} allowed to assume role with no conditions")
                                score = max(score, 8)
                            else:
                                findings.append(f"Account {v} allowed to assume role (conditions present)")
                                score = max(score, 4)
                        else:
                            findings.append(f"AWS principal: {v}")
                elif ptype.lower() == "service":
                    # service principals are common; detect broad service pattern
                    findings.append(f"Service principal allowed: {v}")
                    # suspicious services? none by default; usually low risk
                    score = max(score, 2)
                    # if condition missing and service is 'ec2.amazonaws.com' + wide permissions could be medium
                elif ptype.lower() == "federated":
                    # federated providers require careful review
                    findings.append(f"Federated principal: {v}")
                    # if provider is generic (oidc) and no condition on token issuer/audience -> risk
                    if isinstance(v, str) and ("oidc" in v.lower() or any(fp in v.lower() for fp in FEDERATED_PATTERNS)):
                        if not cond:
                            findings.append(f"Federated provider {v} with no conditions — review allowed tokens/audience")
                            score = max(score, 6)
                        else:
                            findings.append(f"Federated provider {v} with conditions — inspect condition keys (aud, sub, iss)")
                            score = max(score, 4)
                    else:
                        score = max(score, 4)
                else:
                    # unknown principal keys
                    findings.append(f"Principal ({ptype}): {v}")
                    score = max(score, 5)
        # Conditions evaluation
        if cond:
            # look for aws:PrincipalOrgID
            cond_str = json.dumps(cond)
            if "aws:PrincipalOrgID" in cond_str or "PrincipalOrgID" in cond_str:
                findings.append("Condition uses aws:PrincipalOrgID — reduces cross-account risk")
                score = max(score, score - 2) if score >= 2 else score
            if "ExternalId" in cond_str or "externalid" in cond_str.lower() or "sts:ExternalId" in cond_str:
                findings.append("ExternalId condition present — reduces cross-account risk")
                score = max(score, score - 2) if score >= 2 else score
            # Presence of restrictive ArnEquals/ArnLike reduces risk
            if any(k in cond for k in ("ArnEquals", "ArnLike")):
                findings.append("ArnEquals/ArnLike condition present — more restrictive trust")
                score = max(score, score - 1) if score >= 1 else score
            conditions_summary.append(cond)

    # Normalize final score and is_risky
    final_score = max(0, min(10, int(score)))
    # heuristics: anything >=6 flagged risky
    is_risky = final_score >= 6 or any("Wildcard" in f or "Cross-account" in f for f in findings)
    # dedupe findings
    findings = list(dict.fromkeys(findings))
    return {
        "score": final_score,
        "is_risky": is_risky,
        "findings": findings,
        "principals": principals,
        "conditions": conditions_summary
    }

# -----------------------
# Role entry augmentation helper
# -----------------------
def normalize_role_entry(role_entry: Dict) -> Dict:
    """
    Given a role entry (as produced in fetch_iam._light_fetch_region roles loop),
    augment it with PrincipalsInfo (list of principals), TrustPolicyFindings and AssumePolicyRiskScore.
    Returns the augmented role_entry (mutates copy).
    """
    if not isinstance(role_entry, dict):
        return role_entry
    assume_doc = role_entry.get("AssumeRolePolicyDocument") or role_entry.get("AssumeRolePolicy") or {}
    parsed = parse_trust_policy(assume_doc)
    principals = extract_principals(assume_doc)
    analysis = analyze_trust_policy(assume_doc)
    # attach fields in expected shape for graph_builder
    role_entry = dict(role_entry)  # shallow copy to avoid side-effects
    role_entry["PrincipalsInfo"] = principals
    role_entry["TrustPolicyFindings"] = analysis.get("findings", [])
    role_entry["AssumePolicyRiskScore"] = analysis.get("score", 0)
    role_entry["IsRiskyTrust"] = bool(analysis.get("is_risky", False))
    # keep summary for UI
    role_entry["_trust_summary"] = {
        "principals_count": len(principals),
        "score": analysis.get("score", 0),
        "is_risky": analysis.get("is_risky", False),
        "top_findings": analysis.get("findings", [])[:4]
    }
    return role_entry

# -----------------------
# Convenience: build PrincipalsInfo for many roles
# -----------------------
def normalize_roles_list(roles: List[Dict]) -> List[Dict]:
    """
    Apply normalize_role_entry to each role in list (non-destructive copy).
    """
    out = []
    for r in roles or []:
        try:
            out.append(normalize_role_entry(r))
        except Exception as e:
            logger.debug(f"normalize_roles_list: failed for role {r.get('RoleName') if isinstance(r, dict) else str(r)}: {e}")
            out.append(r)
    return out

# -----------------------
# Module end
# -----------------------
