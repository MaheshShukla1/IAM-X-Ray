# core/fetch_iam/iam_principals.py
"""
IAM X-Ray — iam_principals module (Module 2)

Responsibilities:
- Fetch users, groups, roles from IAM (paginated)
- Expand attached + inline policies for each principal (when full=True)
- Parse role assume-role/trust policies into PrincipalsInfo
- Normalize returned entries to the snapshot schema used by graph_builder

Public functions:
- fetch_users(iam_client, full=False)
- fetch_groups(iam_client, full=False)
- fetch_roles(iam_client, full=False)
- parse_assume_role_policy(document) -> List[dict]  (principals info)
- is_aws_managed_policy_arn(arn) -> bool

Note: This module intentionally does NOT fetch managed AWS-owned policy bodies
(if policy arn starts with arn:aws:iam::aws:policy/ it is considered AWS-managed
and is left out from full document expansion — per user requirement).
"""

from __future__ import annotations
import json
import logging
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("fetch_iam.iam_principals")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

AWS_MANAGED_PREFIX = "arn:aws:iam::aws:policy/"

# -----------------------
# Helpers
# -----------------------
def _ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]

def _iso(dt):
    if not dt:
        return None
    try:
        # boto3 returns datetime for CreateDate
        return dt.isoformat()
    except Exception:
        return str(dt)

def is_aws_managed_policy_arn(arn: Optional[str]) -> bool:
    if not isinstance(arn, str):
        return False
    return arn.startswith(AWS_MANAGED_PREFIX)

def _safe_get_policy_document_from_response(resp: Any) -> Optional[Dict]:
    """
    Response from get_*_policy may contain PolicyDocument as dict
    or a urlencoded JSON string in some edge cases; normalize to dict.
    """
    if not resp:
        return None
    if isinstance(resp, dict):
        # Some API responses return {"PolicyDocument": {...}}
        if "PolicyDocument" in resp and isinstance(resp["PolicyDocument"], dict):
            return resp["PolicyDocument"]
        # Or return the document directly
        if "PolicyDocument" in resp and isinstance(resp["PolicyDocument"], str):
            try:
                return json.loads(urllib.parse.unquote(resp["PolicyDocument"]))
            except Exception:
                try:
                    return json.loads(resp["PolicyDocument"])
                except Exception:
                    return None
    return None

def _decode_policy_document(doc):
    """
    Ensure policy document is a JSON dict; if string, try urlunquote + json.
    """
    if not doc:
        return {}
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        try:
            # sometimes boto3 returns a urlencoded JSON string
            return json.loads(urllib.parse.unquote(doc))
        except Exception:
            try:
                return json.loads(doc)
            except Exception:
                return {}
    return {}

# -----------------------
# Principals fetchers
# -----------------------
def fetch_users(iam_client, full: bool = False) -> List[Dict]:
    """
    Fetch users. If full=True:
      - list_groups_for_user
      - list_attached_user_policies
      - list_user_policies + get_user_policy (inline)
    Returns list of user dicts:
    {
      "UserName": ...,
      "Arn": ...,
      "CreateDate": ...,
      "Groups": [...],
      "AttachedPolicies": [{"PolicyName": "...", "Arn": "...", "IsAwsManaged": False}, ...],
      "InlinePolicies": [{"PolicyName": "...", "Document": {...}}, ...]
    }
    """
    out = []
    try:
        paginator = iam_client.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page.get("Users", []):
                entry = {
                    "UserName": u.get("UserName"),
                    "Arn": u.get("Arn"),
                    "CreateDate": _iso(u.get("CreateDate")),
                    "AttachedPolicies": [],
                    "InlinePolicies": [],
                }
                # optionally enrich
                if full:
                    # groups
                    try:
                        groups = iam_client.list_groups_for_user(UserName=entry["UserName"]).get("Groups", [])
                        entry["Groups"] = [g.get("GroupName") for g in groups]
                    except Exception:
                        entry["Groups"] = []
                    # attached managed/custom (but skip AWS-managed body fetch)
                    try:
                        att = iam_client.list_attached_user_policies(UserName=entry["UserName"]).get("AttachedPolicies", [])
                        normalized = []
                        for ap in att:
                            arn = ap.get("PolicyArn") or ap.get("Arn") or ap.get("Arn")
                            pname = ap.get("PolicyName") or ap.get("PolicyName")
                            normalized.append({
                                "PolicyName": pname,
                                "Arn": arn,
                                "IsAwsManaged": is_aws_managed_policy_arn(arn)
                            })
                        entry["AttachedPolicies"] = normalized
                    except Exception:
                        entry["AttachedPolicies"] = []
                    # inline policies (names -> fetch document)
                    try:
                        names = iam_client.list_user_policies(UserName=entry["UserName"]).get("PolicyNames", [])
                        inline = []
                        for name in _ensure_list(names):
                            try:
                                resp = iam_client.get_user_policy(UserName=entry["UserName"], PolicyName=name)
                                doc = _safe_get_policy_document_from_response(resp) or _decode_policy_document(resp.get("PolicyDocument") if isinstance(resp, dict) else None)
                                inline.append({"PolicyName": name, "Document": doc})
                            except Exception as e:
                                logger.debug(f"get_user_policy failed for {entry['UserName']}/{name}: {e}")
                        entry["InlinePolicies"] = inline
                    except Exception:
                        entry["InlinePolicies"] = []
                out.append(entry)
    except Exception as e:
        logger.warning(f"list_users failed: {e}")
    return out

def fetch_groups(iam_client, full: bool = False) -> List[Dict]:
    """
    Fetch groups. If full=True:
      - list_attached_group_policies
      - list_group_policies + get_group_policy
      - For performance do not expand AWS-managed policy bodies if arn is AWS-managed
    Returns:
    {
      "GroupName": ..., "Arn": ..., "AttachedPolicies": [...], "InlinePolicies":[...]
    }
    """
    out = []
    try:
        paginator = iam_client.get_paginator("list_groups")
        for page in paginator.paginate():
            for g in page.get("Groups", []):
                entry = {
                    "GroupName": g.get("GroupName"),
                    "Arn": g.get("Arn"),
                    "AttachedPolicies": [],
                    "InlinePolicies": []
                }
                if full:
                    try:
                        att = iam_client.list_attached_group_policies(GroupName=entry["GroupName"]).get("AttachedPolicies", [])
                        normalized = []
                        for ap in att:
                            arn = ap.get("PolicyArn") or ap.get("Arn")
                            pname = ap.get("PolicyName")
                            normalized.append({
                                "PolicyName": pname,
                                "Arn": arn,
                                "IsAwsManaged": is_aws_managed_policy_arn(arn)
                            })
                        entry["AttachedPolicies"] = normalized
                    except Exception:
                        entry["AttachedPolicies"] = []
                    try:
                        names = iam_client.list_group_policies(GroupName=entry["GroupName"]).get("PolicyNames", [])
                        inline = []
                        for name in _ensure_list(names):
                            try:
                                resp = iam_client.get_group_policy(GroupName=entry["GroupName"], PolicyName=name)
                                doc = _safe_get_policy_document_from_response(resp) or _decode_policy_document(resp.get("PolicyDocument") if isinstance(resp, dict) else None)
                                inline.append({"PolicyName": name, "Document": doc})
                            except Exception as e:
                                logger.debug(f"get_group_policy failed for {entry['GroupName']}/{name}: {e}")
                        entry["InlinePolicies"] = inline
                    except Exception:
                        entry["InlinePolicies"] = []
                out.append(entry)
    except Exception as e:
        logger.warning(f"list_groups failed: {e}")
    return out

def parse_assume_role_policy(document: Any) -> List[Dict]:
    """
    Parse an AssumeRolePolicyDocument and extract principals into a normalized list:
    [
      {"type":"AWS"|"Service"|"Federated"|"Wildcard", "value": "<value>"}
    ]
    """
    principals = []
    try:
        if not document:
            return principals
        stmts = _ensure_list(document.get("Statement", [])) if isinstance(document, dict) else []
        for stmt in stmts:
            principal = stmt.get("Principal", {})
            if principal == "*":
                principals.append({"type": "Wildcard", "value": "*"})
                continue
            if isinstance(principal, dict):
                for k, v in principal.items():
                    vals = v
                    if isinstance(vals, str):
                        vals = [vals]
                    for val in _ensure_list(vals):
                        principals.append({"type": str(k), "value": val})
            # else skip unknown formats
    except Exception as e:
        logger.debug(f"parse_assume_role_policy failed: {e}")
    return principals

def fetch_roles(iam_client, full: bool = False) -> List[Dict]:
    """
    Fetch roles. If full=True:
      - list_attached_role_policies
      - list_role_policies + get_role_policy
    Each role includes:
    {
      "RoleName": ...,
      "Arn": ...,
      "CreateDate": ...,
      "AssumeRolePolicyDocument": {...},
      "PrincipalsInfo": [{"type":"AWS","value":"arn:..."}...],
      "AttachedPolicies": [{"PolicyName": "...", "Arn": "...", "IsAwsManaged": False}, ...],
      "InlinePolicies": [{"PolicyName":"...", "Document": {...}}, ...],
      "AssumePolicyRiskScore": 0,
      "TrustPolicyFindings": [],
      "IsRiskyTrust": False
    }
    """
    out = []
    try:
        paginator = iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            for r in page.get("Roles", []):
                rname = r.get("RoleName")
                assume_raw = r.get("AssumeRolePolicyDocument", {}) or {}
                assume = _decode_policy_document(assume_raw) if assume_raw else {}
                principals_info = parse_assume_role_policy(assume)
                entry = {
                    "RoleName": rname,
                    "Arn": r.get("Arn"),
                    "CreateDate": _iso(r.get("CreateDate")),
                    "AssumeRolePolicyDocument": assume,
                    "PrincipalsInfo": principals_info,
                    "AttachedPolicies": [],
                    "InlinePolicies": [],
                    "AssumePolicyRiskScore": 0,
                    "TrustPolicyFindings": [],
                    "IsRiskyTrust": False,
                }
                if full:
                    try:
                        att = iam_client.list_attached_role_policies(RoleName=rname).get("AttachedPolicies", [])
                        normalized = []
                        for ap in att:
                            arn = ap.get("PolicyArn") or ap.get("Arn")
                            pname = ap.get("PolicyName")
                            normalized.append({
                                "PolicyName": pname,
                                "Arn": arn,
                                "IsAwsManaged": is_aws_managed_policy_arn(arn)
                            })
                        entry["AttachedPolicies"] = normalized
                    except Exception:
                        entry["AttachedPolicies"] = []
                    try:
                        names = iam_client.list_role_policies(RoleName=rname).get("PolicyNames", [])
                        inline = []
                        for name in _ensure_list(names):
                            try:
                                resp = iam_client.get_role_policy(RoleName=rname, PolicyName=name)
                                doc = _safe_get_policy_document_from_response(resp) or _decode_policy_document(resp.get("PolicyDocument") if isinstance(resp, dict) else None)
                                inline.append({"PolicyName": name, "Document": doc})
                            except Exception as e:
                                logger.debug(f"get_role_policy failed for {rname}/{name}: {e}")
                        entry["InlinePolicies"] = inline
                    except Exception:
                        entry["InlinePolicies"] = []
                out.append(entry)
    except Exception as e:
        logger.warning(f"list_roles failed: {e}")
    return out

# -----------------------
# Convenience combined fetch (used by engine)
# -----------------------
def fetch_principals_for_region(iam_client, account_id=None, full=False):
    """
    Return dict:
    {
      "users": [...],
      "groups": [...],
      "roles": [...],
      "_meta": {"account_id": ..., "counts": {...}}
    }
    """
    users = fetch_users(iam_client, full=full)
    groups = fetch_groups(iam_client, full=full)
    roles = fetch_roles(iam_client, full=full)

    counts = {
        "users": len(users),
        "groups": len(groups),
        "roles": len(roles)
    }

    return {
        "users": users,
        "groups": groups,
        "roles": roles,
        "_meta": {
            "account_id": account_id,
            "counts": counts
        }
    }

# End of file: iam_principals.py
