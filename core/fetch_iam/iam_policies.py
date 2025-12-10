# core/fetch_iam/iam_policies.py
"""
IAM X-Ray — iam_policies module (Module 3)

Responsibilities:
- Expand attached/custom managed policy documents (get_policy_version)
- Normalize inline policies (already fetched by iam_principals)
- Provide risk analysis for policy documents (score 0..10)
- Extract action list and resource list per policy
- Build action -> policy map and resource -> policy map
- Public API: fetch_policies_for_region(iam_client, principals_snapshot, full=False)

Notes:
- AWS-managed policies (arn starting with arn:aws:iam::aws:policy/) are not fetched by default,
  only metadata (PolicyName/Arn, IsAwsManaged=True) is provided. This matches product
  requirement: skip AWS-managed policy bodies to save API calls & avoid noise.
"""

from __future__ import annotations
import json
import logging
import urllib.parse
from typing import Any, Dict, List, Tuple, Optional, Set

logger = logging.getLogger("fetch_iam.iam_policies")
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

def _decode_policy_document(doc):
    if not doc:
        return {}
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        try:
            return json.loads(urllib.parse.unquote(doc))
        except Exception:
            try:
                return json.loads(doc)
            except Exception:
                return {}
    return {}

def _is_aws_managed_policy_arn(arn: Optional[str]) -> bool:
    return isinstance(arn, str) and arn.startswith(AWS_MANAGED_PREFIX)

# -----------------------
# Policy document loader / expander
# -----------------------
def _get_policy_version_document(iam_client, policy_arn: str, version_id: Optional[str] = None) -> Optional[Dict]:
    """
    Fetch the policy document for a managed policy (customer-managed).
    If version_id is not provided, will fetch the policy and use DefaultVersionId.
    Returns dict or None.
    """
    try:
        # first get policy metadata to learn default version
        pol = iam_client.get_policy(PolicyArn=policy_arn)
        default_vid = pol.get("Policy", {}).get("DefaultVersionId")
        vid = version_id or default_vid
        if not vid:
            return None
        ver = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=vid)
        doc_raw = ver.get("PolicyVersion", {}).get("Document")
        doc = _decode_policy_document(doc_raw)
        return doc
    except Exception as e:
        logger.debug(f"get_policy_version failed for {policy_arn}: {e}")
        return None

def expand_attached_policies(iam_client, attached_policies: List[Dict], fetch_bodies: bool = False) -> List[Dict]:
    """
    Normalize attached policies list to include Document if fetch_bodies True.
    attached_policies: list items like {"PolicyName": "...", "Arn": "...", "IsAwsManaged": bool}
    Returns list of normalized policy dicts:
      {"PolicyName":..., "Arn":..., "IsAwsManaged":bool, "Document": {...} or {}, "Fetched": bool}
    """
    out = []
    for ap in attached_policies or []:
        arn = ap.get("Arn") or ap.get("PolicyArn") or ap.get("Arn")
        pname = ap.get("PolicyName") or ap.get("PolicyName")
        is_aws_managed = _is_aws_managed_policy_arn(arn)
        pol = {"PolicyName": pname, "Arn": arn, "IsAwsManaged": is_aws_managed, "Document": {}, "Fetched": False}
        if fetch_bodies and arn and not is_aws_managed:
            doc = _get_policy_version_document(iam_client, arn)
            if doc:
                pol["Document"] = doc
                pol["Fetched"] = True
        out.append(pol)
    return out

# -----------------------
# Lightweight but robust policy analyzer
# -----------------------
DANGEROUS_SCORES = {
    "iam:CreatePolicy": 9,
    "iam:CreatePolicyVersion": 9,
    "iam:SetDefaultPolicyVersion": 8,
    "iam:AttachUserPolicy": 8,
    "iam:AttachGroupPolicy": 8,
    "iam:AttachRolePolicy": 8,
    "iam:PutUserPolicy": 8,
    "iam:PutGroupPolicy": 8,
    "iam:PutRolePolicy": 8,
    "iam:UpdateAssumeRolePolicy": 8,
    "iam:PassRole": 9,
    "sts:AssumeRole": 7,
    "iam:CreateAccessKey": 6,
    "iam:CreateLoginProfile": 6,
    "ec2:RunInstances": 5,
    "ec2:TerminateInstances": 8,
    "s3:DeleteObject": 8,
    "*": 10
}

def analyze_policy_document(doc: Dict) -> Dict:
    """
    Return: {"is_risky": bool, "score": int, "findings": [...], "actions": [...], "resources": [...]}
    """
    findings: List[str] = []
    actions_found: Set[str] = set()
    resources_found: Set[str] = set()
    score = 0

    if not isinstance(doc, dict):
        return {"is_risky": False, "score": 0, "findings": [], "actions": [], "resources": []}

    stmts = _ensure_list(doc.get("Statement", []))
    for stmt in stmts:
        try:
            effect = (stmt.get("Effect") or "Allow").lower()
        except Exception:
            effect = "allow"
        # Extract actions
        act_list = _ensure_list(stmt.get("Action") or stmt.get("NotAction") or [])
        for a in act_list:
            if isinstance(a, str):
                actions_found.add(a)
                la = a.lower()
                if la == "*" or "*" in la:
                    findings.append(f"Action wildcard: {a}")
                    score = max(score, 9 if la == "*" else 7)
                # Dangerous actions
                for key, s in DANGEROUS_SCORES.items():
                    if la == key.lower() or (key.endswith(":*") and la.startswith(key.split(":")[0]+":")):
                        findings.append(f"Dangerous action: {a}")
                        score = max(score, s)
        # Extract resources
        res_list = _ensure_list(stmt.get("Resource") or stmt.get("NotResource") or [])
        for r in res_list:
            if isinstance(r, str):
                resources_found.add(r)
                if r.strip() == "*":
                    findings.append("Resource: * (no resource constraint)")
                    score = max(score, 7)
        # NotAction / NotResource likely risky
        if stmt.get("NotAction") or stmt.get("NotResource"):
            findings.append("Policy uses NotAction/NotResource — manual review recommended")
            score = max(score, 6)
        # Effect deny note
        if effect == "deny":
            findings.append("Contains explicit Deny (note: explicit deny takes precedence)")

    final_score = min(10, int(score))
    is_risky = final_score >= 5 or any("Action wildcard" in f or "Dangerous action" in f for f in findings)
    return {
        "is_risky": is_risky,
        "score": final_score,
        "findings": list(dict.fromkeys(findings))[:10],
        "actions": sorted(list(actions_found))[:200],
        "resources": sorted(list(resources_found))[:200]
    }

# -----------------------
# Policy indexing & merging
# -----------------------
def _normalize_inline_policies_from_principal(principal_entries: List[Dict]) -> List[Dict]:
    """
    Given principals entries (users/groups/roles) which may include InlinePolicies list elements
    of shape [{"PolicyName":..., "Document": {...}}, ...], flatten them into normalized policy objects
    and attach metadata 'AttachedTo' (principal identifier).
    """
    out = []
    for p in principal_entries or []:
        # determine the principal identifier name
        principal_id = p.get("UserName") or p.get("GroupName") or p.get("RoleName") or p.get("Arn") or p.get("Principal")
        for inline in _ensure_list(p.get("InlinePolicies") or []):
            pname = inline.get("PolicyName")
            doc = _decode_policy_document(inline.get("Document") or {})
            pol = {
                "PolicyName": pname,
                "Arn": None,
                "Document": doc,
                "IsAwsManaged": False,
                "AttachedTo": principal_id
            }
            out.append(pol)
    return out

def fetch_policies_for_region(iam_client, principals_snapshot: Dict, full: bool = False) -> Tuple[List[Dict], Dict[str, List[str]], Dict[str, List[str]]]:
    """
    Build normalized policies list for the region using principals snapshot produced by iam_principals.fetch_principals_for_region.
    principals_snapshot should include keys "users","groups","roles" each a list of dicts (see iam_principals.py).
    - If full=True, expand attached customer-managed policy documents (get_policy_version).
    Returns:
      policies: list of policy dicts:
        {
          "PolicyName": str,
          "Arn": str or None,
          "Document": {...},
          "IsAwsManaged": bool,
          "IsRisky": bool,
          "RiskScore": int,
          "Findings": [...],
          "Actions": [...],
          "Resources": [...],
          "AttachedTo": "<principal name or group>"  # first owner found, may be None for pure managed policy
        }
      action_map: { action_str: [policy_name1, ...] }
      resource_map: { resource_arn: [policy_name1, ...] }
    """
    policies_out: List[Dict] = []
    action_map: Dict[str, List[str]] = {}
    resource_map: Dict[str, List[str]] = {}

    users = principals_snapshot.get("users", []) or []
    groups = principals_snapshot.get("groups", []) or []
    roles = principals_snapshot.get("roles", []) or []

    # 1) Inline policies first (they include Document already)
    inline_policies = []
    inline_policies += _normalize_inline_policies_from_principal(users)
    inline_policies += _normalize_inline_policies_from_principal(groups)
    inline_policies += _normalize_inline_policies_from_principal(roles)

    for ip in inline_policies:
        doc = _decode_policy_document(ip.get("Document") or {})
        analysis = analyze_policy_document(doc)
        pol_name = ip.get("PolicyName") or f"inline:{ip.get('AttachedTo') or 'unknown'}:{len(policies_out)}"
        pol = {
            "PolicyName": pol_name,
            "Arn": ip.get("Arn"),
            "Document": doc,
            "IsAwsManaged": False,
            "IsRisky": analysis["is_risky"],
            "RiskScore": analysis["score"],
            "Findings": analysis["findings"],
            "Actions": analysis["actions"],
            "Resources": analysis["resources"],
            "AttachedTo": ip.get("AttachedTo")
        }
        policies_out.append(pol)
        for a in pol["Actions"]:
            action_map.setdefault(a, []).append(pol_name)
        for r in pol["Resources"]:
            resource_map.setdefault(r, []).append(pol_name)

    # 2) Attached policies referenced by principals: gather unique ARNs and owners
    attached_index: Dict[str, Dict] = {}  # arn -> {"PolicyName":..., "Owners": set(...), "IsAwsManaged": bool}
    def register_attached_list(att_list, owner_name=None):
        for ap in _ensure_list(att_list):
            arn = ap.get("Arn") or ap.get("PolicyArn") or ap.get("Arn")
            pname = ap.get("PolicyName") or ap.get("PolicyName")
            if not arn and not pname:
                continue
            key = arn or pname
            entry = attached_index.setdefault(key, {"PolicyName": pname or key, "Arn": arn, "Owners": set(), "IsAwsManaged": _is_aws_managed_policy_arn(arn)})
            if owner_name:
                entry["Owners"].add(owner_name)

    for u in users:
        uname = u.get("UserName")
        register_attached_list(u.get("AttachedPolicies", []), owner_name=uname)
    for g in groups:
        gname = g.get("GroupName")
        register_attached_list(g.get("AttachedPolicies", []), owner_name=gname)
    for r in roles:
        rname = r.get("RoleName")
        register_attached_list(r.get("AttachedPolicies", []), owner_name=rname)

    # 3) For each attached (customer-managed) policy, optionally fetch body if full==True
    for key, ap in attached_index.items():
        arn = ap.get("Arn")
        pname = ap.get("PolicyName") or (arn.split("/")[-1] if arn else key)
        owners = sorted(list(ap.get("Owners", [])))
        is_aws_managed = ap.get("IsAwsManaged", False)
        doc = {}
        fetched = False
        if full and arn and not is_aws_managed:
            try:
                doc = _get_policy_version_document(iam_client, arn) or {}
                fetched = True
            except Exception as e:
                logger.debug(f"Failed to fetch policy document for {arn}: {e}")
                doc = {}
        # analyze (if we have doc, analyze; else produce light metadata)
        analysis = analyze_policy_document(doc) if doc else {"is_risky": False, "score": 0, "findings": [], "actions": [], "resources": []}
        pol = {
            "PolicyName": pname,
            "Arn": arn,
            "Document": doc,
            "IsAwsManaged": is_aws_managed,
            "Fetched": fetched,
            "IsRisky": analysis["is_risky"],
            "RiskScore": analysis["score"],
            "Findings": analysis["findings"],
            "Actions": analysis["actions"],
            "Resources": analysis["resources"],
            "AttachedTo": owners[0] if owners else None
        }
        policies_out.append(pol)
        for a in pol["Actions"]:
            action_map.setdefault(a, []).append(pname)
        for r in pol["Resources"]:
            resource_map.setdefault(r, []).append(pname)

    # 4) Deduplicate policy names in maps
    for a, lst in list(action_map.items()):
        action_map[a] = sorted(list(set(lst)))
    for r, lst in list(resource_map.items()):
        resource_map[r] = sorted(list(set(lst)))

    logger.info(f"Built {len(policies_out)} policies (inline+attached), actions_index={len(action_map)} resources_index={len(resource_map)}")
    return policies_out, action_map, resource_map

# End of file: iam_policies.py
