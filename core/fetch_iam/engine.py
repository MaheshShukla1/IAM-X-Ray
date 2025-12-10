# core/fetch_iam/engine.py
"""
IAM X-Ray — fetch engine orchestrator

Responsibilities:
- Orchestrate per-region IAM + resource fetch
- Expand inline + attached managed/customer policies (but skip AWS-managed policies)
- Merge results into a normalized snapshot shape
- Use trust_policy.normalize_role_entry (external module) to annotate roles
- Call resource fetchers for service-level resource inventory
- Call resolver to map policy actions -> resources
- Produce final snapshot dict for graph_builder
"""

from __future__ import annotations
import logging
import time
from datetime import datetime, timezone
from copy import deepcopy
from typing import Dict, Any, List, Optional

import boto3
from botocore.exceptions import ClientError

# core/fetch_iam/engine.py
# use local relative imports to be explicit
from .resource_fetch import fetch_region_resources
from .resolver import map_actions_to_resources, analyze_policy_document
from .trust_policy import normalize_role_entry
from .metadata import build_snapshot_metadata

logger = logging.getLogger("fetch_iam.engine")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

# NOTE: this module intentionally avoids including AWS-managed policies in policy expansion (honors request)

def _normalize_attached(ap):
    """
    Normalize attached policy item into a dict with PolicyName and PolicyArn keys.
    Accepts either {'PolicyName':..., 'PolicyArn':...} or a plain ARN string.
    Returns None on invalid input.
    """
    if not ap:
        return None
    if isinstance(ap, dict):
        # try common keys and normalize naming differences
        name = ap.get("PolicyName") or ap.get("PolicyArn", "").split("/")[-1] or ap.get("Arn")
        arn = ap.get("PolicyArn") or ap.get("Arn")
        return {"PolicyName": name, "PolicyArn": arn}
    if isinstance(ap, str):
        arn = ap
        name = arn.split("/")[-1] if "/" in arn else arn
        return {"PolicyName": name, "PolicyArn": arn}
    return None


def _is_aws_managed_policy_arn(arn: Optional[str]) -> bool:
    if not arn:
        return False
    return isinstance(arn, str) and arn.startswith("arn:aws:iam::aws:policy/")

def expand_attached_and_inline(iam_client, entry: Dict[str, Any], fast_mode: bool = True) -> Dict[str, Any]:
    """
    Given a user/role/group entry that may have attached/inline policy names,
    expand them to include full Document for customer-managed policies only.
    Returns updated entry.
    """
    out = dict(entry)
    # Expand attached policies (attached returns {PolicyName, PolicyArn})
    attached = out.get("AttachedPolicies", []) or []
    expanded = []
    for ap in attached:
        try:
            pname = ap.get("PolicyName") if isinstance(ap, dict) else None
            arn = ap.get("PolicyArn") if isinstance(ap, dict) else (ap if isinstance(ap, str) else None)
            if arn and _is_aws_managed_policy_arn(arn):
                # skip AWS-managed policies (per requirement)
                expanded.append({"PolicyName": pname or arn, "Arn": arn, "Scope": "AWSManaged", "Document": None})
                continue
            if fast_mode:
                expanded.append({"PolicyName": pname or arn, "Arn": arn, "Scope": "Customer", "Document": None})
            else:
                # fetch default version
                try:
                    if arn:
                        v = iam_client.get_policy(PolicyArn=arn).get("Policy", {})
                        default_vid = v.get("DefaultVersionId")
                        if default_vid:
                            pv = iam_client.get_policy_version(PolicyArn=arn, VersionId=default_vid)
                            doc = pv.get("PolicyVersion", {}).get("Document", {})
                            expanded.append({"PolicyName": pname or arn, "Arn": arn, "Scope": "Customer", "Document": doc})
                        else:
                            expanded.append({"PolicyName": pname or arn, "Arn": arn, "Scope": "Customer", "Document": None})
                    else:
                        expanded.append({"PolicyName": pname or arn, "Arn": arn, "Scope": "Unknown", "Document": None})
                except Exception:
                    expanded.append({"PolicyName": pname or arn, "Arn": arn, "Scope": "Customer", "Document": None})
        except Exception:
            continue
    out["AttachedPoliciesExpanded"] = expanded

    # Inline policies (names -> fetch document if not fast)
    inline_names = out.get("InlinePolicies", []) or []
    inline_expanded = []
    for n in inline_names:
        try:
            if fast_mode:
                inline_expanded.append({"PolicyName": n, "Document": None, "Source": "inline"})
            else:
                try:
                    doc = iam_client.get_user_policy(UserName=out.get("UserName"), PolicyName=n)["PolicyDocument"]
                    inline_expanded.append({"PolicyName": n, "Document": doc, "Source": "inline"})
                except Exception:
                    inline_expanded.append({"PolicyName": n, "Document": None, "Source": "inline"})
        except Exception:
            continue
    out["InlinePoliciesExpanded"] = inline_expanded
    return out

def expand_role_policies(iam_client, role_entry: Dict[str, Any], fast_mode: bool=True) -> Dict[str, Any]:
    """
    Expand attached + inline policies for roles. Skip AWS-managed policies documents.
    """
    out = dict(role_entry)
    attached = out.get("AttachedPolicies", []) or []
    expanded = []
    for ap in attached:
        arn = ap.get("PolicyArn") if isinstance(ap, dict) else None
        pname = ap.get("PolicyName") if isinstance(ap, dict) else None
        if arn and _is_aws_managed_policy_arn(arn):
            expanded.append({"PolicyName": pname or arn, "Arn": arn, "Scope": "AWSManaged", "Document": None})
            continue
        if fast_mode:
            expanded.append({"PolicyName": pname or arn, "Arn": arn, "Scope": "Customer", "Document": None})
        else:
            try:
                v = iam_client.get_policy(PolicyArn=arn).get("Policy", {})
                default_vid = v.get("DefaultVersionId")
                if default_vid:
                    pv = iam_client.get_policy_version(PolicyArn=arn, VersionId=default_vid)
                    doc = pv.get("PolicyVersion", {}).get("Document", {})
                    expanded.append({"PolicyName": pname or arn, "Arn": arn, "Scope": "Customer", "Document": doc})
                else:
                    expanded.append({"PolicyName": pname or arn, "Arn": arn, "Scope": "Customer", "Document": None})
            except Exception:
                expanded.append({"PolicyName": pname or arn, "Arn": arn, "Scope": "Customer", "Document": None})
    out["AttachedPoliciesExpanded"] = expanded

    # Inline role policies
    inline_names = out.get("InlinePolicies", []) or []
    inline_expanded = []
    for n in inline_names:
        try:
            if fast_mode:
                inline_expanded.append({"PolicyName": n, "Document": None, "Source": "inline"})
            else:
                try:
                    doc = iam_client.get_role_policy(RoleName=out.get("RoleName"), PolicyName=n)["PolicyDocument"]
                    inline_expanded.append({"PolicyName": n, "Document": doc, "Source": "inline"})
                except Exception:
                    inline_expanded.append({"PolicyName": n, "Document": None, "Source": "inline"})
        except Exception:
            continue
    out["InlinePoliciesExpanded"] = inline_expanded
    return out

def region_fetch_full(session, profile_name: Optional[str], region: str, fast_mode: bool, multi_region: bool=False) -> Dict[str, Any]:
    """
    Perform a robust fetch for a single region. Returns structure with users/groups/roles/policies
    and service resources (via resource_fetch).
    """
    iam = session.client("iam")
    out = {"users": [], "groups": [], "roles": [], "policies": [], "_meta": {}}

    # Snapshot metadata
    out["_meta"]["fetched_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    out["_meta"]["region"] = region

    # -------------------------------------------------------------
    # 1) USERS
    # -------------------------------------------------------------
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page.get("Users", []):
                user = {
                    "UserName": u.get("UserName"),
                    "Arn": u.get("Arn"),
                    "CreateDate": u.get("CreateDate").isoformat() if u.get("CreateDate") else None,
                    "AttachedPolicies": [],
                    "InlinePolicies": []
                }

                if not fast_mode:
                    # Groups
                    try:
                        gr = iam.list_groups_for_user(UserName=user["UserName"]).get("Groups", [])
                        user["Groups"] = [g.get("GroupName") for g in gr]
                    except Exception:
                        user["Groups"] = []

                    # Attached
                    try:
                        att = iam.list_attached_user_policies(UserName=user["UserName"]).get("AttachedPolicies", [])
                        user["AttachedPolicies"] = [_normalize_attached(x) for x in att if _normalize_attached(x)]
                    except Exception:
                        user["AttachedPolicies"] = []

                    # Inline
                    try:
                        inline = iam.list_user_policies(UserName=user["UserName"]).get("PolicyNames", [])
                        user["InlinePolicies"] = inline
                    except Exception:
                        user["InlinePolicies"] = []

                out["users"].append(user)

    except Exception as e:
        logger.warning(f"users list failed: {e}")

    # -------------------------------------------------------------
    # 2) GROUPS
    # -------------------------------------------------------------
    try:
        paginator = iam.get_paginator("list_groups")
        for page in paginator.paginate():
            for g in page.get("Groups", []):
                ge = {
                    "GroupName": g.get("GroupName"),
                    "Arn": g.get("Arn"),
                    "AttachedPolicies": [],
                    "InlinePolicies": []
                }

                if not fast_mode:
                    try:
                        att = iam.list_attached_group_policies(GroupName=ge["GroupName"]).get("AttachedPolicies", [])
                        ge["AttachedPolicies"] = [_normalize_attached(x) for x in att if _normalize_attached(x)]
                    except Exception:
                        ge["AttachedPolicies"] = []

                    try:
                        inline = iam.list_group_policies(GroupName=ge["GroupName"]).get("PolicyNames", [])
                        ge["InlinePolicies"] = inline
                    except Exception:
                        ge["InlinePolicies"] = []

                out["groups"].append(ge)

    except Exception as e:
        logger.warning(f"groups list failed: {e}")

    # -------------------------------------------------------------
    # 3) ROLES (with trust policy analysis)
    # -------------------------------------------------------------
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for r in page.get("Roles", []):
                rname = r.get("RoleName")
                assume_doc = r.get("AssumeRolePolicyDocument") or {}

                role_entry = {
                    "RoleName": rname,
                    "Arn": r.get("Arn"),
                    "AssumeRolePolicyDocument": assume_doc,
                    "AttachedPolicies": [],
                    "InlinePolicies": []
                }

                # Expand trust policy
                try:
                    role_entry = normalize_role_entry(role_entry)
                except Exception:
                    pass

                if not fast_mode:
                    try:
                        att = iam.list_attached_role_policies(RoleName=rname).get("AttachedPolicies", [])
                        role_entry["AttachedPolicies"] = [_normalize_attached(x) for x in att if _normalize_attached(x)]
                    except Exception:
                        role_entry["AttachedPolicies"] = []

                    try:
                        inline = iam.list_role_policies(RoleName=rname).get("PolicyNames", [])
                        role_entry["InlinePolicies"] = inline
                    except Exception:
                        role_entry["InlinePolicies"] = []

                out["roles"].append(role_entry)

    except Exception as e:
        logger.warning(f"roles list failed: {e}")

    # -------------------------------------------------------------
    # 4) POLICIES (customer-managed only)
    # -------------------------------------------------------------
    try:
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for p in page.get("Policies", []):
                p_name = p.get("PolicyName")
                p_arn = p.get("Arn")

                # PATCH #3 — Guaranteed structure
                entry = {
                    "PolicyName": p_name or (p_arn.split("/")[-1] if p_arn else None),
                    "Arn": p_arn,
                    "Document": None,
                    "IsRisky": False,
                    "RiskScore": 0,
                    "Findings": []
                }

                if not fast_mode:
                    try:
                        pol = iam.get_policy(PolicyArn=p_arn).get("Policy", {})
                        vid = pol.get("DefaultVersionId")

                        if vid:
                            pv = iam.get_policy_version(PolicyArn=p_arn, VersionId=vid)
                            doc = pv.get("PolicyVersion", {}).get("Document", {})
                            entry["Document"] = doc

                            # Risk analysis
                            analysis = analyze_policy_document(doc)
                            entry["IsRisky"] = analysis.get("is_risky", False)
                            entry["RiskScore"] = analysis.get("score", 0)
                            entry["Findings"] = analysis.get("findings", [])

                    except Exception as e:
                        logger.debug(f"policy doc fetch failed for {p_arn}: {e}")

                # GUARANTEE Document always exists
                if entry["Document"] is None:
                    entry["Document"] = {}

                out["policies"].append(entry)

    except Exception as e:
        logger.warning(f"list_policies failed: {e}")

    # -------------------------------------------------------------
    # 5) SERVICE RESOURCES (best-effort)
    # -------------------------------------------------------------
    try:
        res = fetch_region_resources(session=boto3.Session(), region_name=region, fast_mode=fast_mode)
        out["_resources"] = res
    except Exception as e:
        logger.debug(f"resource_fetch failed for region {region}: {e}")

    # -------------------------------------------------------------
    # 6) Action -> Resource mapping
    # -------------------------------------------------------------
    try:
        action_map, resource_index = map_actions_to_resources(out["policies"], out.get("_resources", {}))
        out["_action_map"] = action_map
        out["_resource_index"] = resource_index
    except Exception as e:
        logger.debug(f"resolver failed: {e}")

    # -------------------------------------------------------------
    # PATCH #4 — Build action_index for graph_builder speed
    # -------------------------------------------------------------
    action_index = {}
    for p in out.get("policies", []):
        doc = p.get("Document") or {}
        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for stmt in stmts:
            acts = stmt.get("Action") or stmt.get("NotAction") or []
            if not isinstance(acts, list):
                acts = [acts]
            for a in acts:
                if isinstance(a, str):
                    action_index.setdefault(a, []).append(
                        p.get("PolicyName") or p.get("Arn")
                    )

    out["_action_index"] = action_index

    return out

def orchestrate_fetch(session, profile_name: Optional[str], regions: List[str], fast_mode: bool, multi_region: bool=False, progress_callback=None) -> Dict[str, Any]:
    """
    Orchestrate across regions and return final combined snapshot.
    """
    combined = {"_meta": {"fetched_at": datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
                          "regions": [], "fast_mode": bool(fast_mode), "generated_by": "iam-xray-engine"}}
    for idx, region in enumerate(regions):
        try:
            region_snapshot = region_fetch_full(session=session, profile_name=profile_name, region=region, fast_mode=fast_mode, multi_region=multi_region)
            combined["_meta"]["regions"].append(region_snapshot)
            # if single-region, merge top-level
            if not multi_region:
                combined.update({
                    "users": region_snapshot.get("users", []),
                    "groups": region_snapshot.get("groups", []),
                    "roles": region_snapshot.get("roles", []),
                    "policies": region_snapshot.get("policies", []),
                })
            if progress_callback:
                progress_callback((idx+1) / len(regions))
        except Exception as e:
            logger.error(f"region fetch failed for {region}: {e}")
            combined["_meta"].setdefault("warnings", []).append(f"region_failed:{region}:{e}")
            if progress_callback:
                progress_callback((idx+1) / len(regions))
    # finalize metadata
    try:
        final_meta = build_snapshot_metadata(combined)
        combined["_meta"].update(final_meta)
    except Exception as e:
        logger.debug(f"metadata build failed: {e}")

    # -------------------------------------------------------------
    # PATCH #2 — Aggregate per-region _action_index for graph_builder
    # -------------------------------------------------------------
    combined_action_index = {}

    for r in combined["_meta"].get("regions", []):
        # region-level placement (preferred)
        ai = r.get("_action_index")

        # alternative fallback (if metadata builder nested it)
        if not ai:
            ai = r.get("_meta", {}).get("_action_index")

        if not ai:
            continue

        for act, plist in ai.items():
            combined_action_index.setdefault(act, []).extend(plist)

    # Deduplicate policy lists for each action
    for act, lst in combined_action_index.items():
        combined_action_index[act] = sorted(set(lst))

    # Store into top-level meta (graph_builder uses this for performance)
    if combined_action_index:
        combined["_meta"]["action_index"] = combined_action_index

    return combined
