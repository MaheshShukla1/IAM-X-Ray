# core/fetch_iam.py
"""
Lightweight, beta-ready IAM fetcher for IAM X-Ray v0.1.0-beta.

Design goals:
- FAST vs FORCE semantics:
  - FAST (default) -> return cached snapshot quickly if present (seconds)
  - FORCE -> perform fresh light fetch (customer-managed policies, roles, users, groups)
- Access Advisor / service-last-used REMOVED for beta (Option A)
- Minimal risk analysis in-place (wildcards, iam:PassRole, sts:AssumeRole, Resource '*')
- Snapshot metadata (_meta) standardized for graph_builder
- Optional multi-region support
- Optional encryption via core.secure_store
"""
import os
import json
import logging
from datetime import datetime,timezone
from copy import deepcopy
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, NoRegionError, EndpointConnectionError
import functools
import warnings
from core import secure_store
from core import config
from core.cleanup import purge_old_snapshots

logger = logging.getLogger("fetch_iam")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

# Fast detection constants
SENSITIVE_ACTIONS = {"iam:passrole", "sts:assumerole"}
WILDCARD_MARK = "*"


# ---------- Helpers ----------
def _ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def _normalize_action(a):
    return a.lower() if isinstance(a, str) else a


def _action_is_risky(action):
    if not isinstance(action, str):
        return False
    a = _normalize_action(action)
    return a == WILDCARD_MARK or ("*" in a) or (a in SENSITIVE_ACTIONS)


def _light_policy_analysis(doc):
    """
    REAL-WORLD ACCURATE IAM Policy Risk Scoring (2025 Edition)
    Based on AWS Best Practices + Real Red Team Findings
    Score: 0-10 (10 = AdministratorAccess level)
    """
    if not isinstance(doc, dict):
        return {"is_risky": False, "score": 0, "findings": [], "risky_actions": []}

    findings = []
    risky_actions = set()
    score = 0

    stmts = _ensure_list(doc.get("Statement", []))

    for stmt in stmts:
        effect = str(stmt.get("Effect", "Allow")).lower()
        if effect != "allow":
            continue

        actions = _ensure_list(stmt.get("Action", []))
        resources = _ensure_list(stmt.get("Resource", []))
        not_actions = _ensure_list(stmt.get("NotAction", []))

        # Normalize actions
        all_actions = [a.lower() if isinstance(a, str) else "" for a in actions]
        if not_actions:
            all_actions += [f"not:{a.lower()}" if isinstance(a, str) else "" for a in not_actions]

        # 1. Full wildcard (*)
        if any(a == "*" or a.endswith(":*") for a in all_actions):
            if any(r in ["*", "arn:aws:iam::*:*"] for r in resources):
                findings.append("AdministratorAccess equivalent (*:* on * resource)")
                score = max(score, 10)
            else:
                findings.append("Full action wildcard (Action: *)")
                score = max(score, 8)

        # 2. Dangerous privilege escalation actions
        dangerous = {
            "iam:CreatePolicyVersion": 9,
            "iam:SetDefaultPolicyVersion": 8,
            "iam:AttachUserPolicy": 8,
            "iam:AttachGroupPolicy": 8,
            "iam:AttachRolePolicy": 8,
            "iam:PutUserPolicy": 8,
            "iam:PutGroupPolicy": 8,
            "iam:PutRolePolicy": 8,
            "iam:UpdateAssumeRolePolicy": 7,
            "iam:AddUserToGroup": 6,
        }

        for act in all_actions:
            act_clean = act.replace("not:", "")
            if act_clean in dangerous:
                findings.append(f"Privilege Escalation: {act_clean.replace('iam:', '')}")
                score = max(score, dangerous[act_clean])
                risky_actions.add(act_clean)

        # 3. iam:PassRole + ec2:RunInstances = RCE
        has_passrole = any("iam:passrole" in a for a in all_actions)
        has_runinstances = any("ec2:runinstances" in a for a in all_actions)
        if has_passrole and has_runinstances:
            findings.append("RCE Possible: iam:PassRole + ec2:RunInstances")
            score = max(score, 9)

        # 4. sts:AssumeRole with *
        if any("sts:assumerole" in a for a in all_actions):
            if any(r == "*" for r in resources):
                findings.append("Cross-account assumption allowed on any role")
                score = max(score, 9)
            else:
                findings.append("sts:AssumeRole allowed")
                score = max(score, 7)

        # 5. Resource: *
        if any(str(r).strip() == "*" for r in resources):
            findings.append("Resource: * (no resource constraint)")
            score = max(score, 7)

        # 6. Full IAM access
        if any(a in ["iam:*", "iam:*/*"] for a in all_actions):
            findings.append("Full IAM control (iam:*)")
            score = max(score, 9)

    # Final score cap
    final_score = min(10, score) if findings else 0
    is_risky = final_score >= 5

    return {
        "is_risky": is_risky,
        "score": int(final_score),
        "findings": findings[:8],  # limit
        "risky_actions": sorted(list(risky_actions))[:10]
    }


# ---------- Snapshot load/write helpers ----------
def _plaintext_read(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
            return json.loads(raw) if raw else None
    except Exception as e:
        logger.debug(f"_plaintext_read failed for {path}: {e}")
        return None


def load_snapshot(path):
    """
    Load snapshot gracefully:
      - Accepts plaintext or .enc variant (if path doesn't exist but path + '.enc' does)
      - Tries secure_store.decrypt_and_read / read_and_decrypt if present (handles .enc)
      - Falls back to plaintext read
      - Returns None on failure (caller handles)
    """
    if not path:
        return None

    # If plaintext doesn't exist but encrypted variant does, prefer .enc
    candidates = []
    if os.path.exists(path):
        candidates.append(path)
    if os.path.exists(path + ".enc"):
        candidates.append(path + ".enc")

    # If neither exists, return None
    if not candidates:
        return None

    last_err = None
    for p in candidates:
        try:
            # prefer secure_store decrypt API if available
            try:
                if hasattr(secure_store, "decrypt_and_read"):
                    return secure_store.decrypt_and_read(p)
                if hasattr(secure_store, "read_and_decrypt"):
                    return secure_store.read_and_decrypt(p)
            except Exception as e:
                logger.debug(f"secure_store decrypt/read failed for {p}: {e}")

            # plaintext fallback
            res = _plaintext_read(p)
            if res is not None:
                return res
        except Exception as e:
            last_err = e
            logger.debug(f"load_snapshot attempt failed for {p}: {e}")
            continue

    if last_err:
        logger.warning(f"load_snapshot failed: {last_err}")
    return None


# ---------- Diff helpers (kept simple) ----------
def _index_by(items, key):
    out = {}
    for it in items or []:
        k = it.get(key)
        if k:
            out[k] = it
    return out


def _shallow_equal(a, b):
    try:
        return json.dumps(a, sort_keys=True, default=str) == json.dumps(b, sort_keys=True, default=str)
    except Exception:
        return False


def _compute_entity_diff(prev_list, new_list, key):
    prev = _index_by(prev_list, key)
    new = _index_by(new_list, key)
    added = sorted([k for k in new.keys() - prev.keys()])
    removed = sorted([k for k in prev.keys() - new.keys()])
    modified = []
    modified_details = {}
    for k in new.keys() & prev.keys():
        if not _shallow_equal(prev[k], new[k]):
            modified.append(k)
            diff_keys = []
            for field in set(prev[k].keys()) | set(new[k].keys()):
                if prev[k].get(field) != new[k].get(field):
                    diff_keys.append(field)
            modified_details[k] = diff_keys
    return {"added": added, "removed": removed, "modified": sorted(modified), "modified_details": modified_details}


def _apply_change_flags(snapshot, diff):
    for entity, key in [("users", "UserName"), ("groups", "GroupName"), ("roles", "RoleName"), ("policies", "PolicyName")]:
        for name in diff[entity]["added"]:
            x = next((u for u in snapshot.get(entity, []) if u.get(key) == name), None)
            if x:
                x["_changed"] = "added"
        for name in diff[entity]["modified"]:
            x = next((u for u in snapshot.get(entity, []) if u.get(key) == name), None)
            if x:
                x["_changed"] = "modified"


# ---------- Light fetch implementations ----------
@functools.lru_cache()
def _get_boto3_session_cached(profile_name=None, aws_access_key_id=None, aws_secret_access_key=None, aws_session_token=None, region_name=None):
    """
    Return a boto3.Session. Cache to avoid re-init cost across calls.
    """
    kwargs = {}
    if profile_name:
        kwargs["profile_name"] = profile_name
    if aws_access_key_id and aws_secret_access_key:
        kwargs["aws_access_key_id"] = aws_access_key_id
        kwargs["aws_secret_access_key"] = aws_secret_access_key
        if aws_session_token:
            kwargs["aws_session_token"] = aws_session_token
    if region_name:
        kwargs["region_name"] = region_name
    try:
        return boto3.Session(**kwargs) if kwargs else boto3.Session()
    except Exception as e:
        logger.error(f"Failed to init boto3 Session: {e}")
        raise

def _analyze_trust_policy(doc):
    """
    Analyze Role Trust Policy for Risk (Cross-account, *, no conditions)
    """
    if not isinstance(doc, dict):
        return {"score": 0, "findings": [], "is_risky": False}

    findings = []
    score = 0
    stmts = _ensure_list(doc.get("Statement", []))

    for stmt in stmts:
        effect = str(stmt.get("Effect", "Allow")).lower()
        if effect != "allow":
            continue

        principal = stmt.get("Principal", {})
        condition = stmt.get("Condition", {})

        # Wildcard principal
        if principal == "*" or (isinstance(principal, dict) and ("*" in principal or principal.get("*"))):
            if not condition:
                findings.append("Anyone can assume this role (Principal: *)")
                score = 10
            else:
                findings.append("Principal: * with conditions")
                score = max(score, 7)

        # Cross-account trust without ExternalId/StringEquals
        if isinstance(principal, dict):
            aws = _ensure_list(principal.get("AWS", []))
            for p in aws:
                if isinstance(p, str) and p.startswith("arn:aws:iam::") and ":root" not in p:
                    account_id = p.split(":")[4]
                    if not condition.get("StringEquals", {}).get("aws:PrincipalOrgID"):
                        findings.append(f"Cross-account trust: {account_id}")
                        score = max(score, 8)

    is_risky = score >= 6
    return {
        "score": min(10, score),
        "findings": findings[:5],
        "is_risky": is_risky
    }

def _light_fetch_region(iam_client, account_id, fast_mode=True):
    """
    Perform a light (fast) fetch for the provided IAM client.
    Returns dict with users, groups, roles, policies (customer-managed).
    Now with GOD-TIER Risk Scoring + Trust Policy Analysis
    """
    out = {"users": [], "groups": [], "roles": [], "policies": []}

    # Users
    try:
        paginator = iam_client.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page.get("Users", []):
                entry = {
                    "UserName": u.get("UserName"),
                    "Arn": u.get("Arn"),
                    "CreateDate": u.get("CreateDate").isoformat() if u.get("CreateDate") else None,
                    "AttachedPolicies": [],
                    "InlinePolicies": []
                }
                if not fast_mode:
                    try:
                        groups = iam_client.list_groups_for_user(UserName=entry["UserName"]).get("Groups", [])
                        entry["Groups"] = [g.get("GroupName") for g in groups]
                    except Exception: entry["Groups"] = []
                    try:
                        att = iam_client.list_attached_user_policies(UserName=entry["UserName"]).get("AttachedPolicies", [])
                        entry["AttachedPolicies"] = att
                    except Exception: entry["AttachedPolicies"] = []
                    try:
                        inline = iam_client.list_user_policies(UserName=entry["UserName"]).get("PolicyNames", [])
                        entry["InlinePolicies"] = inline
                    except Exception: entry["InlinePolicies"] = []
                out["users"].append(entry)
    except Exception as e:
        logger.warning(f"list_users failed: {e}")

    # Groups
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
                if not fast_mode:
                    try:
                        att = iam_client.list_attached_group_policies(GroupName=entry["GroupName"]).get("AttachedPolicies", [])
                        entry["AttachedPolicies"] = att
                    except Exception: entry["AttachedPolicies"] = []
                    try:
                        inline = iam_client.list_group_policies(GroupName=entry["GroupName"]).get("PolicyNames", [])
                        entry["InlinePolicies"] = inline
                    except Exception: entry["InlinePolicies"] = []
                out["groups"].append(entry)
    except Exception as e:
        logger.warning(f"list_groups failed: {e}")

    # Roles + TRUST POLICY RISK ANALYSIS
    try:
        paginator = iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            for r in page.get("Roles", []):
                rname = r.get("RoleName")
                assume_raw = r.get("AssumeRolePolicyDocument", {})
                assume = assume_raw if isinstance(assume_raw, dict) else {}

                # Parse principals (existing logic)
                principals_info = []
                try:
                    stmts = assume.get("Statement", [])
                    if isinstance(stmts, dict):
                        stmts = [stmts]
                    for s in stmts:
                        principal = s.get("Principal", {})
                        if isinstance(principal, dict):
                            for k in ("Service", "AWS", "Federated"):
                                vals = principal.get(k)
                                if vals:
                                    if isinstance(vals, str):
                                        vals = [vals]
                                    for val in vals:
                                        principals_info.append({"type": k, "value": val})
                        elif principal == "*":
                            principals_info.append({"type": "wildcard", "value": "*"})
                except Exception:
                    principals_info = []

                entry = {
                    "RoleName": rname,
                    "Arn": r.get("Arn"),
                    "AssumeRolePolicyDocument": assume,
                    "PrincipalsInfo": principals_info,
                    "AttachedPolicies": [],
                    "InlinePolicies": [],
                    "AssumePolicyRiskScore": 0,
                    "TrustPolicyFindings": [],
                    "IsRiskyTrust": False
                }

                # Add Trust Policy Risk Analysis
                trust_analysis = _analyze_trust_policy(assume)
                entry["AssumePolicyRiskScore"] = trust_analysis["score"]
                entry["TrustPolicyFindings"] = trust_analysis["findings"]
                entry["IsRiskyTrust"] = trust_analysis["is_risky"]

                if not fast_mode:
                    try:
                        att = iam_client.list_attached_role_policies(RoleName=rname).get("AttachedPolicies", [])
                        entry["AttachedPolicies"] = att
                    except Exception: pass
                    try:
                        inline = iam_client.list_role_policies(RoleName=rname).get("PolicyNames", [])
                        entry["InlinePolicies"] = inline
                    except Exception: pass

                out["roles"].append(entry)
    except Exception as e:
        logger.warning(f"list_roles failed: {e}")

    # Policies + FULL RISK ANALYSIS (only in FULL mode)
    try:
        paginator = iam_client.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for p in page.get("Policies", []):
                p_name = p.get("PolicyName")
                p_arn = p.get("Arn")

                entry = {
                    "PolicyName": p_name,
                    "Arn": p_arn,
                    "Document": {},
                    "IsRisky": False,
                    "RiskScore": 0,
                    "Findings": []
                }

                # FULL MODE: Fetch + Analyze Policy Document
                if not fast_mode:
                    try:
                        version = iam_client.get_policy_version(
                            PolicyArn=p_arn,
                            VersionId=p["DefaultVersionId"]
                        )
                        doc_raw = version["PolicyVersion"]["Document"]

                        # Handle URL-encoded JSON string
                        if isinstance(doc_raw, str):
                            import urllib.parse
                            doc = json.loads(urllib.parse.unquote(doc_raw))
                        else:
                            doc = doc_raw

                        analysis = _light_policy_analysis(doc)
                        entry.update({
                            "Document": doc,
                            "IsRisky": analysis["is_risky"],
                            "RiskScore": analysis["score"],
                            "Findings": analysis["findings"]
                        })
                    except Exception as e:
                        logger.debug(f"Failed to analyze policy {p_name}: {e}")

                out["policies"].append(entry)
    except Exception as e:
        logger.warning(f"list_policies failed: {e}")

    return out

# ---------- Public API: fetch_iam_data ----------
def fetch_iam_data(
    session=None,
    profile_name=None,
    out_path=None,
    fast_mode=True,
    force_fetch=False,
    encrypt=False,
    multi_region=False,
    regions=None,
    progress_callback=None,
    cache_ttl=None,
    **kwargs
):
    """
    Top-level fetch function for IAM snapshots.

    - session/profile_name: optional boto3 Session or profile
    - out_path: output path for snapshot (string)
    - fast_mode: boolean (default True) -> light fetch defaults
    - force_fetch: boolean (default False) -> if False and snapshot exists, return cached
    - encrypt: boolean -> use secure_store to encrypt output (if available)
    - multi_region: boolean -> fetch for multiple regions (not usually needed for IAM, kept for compatibility)
    - regions: list override of regions (if multi_region True)
    - progress_callback: optional function(0.0..1.0) for progress
    """


    # 1) TTL fallback to config if UI didn't pass it
    try:
      default_ttl = getattr(config, "CACHE_TTL", 3600)
    except Exception:
      default_ttl = 3600

    if cache_ttl is None:
       cache_ttl = default_ttl

    logger.info(f"Using cache_ttl = {cache_ttl}s")

    # ✅ Add this block here
    if kwargs:
      warnings.warn(f"Ignoring unsupported parameters: {list(kwargs.keys())}")

    # Normalize out_path using config if not provided
    out_path = out_path or getattr(config, "SNAPSHOT_PATH", os.path.join(getattr(config, "DATA_DIR", "data"), "iam_snapshot.json"))
    out_dir = os.path.dirname(out_path) or "."
    os.makedirs(out_dir, exist_ok=True)

    # FAST cache shortcut: detect either plaintext or .enc snapshot
    cache_candidates = []
    if os.path.exists(out_path):
        cache_candidates.append(out_path)
    if os.path.exists(out_path + ".enc"):
        cache_candidates.append(out_path + ".enc")

    if not force_fetch and fast_mode and cache_candidates:
        # try loading first available candidate; return if valid
        for c in cache_candidates:
            try:
                cached = load_snapshot(c)
                if cached and isinstance(cached, dict):
                    logger.info("FAST: returning cached snapshot (set force_fetch=True to refresh).")
                    return cached
            except Exception as e:
                logger.warning(f"FAST mode: failed to load cached snapshot {c}: {e}")
        # fall through to fetch if cached loads failed

    # Create boto3 session if not provided
    if isinstance(session, boto3.Session):
        session_obj = session
    else:
        # allow profile_name or fallback to default
        session_obj = _get_boto3_session_cached(profile_name)

    # Regions handling: IAM is global but honor one region config for client creation
    if multi_region:
        regions = regions or getattr(config, "DEFAULT_REGIONS", ["us-east-1"])
    else:
        regions = regions or [getattr(config, "AWS_REGION", "us-east-1")]

    combined = {"_meta": {
        "fetched_at":datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "fast_mode": bool(fast_mode),
        "regions": [],
        "warnings": []
    }}

    # Load previous snapshot if present (try both plaintext and .enc)
    prev_snapshot = None
    prev_candidates = []
    if os.path.exists(out_path):
        prev_candidates.append(out_path)
    if os.path.exists(out_path + ".enc"):
        prev_candidates.append(out_path + ".enc")
    for pc in prev_candidates:
        prev_snapshot = load_snapshot(pc)
        if prev_snapshot:
            break

    total_regions = len(regions)
    for idx, region in enumerate(regions):
        try:
            # iam is global but session may require region_name (safe)
            sess = _get_boto3_session_cached(profile_name, region_name=region)
            iam = sess.client("iam")
            # simple check to get account id
            try:
                sts = sess.client("sts")
                caller = sts.get_caller_identity()
                account_id = caller.get("Account")
            except Exception:
                account_id = None
        except (ClientError, NoCredentialsError, NoRegionError, EndpointConnectionError) as e:
            msg = f"Failed to init IAM client for region {region}: {e}"
            logger.error(msg)
            combined["_meta"]["warnings"].append(msg)
            if progress_callback:
                progress_callback((idx + 1) / total_regions)
            continue

        # Light fetch per region
        try:
            region_snapshot = _light_fetch_region(iam, account_id, fast_mode=fast_mode)
        except Exception as e:
            logger.error(f"Light fetch failed for region {region}: {e}")
            combined["_meta"]["warnings"].append(f"region_fetch_failed:{region}:{e}")
            region_snapshot = {"users": [], "groups": [], "roles": [], "policies": []}

        # Add meta for region
        region_meta = {
            "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "fast_mode": bool(fast_mode),
            "account_id": account_id,
            "region": region,
            "counts": {
                "users": len(region_snapshot.get("users", [])),
                "groups": len(region_snapshot.get("groups", [])),
                "roles": len(region_snapshot.get("roles", [])),
                "policies": len(region_snapshot.get("policies", [])),
            }
        }
        region_snapshot["_meta"] = region_meta

        # Compute diff vs prev snapshot (region-aware)
        if prev_snapshot:
            prev_region = None
            if isinstance(prev_snapshot, dict) and prev_snapshot.get("_meta", {}).get("regions"):
                for r in prev_snapshot["_meta"].get("regions", []):
                    if r.get("_meta", {}).get("region") == region:
                        prev_region = r
                        break
            else:
                prev_region = prev_snapshot

            if prev_region:
                diff = {
                    "users": _compute_entity_diff(prev_region.get("users", []), region_snapshot.get("users", []), "UserName"),
                    "groups": _compute_entity_diff(prev_region.get("groups", []), region_snapshot.get("groups", []), "GroupName"),
                    "roles": _compute_entity_diff(prev_region.get("roles", []), region_snapshot.get("roles", []), "RoleName"),
                    "policies": _compute_entity_diff(prev_region.get("policies", []), region_snapshot.get("policies", []), "PolicyName"),
                }
            else:
                diff = {
                    "users": _compute_entity_diff([], region_snapshot.get("users", []), "UserName"),
                    "groups": _compute_entity_diff([], region_snapshot.get("groups", []), "GroupName"),
                    "roles": _compute_entity_diff([], region_snapshot.get("roles", []), "RoleName"),
                    "policies": _compute_entity_diff([], region_snapshot.get("policies", []), "PolicyName"),
                }
        else:
            diff = {
                "users": _compute_entity_diff([], region_snapshot.get("users", []), "UserName"),
                "groups": _compute_entity_diff([], region_snapshot.get("groups", []), "GroupName"),
                "roles": _compute_entity_diff([], region_snapshot.get("roles", []), "RoleName"),
                "policies": _compute_entity_diff([], region_snapshot.get("policies", []), "PolicyName"),
            }

        _apply_change_flags(region_snapshot, diff)

        diff_counts = {
            "added": sum(len(diff[e]["added"]) for e in diff),
            "removed": sum(len(diff[e]["removed"]) for e in diff),
            "modified": sum(len(diff[e]["modified"]) for e in diff),
        }
        risk_sum = sum(p.get("RiskScore", 0) for p in region_snapshot.get("policies", [])) + sum(r.get("AssumePolicyRiskScore", 0) for r in region_snapshot.get("roles", []))
        impact_score = diff_counts["added"] * 2 + diff_counts["modified"] * 1 + (risk_sum * 0.1)

        region_snapshot["_meta"]["diff"] = diff
        region_snapshot["_meta"]["diff_counts"] = diff_counts
        region_snapshot["_meta"]["impact_score"] = impact_score

        combined["_meta"]["regions"].append(region_snapshot)

        # If only single-region mode, merge into top-level arrays for compatibility
        if not multi_region:
            combined["users"] = region_snapshot.get("users", [])
            combined["groups"] = region_snapshot.get("groups", [])
            combined["roles"] = region_snapshot.get("roles", [])
            combined["policies"] = region_snapshot.get("policies", [])
            combined["_meta"]["counts"] = region_snapshot["_meta"]["counts"]
            combined["_meta"]["diff"] = region_snapshot["_meta"]["diff"]
            combined["_meta"]["impact_score"] = region_snapshot["_meta"]["impact_score"]

        if progress_callback:
            progress_callback((idx + 1) / total_regions)

    # aggregated counts for multi-region
    if multi_region:
        counts = {"users": 0, "groups": 0, "roles": 0, "policies": 0}
        for r in combined["_meta"]["regions"]:
            c = r.get("_meta", {}).get("counts", {})
            counts["users"] += c.get("users", 0)
            counts["groups"] += c.get("groups", 0)
            counts["roles"] += c.get("roles", 0)
            counts["policies"] += c.get("policies", 0)
        combined["_meta"]["counts"] = counts
        # simple aggregated diff counts
        agg_counts = {"added": 0, "removed": 0, "modified": 0}
        sum_impact = 0
        for r in combined["_meta"]["regions"]:
            dc = r["_meta"].get("diff_counts", {})
            agg_counts["added"] += dc.get("added", 0)
            agg_counts["removed"] += dc.get("removed", 0)
            agg_counts["modified"] += dc.get("modified", 0)
            sum_impact += r["_meta"].get("impact_score", 0)
        combined["_meta"]["diff"] = {"counts": agg_counts}
        combined["_meta"]["impact_score"] = (sum_impact / len(combined["_meta"]["regions"])) if combined["_meta"]["regions"] else 0

    # Persist snapshot (encrypt or plaintext). Use consistent file name: out_path
    try:
        if encrypt and hasattr(secure_store, "encrypt_and_write"):
            # secure_store.encrypt_and_write will append .enc if needed
            secure_store.encrypt_and_write(combined, out_path)
            logger.info(f"Snapshot encrypted and saved -> {out_path}(.enc)")
        else:
            # Write plaintext atomically
            tmp = out_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(combined, fh, indent=2, default=str)
            os.replace(tmp, out_path)
            logger.info(f"Snapshot written to {out_path}")
    except Exception as e:
        logger.error(f"Failed to write snapshot: {e}")
        combined["_meta"].setdefault("warnings", []).append(f"write_failed:{e}")

    # Purge old snapshots (synchronous; safe)
    try:
        # purge_old_snapshots expects keep_days param optionally; internal cleanup module already knows DATA_DIR
        purge_old_snapshots(getattr(config, "KEEP_DAYS", 30))
    except Exception as e:
        logger.debug(f"purge_old_snapshots error: {e}")

    return combined


# ---------- CLI convenience ----------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="IAM X-Ray - light IAM fetch (beta)")
    parser.add_argument("--profile", help="AWS profile name", default=None)
    parser.add_argument("--out", help="Output snapshot path", default=getattr(config, "SNAPSHOT_PATH", None))
    parser.add_argument("--fast", dest="fast_mode", action="store_true", help="Fast (light) fetch")
    parser.add_argument("--force", dest="force_fetch", action="store_true", help="Force fetch (ignore cache)")
    parser.add_argument("--encrypt", dest="encrypt", action="store_true", help="Encrypt snapshot (if secure_store available)")
    parser.add_argument("--multi_region", dest="multi_region", action="store_true", help="Fetch across DEFAULT_REGIONS")
    args = parser.parse_args()

    s = fetch_iam_data(
        session=None,
        profile_name=args.profile,
        out_path=args.out,
        fast_mode=bool(args.fast_mode),
        force_fetch=bool(args.force_fetch),
        encrypt=bool(args.encrypt),
        multi_region=bool(args.multi_region)
    )
    print("Snapshot meta:", s.get("_meta", {}))
