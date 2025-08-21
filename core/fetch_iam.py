import boto3
import json
import os
import urllib.parse
import logging
from datetime import datetime
from copy import deepcopy
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError, NoRegionError
import time
import random
from core import secure_store
from core.cleanup import purge_old_snapshots

logger = logging.getLogger("fetch_iam")
logger.setLevel(logging.INFO)

# if no handlers, add a basic one (prevents "No handler" in some environments)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

SENSITIVE_ACTIONS = {"iam:passrole", "sts:assumerole"}
WILDCARD_ACTION = "*"
DEFAULT_SNAPSHOT = "data/iam_snapshot.json"
VERSIONED_DIR = "data/snapshots"  # will also store timestamped copies


# ---------- Utility ----------
def _normalize_action(a):
    return a.lower() if isinstance(a, str) else a


def _action_is_risky(action):
    if not isinstance(action, str):
        return False
    a = _normalize_action(action)
    return (a == WILDCARD_ACTION) or ("*" in a) or (a in SENSITIVE_ACTIONS)


def _extract_actions_from_statement(stmt):
    actions = stmt.get("Action") or stmt.get("NotAction") or []
    return [actions] if isinstance(actions, str) else actions


def _ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def _read_snapshot(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
            return json.loads(raw) if raw else None
    except Exception as e:
        logger.warning(f"Failed to read snapshot {path}: {e}")
        return None


# ---------- Principal parsing ----------
def _parse_principal_value(val):
    if isinstance(val, str):
        if val.endswith(".amazonaws.com"):
            return {"type": "service", "value": val}
        elif val.startswith("arn:aws:iam::"):
            return {"type": "account", "value": val}
        elif val in ("*",):
            return {"type": "wildcard", "value": val}
        elif "http" in val or "." in val:
            return {"type": "federated", "value": val}
        else:
            return {"type": "unknown", "value": val}
    return {"type": "unknown", "value": val}


# ---------- Diff helpers ----------
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
            x = next((u for u in snapshot[entity] if u.get(key) == name), None)
            if x:
                x["_changed"] = "added"
        for name in diff[entity]["modified"]:
            x = next((u for u in snapshot[entity] if u.get(key) == name), None)
            if x:
                x["_changed"] = "modified"


# ---------- Extended static analyzer ----------
FINDING = lambda code, sev, msg, hint=None, path=None: {
    "code": code, "severity": sev, "message": msg, "hint": hint, "path": path
}


def _svc(action):
    """Return 'service' of 'service:Action' or '*'."""
    if not isinstance(action, str):
        return ""
    if action == "*":
        return "*"
    parts = action.split(":", 1)
    return parts[0].lower() if len(parts) == 2 else action.lower()


def _analyze_policy_document_extended(doc):
    findings = []
    risky_actions = set()
    if not doc:
        return {"is_risky": False, "risky_actions": [], "score": 0, "findings": []}

    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]

    for idx, stmt in enumerate(stmts):
        path = f"Statement[{idx}]"
        effect = (stmt.get("Effect") or "Allow").lower()

        actions = _ensure_list(stmt.get("Action")) or []
        not_actions = _ensure_list(stmt.get("NotAction")) or []
        resources = _ensure_list(stmt.get("Resource")) or []
        cond = stmt.get("Condition") or {}

        # A1: Wildcard in Action/NotAction
        if "*" in actions or any(isinstance(a, str) and "*" in a for a in actions):
            findings.append(FINDING("ACTION_WILDCARD", "high",
                                   "Action uses '*' or wildcard pattern", "List explicit actions instead of '*'", path))
        if not_actions:
            findings.append(FINDING("NOTACTION_USED", "medium",
                                   "NotAction is used (hard to reason least-privilege)", "Prefer explicit 'Action' allow list", path))

        # A2: Sensitive actions without guard
        alow = [a.lower() for a in actions if isinstance(a, str)]
        if any(a in alow for a in ["iam:passrole", "sts:assumerole"]):
            if "*" in resources or any(r == "*" for r in resources):
                findings.append(FINDING("SENSITIVE_NO_RESOURCE_SCOPE", "high",
                                       "Sensitive action with Resource '*'", "Limit to specific ARNs and require conditions", path))
            if not cond:
                findings.append(FINDING("SENSITIVE_NO_CONDITION", "medium",
                                       "Sensitive action without condition", "Add conditions like aws:ResourceTag, aws:PrincipalArn, ExternalId", path))

        # R1: Resource wildcard with Allow
        if effect == "allow":
            if "*" in resources or any(isinstance(r, str) and r.strip() == "*" for r in resources):
                findings.append(FINDING("RESOURCE_WILDCARD", "high",
                                       "Resource is '*' with Allow", "Scope resources to specific ARNs or tags", path))

        # KMS: Decrypt without constraints
        if any(_svc(a) == "kms" and a.lower().endswith(":decrypt") for a in alow):
            if "*" in resources or not cond:
                findings.append(FINDING("KMS_DECRYPT_PERMISSIVE", "high",
                                       "kms:Decrypt broadly allowed", "Constrain by kms:EncryptionContext conditions and specific key ARNs", path))

        # S3 broad
        if any(_svc(a) == "s3" for a in alow):
            if "*" in resources:
                findings.append(FINDING("S3_BROAD", "medium",
                                       "S3 access with Resource '*'", "Scope to bucket and object ARNs; add aws:userid or IP conditions", path))

        # Collect risky actions set (structural)
        for a in actions or []:
            if _action_is_risky(a):
                risky_actions.add(a)
        # Wildcard resource marker:
        if any(isinstance(r, str) and r.strip() == "*" for r in resources):
            risky_actions.add("Resource:*")

    # Score: weighted
    score = 0
    for f in findings:
        score += {"low": 1, "medium": 2, "high": 4}.get(f["severity"], 1)
    score = max(0, min(10, score))

    return {
        "is_risky": len(findings) > 0 or len(risky_actions) > 0,
        "risky_actions": sorted(list(risky_actions)),
        "score": score,
        "findings": findings
    }


def _analyze_trust_policy(assume_doc):
    findings = []
    if not assume_doc:
        return {"is_risky": False, "risky_actions": [], "score": 0, "findings": []}

    stmts = assume_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]

    risky_actions = set()
    for idx, s in enumerate(stmts):
        path = f"Trust[{idx}]"
        principal = s.get("Principal", {})
        effect = (s.get("Effect") or "Allow").lower()
        if effect != "allow":
            continue

        if principal == "*" or (isinstance(principal, dict) and any(v == "*" for v in principal.values())):
            findings.append(FINDING("TRUST_WILDCARD_PRINCIPAL", "high",
                                   "Trust policy allows '*' principal", "Restrict to specific AWS account/roles or services; consider aws:PrincipalOrgID", path))

        # Service principals
        if isinstance(principal, dict):
            for k in ["Service", "AWS", "Federated"]:
                vals = _ensure_list(principal.get(k))
                if any(v == "*" for v in vals):
                    findings.append(FINDING("TRUST_WILDCARD_COMPONENT", "high",
                                           f"Trust principal '{k}' uses '*'", "Pin to exact principal", path))

        cond = s.get("Condition") or {}
        # If AWS account principal used, suggest ExternalId/Org constraint
        if isinstance(principal, dict) and ("AWS" in principal):
            if not cond:
                findings.append(FINDING("TRUST_NO_CONDITION", "medium",
                                       "Account principal without conditions", "Add external ID or aws:PrincipalOrgID / SourceAccount", path))

        risky_actions.add("Trust:*")

    score = 0
    for f in findings:
        score += {"low": 1, "medium": 2, "high": 4}.get(f["severity"], 1)
    score = max(0, min(10, score))
    return {
        "is_risky": len(findings) > 0,
        "risky_actions": sorted(list(risky_actions)),
        "score": score,
        "findings": findings
    }


# ---------- Access Advisor integration ----------
def _resolve_identifier_to_arn(iam_client, entity_type, identifier, account_id=None):
    """
    If identifier is already an ARN, return it. Otherwise try IAM API calls to get an ARN.
    entity_type: 'user'|'role'|'group'|'policy'
    identifier: may be name or arn
    """
    if not identifier:
        return None

    if isinstance(identifier, str) and identifier.startswith("arn:"):
        return identifier

    try:
        if entity_type == "user":
            resp = iam_client.get_user(UserName=identifier)
            return resp.get("User", {}).get("Arn")
        if entity_type == "role":
            resp = iam_client.get_role(RoleName=identifier)
            return resp.get("Role", {}).get("Arn")
        if entity_type == "group":
            # get_group returns Group structure
            resp = iam_client.get_group(GroupName=identifier)
            return resp.get("Group", {}).get("Arn")
        if entity_type == "policy":
            # identifier may be an ARN already; if not, try list or get_policy by ARN fails for name
            # We'll attempt to find local policy by name via list_policies (Local scope)
            paginator = iam_client.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local"):
                for p in page.get("Policies", []):
                    if p.get("PolicyName") == identifier:
                        return p.get("Arn")
            # fallback: maybe identifier is ARN-like, return as-is
            return identifier
    except ClientError as e:
        logger.debug(f"Could not resolve ARN for {entity_type} {identifier}: {e}")
    except Exception as e:
        logger.debug(f"Resolve ARN exception for {entity_type} {identifier}: {e}")
    # last resort: if account_id and group name, build group ARN
    if account_id and entity_type in ("group",):
        try:
            return f"arn:aws:iam::{account_id}:group/{identifier}"
        except Exception:
            pass
    return None


def _safe_backoff_sleep(attempt):
    # jittered exponential backoff
    base = 0.5
    wait = base * (2 ** attempt)
    jitter = wait * 0.2 * (0.5 - random.random())
    # fallback if math.random not available (shouldn't happen)
    try:
        time.sleep(wait)
    except Exception:
        time.sleep(min(wait, 5))


def fetch_service_last_used(iam_client, entity_type, identifier, account_id=None, max_wait=120):
    """
    Fetch service last accessed details using AWS Access Advisor APIs.

    Returns:
      {
        "services": [ {"service": "s3", "service_namespace":"s3", "last_accessed": ISO8601 or None, "actions": [{"action": "GetObject", "last_accessed": ISO or None, "raw": {...}}], "raw": {...}}, ... ],
        "last_refreshed": ISO8601 or None,
        "status": "success" | "failed" | "timeout" | "unsupported",
        "error": optional error message
      }

    Notes:
    - identifier can be an ARN or a name. We attempt to resolve name -> ARN when needed.
    - max_wait is seconds to poll for job completion (default 120s).
    - Uses ACTION_LEVEL granularity for detailed action info.
    """
    # Validate input
    if not identifier:
        return {"services": [], "last_refreshed": None, "status": "failed", "error": "Missing identifier"}

    # Resolve to ARN if necessary
    arn = identifier if isinstance(identifier, str) and identifier.startswith("arn:") else None
    if not arn:
        arn = _resolve_identifier_to_arn(iam_client, entity_type, identifier, account_id=account_id)
    if not arn:
        return {"services": [], "last_refreshed": None, "status": "failed", "error": f"Could not resolve ARN for {entity_type}:{identifier}"}

    # Attempt to generate details with retries on throttling
    attempts = 0
    max_attempts = 5
    job_id = None
    while attempts < max_attempts:
        try:
            gen_resp = iam_client.generate_service_last_accessed_details(
                Arn=arn,
                Granularity='ACTION_LEVEL'  # For detailed actions
            )
            job_id = gen_resp.get("JobId")
            break
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            msg = str(e)
            if code in ("Throttling", "ThrottlingException", "ServiceUnavailable", "TooManyRequestsException"):
                backoff = (2 ** attempts) * 0.5
                logger.warning(f"Throttled generating Access Advisor details for {arn}, attempt {attempts+1}/{max_attempts}. Backing off {backoff}s.")
                time.sleep(backoff)
                attempts += 1
                continue
            logger.error(f"Access Advisor API failed for {arn} (sanitized).")
            return {"services": [], "last_refreshed": None, "status": "failed", "error": msg}
        except Exception as e:
            logger.error(f"Unexpected error generating Access Advisor details for {arn}: {e}")
            return {"services": [], "last_refreshed": None, "status": "failed", "error": str(e)}

    if not job_id:
        return {"services": [], "last_refreshed": None, "status": "failed", "error": "Failed to start Access Advisor job"}

    # Poll for completion
    start = time.time()
    poll_interval = 3
    while time.time() - start < max_wait:
        try:
            details_resp = iam_client.get_service_last_accessed_details(JobId=job_id)
            status = details_resp.get("JobStatus")
            if status == "COMPLETED":
                services_raw = details_resp.get("ServicesLastAccessed", []) or []
                out_services = []
                for s in services_raw:
                    svc_ns = s.get("ServiceNamespace") or s.get("ServiceName") or s.get("Service")
                    last_time = s.get("LastAuthenticated") or s.get("LastAuthenticatedTime") or s.get("LastAccessedTime") or s.get("LastAccessed")
                    if isinstance(last_time, datetime):
                        last_iso = last_time.isoformat() + "Z" if last_time.tzinfo is None else last_time.isoformat()
                    else:
                        last_iso = str(last_time) if last_time else None

                    actions = []
                    for act in s.get("TrackedActionsLastAccessed", []):
                        act_last = act.get("LastAccessedTime") or act.get("LastAccessed")
                        if isinstance(act_last, datetime):
                            act_iso = act_last.isoformat() + "Z" if act_last.tzinfo is None else act_last.isoformat()
                        else:
                            act_iso = str(act_last) if act_last else None
                        actions.append({
                            "action": act.get("ActionName"),
                            "last_accessed": act_iso,
                            "raw": act
                        })

                    out_services.append({
                        "service": svc_ns,
                        "service_namespace": svc_ns,
                        "last_accessed": last_iso,
                        "actions": actions,
                        "raw": s
                    })

                last_ref = None
                js_date = details_resp.get("JobCompletionDate") or details_resp.get("JobCreationDate")
                if isinstance(js_date, datetime):
                    last_ref = js_date.isoformat() + "Z" if js_date.tzinfo is None else js_date.isoformat()
                elif js_date:
                    last_ref = str(js_date)
                return {"services": out_services, "last_refreshed": last_ref, "status": "success"}
            elif status in ("IN_PROGRESS", "INPROGRESS", "IN_PROGRESS", None):
                time.sleep(poll_interval)
                continue
            elif status == "FAILED":
                err = details_resp.get("Error", {}).get("Message", "Job failed")
                return {"services": [], "last_refreshed": None, "status": "failed", "error": err}
            else:
                # Unknown status
                return {"services": [], "last_refreshed": None, "status": "failed", "error": f"Unknown job status: {status}"}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("Throttling", "ThrottlingException", "ServiceUnavailable", "TooManyRequestsException"):
                logger.warning(f"Throttled while polling Access Advisor job {job_id} for {arn}; backing off.")
                time.sleep(5)
                continue
            logger.error(f"get_service_last_accessed_details failed for job {job_id}: {e}")
            return {"services": [], "last_refreshed": None, "status": "failed", "error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected polling error for job {job_id}: {e}")
            return {"services": [], "last_refreshed": None, "status": "failed", "error": str(e)}

    # timed out
    return {"services": [], "last_refreshed": None, "status": "timeout", "error": f"Timed out after {max_wait}s"}


# ---------- Add usage-based findings ----------
def _add_usage_based_findings(snapshot):
    from datetime import timedelta

    for entity_type, entities in [("users", snapshot["users"]), ("groups", snapshot["groups"]), ("roles", snapshot["roles"]), ("policies", snapshot["policies"])]:
        for entity in entities:
            slu = entity.get("ServiceLastUsed", {})
            if slu.get("status") != "success":
                continue

            used_actions = set()
            for svc in slu.get("services", []):
                svc_last = svc.get("last_accessed")
                if svc_last:
                    try:
                        last_dt = datetime.fromisoformat(svc_last.replace("Z", "+00:00"))
                        if datetime.utcnow() - last_dt < timedelta(days=90):
                            for act in svc.get("actions", []):
                                act_name = act.get("action")
                                if act_name:
                                    used_actions.add(_normalize_action(act_name))
                    except Exception:
                        pass

            # Collect all allowed actions from policies
            policy_docs = []
            if entity_type == "policy":
                doc = entity.get("Document")
                if doc:
                    policy_docs.append((entity["PolicyName"], doc, entity["Findings"]))
            else:
                # Attached and inline
                attached_names = [ap.get("PolicyName") for ap in entity.get("AttachedPolicies", [])]
                inline_names = entity.get("InlinePolicies", [])
                for p_name in attached_names + inline_names:
                    pol = next((p for p in snapshot["policies"] if p["PolicyName"] == p_name or p["PolicyName"].endswith(f"::INLINE::{p_name}")), None)
                    if pol:
                        doc = pol.get("Document")
                        if doc:
                            policy_docs.append((p_name, doc, pol["Findings"]))

            for p_name, doc, findings_list in policy_docs:
                all_allowed = set()
                for stmt in _ensure_list(doc.get("Statement", [])):
                    if stmt.get("Effect") == "Allow":
                        for a in _extract_actions_from_statement(stmt):
                            if isinstance(a, str):
                                all_allowed.add(_normalize_action(a))

                unused = all_allowed - used_actions

                for ua in unused:
                    findings_list.append(FINDING("UNUSED_ACTION", "medium", f"Remove unused action: {ua}", "Based on Access Advisor data (unused in last 90 days)"))


# ---------- Risk propagation ----------
def _propagate_risk(snapshot):
    risky_policies = {p["PolicyName"] for p in snapshot["policies"] if p.get("IsRisky")}
    risky_roles = {r["RoleName"] for r in snapshot["roles"] if r.get("AssumePolicyRisk")}

    for role in snapshot["roles"]:
        for ap in role.get("AttachedPolicies", []) or []:
            if ap.get("PolicyName") in risky_policies:
                role["AssumePolicyRisk"] = True
                risky_roles.add(role["RoleName"])

    for user in snapshot["users"]:
        user_risky = False
        for ap in user.get("AttachedPolicies", []) or []:
            if ap.get("PolicyName") in risky_policies:
                user_risky = True
        if user_risky:
            user["IsRisky"] = True


# 🔑 Main Fetch
def fetch_iam_data(
    session=None,
    profile_name=None,
    out_path=DEFAULT_SNAPSHOT,
    fast_mode=True,
    force_fetch=False,
    encrypt=False
):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    if not force_fetch and os.path.exists(out_path):
        cached = _read_snapshot(out_path)
        if cached:
            logger.info("Returning cached snapshot (set force_fetch=True to refresh & compute diff).")
            return cached

    # --- session handling ---
    if session is None:
        session_args = {"profile_name": profile_name} if profile_name else {}
        try:
            session = boto3.Session(**session_args) if session_args else boto3.Session()
        except (ClientError, EndpointConnectionError, NoCredentialsError, NoRegionError) as e:
            logger.error("Failed to create AWS session (sanitized error).")
        return {"_meta": {"error": str(e.__class__.__name__)}}

    try:
        iam = session.client("iam")
        sts = session.client("sts")
        try:
            caller = sts.get_caller_identity()
            account_id = caller.get("Account")
        except Exception:
            account_id = None
    except (ClientError, EndpointConnectionError, NoCredentialsError, NoRegionError) as e:
        logger.error(f"Failed to create AWS clients: {e}")
        return {"_meta": {"error": str(e)}}

    snapshot = {
        "_meta": {
            "fetched_at": datetime.utcnow().isoformat() + "Z",
            "fast_mode": bool(fast_mode),
            "warnings": [],
            "account_id": account_id,
            "capabilities": {"usage_last_used": "enabled"}
        },
        "users": [], "groups": [], "roles": [], "policies": []
    }

    # --- Users ---
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page.get("Users", []):
                user_arn = u.get("Arn")
                # Try to fetch ServiceLastUsed (best-effort)
                slu = {}
                try:
                    slu = fetch_service_last_used(iam, "user", user_arn or u.get("UserName"), account_id=account_id, max_wait=60)
                except Exception as e:
                    logger.debug(f"ServiceLastUsed error for user {u.get('UserName')}: {e}")
                    slu = {"services": [], "last_refreshed": None, "status": "failed", "error": str(e)}
                entry = {
                    "UserName": u.get("UserName"),
                    "Arn": user_arn,
                    "CreateDate": u.get("CreateDate").isoformat() if u.get("CreateDate") else None,
                    "ServiceLastUsed": slu
                }
                snapshot["users"].append(entry)
        logger.info(f"Fetched {len(snapshot['users'])} users")
    except Exception as e:
        logger.error(f"list_users failed: {e}")
        snapshot["_meta"]["warnings"].append(f"list_users failed: {e}")

    # --- Groups ---
    try:
        paginator = iam.get_paginator("list_groups")
        for page in paginator.paginate():
            for g in page.get("Groups", []):
                gname = g.get("GroupName")
                g_arn = g.get("Arn") or None
                # Try to fetch group ARN if missing/resolvable
                slu = {}
                try:
                    slu = fetch_service_last_used(iam, "group", g_arn or gname, account_id=account_id, max_wait=60)
                except Exception as e:
                    logger.debug(f"ServiceLastUsed error for group {gname}: {e}")
                    slu = {"services": [], "last_refreshed": None, "status": "failed", "error": str(e)}

                entry = {
                    "GroupName": gname,
                    "ServiceLastUsed": slu
                }
                if not fast_mode:
                    try:
                        entry["AttachedPolicies"] = iam.list_attached_group_policies(GroupName=gname).get("AttachedPolicies", [])
                        entry["InlinePolicies"] = iam.list_group_policies(GroupName=gname).get("PolicyNames", [])
                    except Exception as e:
                        entry["AttachedPolicies"] = []
                        entry["InlinePolicies"] = []
                        snapshot["_meta"]["warnings"].append(f"group {gname} policy fetch failed: {e}")
                snapshot["groups"].append(entry)
        logger.info(f"Fetched {len(snapshot['groups'])} groups")
    except Exception as e:
        logger.error(f"list_groups failed: {e}")
        snapshot["_meta"]["warnings"].append(f"list_groups failed: {e}")

    # --- Roles ---
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for r in page.get("Roles", []):
                rname = r.get("RoleName")
                assume_raw = r.get("AssumeRolePolicyDocument")
                assume = {}
                try:
                    if isinstance(assume_raw, str):
                        decoded = urllib.parse.unquote(assume_raw)
                        assume = json.loads(decoded)
                    elif isinstance(assume_raw, dict):
                        assume = assume_raw
                except Exception as e:
                    logger.warning(f"decode assume doc for {rname} failed: {e}")
                    snapshot["_meta"]["warnings"].append(f"decode assume doc for {rname} failed: {e}")
                    assume = {}

                principals_info = []
                stmts = assume.get("Statement", [])
                if isinstance(stmts, dict):
                    stmts = [stmts]
                for s in stmts:
                    principal = s.get("Principal", {})
                    if isinstance(principal, dict):
                        vals = principal.get("AWS") or principal.get("Service") or principal.get("Federated") or []
                        if isinstance(vals, str):
                            vals = [vals]
                        for pr in vals:
                            principals_info.append(_parse_principal_value(pr))
                    elif principal == "*":
                        principals_info.append({"type": "wildcard", "value": "*"})

                attached, inline = [], []
                if not fast_mode:
                    try:
                        attached = iam.list_attached_role_policies(RoleName=rname).get("AttachedPolicies", [])
                        inline = iam.list_role_policies(RoleName=rname).get("PolicyNames", [])
                    except Exception as e:
                        logger.error(f"role {rname} policy fetch failed: {e}")
                        snapshot["_meta"]["warnings"].append(f"role {rname} policy fetch failed: {e}")

                # trust analyzer
                trust_eval = _analyze_trust_policy(assume or {})

                # fetch ServiceLastUsed for role
                slu = {}
                try:
                    slu = fetch_service_last_used(iam, "role", r.get("Arn") or rname, account_id=account_id, max_wait=60)
                except Exception as e:
                    logger.debug(f"ServiceLastUsed error for role {rname}: {e}")
                    slu = {"services": [], "last_refreshed": None, "status": "failed", "error": str(e)}

                snapshot["roles"].append({
                    "RoleName": rname,
                    "Arn": r.get("Arn"),
                    "AssumeRolePolicyDocument": assume,
                    "AssumePolicyRisk": trust_eval["is_risky"],
                    "AssumePolicyRiskActions": trust_eval["risky_actions"],
                    "AssumePolicyRiskScore": trust_eval["score"],
                    "AssumePolicyFindings": trust_eval["findings"],
                    "PrincipalsInfo": principals_info,
                    "AttachedPolicies": attached,
                    "InlinePolicies": inline,
                    "ServiceLastUsed": slu
                })
        logger.info(f"Fetched {len(snapshot['roles'])} roles")
    except Exception as e:
        logger.error(f"list_roles failed: {e}")
        snapshot["_meta"]["warnings"].append(f"list_roles failed: {e}")

    # --- Users' group membership & policies ---
    if not fast_mode:
        for user in snapshot.get("users", []):
            uname = user.get("UserName")
            try:
                groups = iam.list_groups_for_user(UserName=uname).get("Groups", [])
                user["Groups"] = [g.get("GroupName") for g in groups]
            except Exception as e:
                logger.error(f"user {uname} group fetch failed: {e}")
                user["Groups"] = []
                snapshot["_meta"]["warnings"].append(f"user {uname} group fetch failed: {e}")
            try:
                att = iam.list_attached_user_policies(UserName=uname).get("AttachedPolicies", [])
                user["AttachedPolicies"] = att
                inline = iam.list_user_policies(UserName=uname).get("PolicyNames", [])
                user["InlinePolicies"] = inline
            except Exception as e:
                logger.error(f"user {uname} policy fetch failed: {e}")
                user.setdefault("AttachedPolicies", [])
                user.setdefault("InlinePolicies", [])
                snapshot["_meta"]["warnings"].append(f"user {uname} policy fetch failed: {e}")

    # --- Policies (CUSTOM ONLY) ---
    scope = "Local"
    try:
        for page in iam.get_paginator("list_policies").paginate(Scope=scope):
            for p in page.get("Policies", []):
                p_arn = p.get("Arn")
                p_name = p.get("PolicyName")
                entry = {"PolicyName": p_name, "Arn": p_arn, "Document": {},
                         "IsRisky": False, "RiskActions": [], "RiskScore": 0, "Findings": []}
                # fetch default version + analyze
                try:
                    meta = iam.get_policy(PolicyArn=p_arn).get("Policy", {})
                    ver = meta.get("DefaultVersionId")
                    if ver:
                        doc = iam.get_policy_version(PolicyArn=p_arn, VersionId=ver).get("PolicyVersion", {}).get("Document", {})
                        entry["Document"] = doc
                        ext = _analyze_policy_document_extended(doc or {})
                        entry["IsRisky"] = ext["is_risky"]
                        entry["RiskActions"] = ext["risky_actions"]
                        entry["RiskScore"] = ext["score"]
                        entry["Findings"] = ext["findings"]
                except Exception as e:
                    logger.error(f"policy {p_name} doc fetch failed: {e}")
                    snapshot["_meta"]["warnings"].append(f"policy {p_name} doc fetch failed: {e}")

                # Fetch ServiceLastUsed for policy (best-effort)
                slu = {}
                try:
                    slu = fetch_service_last_used(iam, "policy", p_arn, account_id=account_id, max_wait=60)
                except Exception as e:
                    logger.debug(f"ServiceLastUsed error for policy {p_name}: {e}")
                    slu = {"services": [], "last_refreshed": None, "status": "failed", "error": str(e)}
                entry["ServiceLastUsed"] = slu

                snapshot["policies"].append(entry)
        logger.info(f"Fetched {len(snapshot['policies'])} customer-managed policies")
    except Exception as e:
        logger.error(f"list_policies failed: {e}")
        snapshot["_meta"]["warnings"].append(f"list_policies failed: {e}")

    # Optionally: Inline policy bodies (users/groups/roles) — analyze too
    if not fast_mode:
        # Users inline
        for u in snapshot.get("users", []):
            uname = u.get("UserName")
            for pname in u.get("InlinePolicies", []) or []:
                try:
                    pol = iam.get_user_policy(UserName=uname, PolicyName=pname)
                    doc = pol.get("PolicyDocument", {})
                    ext = _analyze_policy_document_extended(doc or {})
                    snapshot["policies"].append({
                        "PolicyName": f"{uname}::INLINE::{pname}",
                        "Arn": None,
                        "Document": doc,
                        "IsRisky": ext["is_risky"],
                        "RiskActions": ext["risky_actions"],
                        "RiskScore": ext["score"],
                        "Findings": ext["findings"],
                        "_inline_of": {"type": "user", "name": uname}
                    })
                except Exception as e:
                    snapshot["_meta"]["warnings"].append(f"user inline policy fetch failed {uname}/{pname}: {e}")

        # Groups inline
        for g in snapshot.get("groups", []):
            gname = g.get("GroupName")
            for pname in g.get("InlinePolicies", []) or []:
                try:
                    pol = iam.get_group_policy(GroupName=gname, PolicyName=pname)
                    doc = pol.get("PolicyDocument", {})
                    ext = _analyze_policy_document_extended(doc or {})
                    snapshot["policies"].append({
                        "PolicyName": f"{gname}::INLINE::{pname}",
                        "Arn": None,
                        "Document": doc,
                        "IsRisky": ext["is_risky"],
                        "RiskActions": ext["risky_actions"],
                        "RiskScore": ext["score"],
                        "Findings": ext["findings"],
                        "_inline_of": {"type": "group", "name": gname}
                    })
                except Exception as e:
                    snapshot["_meta"]["warnings"].append(f"group inline policy fetch failed {gname}/{pname}: {e}")

        # Roles inline
        for r in snapshot.get("roles", []):
            rname = r.get("RoleName")
            for pname in r.get("InlinePolicies", []) or []:
                try:
                    pol = iam.get_role_policy(RoleName=rname, PolicyName=pname)
                    doc = pol.get("PolicyDocument", {})
                    ext = _analyze_policy_document_extended(doc or {})
                    snapshot["policies"].append({
                        "PolicyName": f"{rname}::INLINE::{pname}",
                        "Arn": None,
                        "Document": doc,
                        "IsRisky": ext["is_risky"],
                        "RiskActions": ext["risky_actions"],
                        "RiskScore": ext["score"],
                        "Findings": ext["findings"],
                        "_inline_of": {"type": "role", "name": rname}
                    })
                except Exception as e:
                    snapshot["_meta"]["warnings"].append(f"role inline policy fetch failed {rname}/{pname}: {e}")

    # propagate risk
    _propagate_risk(snapshot)

    # add usage-based findings
    _add_usage_based_findings(snapshot)

    snapshot["_meta"]["counts"] = {
        "users": len(snapshot.get("users", [])),
        "groups": len(snapshot.get("groups", [])),
        "roles": len(snapshot.get("roles", [])),
        "policies": len(snapshot.get("policies", []))
    }

    # diff vs previous
    prev = _read_snapshot(out_path)
    diff = {
        "users": _compute_entity_diff(prev.get("users", []) if prev else [], snapshot["users"], "UserName"),
        "groups": _compute_entity_diff(prev.get("groups", []) if prev else [], snapshot["groups"], "GroupName"),
        "roles": _compute_entity_diff(prev.get("roles", []) if prev else [], snapshot["roles"], "RoleName"),
        "policies": _compute_entity_diff(prev.get("policies", []) if prev else [], snapshot["policies"], "PolicyName"),
    }
    diff["counts"] = {
        "added": sum(len(diff[t]["added"]) for t in ["users", "groups", "roles", "policies"]),
        "removed": sum(len(diff[t]["removed"]) for t in ["users", "groups", "roles", "policies"]),
        "modified": sum(len(diff[t]["modified"]) for t in ["users", "groups", "roles", "policies"]),
    }
    diff["impact_score"] = (diff["counts"]["added"] * 2) + (diff["counts"]["modified"] * 1) - (diff["counts"]["removed"] * 1)
    snapshot["_meta"]["diff_details"] = {e: diff[e]["modified_details"] for e in ["users", "groups", "roles", "policies"]}
    snapshot["_meta"]["diff"] = diff

    # --- SAVE (single latest only) ---
    try:
        if encrypt:
            secure_store.encrypt_and_write(snapshot, out_path)
        else:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2, default=str)

        # cleanup old snapshots only after save
        purge_old_snapshots("data/snapshots", keep_days=30)

    except Exception as e:
        snapshot["_meta"]["warnings"].append(f"write_snapshot_failed: {e}")


    return snapshot


if __name__ == "__main__":
    s = fetch_iam_data(fast_mode=False, force_fetch=True)
    print("Fetched counts:", s.get("_meta", {}).get("counts"))
    print("Diff:", s.get("_meta", {}).get("diff", {}).get("counts"))
    print("Impact Score:", s.get("_meta", {}).get("diff", {}).get("impact_score"))