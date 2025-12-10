"""
IAM X-Ray — Resource Inventory Fetcher (PRO Edition)

This module fetches region-scoped AWS resources that IAM policies reference.

Supported:
- S3 Buckets
- KMS Keys
- Lambda Functions
- SecretsManager Secrets
- SSM Parameters (names only for speed)
- DynamoDB Tables

All fetchers are best-effort and safe in restricted IAM setups.
"""

import boto3
import logging

logger = logging.getLogger("iamxray.resource_fetch")
logger.setLevel(logging.INFO)


# ------------------------------
# Helpers
# ------------------------------
def _safe_call(func, default):
    try:
        return func()
    except Exception:
        return default


# ------------------------------
# Main entry: fetch resources for ONE region
# ------------------------------
def fetch_region_resources(session: boto3.Session, region_name: str, fast_mode: bool = True):
    """
    Returns:
    {
        "s3": [ "arn:aws:s3:::bucket", ... ],
        "kms": [ "arn:aws:kms:region:acct:key/id", ... ],
        "lambda": [ "arn:aws:lambda:region:acct:function:name", ... ],
        "secrets": [ "arn:aws:secretsmanager:region:acct:secret:..."],
        "ssm": [ "/path/param", "/prod/db/password" ],
        "dynamodb": [ "arn:aws:dynamodb:region:acct:table/TableName" ]
    }
    """
    resources = {
        "s3": [],
        "kms": [],
        "lambda": [],
        "secrets": [],
        "ssm": [],
        "dynamodb": []
    }

    # Establish client
    s = session or boto3.Session()
    s3 = s.client("s3", region_name=region_name)
    kms = s.client("kms", region_name=region_name)
    lam = s.client("lambda", region_name=region_name)
    sec = s.client("secretsmanager", region_name=region_name)
    ssm = s.client("ssm", region_name=region_name)
    ddb = s.client("dynamodb", region_name=region_name)

    # ------------------------------------------------------------------
    # S3 LIST (global service, but ARNs require region context)
    # ------------------------------------------------------------------
    try:
        resp = s3.list_buckets()
        for b in resp.get("Buckets", []):
            name = b.get("Name")
            if name:
                arn = f"arn:aws:s3:::{name}"
                resources["s3"].append(arn)
    except Exception as e:
        logger.debug(f"S3 fetch failed: {e}")

    # ------------------------------------------------------------------
    # KMS KEYS
    # ------------------------------------------------------------------
    try:
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for k in page.get("Keys", []):
                key_arn = k.get("KeyArn")
                if key_arn:
                    resources["kms"].append(key_arn)
    except Exception as e:
        logger.debug(f"KMS fetch failed: {e}")

    # ------------------------------------------------------------------
    # LAMBDA FUNCTIONS
    # ------------------------------------------------------------------
    try:
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for f in page.get("Functions", []):
                arn = f.get("FunctionArn")
                if arn:
                    resources["lambda"].append(arn)
    except Exception as e:
        logger.debug(f"Lambda fetch failed: {e}")

    # ------------------------------------------------------------------
    # SECRETS MANAGER
    # ------------------------------------------------------------------
    try:
        paginator = sec.get_paginator("list_secrets")
        for page in paginator.paginate():
            for sct in page.get("SecretList", []):
                arn = sct.get("ARN")
                if arn:
                    resources["secrets"].append(arn)
    except Exception as e:
        logger.debug(f"Secrets fetch failed: {e}")

    # ------------------------------------------------------------------
    # SSM PARAMETER NAMES (only names → avoid heavy GetParameter calls)
    # ------------------------------------------------------------------
    try:
        paginator = ssm.get_paginator("describe_parameters")
        for page in paginator.paginate():
            for p in page.get("Parameters", []):
                name = p.get("Name")
                if name:
                    resources["ssm"].append(name)
    except Exception as e:
        logger.debug(f"SSM fetch failed: {e}")

    # ------------------------------------------------------------------
    # DYNAMODB TABLES
    # ------------------------------------------------------------------
    try:
        paginator = ddb.get_paginator("list_tables")
        for page in paginator.paginate():
            for tname in page.get("TableNames", []):
                arn = f"arn:aws:dynamodb:{region_name}:{session.client('sts').get_caller_identity()['Account']}:table/{tname}"
                resources["dynamodb"].append(arn)
    except Exception as e:
        logger.debug(f"DynamoDB fetch failed: {e}")

    return resources
