"""
IAM X-Ray — (NO circular imports)
"""

def fetch_iam_data(*args, **kwargs):
    from .wrapper import fetch_iam_data as _f
    return _f(*args, **kwargs)

def load_snapshot(*args, **kwargs):
    from .wrapper import load_snapshot as _l
    return _l(*args, **kwargs)

__all__ = ["fetch_iam_data", "load_snapshot"]
