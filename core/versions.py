# core/versions.py
"""
IAM X-Ray • Stable Beta
Accurate version manifest matching real project capabilities.
"""

VERSION = "1.0.0-beta"

FEATURES = {
    "auth_onboarding": [
        "3-step onboarding: Welcome → Create Password → Login",
        "Secure master-password vault (SHA-256 + salt)",
        "Remember-me token (7 days, secure local storage)",
        "Centered minimalist UI with SaaS-style cards",
        "Demo Mode with correct session isolation",
        "Password strength meter (zxcvbn or fallback heuristic)",
        "Password reset flow without deleting snapshots",
    ],

    "ui_ux": [
        "Graph-first workflow (Cytoscape via HTML export)",
        "Fully styled Table View with badges + metrics",
        "Hover tooltips everywhere (HTML title tooltips)",
        "Debounced graph search (fast highlight)",
        "Auto-scroll-to-graph after snapshot fetch",
        "Minimalist dark theme (Palette-1 security blue/teal)",
        "Warning-free sidebar (no empty labels)",
        "Optimized layout: No jank, no rerun flicker",
    ],

    "core_engine": [
        "Snapshot caching (Fast Mode)",
        "Live fetch via AWS Profile / Env Keys",
        "Encrypted snapshot support",
        "TTL-based cache reuse",
        "Snapshot diff engine (Changes Only filter)",
        "Auto fallback to demo snapshot",
        "Safe resilient snapshot loader",
    ],

    "graph": [
        "Graph caching keyed by snapshot fingerprint",
        "Highlight-on-search (nodes/actions)",
        "Risk-aware nodes & edge styling",
        "Service-level clustering (Collapse A style)",
        "Meta export: filtered nodes, risk count, JSON export",
        "Raw graph export for offline analysis",
    ],

    "security": [
        "Local-only vault (no cloud telemetry)",
        "SHA-256 salted master password hashing",
        "OS sandbox compatibility (Docker ready)",
        "Encrypted-at-rest snapshot option",
        "Safe remember-me mechanism",
    ],
}

PLANNED_NEXT = {
    "auth_onboarding": [
        "OS keychain integration",
        "Biometric unlock on desktop build",
        "Multi-user workspace mode",
    ],

    "ui_ux": [
        "Quick Search (⌘K) global command palette",
        "Inspector drawer for principals",
        "Advanced Table View: saved filters + profiles",
        "Graph Focus Mode",
    ],

    "graph": [
        "Group collapsing for 200+ node datasets",
        "Service permission heatmap visualization",
        "Automatic attack-path detection (MITRE mapping)",
    ],

    "core_engine": [
        "Deep AWS service expansion: S3, EC2, Lambda, RDS, KMS",
        "STS session analyzer",
        "Cross-account IAM mapping",
        "Service boundary risk modeling",
    ],
}
