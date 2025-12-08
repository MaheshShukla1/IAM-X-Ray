# core/versions.py

VERSION = "1.0.0-beta"

FEATURES = {
    "auth_onboarding": [
        "Premium 3-step onboarding wizard",
        "Centered welcome screen (Palette 1)",
        "Linear + IAM Nodes hybrid SVG branding",
        "Demo Mode with correct navigation + state flags",
        "Remember-me token (7 days, secure)",
        "Safe password reset (keeps snapshots intact)",
        "Password strength meter (zxcvbn / fallback heuristic)",
        "Beautiful CSS animations & micro-interactions",
        "SVG illustration (A+E hybrid: gradient waves + IAM graph nodes)",
    ],

    "ui_ux": [
        "Graph-first UX",
        "Optimized Table View (clean metrics + risk labels)",
        "Debounced search box for graph",
        "Auto-scroll-to-graph after fetch",
        "Tooltips across Graph / Sidebar / Metrics",
        "Palette-1 theming (security blue/teal)",
        "Improved modals & animations",
        "Fully centered onboarding screens",
        "Zero layout shift across reruns",
    ],

    "core_engine": [
        "Snapshot cache (fast mode)",
        "Snapshot diffing for 'Changes Only'",
        "IAM Data Fetch v2 (faster + safer)",
        "Auto fallback to demo snapshot if missing",
        "Config-safe AWS region detection",
        "Encrypted snapshot storage (optional)",
        "Better multi-region plumbing (foundation ready)",
        "Refactored cleanup utilities",
    ],

    "graph": [
        "Graph caching keyed by snapshot fingerprint",
        "Highlight-on-search (debounced)",
        "Risky-only filter for graph edges/nodes",
        "Improved node tooltips",
        "Faster rebuild path due to lazy-load",
        "SVG icon alignment + better spacing",
    ],

    "security": [
        "Local-only vault (no telemetry, no network send)",
        "SHA-256 salted-hash for master password",
        "Tamper-detection: BUILD_HASH verification",
        "Runtime user sandbox in Docker",
        "Secure remember-token storage",
    ],
}

PLANNED_NEXT = {
    "auth_onboarding": [
        "Multi-user workspace mode",
        "Password-less unlock with OS keychain",
        "Biometric unlock on desktop builds",
    ],

    "ui_ux": [
        "Advanced Table View (saved views, filters, column profiles)",
        "Inspector drawer for Users/Roles/Policies",
        "Global Quick Search (⌘K style)",
    ],

    "graph": [
        "Focus Mode for deep investigation",
        "Group collapsing for 200+ nodes",
        "Permission heatmap (service-level exposure)",
        "Attack-path auto-detection (MITRE mapping)",
    ],

    "core_engine": [
        "Expand AWS parsing: S3, EC2, Lambda, KMS, RDS policies",
        "STS session analyzer",
        "Cross-account IAM map builder",
        "Service boundary risk modeling",
    ]
}
