# 🔍 **IAM X-Ray - AWS IAM Visualizer**

[![GitHub release](https://img.shields.io/github/v/release/MaheshShukla1/IAM-X-Ray)](https://github.com/MaheshShukla1/IAM-X-Ray/releases)
[![GitHub stars](https://img.shields.io/github/stars/MaheshShukla1/IAM-X-Ray)](https://github.com/MaheshShukla1/IAM-X-Ray/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/MaheshShukla1/IAM-X-Ray)](https://github.com/MaheshShukla1/IAM-X-Ray/issues)
[![Tests](https://github.com/MaheshShukla1/IAM-X-Ray/actions/workflows/ci.yml/badge.svg)](https://github.com/MaheshShukla1/IAM-X-Ray/actions)
[![Docker Image](https://img.shields.io/badge/Docker-ready-blue)](https://hub.docker.com/r/MaheshShukla1/iam-xray)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

**Visual AWS IAM Access Map — Modern, Fast, Open Source**

> "Defenders think in lists. Attackers think in graphs. As long as this is true, attackers win." – [@JohnLaTwC](https://twitter.com/JohnLaTwC)

IAM X-Ray converts your AWS IAM environment into an **interactive knowledge graph**, helping you instantly understand:
- **Which user/role can do what**
- **Which policies are risky** (wildcards, PassRole, escalations)
- **Which policies changed recently** (diff + impact scores)
- **Who can access critical services** (S3, IAM, EC2, Lambda)
- **Privilege escalation relationships**
- **Risky paths & misconfigurations**

Built for **security teams, DevOps, cloud engineers, auditors**, and learners. No complex setup—demo in seconds!

![Demo Graph Teaser](https://github.com/MaheshShukla1/IAM-X-Ray/raw/main/docs/demo-graph.png)  
*(Interactive graph highlighting risky AdminPolicy—try it live!)*

---

## 🚀 Features

| Category | Highlights |
|----------|------------|
| **🔐 Secure Local Access** | Local password (salted SHA-256), session timeout, "Remember me" token, reset tools. |
| **⚡ Fast IAM Snapshot Fetch** | FAST (cache) vs FORCE (fresh); multi-region; AWS Profile/Env Keys/Demo modes. |
| **🕸 IAM Graph Visualizer** | PyVis interactive graph; risk highlights (red/orange/green); auto-trim (200-node cap); export JSON/HTML. |
| **🔍 Smart Search** | Action/entity fuzzy search; "Who can do X?"; details panel (JSON/relationships/findings). |
| **📦 Snapshots** | JSON or encrypted `.json.enc` (Fernet); diff engine; impact scores; CSV export for risky policies. |
| **🧹 Maintenance** | Purge old snaps (backups); full reset; preflight checks; cross-platform scripts; Docker-ready. |

### Why IAM X-Ray? (vs. Open-Source Peers)
Compared to tools like PMapper (CLI graph risks, 1.5k stars), Aaia (Neo4j IAM grapher, 300 stars), and IAM APE (policy evaluator, PyPI-focused):

| Feature/Aspect | IAM X-Ray (Ours) | PMapper | Aaia | IAM APE | Why It Matters |
|----------------|------------------|---------|------|---------|---------------|
| **Built-in Demo Mode** | ✅ Instant no-AWS graph (committed sample) | ❌ CLI-only, needs AWS | ❌ Requires Neo4j setup | ❌ No demo, policy-focused | Zero-friction onboarding—try in seconds, no creds hassle. |
| **Interactive Web UI** | ✅ Streamlit-based, browser-ready | ❌ CLI + SVG export | ❌ Cypher queries only | ❌ CLI outputs | Visual exploration without tools—click to drill down. |
| **Cross-OS Scripts** | ✅ Bash/PS1 for Linux/Win/Mac | ❌ Unix-heavy | ❌ Linux-only | ❌ Pip global | Seamless install on any desktop—no "works on my machine." |
| **Encryption Toggle** | ✅ Fernet auto-key for snapshots | ❌ Plaintext dumps | ❌ No storage focus | ❌ No export encryption | Secure local analysis—prod-ready without leaks. |
| **Risky CSV Export** | ✅ One-click risky policies | ❌ Manual graph queries | ❌ No export | ✅ Policy summary, but no graph tie-in | Quick audits—share findings without full data. |
| **Auto-Preflight Checks** | ✅ Python/data/key validation on launch | ❌ Manual deps | ❌ Neo4j health manual | ❌ Assumes pip | Catches issues early—no "why didn't it work?" surprises. |
| **Docker One-Command** | ✅ Compose up → ready | ✅ Docker, but CLI | ❌ No Docker | ❌ No container | Portable for teams—run anywhere, persist data. |

Unique edge: **UI-first with demo**—peers are CLI/Neo4j-heavy (setup friction); we prioritize accessibility for all skill levels.

---

## 🛠 Quick Start

### **Prerequisites**
- Python 3.11+ (auto-checked)
- AWS CLI (optional, for live fetch)
- Docker (optional)

### **Option 1: Local Install (Recommended)**
#### Linux / macOS
```bash
git clone https://github.com/MaheshShukla1/IAM-X-Ray.git
cd IAM-X-Ray
./install.sh  # Auto-handles chmod if needed
./start.sh
```

### **Option 2: Docker**

```bash
git clone https://github.com/<user>/iam-xray.git
cd iam-xray
docker-compose up --build
```

Open: 👉 http://localhost:8501

### **Demo Mode (No AWS Required)**

- Auto-loads from data/sample_snapshot.json (committed—3 users, risky policies).
- Sidebar: Select "Demo" → Instant graph!
- If missing: Auto-recreated on first run.

---

## 📖 Usage Examples

1. **Launch & Demo**:
    - App opens → Sidebar "Demo" → Graph loads (users → policies → actions visualized).
    - Search: "s3:*" → Highlights risky resources.
2. **Live AWS Fetch**:
    - Sidebar: "AWS Profile" → Enter profile name → "Force Fetch" → Analyzes risks → Encrypted snapshot saved.
    - Diff: Compare old/new → Impact score in tabs.
3. **Export & Analyze**:
    - "Download Snapshot (JSON)" → Full data.
    - "Export Risky Policies (CSV)" → AdminPolicy rows with findings.

[Search Example](https://github.com/MaheshShukla1/IAM-X-Ray/raw/main/docs/search-results.png) _(Search "iam:PassRole" → Findings panel)_

[Export CSV](https://github.com/MaheshShukla1/IAM-X-Ray/raw/main/docs/export-csv.png) _(Risky policies table—pipe-separated findings)_


## 🏗 Project Structure

```text
IAM-X-Ray/
│
├── app/                 # UI Layer (Streamlit)
│   └── main.py          # Main app entrypoint
│
├── core/                # Domain Logic
│   ├── config.py        # ENV + secrets management
│   ├── fetch_iam.py     # AWS IAM fetcher (FAST/FORCE)
│   ├── secure_store.py  # Fernet encryption/decryption
│   ├── graph_builder.py # NetworkX + PyVis graph engine
│   └── cleanup.py       # Purge/reset utilities
│
├── data/                # Runtime Data
│   ├── sample_snapshot.json  # Demo (committed)
│   └── snapshots/       # User snaps (ignored)
│
├── docs/                # Extra docs (optional)
│
├── tests/               # Unit tests (pytest-cov)
│
├── .github/workflows/   # CI/CD (tests + coverage)
│   └── ci.yml
│
├── setup.sh / setup.ps1 # Cross-OS install
├── start.sh / start.ps1# Launch scripts
├── requirements.txt     # Deps (streamlit, boto3, etc.)
├── Dockerfile           # Container build
├── docker-compose.yml   # Stack
├── .gitignore           # Ignores runtime/secrets
└── README.md
```

## 🧪 Preflight & Troubleshooting

On launch, IAM X-Ray checks:

- Python 3.11+
- Data dir writable
- Fernet key (auto-gen if missing)
- Demo snapshot (auto-fix if invalid)

**Common Issues**:

- **"No AWS Credentials"**: Use Demo mode or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY in sidebar.
- **Port 8501 Busy**: Kill process or edit --server.port.
- **Encryption Fail**: Check .env (auto-created); fallback to plaintext.
- **Graph Too Big**: Auto-pruned to 200 nodes—Force fetch smaller regions.
- **Windows Paths**: Use PowerShell; avoid cmd.exe.

Run pytest for tests: pip install -r requirements.txt && pytest --cov=core --cov=app.

---

## 🔐 Security Notes

- **Auth**: Salted SHA-256 hashes; no cloud storage.
- **Encryption**: Fernet (auto-key in .env); toggle in UI.
- **Data**: Runtime files ignored (.gitignore); backups on purge.
- **Docker**: Non-root user; volumes for persistence.
- **Audits**: Risk scores for wildcards/PassRole; no external deps scan.

For prod: Rotate Fernet key monthly; use AWS STS for short-lived creds.

---

## 🤝 Contributing

We love contributions! IAM X-Ray is open-source—help make IAM safer.

1. **Fork & Clone**: git clone https://github.com/MaheshShukla1/IAM-X-Ray.git
2. **Branch**: git checkout -b feature/new-risk-rule
3. **Develop**: Add tests; run pytest.
4. **PR**: Target main; describe changes.
5. **Issues**: Use [template](https://github.com/MaheshShukla1/IAM-X-Ray/issues/new) for bugs/features.

- Code Style: Black + mypy (pre-commit hook coming).
- Docs: Update README for new features.
- Community: [Discussions](https://github.com/MaheshShukla1/IAM-X-Ray/discussions) or Twitter [@yourhandle](https://twitter.com/yourhandle).

**Full Contributing Guide**: CONTRIBUTING.md **Code of Conduct**: CODE_OF_CONDUCT.md | [Contributor Covenant](https://www.contributor-covenant.org/version/2/0/code_of_conduct/).

---

## 📄 License

```
This project is licensed under a Custom Non-Commercial Open Source License (see LICENSE_NONCOMMERCIAL.md).
**Commercial use, including SaaS or paid products, is prohibited without written permission.**
For licensing queries, contact: maheshcloudsec1@gmail.com
```


