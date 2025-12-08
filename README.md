# 🔍 **IAM X-Ray — AWS IAM Attack Graph & Risk Analyzer (v1.0.0-beta)**

**Modern. Visual. Secure. 100% Local.**

> “Defenders think in lists. Attackers think in graphs. As long as this is true, attackers win.”  
> — _John Lambert, Microsoft Security_


[![GitHub release](https://img.shields.io/github/v/release/MaheshShukla1/IAM-X-Ray)](https://github.com/MaheshShukla1/IAM-X-Ray/releases)
[![GitHub stars](https://img.shields.io/github/stars/MaheshShukla1/IAM-X-Ray)](https://github.com/MaheshShukla1/IAM-X-Ray/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/MaheshShukla1/IAM-X-Ray)](https://github.com/MaheshShukla1/IAM-X-Ray/issues)
[![Tests](https://github.com/MaheshShukla1/IAM-X-Ray/actions/workflows/ci.yml/badge.svg)](https://github.com/MaheshShukla1/IAM-X-Ray/actions)
[![Docker Image](https://img.shields.io/badge/Docker-ready-blue)](https://hub.docker.com/r/MaheshShukla1/iam-xray)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-orange)](LICENSE)

## 🧭 **What Is IAM X-Ray?**

IAM X-Ray is a **visual AWS IAM exploration and attack-surface analysis tool**.  
It converts your IAM environment into an **interactive attack graph** that reveals:

- Which identities (Users / Roles) have what permissions
    
- Privilege escalation paths across services
    
- Toxic permission combinations
    
- Risky policies (wildcards, PassRole, STS abuse, admin actions)
    
- What changed between snapshots (diff engine)
    
- Who can access sensitive services (IAM, S3, Lambda, EC2, KMS, STS)
    

Designed for:

- Security Engineers
    
- DevOps / SRE
    
- Cloud Architects
    
- SOC / Audit teams
    
- Learners exploring AWS IAM
    

---

## ✨ **What’s New in v1.0.0-beta**

### 🔐 **Premium 3-Step Onboarding**

- Welcome → Why IAM X-Ray → Master Password setup
    
- Secure local vault (SHA-256 + salt)
    
- Password strength meter (zxcvbn fallback)
    
- “Remember this device for 7 days” token
    
- Fully offline (no telemetry)
    

### 🎨 **New Branding + UI**

- Cyber Blue gradient palette
    
- SVG logo (IAM graph + shield)
    
- Linear-style illustration
    
- Smooth animations (fade, slide)
    
- Polished layout with centered hero card
    
- Seamless dark theme support
    

### ⚡ **Engine Improvements**

- Faster graph building
    
- Smarter trimming of large IAM environments
    
- Diff engine: Added / Removed / Changed policies
    
- Faster FAST fetch mode (cached)
    
- New snapshot structure (versioned)
    

### 🐳 **Docker-First Deployment**

- Multi-stage slim image
    
- Non-root runtime user
    
- Build hash (tamper detection)
    
- Automatic healthcheck
    

---

## 🖼 **Screenshots**

_(Add screenshots in these placeholders later)_

### **Onboarding**

### **Attack Graph**

### **Risk Panel / Policy Detail**

### **Snapshot Diff**

### **Video Demo**

👉 _(Add your YouTube link here later)_

---

# 🚀 **Quick Start**

## **Option A — Run with Docker (Recommended)**

```bash
git clone https://github.com/MaheshShukla1/IAM-X-Ray.git
cd IAM-X-Ray
docker-compose up --build
```

Then open:

👉 [http://localhost:8501](http://localhost:8501)

### Docker Features

- Auto demo snapshot
    
- Non-root runtime
    
- Local persistent snapshots (`./data:/app/data`)
    
- SHA-256 build hash validation
    

---

## **Option B — Local Python Install**

```bash
git clone https://github.com/MaheshShukla1/IAM-X-Ray.git
cd IAM-X-Ray
pip install -r requirements.txt
streamlit run app/main.py
```

# 🕹 Demo Mode (No AWS Required)

IAM X-Ray ships with a prebuilt sample IAM graph:

```bash
data/sample_snapshot.json
```

Use:

- “Try Demo Mode” on onboarding screen  
    or
    
- Sidebar → Mode → **Demo**
    

Perfect for learners, audits, interviews, or quick demos.

---

# 🕸 **IAM Attack Graph Engine**

IAM X-Ray builds a **dynamic attack graph** using:

- NetworkX
    
- PyVis
    
- Custom risk annotations
    
- Node grouping
    
- Interactive tooltips
    
- Graph trimming (keeps important nodes only)
    

Graph nodes include:

- Users
    
- Roles
    
- Policies
    
- Inline policies
    
- Services accessed
    

Highlighted risks:

- Wildcards (`"*"`)
    
- IAM privilege escalation
    
- PassRole → Lambda/EC2 privilege chain
    
- STS AssumeRole loops
    
- Admin-equivalent permissions
    

---

# 🧠 **Why IAM X-Ray? (vs Competitors)**

Comparison vs the three closest open-source IAM tools:

### **PMapper (1.5k⭐) — attack path analyzer (CLI)**

### **Aaia (300⭐) — IAM → Neo4j graph builder**

### **IAM APE — policy evaluation engine**

|Feature / Aspect|**IAM X-Ray**|**PMapper**|**Aaia**|**IAM APE**|Why It Matters|
|---|---|---|---|---|---|
|**Built-in Demo Mode**|✅ Yes (instant graph)|❌ No|❌ Requires Neo4j|❌ No|Reduces friction; demo without AWS creds|
|**Interactive Web UI**|✅ Yes (Streamlit)|❌ CLI-only|❌ Needs Cypher|❌ CLI|Clickable, explorable graph|
|**3-Step Onboarding**|✅ Premium wizard|❌ None|❌ None|❌ None|Better adoption + trust|
|**Password-protected vault**|✅ Yes|❌ No|❌ No|❌ No|Secure offline operation|
|**Diff snapshots**|✅ Added/Removed/Changed|⚠ Partial|❌ No|❌ No|Track IAM drift|
|**Risk Scoring Engine**|✅ Rich|⚠ Basic|❌ None|⚠ Policy-only|Faster detection of toxic combinations|
|**Graph Builder**|⭐ Interactive, trimmed|⚠ Static SVG|🔄 Neo4j heavy|❌ None|Visual clarity & performance|
|**CSV export (risky only)**|✅ Yes|⚠ Manual|❌ No|⚠ Summary only|Audit-ready reports|
|**Docker one-command**|✅ Yes|⚠ CLI|❌ Neo4j required|❌ No|Easy team adoption|
|**Zero external services**|✅ Fully local|⚠ AWS-only|❌ Neo4j server|⚠ AWS IAM only|Privacy + compliance|
|**Beginner-friendly**|⭐ Yes|❌ Steep|❌ Requires DB|⚠ Technical|Onboarding matters|

🟩 **IAM X-Ray is the only tool combining:**  
✔ Attack graph  
✔ Web UI  
✔ Demo mode  
✔ Snapshot diffing  
✔ Local vault  
✔ Docker-first deployment

---

# 🧱 Project Structure

```arduino
IAM-X-Ray/
├── app/
│   ├── main.py
│   └── assets/
│
├── core/
│   ├── auth.py
│   ├── cleanup.py
│   ├── config.py
│   ├── fetch_iam.py
│   ├── graph_builder.py
│   └── secure_store.py
│
├── data/
│   ├── sample_snapshot.json
│   └── snapshots/
│
├── docs/
│
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── README.md
└── tests/
```

# 🔐 Security Model

- All data stored **locally**
    
- Vault secured with salted SHA-256 hash
    
- Optional 7-day token
    
- Fernet encryption for snapshots
    
- Docker: non-root runtime user
    
- Zero telemetry
    
- Offline by design
    

---

# 🧪 Running Tests

```bash
pytest --cov=core --cov=app
```

# 🛣 Roadmap (Post-Beta)

- IAM entity inspector
    
- STS session graphing
    
- Service-level access heatmaps
    
- Node collapsing for 100+ identities
    
- Advanced table filters
    
- Upload your own IAM logs / CloudTrail
    
- MITRE ATT&CK mapping
    
- Permission expansion engine
    

---

# 👨‍💻 Contributing

Contributions are welcome!  
Please open an issue or PR.

---


## 📄 License — BUSL-1.1 + Custom Terms (Non-Commercial)

IAM X-Ray is released under the **Business Source License 1.1 (BUSL-1.1)** along with additional IAM-specific restrictions.

---

### 🔒 Allowed Before the Change Date (Jan 1, 2030)

You are permitted to use IAM X-Ray for:

- Personal learning & experiments  
- Academic & research projects  
- Security education, training & demos  
- Non-commercial internal use  
- Modifying, forking & contributing  

---

### ❌ Commercial Use Strictly Prohibited

You may NOT use IAM X-Ray for:

- Business or enterprise environments  
- Paid consulting, audits, or client work  
- SaaS, hosting, or cloud-delivered services  
- Selling, renting, leasing, or rebranding  
- Using it inside commercial or revenue-generating tools  
- Training or improving **commercial AI/ML models**  

---

### 🔄 After the Change Date (2030)

IAM X-Ray will automatically convert to the  
**Apache License 2.0**, allowing full commercial usage.

---

### 🏢 Commercial Licensing Available

Required for:

- Enterprise deployments  
- B2B/SaaS/cloud-hosted services  
- Security consulting & auditing  
- Internal business operations  

📩 Contact: **maheshcloudsec1@gmail.com**

---

### ⚖ Legal Notice

IAM X-Ray is provided **“AS IS”**, without warranties.  
Any violation results in **immediate license termination**.  

For complete terms, see: **LICENSE (BUSL-1.1)**  
