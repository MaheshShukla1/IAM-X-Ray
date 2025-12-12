# 🔍 **IAM X-Ray — AWS IAM Attack Graph & Risk Analyzer (v0.1.0-beta)**

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
[![License Summary](https://img.shields.io/badge/License-Summary-blue)](LICENSE_NONCOMMERCIAL.md)

## 📘 Table of Contents

- [What Is IAM X-Ray?](#what-is-iam-x-ray)
- [What’s New in v0.1.0-beta](#whats-new-in-v010-beta)
- [Screenshots & Demo](#screenshots--demo)
- [Video Demo](#video-demo)
- [Quick Start](#quick-start)
- [Docker Deployment](#docker-deployment-recommended)
- [Demo Mode (No AWS Required)](#demo-mode-no-aws-required)
- [IAM Attack Graph Engine](#iam-attack-graph-engine)
- [Why IAM X-Ray? (Competitive Comparison)](#why-iam-x-ray-vs-others)
- [Project Structure](#project-structure)
- [Security Model](#security-model)
- [Running Tests](#running-tests)
- [Roadmap (Post-Beta)](#roadmap-post-beta)
- [Contributing](#contributing)
- [License — BUSL 1.1 + IAM Specific Non Commercial Terms](#license--busl-1-1--iam-specific-non-commercial-terms)

---

# What Is IAM X-Ray?


IAM X-Ray is a **visual AWS IAM analysis and attack-surface discovery tool**.  
It converts IAM Users, Roles, Groups, Policies, and Trust relationships into an **interactive attack graph**.

It helps you instantly understand:

- Who can access what
    
- How privilege escalation paths form
    
- Which permissions create risk
    
- What changed between IAM snapshots
    
- How AWS entities are connected
    

⚡ **Designed for:**

- Security Engineers
    
- Cloud Architects
    
- DevOps / SRE
    
- SOC teams
    
- AWS learners
    

Everything runs _locally_, offline, and no data leaves your machine.

---

#  What’s New in v0.1.0-beta

### 🔐 **Secure Onboarding Flow**

- Master password setup
    
- Local vault secured with salted SHA-256
    
- 7-day "Remember Me" token
    
- No telemetry
    

### 🎨 **New UI + Branding**

- Cyber Blue gradient theme
    
- Streamlined layout
    
- Smooth animations
    
- Dark-mode polished
    
- Clean control panel
    

### ⚡ **Engine Enhancements**

- Faster graph rendering
    
- Faster FAST (cached) fetch mode
    
- New snapshot metadata format
    
- Smarter IAM entity trimming
    
- Diff engine: Added / Removed / Modified
    

### 🐳 **Optimized Docker Image**

- Multi-stage build
    
- Non-root runtime user
    
- Build hash validation
    
- Automatic healthcheck
    
- ~200MB slim image
    

---

# Screenshots & Demo

### 🕸 Attack Graph Visualization
![Attack Graph](app/assets/attach_graph.png)

### 🔐 Onboarding Screen
![Onboarding](app/assets/onboarding.png)

### 📊 IAM Summary Dashboard
![Dashboard](app/assets/summary.png)

---

# Video Demo

👉 _Add your YouTube link here_

---

# Quick Start

Clone and run:

```bash
git clone https://github.com/MaheshShukla1/IAM-X-Ray.git
cd IAM-X-Ray
docker-compose up --build
```

Visit:

👉 [http://localhost:8501](http://localhost:8501)

---

# Docker Deployment (Recommended)

### **Pull Image**

```bash
docker pull maheshcloud1/iam-xray:v0.1.0-beta
```
##### Option A — Use AWS CLI Profiles

```bash
docker run -p 8501:8501 \
  -v "${USERPROFILE:-$HOME}/.aws:/home/iamx/.aws:ro" \
  -v "$(pwd)/data:/app/data" \
  maheshcloud1/iam-xray:v0.1.0-beta
```

##### [](https://hub.docker.com/r/maheshcloud1/iam-xray#option-b--environment-variables)
### **Run**

```bash
docker run -p 8501:8501 maheshcloud1/iam-xray:v0.1.0-beta
```

Open UI:

👉 [http://localhost:8501](http://localhost:8501)

---

## 🔐 **Run With AWS Credentials**

### Option A — Environment Variables


```bash
docker run \
  -e AWS_ACCESS_KEY_ID=YOUR_KEY \
  -e AWS_SECRET_ACCESS_KEY=YOUR_SECRET \
  -e AWS_SESSION_TOKEN=YOUR_TOKEN \
  -p 8501:8501 \
  maheshcloud1/iam-xray:v0.1.0-beta
```

### Option B — Use AWS CLI Profiles

#### Windows:

```powershell
docker run ^
  -v "$env:USERPROFILE\.aws:/home/iamx/.aws:ro" ^
  -p 8501:8501 ^
  maheshcloud1/iam-xray:v0.1.0-beta
```

#### Linux / Mac:

```bash
docker run \
  -v ~/.aws:/home/iamx/.aws:ro \
  -p 8501:8501 \
  maheshcloud1/iam-xray:v0.1.0-beta
```

# Demo Mode (No AWS Required)

IAM X-Ray includes a prebuilt IAM environment:

```bash
data/sample_snapshot.json
```

Use:

- **Onboarding → Demo Mode**, or
    
- **Sidebar → Mode → Demo**
    

No keys required.

---

# IAM Attack Graph Engine

IAM X-Ray uses:

- NetworkX
    
- PyVis
    
- IAM policy expansion logic
    
- Trust policy parser
    
- Resource mapping resolver
    
- Graph trimming algorithm
    
- Risk scoring engine
    

### Graph Nodes:

- Users
    
- Groups
    
- Roles
    
- Policies (managed + inline)
    
- Services
    

### Detects:

- Wildcards (`"*"`)
    
- PassRole → EC2/Lambda escalation
    
- Admin-equivalent roles
    
- STS role chaining
    
- Toxic permission combos
    
- High-risk policies
    

---

#  Why IAM X-Ray? (vs Others)

|Feature|**IAM X-Ray**|PMapper|Aaia|IAM APE|
|---|---|---|---|---|
|Interactive Graph UI|✅|❌|❌|❌|
|Demo Mode|✅|❌|❌|❌|
|Diff Snapshots|✅|⚠|❌|❌|
|Risk Engine|⭐ Rich|⚠ Basic|❌|⚠|
|Docker One-Command|✅|⚠|❌ Neo4j|❌|
|Local Vault|✅|❌|❌|❌|
|Beginner-Friendly|⭐ Yes|❌|❌|⚠|

IAM X-Ray is the only tool combining:

- Interactive graph
    
- Demo mode
    
- Snapshot diff
    
- Local vault
    
- Docker-first design
    

---

#  Project Structure


```text
IAM-X-Ray/
├── app/
│   ├── main.py
│   └── assets/
├── core/
│   ├── auth.py
│   ├── cleanup.py
│   ├── config.py
│   ├── graph_builder.py
│   ├── secure_store.py
│   └── fetch_iam/
│       ├── engine.py
│       ├── iam_policies.py
│       ├── iam_principals.py
│       ├── trust_policy.py
│       ├── resolver.py
│       ├── resource_fetch.py
│       └── metadata.py
├── data/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── tests/
```

# Security Model

- All data stored locally
    
- No telemetry
    
- Optional encrypted snapshots
    
- Master password vault
    
- SHA-256 + salt
    
- Non-root Docker user
    
- Offline-first
    
- Temp tokens auto-expire
    

---

# Running Tests


```bash
pytest --cov=core --cov=app
```

# 🛣 Roadmap (Post-Beta)

- IAM entity inspector
    
- Service access heatmaps
    
- Advanced risk model
    
- Action-to-resource lineage
    
- CloudTrail ingestion
    
- MITRE ATT&CK mapping
    
- Permission chain simulator
    
- Multi-account merging
    

---

# Contributing

Pull requests and issues are welcome!

---

# 📄 License — BUSL 1.1 + IAM Specific Non Commercial Terms

IAM X-Ray follows **Business Source License 1.1** with additional IAM-specific restrictions.

### Before Change Date (Jan 1, 2030)

✔ Personal / academic / demo use  
✔ Research  
✔ Non-commercial internal use  
✔ Modifying / contributing

### ❌ Not Allowed

- Commercial use
    
- Paid consulting
    
- B2B / SaaS
    
- Hosted/cloud services
    
- Rebranding
    
- Training commercial AI models
    

### After 2030

Automatically becomes **Apache 2.0**.

### Commercial Licensing

Email: **maheshcloudsec1@gmail.com**

