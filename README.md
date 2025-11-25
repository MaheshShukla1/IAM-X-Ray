# 🔍 **IAM X-Ray - AWS IAM VISUALIZER**

![GitHub release](https://img.shields.io/github/v/release/<user>/<repo>)
![GitHub stars](https://img.shields.io/github/stars/<user>/<repo>)
![GitHub issues](https://img.shields.io/github/issues/<user>/<repo>)
![Docker Image](https://img.shields.io/badge/Docker-ready-blue)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**Visual AWS IAM Access Map — Modern, Fast, Open Source**

IAM X-Ray converts your AWS IAM environment into a **visual knowledge graph**, helping you instantly understand:

- **Which user/role can do what**
    
- **Which policies are risky**
    
- **Which policies changed recently**
    
- **Who can access critical services (S3, IAM, EC2, Lambda)**
    
- **Privilege escalation relationships**
    
- **Risky paths & misconfigurations**
    

Built for **security teams, DevOps, cloud engineers, auditors**, and learners.

---

## 🚀 Features

### **🔐 Secure Local Access**

- Local password protection
    
- Session timeout + lockout
    
- “Remember me” 24h token
    
- Password reset + full app reset
    

### **⚡ Fast IAM Snapshot Fetch**

- Fast mode (use cache)
    
- Force mode (fresh fetch)
    
- Multi-region ready
    
- Support for:
    
    - AWS Profile
        
    - Env Keys
        
    - Demo Mode (no AWS required)
        

### **🕸 IAM Graph Visualizer**

- PyVis powered interactive graph
    
- Highlights risky entities
    
- Shows relationships clearly
    
- Auto-trims oversized graphs
    
- Empty-state suggestions
    

### **🔍 Smart Search**

- Search policies, actions, users, roles
    
- “Who can perform this action?”
    
- Fuzzy matching suggestions
    
- Entity details & findings view
    

### **📦 Snapshots**

- JSON or Encrypted `.json.enc` snapshots
    
- Diff engine
    
- Impact score
    
- Downloadable graph JSON
    
- Export risky policies CSV
    

### **🧹 Maintenance Tools**

- Purge old snapshots (with backups)
    
- Full app reset
    
- Preflight diagnostics
    
- Cross-platform setup scripts
    
- Docker-ready
    

---

# 🛠 Quick Start

## **Option 1 — One-Click Installer**

### **Linux / macOS**

```bash
chmod +x setup.sh
./setup.sh
./start.sh
```

### **Windows (PowerShell)**

```arduino
.\setup.ps1
.\start.ps1
```

## **Option 3 — Docker**

```css
docker-compose up --build
```

Then open:

👉 [http://localhost:8501](http://localhost:8501)


# 👁 Demo Mode (No AWS Required)

Demo snapshot auto-loads from:

```bash
data/sample_snapshot.json
```

If missing → auto-created.


# 🏗 Folder Structure


```powershell
iam-xray/
│
├── app/
│   └── main.py               # Streamlit app
│
├── core/
│   ├── config.py             # ENV config + defaults
│   ├── fetch_iam.py          # IAM fetch engine
│   ├── secure_store.py       # Encryption / decryption
│   ├── graph_builder.py      # Build visualization graph
│   ├── cleanup.py            # Purge + full reset logic
│
├── data/
│   ├── sample_snapshot.json  # Demo snapshot (tracked)
│   └── ...runtime files...   # Ignored (snapshots/auth)
│
├── setup.sh
├── setup.ps1
├── start.sh
├── start.ps1
├── install.sh
│
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .gitignore
├── .dockerignore
└── README.md
```

# 🧪 Preflight Diagnostics

Before login, IAM X-Ray checks:

- Python version
    
- Data directory permission
    
- Encryption key
    
- Demo snapshot
    
- Environment validity
    

---

# 🔐 Security Notes

- Local password stored as salted SHA-256
    
- Encrypted snapshots via Fernet
    
- All sensitive files ignored via `.gitignore`
    
- Docker isolates runtime data inside `/data`
