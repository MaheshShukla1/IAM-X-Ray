# IAM X-Ray: AWS IAM Visualizer

[![GitHub Stars](https://img.shields.io/github/stars/yourusername/iam-x-ray?style=social)](https://github.com/yourusername/iam-x-ray/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/yourusername/iam-x-ray?style=social)](https://github.com/yourusername/iam-x-ray/network/members)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/downloads/)
[![Streamlit App](https://img.shields.io/badge/Streamlit-Run-red?logo=streamlit)](https://streamlit.io/)

IAM X-Ray is an open-source Python tool for visualizing, analyzing, and securing AWS Identity and Access Management (IAM) configurations. Built with Streamlit for an interactive UI, it fetches IAM data, builds relationship graphs, detects risks, and provides actionable insights—all in a secure, encrypted manner.

See your AWS permissions like an X-Ray.
Visualize who can touch what — before attackers do.

## Purpose and Use-Cases

IAM X-Ray helps AWS users audit and optimize IAM setups to prevent security risks like over-privileged roles or unused policies. Key use-cases include:

- **Security Audits**: Identify risky actions (e.g., wildcard permissions) and compute risk scores.
- **Compliance Checks**: Track changes with diffs, monitor service last used, and purge old snapshots.
- **Visualization**: Interactive graphs of users, groups, roles, and policies for better understanding.
- **DevOps Workflows**: Multi-region fetching, email alerts for high-impact changes, and demo mode for quick testing.
- **Education**: Learn AWS IAM through visual demos without real credentials.

Whether you're a cloud security engineer spotting vulnerabilities or a DevOps team optimizing access, IAM X-Ray makes IAM management intuitive and proactive.

## Features and Functionality

- **IAM Data Fetching**: Pull users, groups, roles, policies via Boto3; supports multi-region and scheduled runs.
- **Interactive Graph Visualization**: NetworkX and PyVis-powered graphs with highlighting, export (SVG/PNG), and clustering.
- **Risk Analysis**: Scores policies for risks; detects unused actions using Access Advisor.
- **Secure Storage**: Encrypted snapshots (Fernet); authentication with bcrypt and session expiry.
- **Cleanup and Alerts**: Background purging of old data; SMTP email for high-risk diffs.
- **UI/UX**: Modern Streamlit interface with tabs (Graph, Details, Summary), search, and downloads (JSON/CSV).
- **Demo Mode**: Pre-loaded sample data for instant exploration.
- **Extensibility**: Modular core (e.g., add AI policy recommendations via OpenAI key).

## Installation and Setup Instructions

### Prerequisites
- Python 3.8+
- Git

### Quick Start
1. Clone the repository:
```
git clone https://github.com/yourusername/iam-x-ray.git
cd iam-x-ray
```
2. Run setup script (creates venv, installs deps, generates .env and demo data):
```python
python setup.py
```


3. Activate virtual environment:
- Unix/Linux/Mac: `source venv/bin/activate`
- Windows: `venv\Scripts\activate`

4. Run the app:
```
streamlit run app/main.py
```
- Demo mode starts automatically. For full mode, edit `.env` with AWS credentials (AWS_ACCESS_KEY_ID, etc.).

### Docker Option
docker-compose up


Access at http://localhost:8501.

### Configuration
Edit `.env` for custom settings (e.g., AWS_REGION, KEEP_DAYS for snapshot retention).

## Usage Examples

### Demo Mode
Launch and explore sample IAM graph without AWS creds.

### Full Fetch and Analysis
1. Add AWS creds to `.env`.
2. Click "Fetch IAM Data" in sidebar.
3. View graph (larger, zoomable for readability), details, and summaries.

**Screenshot: Interactive IAM Graph**
![IAM Graph Screenshot](assets/graph-screenshot.png)  
*(Large, readable visualization with node highlighting.)*

**Screenshot: Risk Summary Tab**
![Risk Summary](assets/summary-screenshot.png)  
*(Metrics, unused actions warnings.)*

### CLI Mode
```python
python core/fetch_iam.py --multi_region --encrypt
```

Outputs fetched counts, diffs, and impact scores.

## Beta Release Notes

**Version 0.1.0-beta** (October 2025):
- Initial release with core fetching, graphing, and security features.
- Known Limitations: Large IAM sets (>200 nodes) may require clustering tweaks; no mobile optimization yet.
- Feedback: Open issues for bugs or features. Contributions welcome!
- Roadmap: Add AI-powered policy recommendations, more visualizations (e.g., heatmaps), and CI/CD pipelines.

## Contributing

1. Fork the repo.
2. Create a branch: `git checkout -b feature/xyz`.
3. Commit changes: `git commit -m 'Add XYZ'`.
4. Push: `git push origin feature/xyz`.
5. Open a Pull Request.

Follow PEP8; run `black .` and `pytest` before PR.

## License

MIT License - see [LICENSE](LICENSE) for details.

---

For questions, star the repo or open an issue. Built with ❤️ for AWS security!
