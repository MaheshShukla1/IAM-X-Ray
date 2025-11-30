# setup.ps1 - Windows Installer for IAM-X-RAY
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "=== IAM-X-RAY Windows setup ==="

# Locate Python
$pythonCmd = $null

$py3 = Get-Command python3 -ErrorAction SilentlyContinue
if ($py3) { $pythonCmd = $py3.Path }

if (-not $pythonCmd) {
    $py = Get-Command python -ErrorAction SilentlyContinue
    if ($py) { $pythonCmd = $py.Path }
}

if (-not $pythonCmd) {
    Write-Host "Python 3.9+ not found in PATH."
    exit 1
}

# Check Python version
$versionCheck = & $pythonCmd -c 'import sys; print("{}.{}".format(sys.version_info.major, sys.version_info.minor))'

if ([version]$versionCheck -lt [version]"3.9") {
    Write-Host "Python 3.9+ required. Found: $versionCheck"
    exit 1
}

Write-Host "Python detected: $versionCheck"

# Create virtualenv
if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment (.venv)..."
    & $pythonCmd -m venv .venv
}

# Activate venv
$activate = ".venv\Scripts\Activate.ps1"
if (Test-Path $activate) {
    Write-Host "Activating virtual environment..."
    . $activate
}

# Install dependencies
Write-Host "Installing dependencies..."
try {
    python -m pip install --upgrade pip
    if (Test-Path "requirements.txt") {
        python -m pip install -r requirements.txt
    }
} catch {
    Write-Host "Dependency installation failed."
}

# Create .env
if (-not (Test-Path ".env")) {
    Write-Host "Generating Fernet key..."
    try {
        $fernet = & $pythonCmd -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
    } catch {
        Write-Host "cryptography not installed."
        exit 1
    }

    $envContent = @"
IAM_XRAY_FERNET_KEY=$fernet
AWS_REGION=us-east-1
CACHE_TTL=3600
KEEP_DAYS=30
"@

    Set-Content ".env" $envContent -Encoding UTF8
    Write-Host ".env created"
}

# Create demo snapshot
Write-Host "Creating demo snapshot..."

$pythonSnippet = @'
import os, json
os.makedirs("data", exist_ok=True)
demo_path = "data/sample_snapshot.json"
if os.path.exists(demo_path):
    print("Demo snapshot already exists")
else:
    demo = {
        "_meta": {"fetched_at": "demo", "fast_mode": True, "counts": {"users": 3, "roles": 1, "policies": 3}},
        "users": [
            {"UserName": "alice", "Arn": "arn:aws:iam::123456:user/alice", "IsRisky": True, "AttachedPolicies":[{"PolicyName": "AdminPolicy"}]},
            {"UserName": "bob", "Arn": "arn:aws:iam::123456:user/bob", "IsRisky": False, "AttachedPolicies":[{"PolicyName": "ReadOnlyPolicy"}]}
        ],
        "roles": [
            {"RoleName": "DemoRole", "AttachedPolicies":[{"PolicyName": "DemoPolicy"}], "AssumePolicyRisk": False}
        ],
        "groups": [],
        "policies": [
            {"PolicyName": "AdminPolicy", "RiskScore":9, "IsRisky":True, "Arn":"arn:aws:iam::123456:policy/AdminPolicy"},
            {"PolicyName": "ReadOnlyPolicy", "RiskScore":1, "IsRisky":False, "Arn":"arn:aws:iam::123456:policy/ReadOnlyPolicy"}
        ]
    }
    with open(demo_path, "w", encoding="utf-8") as f:
        json.dump(demo, f, indent=2)
    print("Demo snapshot created")
'@

$tmp = Join-Path $env:TEMP ("iamxray_demo_{0}.py" -f (New-Guid))
Set-Content -Path $tmp -Value $pythonSnippet -Encoding UTF8

try {
    & $pythonCmd $tmp
} finally {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "===================================="
Write-Host "Setup Complete"
Write-Host "Run with: .\start.ps1"
Write-Host "===================================="
Write-Host ""