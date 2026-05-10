# 🤖 Code Review MCP Server

> An open-source, AI-powered automated code review server built on the **Model Context Protocol (MCP)**. Push code to any registered GitHub repository and get automatic security scanning, quality review, and a ready-to-merge fix PR delivered to your inbox — all for free.

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green?logo=fastapi)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Free](https://img.shields.io/badge/Cost-100%25%20Free-brightgreen)](https://github.com)

---

## 📋 Table of Contents

- [What This Does](#-what-this-does)
- [How It Works](#-how-it-works)
- [Tech Stack](#-tech-stack)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Running the Server](#-running-the-server)
- [Setting Up the Tunnel (Free Permanent URL)](#-setting-up-the-tunnel-free-permanent-url)
- [Always-Live Deployment (Auto-start on Boot)](#-always-live-deployment-auto-start-on-boot)
- [Managing Repositories](#-managing-repositories)
- [Testing All Features](#-testing-all-features)
- [API Reference](#-api-reference)
- [Troubleshooting](#-troubleshooting)
- [Project Structure](#-project-structure)

---

## 🎯 What This Does

Developers today manually review pull requests, run security scanners, check code quality, and coordinate feedback across multiple tools. This server **automates all of that**.

When a developer pushes a commit or opens a PR on any registered repository, this server:

1. **Clones the repository** and extracts only the changed files
2. **Scans for vulnerabilities** using 3 layers: AST analysis, Bandit, and Semgrep
3. **Reviews code quality** using Groq's free LLM (LLaMA 3.3 70B)
4. **Generates fixes** — rewrites flagged files with all issues resolved
5. **Opens a Pull Request** on GitHub with a full findings report
6. **Sends an approval email** with ✅ Approve / ❌ Reject buttons
7. **Auto-merges or closes** the PR based on your email click

**It also works on any public GitHub repo on-demand** — just POST the URL and the full pipeline runs without any webhook setup on that repo.

---

## 🔄 How It Works

```
GitHub Push / PR Event
        ↓
Cloudflare Tunnel (permanent free URL)
        ↓
FastAPI receives webhook → verifies GitHub signature
        ↓
Registry check → is this repo registered?
        ↓
LangGraph Orchestrator routes to agents:
  ├── CodeFetcherAgent (GitPython) → clones repo, extracts diff
  ├── VulnScannerAgent → runs in parallel:
  │     ├── AST Scanner   → eval(), hardcoded secrets, bare except
  │     ├── Bandit        → SQL injection, weak crypto, shell injection
  │     └── Semgrep       → OWASP Top 10, XSS, SSRF, path traversal
  └── CodeReviewerAgent (Groq LLM) → quality, performance, docs
        ↓
AutoFixAgent (LLM) → rewrites files with all fixes applied
        ↓
PRCreatorAgent (PyGitHub) → opens PR with full findings report
        ↓
EmailNotifierAgent (SMTP) → sends approve/reject email
        ↓
Developer clicks button in email
        ↓
ApprovalCallback → merges or closes PR + deletes review branch
```

---

## 🛠 Tech Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| Web server | FastAPI + Uvicorn | Async, fast, auto-docs |
| Orchestration | LangGraph + LangChain | Agent routing pipeline |
| LLM | Groq API (free tier) | LLaMA 3.3 70B — fast & free |
| Git operations | GitPython | Clone, diff, checkout |
| GitHub API | PyGitHub | Open PRs, merge, branch management |
| Python security | Bandit | Industry-standard Python scanner |
| Multi-language | Semgrep | OWASP rules, works on JS/TS/Go/Java |
| AST analysis | Python `ast` module | Built-in, no install needed |
| Email | SMTP (Gmail) | Approval notifications |
| Token signing | itsdangerous | Tamper-proof approval links |
| Tunnel | Cloudflare Tunnel / ngrok | Free permanent public URL |
| Config | pydantic-settings | Typed env variable loading |

---

## 📦 Prerequisites

Before installing, make sure you have:

- **Python 3.11+** — [python.org/downloads](https://python.org/downloads)
- **Git** — [git-scm.com](https://git-scm.com)
- **A GitHub account** with a personal access token
- **A Groq API key** (free) — [console.groq.com](https://console.groq.com)
- **A Gmail account** with an App Password enabled
- **Semgrep** installed separately:

```bash
# Mac
brew install semgrep

# Windows / Linux
pip install semgrep
```

---

## 🚀 Installation

### Step 1: Clone this repository

```bash
git clone https://github.com/kumarvarun3162/CodeReview-MCP.git
cd CodeReview-MCP
```

### Step 2: Create and activate a virtual environment

```bash
# Create
python -m venv venv

# Activate (Mac/Linux)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate
```

### Step 3: Install dependencies

```bash
pip install -r requirements.txt
```

---

## ⚙️ Configuration

### Step 1: Create your `.env` file

Copy the example and fill in your values:

```bash
# Mac/Linux
cp .env.example .env

# Windows
copy .env.example .env
```

Open `.env` and fill in every value:

```env
# ── Groq LLM (free at console.groq.com) ──────────────────────────
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxx

# ── GitHub ────────────────────────────────────────────────────────
# Create at: github.com/settings/tokens → classic token
# Required scopes: repo, pull_requests, workflow
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx

# ── Webhook security ──────────────────────────────────────────────
# Generate with: python -c "import secrets; print(secrets.token_hex(32))"
GITHUB_WEBHOOK_SECRET=your_random_secret_here

# ── Email (Gmail) ─────────────────────────────────────────────────
# Use an App Password, NOT your Gmail password
# Enable at: myaccount.google.com/security → 2FA → App Passwords
SMTP_EMAIL=your_gmail@gmail.com
SMTP_PASSWORD=xxxx_xxxx_xxxx_xxxx

# ── Token signing ─────────────────────────────────────────────────
# Generate with: python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=another_random_secret_here

# ── Server ────────────────────────────────────────────────────────
HOST=0.0.0.0
PORT=8000
DEBUG=True

# ── Public URL (set this after tunnel setup) ──────────────────────
SERVER_BASE_URL=https://your-tunnel-url-here
```

### Step 2: Generate your secrets

Run these in your terminal and paste the outputs into `.env`:

```bash
# For GITHUB_WEBHOOK_SECRET
python -c "import secrets; print(secrets.token_hex(32))"

# For SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"
```

### Step 3: Get your GitHub Token

1. Go to [github.com/settings/tokens](https://github.com/settings/tokens)
2. Click **Generate new token (classic)**
3. Check scopes: `repo`, `workflow`
4. Copy the token → paste as `GITHUB_TOKEN`

### Step 4: Get your Groq API Key (free)

1. Go to [console.groq.com](https://console.groq.com)
2. Sign up for free → API Keys → Create Key
3. Copy the key → paste as `GROQ_API_KEY`

### Step 5: Get your Gmail App Password

1. Enable 2-Factor Authentication on your Google account
2. Go to [myaccount.google.com/security](https://myaccount.google.com/security)
3. Search "App Passwords" → create one named `code-review-mcp`
4. Copy the 16-character password → paste as `SMTP_PASSWORD`

---

## ▶️ Running the Server

### Development mode (manual start)

```bash
# Make sure venv is activated first
source venv/bin/activate        # Mac/Linux
venv\Scripts\activate           # Windows

python main.py
```

You should see:
```
Starting Code Review MCP Server on 0.0.0.0:8000
INFO: Uvicorn running on http://0.0.0.0:8000
```

Test it's alive:
```bash
curl http://localhost:8000/health
# {"status":"ok","server":"Code Review MCP Server v0.1.0"}
```

---

## 🌐 Setting Up the Tunnel (Free Permanent URL)

You need a public URL so GitHub can reach your local server.
**Choose one option — both are completely free.**

---

### Option A: Cloudflare Tunnel (recommended — truly permanent)

**Step 1: Install cloudflared**

```bash
# Mac
brew install cloudflare/cloudflare/cloudflared

# Windows — download from:
# https://github.com/cloudflare/cloudflared/releases/latest
# → cloudflared-windows-amd64.msi → install it

# Verify
cloudflared --version
```

**Step 2: Authenticate**

```bash
cloudflared login
# Opens browser → log in to Cloudflare (free account) → Authorize
```

**Step 3: Create a named tunnel**

```bash
cloudflared tunnel create code-review-mcp
```

Copy the tunnel ID shown (looks like `a1b2c3d4-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).

**Step 4: Create `cloudflare-tunnel.yml` in your project root**

```yaml
tunnel: a1b2c3d4-xxxx-xxxx-xxxx-xxxxxxxxxxxx
credentials-file: C:\Users\YOUR_NAME\.cloudflared\a1b2c3d4-xxxx.json

ingress:
  - service: http://localhost:8000
```

> On Mac/Linux the credentials file path is `~/.cloudflared/a1b2c3d4-xxxx.json`

**Step 5: Start the tunnel**

```bash
cloudflared tunnel --config cloudflare-tunnel.yml run code-review-mcp
```

Your permanent URL appears in the output:
```
https://code-review-mcp-abc123.cfargotunnel.com
```

**Step 6: Update `.env`**

```env
SERVER_BASE_URL=https://code-review-mcp-abc123.cfargotunnel.com
```

---

### Option B: ngrok (easiest setup)

**Step 1: Download and install**

Go to [ngrok.com/download](https://ngrok.com/download) → download for your OS → install.

**Step 2: Sign up free and connect your account**

```bash
ngrok config add-authtoken YOUR_NGROK_TOKEN
```

**Step 3: Claim your free static domain**

Go to [dashboard.ngrok.com/cloud-edge/domains](https://dashboard.ngrok.com/cloud-edge/domains) → **New Domain** → copy your free static domain.

**Step 4: Start the tunnel**

```bash
ngrok http --domain=your-domain.ngrok-free.app 8000
```

**Step 5: Update `.env`**

```env
SERVER_BASE_URL=https://your-domain.ngrok-free.app
```

---

## 🔄 Always-Live Deployment (Auto-start on Boot)

Run these steps so the server starts automatically and never needs manual intervention.

### Windows — NSSM (Non-Sucking Service Manager)

**Step 1: Download NSSM**

Go to [nssm.cc/download](https://nssm.cc/download) → download ZIP → extract to `C:\nssm\`

**Step 2: Create `logs/` folder**

```cmd
mkdir E:\CodeReview-MCP\logs
```

**Step 3: Create `start_server.bat`** in your project root:

```bat
@echo off
cd /d E:\CodeReview-MCP
call venv\Scripts\activate.bat
python main.py
```

**Step 4: Create `start_tunnel.bat`** (choose Cloudflare OR ngrok):

```bat
REM For Cloudflare:
@echo off
cloudflared tunnel --config E:\CodeReview-MCP\cloudflare-tunnel.yml run code-review-mcp

REM For ngrok (replace with your domain):
REM ngrok http --domain=your-domain.ngrok-free.app 8000
```

**Step 5: Install as Windows Services** (run Command Prompt as Administrator):

```cmd
C:\nssm\win64\nssm.exe install CodeReviewMCP "E:\CodeReview-MCP\start_server.bat"
C:\nssm\win64\nssm.exe set CodeReviewMCP AppStdout "E:\CodeReview-MCP\logs\server.log"
C:\nssm\win64\nssm.exe set CodeReviewMCP AppStderr "E:\CodeReview-MCP\logs\server_error.log"
C:\nssm\win64\nssm.exe set CodeReviewMCP Start SERVICE_AUTO_START

C:\nssm\win64\nssm.exe install CodeReviewTunnel "E:\CodeReview-MCP\start_tunnel.bat"
C:\nssm\win64\nssm.exe set CodeReviewTunnel AppStdout "E:\CodeReview-MCP\logs\tunnel.log"
C:\nssm\win64\nssm.exe set CodeReviewTunnel AppStderr "E:\CodeReview-MCP\logs\tunnel_error.log"
C:\nssm\win64\nssm.exe set CodeReviewTunnel Start SERVICE_AUTO_START

C:\nssm\win64\nssm.exe start CodeReviewMCP
C:\nssm\win64\nssm.exe start CodeReviewTunnel
```

**Step 6: Verify services are running**

```cmd
C:\nssm\win64\nssm.exe status CodeReviewMCP
C:\nssm\win64\nssm.exe status CodeReviewTunnel
```

Both should show `SERVICE_RUNNING`.

**After pushing new code, restart the server service:**

```cmd
C:\nssm\win64\nssm.exe restart CodeReviewMCP
```

---

### Mac/Linux — systemd

Create `/etc/systemd/system/code-review-mcp.service`:

```ini
[Unit]
Description=Code Review MCP Server
After=network.target

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/path/to/CodeReview-MCP
ExecStart=/path/to/CodeReview-MCP/venv/bin/python main.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable code-review-mcp
sudo systemctl start code-review-mcp
sudo systemctl status code-review-mcp
```

---

## 🗂 Managing Repositories

The server maintains a registry (`repos.json`) of repos it monitors via webhook. You can add, remove, pause, and list repos via the API — **no hardcoding, no server restart needed**.

### Add a repository

```bash
curl -X POST https://YOUR-TUNNEL-URL/repos/add \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "owner/repo-name",
    "notify_email": "you@gmail.com",
    "branch": "main"
  }'
```

After adding, go to `https://github.com/owner/repo-name/settings/hooks` and add a webhook:

| Field | Value |
|-------|-------|
| Payload URL | `https://YOUR-TUNNEL-URL/webhook` |
| Content type | `application/json` |
| Secret | Your `GITHUB_WEBHOOK_SECRET` from `.env` |
| Events | ✅ Pushes, ✅ Pull requests |

### Remove a repository

```bash
curl -X DELETE https://YOUR-TUNNEL-URL/repos/remove \
  -H "Content-Type: application/json" \
  -d '{"repo_full_name": "owner/repo-name"}'
```

### List all registered repositories

```bash
curl https://YOUR-TUNNEL-URL/repos/list
```

### Pause / resume a repository (without removing)

```bash
curl -X PATCH "https://YOUR-TUNNEL-URL/repos/toggle?repo_full_name=owner/repo&enabled=false"
```

---

## 🧪 Testing All Features

Follow these steps in order to verify every part of the system works.

### Test 1: Server is alive

```bash
curl http://localhost:8000/health
```
✅ Expected: `{"status":"ok","server":"Code Review MCP Server v0.1.0"}`

### Test 2: On-demand analysis of any public repo (no webhook needed)

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/tiangolo/fastapi",
    "branch": "master",
    "notify_email": "your@gmail.com"
  }'
```

Watch your server terminal. Within 30–60 seconds you should see the full pipeline run:
- Clone → Diff → AST scan → Bandit → Semgrep → LLM review → report printed

### Test 3: Webhook trigger

**Step 1:** Register your own repo:
```bash
curl -X POST http://localhost:8000/repos/add \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "YOUR_USERNAME/CodeReview-MCP",
    "notify_email": "your@gmail.com",
    "branch": "main"
  }'
```

**Step 2:** Install the webhook on your repo at:
`https://github.com/YOUR_USERNAME/CodeReview-MCP/settings/hooks`

**Step 3:** Push a Python file with a vulnerability:
```bash
cat > test_vuln.py << 'EOF'
import pickle, os
password = "super_secret_123"
def run(cmd): os.system(cmd)
def load(data): return pickle.loads(data)
try:
    x = eval(input())
except:
    pass
EOF

git add test_vuln.py
git commit -m "test: trigger webhook scan"
git push origin main
```

✅ Expected in terminal: full scan report with critical findings

### Test 4: Full pipeline — auto-fix + PR + email

Use a repo where your GitHub token has write access. After the push from Test 3, you should see:
- `[AutoFix]` fixing files
- `[PRCreator]` opening a PR — check your GitHub repo for a new PR
- `[Email]` sent — check your inbox

### Test 5: Approve the PR via email

1. Open the email from your server
2. Click **✅ Approve & Merge**
3. Your browser opens and shows a confirmation page
4. Check GitHub — the PR should be merged and the branch deleted

### Test 6: Reject a PR via email

Run the pipeline again (push another change), then click **❌ Reject & Close** in the email.

### Test 7: Verify the tunnel URL works from outside

Share your tunnel URL with a friend or use your phone's mobile data (not WiFi):
```bash
curl https://YOUR-TUNNEL-URL/health
```
✅ Expected: same health response — your server is publicly reachable

### Test 8: Add and remove repos via API

```bash
# Add
curl -X POST https://YOUR-TUNNEL-URL/repos/add \
  -H "Content-Type: application/json" \
  -d '{"repo_url":"facebook/react","notify_email":"you@gmail.com","branch":"main"}'

# List — verify it's there
curl https://YOUR-TUNNEL-URL/repos/list

# Remove
curl -X DELETE https://YOUR-TUNNEL-URL/repos/remove \
  -H "Content-Type: application/json" \
  -d '{"repo_full_name":"facebook/react"}'

# List again — verify it's gone
curl https://YOUR-TUNNEL-URL/repos/list
```

### Test 9: Verify auto-start after reboot (Windows)

1. Restart your computer
2. After reboot, wait 30 seconds, then:
```bash
curl https://YOUR-TUNNEL-URL/health
```
✅ Expected: server responds without you starting anything manually

---

## 📡 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Check server status |
| `POST` | `/webhook` | GitHub webhook receiver (called by GitHub) |
| `POST` | `/analyze` | On-demand analysis of any repo URL |
| `POST` | `/repos/add` | Register a repo for webhook monitoring |
| `DELETE` | `/repos/remove` | Remove a repo from monitoring |
| `GET` | `/repos/list` | List all registered repos |
| `PATCH` | `/repos/toggle` | Pause or resume a repo |
| `GET` | `/callback/{action}/{token}` | Approval/rejection callback (called via email) |
| `GET` | `/docs` | Auto-generated interactive API docs (FastAPI) |

> 💡 Visit `http://localhost:8000/docs` in your browser to see and test all endpoints interactively via FastAPI's built-in Swagger UI.

---

## 🔧 Troubleshooting

### `PermissionError` when deleting workspace (Windows)

Git marks `.git/objects/` files as read-only on Windows. This is fixed in `core/workspace.py` with the `_force_remove_readonly` handler. If you still see it, make sure you have the latest version of `workspace.py`.

### `0 files found` after a push

You likely pushed a non-source file (like `README.md`). The scanner only processes `.py`, `.js`, `.ts`, `.java`, `.go`, `.rb` files. Push a change to a Python file to test.

### Webhook shows 403 — signature mismatch

The `GITHUB_WEBHOOK_SECRET` in your `.env` must exactly match what you entered in the GitHub webhook settings. No extra spaces. Re-copy and paste both.

### LLM returns no findings

Check your `GROQ_API_KEY` is valid. Test it:
```bash
python -c "
from langchain_groq import ChatGroq
from core.config import settings
llm = ChatGroq(api_key=settings.groq_api_key, model='llama-3.3-70b-versatile')
print(llm.invoke('say hello').content)
"
```

### Email not sending

1. Make sure you're using a **Gmail App Password** — not your regular Gmail password
2. 2-Factor Authentication must be enabled on your Google account
3. Test SMTP directly:
```bash
python -c "
import smtplib, ssl
from core.config import settings
ctx = ssl.create_default_context()
with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=ctx) as s:
    s.login(settings.smtp_email, settings.smtp_password)
    print('SMTP login successful')
"
```

### PR creation fails — 403 or 404

Your GitHub token needs the `repo` scope. Go to [github.com/settings/tokens](https://github.com/settings/tokens) → click your token → verify `repo` is checked.

### Cloudflare tunnel URL not showing

Run `cloudflared tunnel info code-review-mcp` to see your tunnel's assigned URL.

### Bandit / Semgrep not found

```bash
pip install bandit
pip install semgrep

# Verify
bandit --version
semgrep --version
```

---

## 📁 Project Structure

```
CodeReview-MCP/
│
├── agents/                      # AI agents — each does one job
│   ├── __init__.py
│   ├── models.py                # Shared data types: FileInfo, FetchedCode, etc.
│   ├── code_fetcher.py          # Clones repos, extracts diffs (GitPython)
│   ├── code_reviewer.py         # LLM-based code quality review (Groq)
│   ├── vuln_scanner.py          # Orchestrates all scanners in parallel
│   ├── auto_fix.py              # LLM rewrites files with fixes applied
│   ├── pr_creator.py            # Opens PRs on GitHub (PyGitHub)
│   └── email_notifier.py        # Sends approval emails (SMTP + tokens)
│
├── api/                         # FastAPI web layer
│   ├── __init__.py
│   ├── app.py                   # All routes + pipeline runner
│   ├── models.py                # Request/response models (AnalysisJob, etc.)
│   ├── security.py              # GitHub webhook signature verification
│   └── webhook_parser.py        # Parses push/PR events into AnalysisJob
│
├── core/                        # Shared infrastructure
│   ├── __init__.py
│   ├── config.py                # Pydantic settings — loads from .env
│   ├── workspace.py             # Temp directory lifecycle per job
│   └── repo_registry.py         # JSON-based registry of monitored repos
│
├── tools/                       # Static analysis tools (called by vuln_scanner)
│   ├── __init__.py
│   ├── ast_scanner.py           # Python AST walker — no external dependency
│   ├── bandit_scanner.py        # Wrapper around Bandit CLI
│   └── semgrep_scanner.py       # Wrapper around Semgrep CLI
│
├── utils/                       # Helper utilities
│   ├── __init__.py
│   └── diff_summary.py          # Formats code context for LLM prompts
│
├── tests/                       # Test files
│   └── __init__.py
│
├── logs/                        # Service logs (auto-created, gitignored)
├── workspace/                   # Temp clone dirs (auto-created, gitignored)
│
├── main.py                      # Entry point — starts Uvicorn
├── repos.json                   # Registry of monitored repos (auto-created)
├── cloudflare-tunnel.yml        # Cloudflare tunnel config
├── start_server.bat             # Windows service start script
├── start_tunnel.bat             # Windows tunnel start script
├── requirements.txt             # All Python dependencies
├── .env                         # Your secrets (never committed)
├── .env.example                 # Template for .env
└── .gitignore
```

---

## 🤝 Adding This Server to Someone Else's Repo

If another developer wants their repo reviewed by your server:

1. **You** register their repo:
   ```bash
   curl -X POST https://YOUR-TUNNEL-URL/repos/add \
     -H "Content-Type: application/json" \
     -d '{"repo_url":"their-username/their-repo","notify_email":"their@email.com"}'
   ```

2. **They** add a webhook on their repo at `Settings → Webhooks → Add webhook`:
   - Payload URL: `https://YOUR-TUNNEL-URL/webhook`
   - Content type: `application/json`
   - Secret: your `GITHUB_WEBHOOK_SECRET`
   - Events: Pushes + Pull requests

3. From that point on, every push to their repo triggers your full pipeline automatically.

4. To stop: call `/repos/remove` and ask them to delete the webhook.

---

## 📄 License

MIT License — free for personal and commercial use. See [LICENSE](LICENSE).

---

## 🙏 Acknowledgements

- [Groq](https://groq.com) — free LLM API powering the AI review
- [Semgrep](https://semgrep.dev) — open-source static analysis
- [Bandit](https://bandit.readthedocs.io) — Python security linter
- [FastAPI](https://fastapi.tiangolo.com) — the web framework
- [LangGraph](https://langchain-ai.github.io/langgraph/) — agent orchestration
- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) — free permanent public URLs

---

*Built with ❤️ — fully open source, zero cost to run.*
