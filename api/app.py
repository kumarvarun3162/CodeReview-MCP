# api/app.py
import json
import asyncio
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks, Header
from fastapi.responses import JSONResponse, HTMLResponse          # ← combined, no duplicate
from typing import Optional
from pydantic import BaseModel

from api.models import AnalysisJob, ManualAnalysisRequest
from api.security import verify_github_signature
from api.webhook_parser import parse_push_event, parse_pull_request_event
from core.config import settings
from core.workspace import workspace_manager
from core.repo_registry import repo_registry, RegisteredRepo
from agents.code_fetcher import CodeFetcherAgent
from agents.vuln_scanner import VulnScannerAgent
from agents.auto_fix import AutoFixAgent
from agents.pr_creator import PRCreatorAgent
from agents.email_notifier import EmailNotifierAgent              # ← imported once
from utils.diff_summary import build_diff_summary
from itsdangerous import SignatureExpired, BadSignature
from github import Github, GithubException


app = FastAPI(
    title="Code Review MCP Server",
    description="Automated multi-agent code review for any GitHub repository",
    version="0.1.0",
)

# Single shared instance
_email_notifier = EmailNotifierAgent()


# ── Pipeline runner ────────────────────────────────────────────────────────

async def run_analysis_job(job: AnalysisJob):
    print(f"\n[Pipeline] ▶ {job.repo_full_name} ({job.triggered_by})")

    code_fetcher   = CodeFetcherAgent()
    vuln_scanner   = VulnScannerAgent()
    auto_fix       = AutoFixAgent()
    pr_creator     = PRCreatorAgent()
    email_notifier = EmailNotifierAgent()

    async with workspace_manager.job_workspace(job.repo_full_name, job.branch) as workspace:
        try:
            # Phase 3 — Fetch
            fetched = await code_fetcher.fetch(job, workspace)
            print(build_diff_summary(fetched))
            if not fetched.files:
                print("[Pipeline] No analyzable files found. Done.")
                return

            # Phase 4 — Scan + Review
            report = await vuln_scanner.scan(fetched)
            if not report.has_critical_issues:
                print("[Pipeline] No critical/high issues found. No PR needed.")
                return

            # Phase 5 — Auto-fix → PR → Email
            fix_result = await auto_fix.fix(fetched, report)

            pr = await pr_creator.create_pr(fix_result, report, job)
            if not pr:
                print("[Pipeline] PR creation failed. Done.")
                return

            await email_notifier.send_approval_email(pr, report, job)
            print(f"[Pipeline] ✅ Complete. PR #{pr.pr_number}: {pr.pr_url}")

        except ValueError as e:
            print(f"[Pipeline] ✗ {e}")
        except Exception as e:
            print(f"[Pipeline] ✗ Unexpected error: {e}")
            raise


# ── Route 1: GitHub Webhook ────────────────────────────────────────────────

@app.post("/webhook")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: Optional[str] = Header(None),
):
    body = await verify_github_signature(request)
    payload = json.loads(body)

    job: Optional[AnalysisJob] = None

    if x_github_event == "ping":
        return JSONResponse({"status": "pong", "message": "Webhook connected!"})
    elif x_github_event == "push":
        job = parse_push_event(payload)
    elif x_github_event == "pull_request":
        job = parse_pull_request_event(payload)
    else:
        return JSONResponse({"status": "ignored", "event": x_github_event})

    if job is None:
        return JSONResponse({"status": "skipped", "reason": "Event not actionable"})

    # Registry check — only process registered repos
    if not repo_registry.is_registered(job.repo_full_name):
        print(f"[Webhook] Ignored unregistered repo: {job.repo_full_name}")
        return JSONResponse({
            "status": "ignored",
            "reason": f"Repo '{job.repo_full_name}' not registered. Call POST /repos/add first."
        })

    # Use the registered email for notifications
    registered = repo_registry.get_repo(job.repo_full_name)
    if registered:
        job.author_email = registered.notify_email

    # ✅ BUG 1 FIX — actually queue the job and return a response
    background_tasks.add_task(run_analysis_job, job)
    return JSONResponse({
        "status": "queued",
        "repo": job.repo_full_name,
        "branch": job.branch,
    })


# ── Route 2: Manual on-demand analysis ────────────────────────────────────

@app.post("/analyze")
async def analyze_repo(
    request_body: ManualAnalysisRequest,
    background_tasks: BackgroundTasks,
):
    try:
        parts = request_body.repo_url.rstrip("/").split("/")
        repo_full_name = f"{parts[-2]}/{parts[-1]}"
        # Strip .git from name if present
        if repo_full_name.endswith(".git"):
            repo_full_name = repo_full_name[:-4]
    except (IndexError, ValueError):
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub URL. Expected: https://github.com/owner/repo"
        )

    clone_url = request_body.repo_url
    if not clone_url.endswith(".git"):
        clone_url += ".git"

    job = AnalysisJob(
        repo_url=clone_url,
        repo_full_name=repo_full_name,
        branch=request_body.branch,
        triggered_by="manual",
        author_email=request_body.notify_email,
    )

    background_tasks.add_task(run_analysis_job, job)

    return JSONResponse({
        "status": "queued",
        "repo": repo_full_name,
        "branch": request_body.branch,
        "message": f"Analysis started. Results → {request_body.notify_email or 'no email'}",
    })


# ── Route 3: Repo Registry ────────────────────────────────────────────────

class AddRepoRequest(BaseModel):
    repo_url: str
    notify_email: str
    branch: str = "main"

class RemoveRepoRequest(BaseModel):
    repo_full_name: str


@app.post("/repos/add")
async def add_repo(body: AddRepoRequest):
    repo = repo_registry.add_repo(
        repo_full_name=body.repo_url,
        notify_email=body.notify_email,
        branch=body.branch,
    )
    return {
        "status": "added",
        "repo": repo.repo_full_name,
        "notify_email": repo.notify_email,
        "branch": repo.branch,
        "message": (
            f"Webhook URL for this repo: your_tunnel_url/webhook  "
            f"Set it at: https://github.com/{repo.repo_full_name}/settings/hooks"
        )
    }


@app.delete("/repos/remove")
async def remove_repo(body: RemoveRepoRequest):
    removed = repo_registry.remove_repo(body.repo_full_name)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Repo not found: {body.repo_full_name}")
    return {"status": "removed", "repo": body.repo_full_name}


@app.get("/repos/list")
async def list_repos():
    repos = repo_registry.list_repos()
    return {
        "total": len(repos),
        "repos": [r.model_dump() for r in repos]
    }


@app.patch("/repos/toggle")
async def toggle_repo(repo_full_name: str, enabled: bool):
    ok = repo_registry.set_enabled(repo_full_name, enabled)
    if not ok:
        raise HTTPException(status_code=404, detail="Repo not found")
    return {"status": "updated", "repo": repo_full_name, "enabled": enabled}


# ── Route 4: Approval Callback ────────────────────────────────────────────

@app.get("/callback/{action}/{token}", response_class=HTMLResponse)
async def approval_callback(action: str, token: str):
    if action not in ("approve", "reject"):
        return _html_result("❌ Invalid Action", "Unknown action. Nothing was done.", "#dc2626")

    try:
        payload = _email_notifier.verify_token(token, action)
    except SignatureExpired:
        return _html_result(
            "⏰ Link Expired",
            "This approval link has expired (48h limit). Merge or close the PR manually on GitHub.",
            "#f59e0b"
        )
    except BadSignature:
        return _html_result(
            "❌ Invalid Link",
            "This link is invalid or tampered with. Nothing was done.",
            "#dc2626"
        )

    repo_name   = payload["repo"]
    pr_number   = payload["pr_number"]
    branch_name = payload["branch"]

    try:
        github = Github(settings.github_token)
        repo   = github.get_repo(repo_name)
        pr     = repo.get_pull(pr_number)

        if action == "approve":
            pr.merge(
                merge_method="squash",
                commit_title=f"Auto-merge: {pr.title}",
                commit_message="Merged via Code Review MCP Server.",
            )
            try:
                repo.get_git_ref(f"heads/{branch_name}").delete()
            except GithubException:
                pass
            return _html_result(
                "✅ PR Approved & Merged",
                f"Pull Request #{pr_number} on {repo_name} has been merged. Branch deleted.",
                "#16a34a"
            )
        else:
            pr.edit(state="closed")
            try:
                repo.get_git_ref(f"heads/{branch_name}").delete()
            except GithubException:
                pass
            return _html_result(
                "❌ PR Rejected & Closed",
                f"Pull Request #{pr_number} on {repo_name} has been closed. No changes merged.",
                "#dc2626"
            )

    except GithubException as e:
        return _html_result("⚠️ GitHub Error", str(e), "#f59e0b")


def _html_result(title: str, message: str, color: str) -> str:
    icon = title.split()[0]
    heading = " ".join(title.split()[1:])
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title>
<meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
             background:#f8fafc;display:flex;align-items:center;
             justify-content:center;min-height:100vh;margin:0;">
  <div style="background:white;border-radius:16px;padding:48px;text-align:center;
              box-shadow:0 4px 24px rgba(0,0,0,0.08);max-width:480px;">
    <div style="font-size:56px;margin-bottom:16px;">{icon}</div>
    <h1 style="color:{color};margin:0 0 16px;font-size:24px;">{heading}</h1>
    <p style="color:#64748b;line-height:1.6;margin:0 0 24px;">{message}</p>
    <a href="https://github.com"
       style="display:inline-block;background:#1e293b;color:white;
              padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;">
      Go to GitHub
    </a>
  </div>
</body></html>"""


# ── Route 5: Health check ─────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    return {"status": "ok", "server": "Code Review MCP Server v0.1.0"}