# api/app.py
import json
import asyncio
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks, Header
from fastapi.responses import JSONResponse
from typing import Optional

from api.models import AnalysisJob, ManualAnalysisRequest
from api.security import verify_github_signature
from api.webhook_parser import parse_push_event, parse_pull_request_event
from core.config import settings


from pathlib import Path
from core.workspace import workspace_manager
from agents.code_fetcher import CodeFetcherAgent
from utils.diff_summary import build_diff_summary

app = FastAPI(
    title="Code Review MCP Server",
    description="Automated multi-agent code review for any GitHub repository",
    version="0.1.0",
)


# ---------------------------------------------------------------------------
# Helper: background job runner
# We run analysis in the background so the webhook endpoint can return
# HTTP 200 immediately. GitHub expects a fast response — if you take
# longer than 10 seconds, GitHub marks the delivery as failed.
# ---------------------------------------------------------------------------

async def run_analysis_job(job: AnalysisJob):
    """
    Main pipeline runner. Phases 4 and 5 will add more steps below.
    """
    print(f"\n[Pipeline] Starting job: {job.repo_full_name} ({job.triggered_by})")

    code_fetcher = CodeFetcherAgent()

    # Workspace is created and automatically cleaned up after analysis
    async with workspace_manager.job_workspace(job.repo_full_name, job.branch) as workspace:
        try:
            # Phase 3: Fetch the code
            fetched_code = await code_fetcher.fetch(job, workspace)

            # Print a human-readable summary of what was fetched
            summary = build_diff_summary(fetched_code)
            print(summary)

            print(f"[Pipeline] Code fetched successfully.")
            print(f"[Pipeline] {len(fetched_code.files)} files ready for scanning.")

            # ── Phase 4 will go here ──────────────────────────────────
            # scan_results = await vuln_scanner.scan(fetched_code)
            # review = await code_reviewer.review(fetched_code)
            # ─────────────────────────────────────────────────────────

            # ── Phase 5 will go here ──────────────────────────────────
            # fixed_code = await auto_fix_agent.fix(fetched_code, scan_results)
            # pr = await pr_creator.create_pr(fixed_code, job)
            # await email_notifier.send_approval(pr, job)
            # ─────────────────────────────────────────────────────────

        except ValueError as e:
            # Known errors (bad URL, private repo, bad branch)
            print(f"[Pipeline] Error: {e}")
        except Exception as e:
            # Unexpected errors — log but don't crash the server
            print(f"[Pipeline] Unexpected error for {job.repo_full_name}: {e}")
            raise
# ---------------------------------------------------------------------------
# Route 1: GitHub webhook (automatic trigger)
# ---------------------------------------------------------------------------

@app.post("/webhook")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: Optional[str] = Header(None),
):
    """
    Receives events directly from GitHub.
    GitHub calls this automatically on push or PR events.

    Steps:
    1. Verify the request is genuinely from GitHub (signature check)
    2. Parse the payload based on event type
    3. Create an AnalysisJob
    4. Queue it as a background task
    5. Return 200 immediately so GitHub doesn't retry
    """
    # Step 1: Verify GitHub's signature
    body = await verify_github_signature(request)
    payload = json.loads(body)

    # Step 2: Route by event type
    job: Optional[AnalysisJob] = None

    if x_github_event == "push":
        job = parse_push_event(payload)

    elif x_github_event == "pull_request":
        job = parse_pull_request_event(payload)

    elif x_github_event == "ping":
        # GitHub sends a ping when you first set up a webhook
        # Just confirm we're alive
        return JSONResponse({"status": "pong", "message": "Webhook connected!"})

    else:
        # We don't handle this event type — that's fine, just ignore it
        return JSONResponse({"status": "ignored", "event": x_github_event})

    if job is None:
        return JSONResponse({"status": "skipped", "reason": "Event not actionable"})

    # Step 3: Queue analysis as background task
    background_tasks.add_task(run_analysis_job, job)

    return JSONResponse({
        "status": "queued",
        "repo": job.repo_full_name,
        "branch": job.branch,
    })


# ---------------------------------------------------------------------------
# Route 2: Manual on-demand analysis (any repo URL)
# ---------------------------------------------------------------------------

@app.post("/analyze")
async def analyze_repo(
    request_body: ManualAnalysisRequest,
    background_tasks: BackgroundTasks,
):
    """
    Manually trigger analysis on ANY GitHub repository.

    Usage:
        POST /analyze
        {
            "repo_url": "https://github.com/someone/their-repo",
            "branch": "main",
            "notify_email": "you@example.com"
        }

    This is what lets you analyze repos you don't own.
    No webhook setup needed on that repo.
    """
    # Extract repo full name from URL
    # "https://github.com/owner/repo" → "owner/repo"
    try:
        parts = request_body.repo_url.rstrip("/").split("/")
        repo_full_name = f"{parts[-2]}/{parts[-1]}"
    except (IndexError, ValueError):
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub URL. Expected format: https://github.com/owner/repo"
        )

    # Build the clone URL (add .git if missing)
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
        "message": f"Analysis started. Results will be sent to {request_body.notify_email or 'no email provided'}",
    })


# ---------------------------------------------------------------------------
# Route 3: Health check
# ---------------------------------------------------------------------------

@app.get("/health")
async def health_check():
    """Simple health check — used to verify the server is alive."""
    return {"status": "ok", "server": "Code Review MCP Server v0.1.0"}