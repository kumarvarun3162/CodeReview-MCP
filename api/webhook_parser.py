# api/webhook_parser.py
import json
from typing import Optional
from api.models import AnalysisJob


def parse_push_event(payload: dict) -> Optional[AnalysisJob]:
    """
    Converts a raw GitHub push event payload into an AnalysisJob.

    GitHub sends a LOT of data in a push event. We extract only
    what we need and pack it into our clean AnalysisJob object.
    """
    # Skip if it's a branch deletion (no code to analyze)
    if payload.get("deleted", False):
        return None

    # Skip pushes to non-main branches (configurable later)
    ref = payload.get("ref", "")           # e.g. "refs/heads/main"
    branch = ref.replace("refs/heads/", "") # → "main"

    repo = payload.get("repository", {})
    pusher = payload.get("pusher", {})
    head_commit = payload.get("head_commit", {})

    # Try to get the author's email for notifications
    author_email = (
        head_commit.get("author", {}).get("email")
        or pusher.get("email")
    )

    return AnalysisJob(
        repo_url=repo.get("clone_url", ""),
        repo_full_name=repo.get("full_name", ""),
        branch=branch,
        commit_sha=head_commit.get("id"),
        triggered_by="webhook",
        author_email=author_email,
    )


def parse_pull_request_event(payload: dict) -> Optional[AnalysisJob]:
    """
    Converts a GitHub pull_request event into an AnalysisJob.
    Only triggers on opened or synchronize (new commits pushed to PR).
    """
    action = payload.get("action", "")

    # Only analyze when a PR is opened or updated, not closed/labeled/etc.
    if action not in ("opened", "synchronize"):
        return None

    pr = payload.get("pull_request", {})
    repo = payload.get("repository", {})

    return AnalysisJob(
        repo_url=repo.get("clone_url", ""),
        repo_full_name=repo.get("full_name", ""),
        branch=pr.get("head", {}).get("ref", "main"),
        commit_sha=pr.get("head", {}).get("sha"),
        pr_number=pr.get("number"),
        triggered_by="webhook",
        author_email=pr.get("user", {}).get("email"),
    )