from pydantic import BaseModel, HttpUrl
from typing import Optional
from enum import Enum


class EventType(str, Enum):
    """Types of GitHub events we care about"""
    PUSH = "push"
    PULL_REQUEST = "pull_request"


class AnalysisJob(BaseModel):
    """
    The single unified job object.
    Both /webhook and /analyze create one of these.
    The rest of the pipeline only ever sees this object —
    it doesn't care whether it came from a webhook or a manual request.
    """
    repo_url: str                        # e.g. https://github.com/user/repo
    repo_full_name: str                  # e.g. "user/repo"
    branch: str = "main"                 # which branch to analyze
    commit_sha: Optional[str] = None     # specific commit (from webhook)
    pr_number: Optional[int] = None      # PR number if triggered by a PR event
    triggered_by: str = "manual"         # "webhook" or "manual"
    author_email: Optional[str] = None   # who to notify


class ManualAnalysisRequest(BaseModel):
    """
    Body for POST /analyze
    You send this when you want to analyze any repo by URL.
    """
    repo_url: str    # e.g. "https://github.com/torvalds/linux"
    branch: str = "main"
    notify_email: Optional[str] = None   # where to send results