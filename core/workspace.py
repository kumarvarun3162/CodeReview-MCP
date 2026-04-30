# core/workspace.py
import os
import shutil
import tempfile
from pathlib import Path
from datetime import datetime
from contextlib import asynccontextmanager


class WorkspaceManager:
    """
    Manages temporary disk space for cloned repositories.

    Each analysis job gets its own isolated folder.
    The folder is automatically deleted when analysis finishes
    (or crashes — the context manager handles both cases).

    Folder naming: workspace/owner__repo__branch__HHMMSS
    Example:       workspace/torvalds__linux__main__143022
    """

    def __init__(self, base_dir: str = "workspace"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)

    def create_job_workspace(self, repo_full_name: str, branch: str) -> Path:
        """
        Creates a unique directory for one analysis job.
        repo_full_name: "owner/repo"  →  sanitized to "owner__repo"
        """
        timestamp = datetime.now().strftime("%H%M%S%f")[:8]
        safe_name = repo_full_name.replace("/", "__").replace("\\", "__")
        safe_branch = branch.replace("/", "_")
        folder_name = f"{safe_name}__{safe_branch}__{timestamp}"

        workspace_path = self.base_dir / folder_name
        workspace_path.mkdir(parents=True, exist_ok=True)

        print(f"[Workspace] Created: {workspace_path}")
        return workspace_path

    def cleanup(self, workspace_path: Path):
        """Deletes the workspace folder and everything inside it."""
        if workspace_path.exists():
            shutil.rmtree(workspace_path)
            print(f"[Workspace] Cleaned up: {workspace_path}")

    @asynccontextmanager
    async def job_workspace(self, repo_full_name: str, branch: str):
        """
        Context manager — use this in agents so cleanup is guaranteed.

        Usage:
            async with workspace_manager.job_workspace("owner/repo", "main") as path:
                # clone, analyze, etc. — path is your workspace
            # folder is automatically deleted here, even if an error occurred
        """
        path = self.create_job_workspace(repo_full_name, branch)
        try:
            yield path          # give the caller the path
        finally:
            self.cleanup(path)  # always runs, even on exception


# Single shared instance
workspace_manager = WorkspaceManager()