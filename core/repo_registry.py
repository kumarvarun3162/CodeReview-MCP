# core/repo_registry.py
import json
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class RegisteredRepo(BaseModel):
    """One entry in the repo registry"""
    repo_full_name: str          # "owner/repo"
    repo_url: str                # "https://github.com/owner/repo.git"
    notify_email: str            # who gets the approval email
    branch: str = "main"        # which branch to watch
    added_at: str = ""          # timestamp when registered
    enabled: bool = True         # can pause without removing


class RepoRegistry:
    """
    File-based registry of repos the server monitors via webhook.
    Thread-safe — multiple background jobs can read simultaneously.

    Storage: repos.json in the project root.
    Format:  {"owner/repo": {RegisteredRepo dict}, ...}

    Why file-based and not a database?
    For this use case, the registry rarely changes and is small.
    A JSON file is simpler, portable, and human-readable.
    You can edit it directly in VS Code if needed.
    """

    def __init__(self, registry_file: str = "repos.json"):
        self.registry_file = Path(registry_file)
        self._lock = threading.RLock()   # reentrant lock for thread safety
        self._ensure_file()

    def _ensure_file(self):
        """Creates repos.json with empty registry if it doesn't exist"""
        if not self.registry_file.exists():
            self._write({})
            print(f"[Registry] Created new registry at {self.registry_file}")

    def _read(self) -> dict:
        with self._lock:
            try:
                return json.loads(self.registry_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, FileNotFoundError):
                return {}

    def _write(self, data: dict):
        with self._lock:
            self.registry_file.write_text(
                json.dumps(data, indent=2),
                encoding="utf-8"
            )

    # ── Public API ────────────────────────────────────────────────────────────

    def add_repo(
        self,
        repo_full_name: str,
        notify_email: str,
        branch: str = "main",
    ) -> RegisteredRepo:
        """
        Adds a repo to the registry.
        If it already exists, updates its settings.
        """
        # Normalize: strip .git, lowercase, strip trailing slash
        name = repo_full_name.strip().lower().rstrip("/")
        if name.endswith(".git"):
            name = name[:-4]

        # Accept full URLs too: https://github.com/owner/repo → owner/repo
        if "github.com/" in name:
            name = name.split("github.com/")[-1]

        repo_url = f"https://github.com/{name}.git"
        entry = RegisteredRepo(
            repo_full_name=name,
            repo_url=repo_url,
            notify_email=notify_email,
            branch=branch,
            added_at=datetime.utcnow().isoformat(),
            enabled=True,
        )

        data = self._read()
        data[name] = entry.model_dump()
        self._write(data)

        print(f"[Registry] Added: {name} (notify: {notify_email})")
        return entry

    def remove_repo(self, repo_full_name: str) -> bool:
        """Removes a repo from the registry. Returns True if it existed."""
        name = repo_full_name.strip().lower()
        data = self._read()
        if name in data:
            del data[name]
            self._write(data)
            print(f"[Registry] Removed: {name}")
            return True
        return False

    def get_repo(self, repo_full_name: str) -> Optional[RegisteredRepo]:
        """Returns a registered repo or None if not found"""
        name = repo_full_name.strip().lower()
        data = self._read()
        if name in data:
            return RegisteredRepo(**data[name])
        return None

    def is_registered(self, repo_full_name: str) -> bool:
        """Quick check — is this repo registered and enabled?"""
        repo = self.get_repo(repo_full_name)
        return repo is not None and repo.enabled

    def list_repos(self) -> list[RegisteredRepo]:
        """Returns all registered repos"""
        data = self._read()
        return [RegisteredRepo(**v) for v in data.values()]

    def set_enabled(self, repo_full_name: str, enabled: bool) -> bool:
        """Pause/resume a repo without removing it"""
        name = repo_full_name.strip().lower()
        data = self._read()
        if name in data:
            data[name]["enabled"] = enabled
            self._write(data)
            state = "enabled" if enabled else "paused"
            print(f"[Registry] {name} is now {state}")
            return True
        return False


# Shared instance used across the app
repo_registry = RepoRegistry()