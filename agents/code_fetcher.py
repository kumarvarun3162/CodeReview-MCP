# import os
# from pathlib import Path
# from typing import Optional

# # ── Windows fix: must happen BEFORE `import git` ──────────────────────────
# # GitPython crashes at import time if it can't find git.exe in PATH.
# # Setting this env var tells it exactly where to look.
# if os.name == "nt":
#     _git_candidates = [
#         r"C:\Program Files\Git\bin\git.exe",
#         r"C:\Program Files (x86)\Git\bin\git.exe",
#     ]
#     for _candidate in _git_candidates:
#         if os.path.exists(_candidate):
#             os.environ["GIT_PYTHON_GIT_EXECUTABLE"] = _candidate
#             break
# # ──────────────────────────────────────────────────────────────────────────

from pathlib import Path
from typing import Optional


from git import Repo, GitCommandError, InvalidGitRepositoryError

from api.models import AnalysisJob
from agents.models import (
    FileInfo, DiffHunk, FetchedCode,
    SupportedLanguage, EXTENSION_MAP
)
from core.config import settings

# Files and folders we never want to analyze
IGNORED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", ".next", "target", "vendor", ".idea",
    ".vscode", "coverage", ".pytest_cache", "migrations",
}

IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".pdf", ".zip", ".tar", ".gz", ".lock", ".sum",
    ".min.js", ".min.css", ".map",
}

# Don't analyze files larger than 5MB (minified JS, generated code, etc.)
MAX_FILE_SIZE_BYTES = 5000_000


class CodeFetcherAgent:
    """
    Responsible for:
    1. Cloning a GitHub repository to a local workspace
    2. Checking out the right branch/commit
    3. Extracting files to analyze (diff-only or full scan)
    4. Returning a FetchedCode object for downstream agents

    This agent knows nothing about security scanning or LLMs.
    Its only job is: get the code.
    """

    def __init__(self):
        self.github_token = settings.github_token

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def fetch(self, job: AnalysisJob, workspace_path: Path) -> FetchedCode:
        """
        Main method. Call this with a job and a workspace path.
        Returns FetchedCode ready for Phase 4.
        """
        print(f"[CodeFetcher] Starting fetch for {job.repo_full_name} ({job.branch})")

        # Step 1: Clone the repository
        repo = await self._clone_repo(job, workspace_path)

        # Step 2: Checkout the right commit
        if job.commit_sha:
            await self._checkout_commit(repo, job.commit_sha)

        # Step 3: Extract files based on mode
        if job.triggered_by == "webhook" and job.commit_sha:
            # Webhook mode: only analyze what changed
            files, diff_hunks = await self._extract_diff(repo, job.commit_sha)
            is_full_scan = False
            print(f"[CodeFetcher] Diff mode: {len(files)} changed files found")
        else:
            # Manual mode: scan everything
            files = await self._extract_all_files(workspace_path)
            diff_hunks = []
            is_full_scan = True
            print(f"[CodeFetcher] Full scan mode: {len(files)} files found")

        total_lines = sum(len(f.content.splitlines()) for f in files)

        return FetchedCode(
            repo_full_name=job.repo_full_name,
            branch=job.branch,
            commit_sha=job.commit_sha,
            files=files,
            diff_hunks=diff_hunks,
            workspace_path=str(workspace_path),
            is_full_scan=is_full_scan,
            total_lines_analyzed=total_lines,
        )

    # ------------------------------------------------------------------
    # Step 1: Clone
    # ------------------------------------------------------------------

    async def _clone_repo(self, job: AnalysisJob, workspace_path: Path) -> Repo:
        """
        Clones the repository into workspace_path/repo/.

        For private repos: injects the GitHub token into the clone URL.
        Uses shallow clone (depth=1) for speed — we only need recent history.
        For diff analysis we need depth=2 (current + parent commit).
        """
        repo_dir = workspace_path / "repo"

        # Build the authenticated clone URL
        # Public:  https://github.com/owner/repo.git
        # Private: https://TOKEN@github.com/owner/repo.git
        clone_url = self._build_clone_url(job.repo_url)

        print(f"[CodeFetcher] Cloning {job.repo_full_name} → branch: {job.branch}")

        try:
            repo = Repo.clone_from(
                url=clone_url,
                to_path=str(repo_dir),
                branch=job.branch,
                depth=2,          # depth=2 gives us current + parent (needed for diff)
                single_branch=True,  # only fetch this branch, much faster
            )
            print(f"[CodeFetcher] Clone complete")
            return repo

        except GitCommandError as e:
            error_msg = str(e)

            if "Repository not found" in error_msg or "not found" in error_msg.lower():
                raise ValueError(
                    f"Repository '{job.repo_full_name}' not found. "
                    f"Check the URL or provide a GitHub token for private repos."
                )
            elif "Remote branch" in error_msg and "not found" in error_msg:
                raise ValueError(
                    f"Branch '{job.branch}' not found in {job.repo_full_name}. "
                    f"Check the branch name."
                )
            elif "Authentication failed" in error_msg:
                raise ValueError(
                    f"Authentication failed for {job.repo_full_name}. "
                    f"Repository may be private. Provide a valid GitHub token."
                )
            else:
                raise ValueError(f"Git clone failed: {error_msg}")

    def _build_clone_url(self, repo_url: str) -> str:
        """
        Injects GitHub token into clone URL for authenticated access.
        This works for both public and private repos.

        https://github.com/owner/repo.git
        → https://TOKEN@github.com/owner/repo.git
        """
        if self.github_token and "github.com" in repo_url:
            # Insert token between https:// and github.com
            return repo_url.replace(
                "https://",
                f"https://{self.github_token}@"
            )
        return repo_url

    # ------------------------------------------------------------------
    # Step 2: Checkout
    # ------------------------------------------------------------------

    async def _checkout_commit(self, repo: Repo, commit_sha: str):
        """
        Checks out a specific commit so we analyze exactly
        the state of the code at that point in time.
        """
        try:
            repo.git.checkout(commit_sha)
            print(f"[CodeFetcher] Checked out commit: {commit_sha[:8]}")
        except GitCommandError as e:
            # Non-fatal: if checkout fails, we stay on the branch HEAD
            print(f"[CodeFetcher] Warning: could not checkout {commit_sha[:8]}: {e}")

    # ------------------------------------------------------------------
    # Step 3A: Extract diff (webhook mode)
    # ------------------------------------------------------------------

    async def _extract_diff(
        self, repo: Repo, commit_sha: str
    ) -> tuple[list[FileInfo], list[DiffHunk]]:
        """
        For webhook mode: compares the current commit to its parent.
        Only returns files that actually changed.

        This is efficient — if 2 files changed in a 500-file repo,
        we only analyze those 2 files.
        """
        files: list[FileInfo] = []
        diff_hunks: list[DiffHunk] = []

        try:
            current_commit = repo.commit(commit_sha)
        except Exception:
            current_commit = repo.head.commit

        # Get parent commit (what the code looked like before this push)
        if not current_commit.parents:
            # First commit in repo — no parent, so full scan instead
            print("[CodeFetcher] First commit detected, switching to full scan")
            return await self._extract_all_files(Path(repo.working_dir)), []

        parent_commit = current_commit.parents[0]

        # Get the diff between parent and current
        diffs = parent_commit.diff(current_commit)

        for diff_item in diffs:
            # Skip deleted files
            if diff_item.deleted_file:
                continue

            file_path = diff_item.b_path  # path in the new (current) commit

            # Skip files we can't or shouldn't analyze
            if self._should_skip_file(file_path):
                continue

            # Get language from extension
            language = self._detect_language(file_path)
            if language == SupportedLanguage.UNKNOWN:
                continue

            # Read the full file content from disk
            full_path = Path(repo.working_dir) / file_path
            content = self._read_file_safely(full_path)
            if content is None:
                continue

            # Figure out which line numbers changed
            changed_lines = self._extract_changed_lines(diff_item.diff)

            files.append(FileInfo(
                path=file_path,
                language=language,
                content=content,
                changed_lines=changed_lines,
                is_new_file=diff_item.new_file,
            ))

            # Parse diff hunks for detailed change info
            hunks = self._parse_diff_hunks(file_path, diff_item.diff)
            diff_hunks.extend(hunks)

        return files, diff_hunks

    def _extract_changed_lines(self, diff_bytes: bytes) -> list[int]:
        """
        Parses a git diff to find which line numbers were added/changed.
        We focus on added lines (the new code) since that's what needs review.

        Diff format example:
        @@ -10,7 +10,9 @@   ← means: starting at line 10 in new file
        +    new code here   ← added line
        """
        if not diff_bytes:
            return []

        changed_lines = []
        current_line = 0

        try:
            diff_text = diff_bytes.decode("utf-8", errors="replace")
        except Exception:
            return []

        for line in diff_text.splitlines():
            if line.startswith("@@"):
                # Parse the new file line number from @@ -old +new @@
                # Example: "@@ -10,7 +15,9 @@" → new start = 15
                parts = line.split("+")
                if len(parts) > 1:
                    new_part = parts[1].split("@@")[0].strip()
                    start = int(new_part.split(",")[0])
                    current_line = start - 1  # -1 because we increment before use

            elif line.startswith("+") and not line.startswith("+++"):
                current_line += 1
                changed_lines.append(current_line)

            elif not line.startswith("-"):
                current_line += 1

        return changed_lines

    def _parse_diff_hunks(self, file_path: str, diff_bytes: bytes) -> list[DiffHunk]:
        """Parses raw diff bytes into structured DiffHunk objects"""
        if not diff_bytes:
            return []

        hunks = []
        current_hunk = None
        old_line = new_line = 0

        try:
            diff_text = diff_bytes.decode("utf-8", errors="replace")
        except Exception:
            return []

        for line in diff_text.splitlines():
            if line.startswith("@@"):
                if current_hunk:
                    hunks.append(current_hunk)

                # Parse "@@ -old_start,count +new_start,count @@"
                try:
                    parts = line.split(" ")
                    old_info = parts[1].lstrip("-").split(",")
                    new_info = parts[2].lstrip("+").split(",")
                    old_line = int(old_info[0])
                    new_line = int(new_info[0])
                    current_hunk = DiffHunk(
                        file_path=file_path,
                        old_start=old_line,
                        new_start=new_line,
                        added_lines=[],
                        removed_lines=[],
                    )
                except (IndexError, ValueError):
                    continue

            elif current_hunk:
                if line.startswith("+") and not line.startswith("+++"):
                    current_hunk.added_lines.append(line[1:])
                elif line.startswith("-") and not line.startswith("---"):
                    current_hunk.removed_lines.append(line[1:])

        if current_hunk:
            hunks.append(current_hunk)

        return hunks

    # ------------------------------------------------------------------
    # Step 3B: Extract all files (manual / full scan mode)
    # ------------------------------------------------------------------

    async def _extract_all_files(self, workspace_path: Path) -> list[FileInfo]:
        """
        For manual mode: walks the entire repo and collects
        all analyzable source files.

        Skips: node_modules, venv, build artifacts, binary files, huge files.
        """
        files: list[FileInfo] = []

        # The actual repo is cloned into workspace_path/repo/
        repo_dir = workspace_path / "repo"
        if not repo_dir.exists():
            repo_dir = workspace_path  # fallback

        for root, dirs, filenames in os.walk(repo_dir):
            # Prune ignored directories in-place (stops os.walk from descending)
            dirs[:] = [
                d for d in dirs
                if d not in IGNORED_DIRS and not d.startswith(".")
            ]

            for filename in filenames:
                file_path = Path(root) / filename
                relative_path = str(file_path.relative_to(repo_dir))

                if self._should_skip_file(relative_path):
                    continue

                language = self._detect_language(filename)
                if language == SupportedLanguage.UNKNOWN:
                    continue

                content = self._read_file_safely(file_path)
                if content is None:
                    continue

                files.append(FileInfo(
                    path=relative_path,
                    language=language,
                    content=content,
                    changed_lines=[],   # empty = full file is relevant
                    is_new_file=False,
                ))

        return files

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _detect_language(self, file_path: str) -> SupportedLanguage:
        """Detects programming language from file extension"""
        suffix = Path(file_path).suffix.lower()
        return EXTENSION_MAP.get(suffix, SupportedLanguage.UNKNOWN)

    def _should_skip_file(self, file_path: str) -> bool:
        """Returns True if this file should be excluded from analysis"""
        path = Path(file_path)

        # Check if any part of the path is an ignored directory
        for part in path.parts[:-1]:  # all parts except filename
            if part in IGNORED_DIRS or part.startswith("."):
                return True

        # Check extension
        suffix = path.suffix.lower()
        if suffix in IGNORED_EXTENSIONS:
            return True

        # Skip hidden files
        if path.name.startswith("."):
            return True

        return False

    def _read_file_safely(self, file_path: Path) -> Optional[str]:
        """
        Reads file content as text, with safety checks.
        Returns None if file can't be read or should be skipped.
        """
        try:
            # Skip files that are too large
            if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                print(f"[CodeFetcher] Skipping large file: {file_path.name}")
                return None

            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()

        except (OSError, PermissionError) as e:
            print(f"[CodeFetcher] Could not read {file_path.name}: {e}")
            return None