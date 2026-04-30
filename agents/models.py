from pydantic import BaseModel
from typing import Optional
from enum import Enum


class SupportedLanguage(str, Enum):
    """Languages our scanners can handle"""
    PYTHON     = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA       = "java"
    GO         = "go"
    RUBY       = "ruby"
    UNKNOWN    = "unknown"


# Maps file extensions to language names
EXTENSION_MAP = {
    ".py":   SupportedLanguage.PYTHON,
    ".js":   SupportedLanguage.JAVASCRIPT,
    ".jsx":  SupportedLanguage.JAVASCRIPT,
    ".ts":   SupportedLanguage.TYPESCRIPT,
    ".tsx":  SupportedLanguage.TYPESCRIPT,
    ".java": SupportedLanguage.JAVA,
    ".go":   SupportedLanguage.GO,
    ".rb":   SupportedLanguage.RUBY,
}


class FileInfo(BaseModel):
    """Represents one source file extracted from the repo"""
    path: str                        # relative path: "src/auth/login.py"
    language: SupportedLanguage      # detected from extension
    content: str                     # full file content as string
    changed_lines: list[int] = []    # line numbers that changed (empty = whole file)
    is_new_file: bool = False        # True if file was just created in this commit


class DiffHunk(BaseModel):
    """One contiguous block of changes in a diff"""
    file_path: str
    old_start: int       # line number where the change starts in old file
    new_start: int       # line number where the change starts in new file
    added_lines: list[str]    # lines that were added
    removed_lines: list[str]  # lines that were removed


class FetchedCode(BaseModel):
    """
    The complete output of CodeFetcherAgent.
    Everything Phase 4 needs to run its scanners.
    """
    repo_full_name: str
    branch: str
    commit_sha: Optional[str]
    files: list[FileInfo]           # all files to analyze
    diff_hunks: list[DiffHunk]      # raw diff (webhook mode only)
    workspace_path: str             # where on disk the repo lives
    is_full_scan: bool              # True = manual, False = diff-only (webhook)
    total_lines_analyzed: int       # for logging/metrics

    @property
    def files_by_language(self) -> dict[str, list[FileInfo]]:
        """Groups files by language — useful for running language-specific scanners"""
        result: dict[str, list[FileInfo]] = {}
        for f in self.files:
            lang = f.language.value
            result.setdefault(lang, []).append(f)
        return result