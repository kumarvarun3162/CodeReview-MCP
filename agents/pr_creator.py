# agents/pr_creator.py
import base64
from dataclasses import dataclass
from typing import Optional
from github import Github, GithubException, Repository
from agents.auto_fix import FixResult, FixedFile
from agents.code_reviewer import ReviewReport
from api.models import AnalysisJob
from core.config import settings


@dataclass
class CreatedPR:
    """Info about the PR that was created"""
    pr_number: int
    pr_url: str
    branch_name: str
    repo_full_name: str
    title: str


class PRCreatorAgent:
    """
    Creates a GitHub PR with the auto-fixed code.

    Steps:
    1. Get the target repo via GitHub API
    2. Create a new branch: code-review/fix-{sha}
    3. Push each fixed file to that branch
    4. Open a PR with a detailed description including all findings
    5. Return the PR info for the email notifier
    """

    def __init__(self):
        self.github = Github(settings.github_token)

    async def create_pr(
        self,
        fix_result: FixResult,
        report: ReviewReport,
        job: AnalysisJob,
    ) -> Optional[CreatedPR]:
        """
        Main entry point. Creates a PR and returns its details.
        Returns None if PR creation fails or there's nothing to fix.
        """
        if not fix_result.fixed_files:
            print("[PRCreator] No fixed files to commit — skipping PR creation")
            return None

        try:
            repo = self.github.get_repo(report.repo_full_name)
        except GithubException as e:
            print(f"[PRCreator] Cannot access repo {report.repo_full_name}: {e}")
            return None

        # Create branch name
        sha_short = (report.commit_sha or "auto")[:8]
        branch_name = f"code-review/fix-{sha_short}"

        # Get the base branch SHA to branch off from
        try:
            base_ref = repo.get_branch(job.branch)
            base_sha = base_ref.commit.sha
        except GithubException:
            print(f"[PRCreator] Branch '{job.branch}' not found")
            return None

        # Create the review branch
        try:
            repo.create_git_ref(
                ref=f"refs/heads/{branch_name}",
                sha=base_sha
            )
            print(f"[PRCreator] Created branch: {branch_name}")
        except GithubException as e:
            if "already exists" in str(e):
                # Branch from a previous run — reuse it
                print(f"[PRCreator] Branch already exists, reusing: {branch_name}")
            else:
                print(f"[PRCreator] Failed to create branch: {e}")
                return None

        # Push each fixed file to the branch
        for fixed_file in fix_result.fixed_files:
            self._push_file(repo, fixed_file, branch_name)

        # Build the PR body
        pr_title = self._build_pr_title(report)
        pr_body = self._build_pr_body(report, fix_result, job)

        # Open the PR
        try:
            pr = repo.create_pull(
                title=pr_title,
                body=pr_body,
                head=branch_name,
                base=job.branch,
            )
            print(f"[PRCreator] PR opened: {pr.html_url}")
            return CreatedPR(
                pr_number=pr.number,
                pr_url=pr.html_url,
                branch_name=branch_name,
                repo_full_name=report.repo_full_name,
                title=pr_title,
            )
        except GithubException as e:
            print(f"[PRCreator] Failed to open PR: {e}")
            return None

    def _push_file(
        self, repo: Repository.Repository,
        fixed_file: FixedFile,
        branch_name: str,
    ):
        """Pushes one fixed file to the review branch"""
        try:
            # Try to get the existing file (to get its SHA for update)
            try:
                existing = repo.get_contents(fixed_file.original_path, ref=branch_name)
                file_sha = existing.sha
                repo.update_file(
                    path=fixed_file.original_path,
                    message=f"fix: auto-fix issues in {fixed_file.original_path}",
                    content=fixed_file.fixed_content,
                    sha=file_sha,
                    branch=branch_name,
                )
            except GithubException:
                # File doesn't exist yet on this branch — create it
                repo.create_file(
                    path=fixed_file.original_path,
                    message=f"fix: auto-fix issues in {fixed_file.original_path}",
                    content=fixed_file.fixed_content,
                    branch=branch_name,
                )
            print(f"[PRCreator] Pushed: {fixed_file.original_path}")
        except GithubException as e:
            print(f"[PRCreator] Failed to push {fixed_file.original_path}: {e}")

    def _build_pr_title(self, report: ReviewReport) -> str:
        total = report.total_findings
        critical = report.critical_count
        high = report.high_count
        if critical > 0:
            return f"🔴 Code Review: {critical} critical issue{'s' if critical > 1 else ''} found & fixed"
        elif high > 0:
            return f"🟠 Code Review: {high} high-severity issue{'s' if high > 1 else ''} found & fixed"
        return f"🟡 Code Review: {total} issue{'s' if total > 1 else ''} found & fixed"

    def _build_pr_body(
        self,
        report: ReviewReport,
        fix_result: FixResult,
        job: AnalysisJob,
    ) -> str:
        """Builds a rich markdown PR description"""

        commit_ref = f"`{report.commit_sha[:10]}`" if report.commit_sha else "latest commit"

        lines = [
            "## 🤖 Automated Code Review Report",
            "",
            f"**Repository:** `{report.repo_full_name}`  ",
            f"**Branch:** `{job.branch}`  ",
            f"**Triggered by:** {commit_ref}  ",
            f"**Files reviewed:** {report.files_reviewed}  ",
            "",
            "---",
            "",
            "## 📊 Findings Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| 🔴 Critical | {report.critical_count} |",
            f"| 🟠 High | {report.high_count} |",
            f"| 🟡 Medium | {report.medium_count} |",
            f"| 🟢 Low | {report.low_count} |",
            f"| **Total** | **{report.total_findings}** |",
            "",
            "---",
            "",
            "## 💡 Overall Assessment",
            "",
            report.overall_summary,
            "",
            "---",
            "",
        ]

        # Auto-fixed files section
        if fix_result.fixed_files:
            lines += [
                "## ✅ Auto-Fixed Issues",
                "",
                "The following issues were automatically fixed in this PR:",
                "",
            ]
            for ff in fix_result.fixed_files:
                lines.append(f"**`{ff.original_path}`**")
                for fix in ff.fixes_applied:
                    lines.append(f"- {fix}")
                lines.append("")

        # Detailed findings
        if report.llm_findings:
            lines += ["## 🔍 Detailed Findings", ""]
            for f in report.llm_findings:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(f.severity, "⚪")
                line_ref = f"Line {f.line}" if f.line else "General"
                lines.append(f"### {emoji} `{f.file_path}` — {line_ref}")
                lines.append(f"**{f.title}** `[{f.severity.upper()}]` `[{f.category}]`  ")
                lines.append(f"{f.description}  ")
                if f.suggested_fix:
                    lines.append("")
                    lines.append("<details><summary>Suggested fix</summary>")
                    lines.append("")
                    lines.append(f"```{f.file_path.split('.')[-1]}")
                    lines.append(f.suggested_fix)
                    lines.append("```")
                    lines.append("</details>")
                lines.append("")

        lines += [
            "---",
            "",
            "> *This PR was created automatically by [Code Review MCP Server](https://github.com/kumarvarun3162/CodeReview-MCP).*  ",
            "> *Review the changes, then click **Approve** or **Reject** in the email notification.*",
        ]

        return "\n".join(lines)