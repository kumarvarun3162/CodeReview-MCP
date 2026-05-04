# agents/code_reviewer.py
from dataclasses import dataclass, field
from typing import Optional
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from agents.models import FetchedCode, FileInfo
from tools.ast_scanner import ASTFinding
from tools.bandit_scanner import BanditFinding
from tools.semgrep_scanner import SemgrepFinding
from utils.diff_summary import build_file_context_for_llm
from core.config import settings


@dataclass
class LLMFinding:
    """One issue identified by the LLM code reviewer"""
    file_path: str
    line: Optional[int]
    severity: str
    category: str       # "quality" | "security" | "performance" | "documentation"
    title: str
    description: str
    suggested_fix: str  # actual corrected code snippet


@dataclass
class ReviewReport:
    """
    Complete output of Phase 4.
    Contains all findings from all scanners + LLM review.
    Phase 5 reads this to generate patches.
    """
    repo_full_name: str
    commit_sha: Optional[str]
    files_reviewed: int

    # Raw findings from static scanners
    ast_findings:     list[ASTFinding]     = field(default_factory=list)
    bandit_findings:  list[BanditFinding]  = field(default_factory=list)
    semgrep_findings: list[SemgrepFinding] = field(default_factory=list)
    llm_findings:     list[LLMFinding]     = field(default_factory=list)

    # Summary counts by severity
    critical_count: int = 0
    high_count:     int = 0
    medium_count:   int = 0
    low_count:      int = 0

    # The LLM's overall narrative summary
    overall_summary: str = ""

    def compute_severity_counts(self):
        """Counts findings by severity across all scanners"""
        all_severities = (
            [f.severity for f in self.ast_findings]
            + [f.severity for f in self.bandit_findings]
            + [f.severity for f in self.semgrep_findings]
            + [f.severity for f in self.llm_findings]
        )
        self.critical_count = all_severities.count("critical")
        self.high_count     = all_severities.count("high")
        self.medium_count   = all_severities.count("medium")
        self.low_count      = all_severities.count("low")

    @property
    def total_findings(self) -> int:
        return (self.critical_count + self.high_count
                + self.medium_count + self.low_count)

    @property
    def has_critical_issues(self) -> bool:
        return self.critical_count > 0 or self.high_count > 0


class CodeReviewerAgent:
    """
    Uses Groq's LLM to review code quality, style, performance,
    and documentation. Takes scanner findings as context so the LLM
    can reason about them alongside the actual code.
    """

    # Max characters of code to send per LLM call
    # Groq's free tier supports 8192 tokens — we stay well under that
    MAX_CODE_CHARS = 12_000

    def __init__(self):
        self.llm = ChatGroq(
            api_key=settings.groq_api_key,
            model="llama-3.3-70b-versatile",  # best free model on Groq
            temperature=0.1,   # low temperature = more consistent, less creative
            max_tokens=4096,
        )

    async def review(
        self,
        fetched: FetchedCode,
        ast_findings: list[ASTFinding],
        bandit_findings: list[BanditFinding],
        semgrep_findings: list[SemgrepFinding],
    ) -> tuple[list[LLMFinding], str]:
        """
        Main entry point. Reviews all files and returns:
        - list of LLMFinding objects
        - overall summary string
        """
        all_llm_findings: list[LLMFinding] = []
        file_reviews: list[str] = []

        # Group static findings by file path for easy lookup
        ast_by_file = _group_by_file(ast_findings, "file_path")
        bandit_by_file = _group_by_file(bandit_findings, "file_path")
        semgrep_by_file = _group_by_file(semgrep_findings, "file_path")

        print(f"[CodeReviewer] Reviewing {len(fetched.files)} files with Groq LLM...")

        for file in fetched.files:
            # Collect all static findings for this file
            file_static_findings = (
                ast_by_file.get(file.path, [])
                + bandit_by_file.get(file.path, [])
                + semgrep_by_file.get(file.path, [])
            )

            findings, summary = await self._review_single_file(
                file, file_static_findings
            )
            all_llm_findings.extend(findings)
            if summary:
                file_reviews.append(f"**{file.path}**: {summary}")

        # Generate an overall cross-file summary
        overall = await self._generate_overall_summary(
            fetched, all_llm_findings, file_reviews
        )

        return all_llm_findings, overall

    async def _review_single_file(
        self,
        file: FileInfo,
        static_findings: list,
    ) -> tuple[list[LLMFinding], str]:
        """Reviews one file and returns its LLM findings"""

        code_context = build_file_context_for_llm(file, max_lines=150)

        # Truncate if too long
        if len(code_context) > self.MAX_CODE_CHARS:
            code_context = code_context[:self.MAX_CODE_CHARS] + "\n... (truncated)"

        # Format static findings as context for the LLM
        static_context = _format_static_findings(static_findings)

        system_prompt = """You are a senior software engineer conducting a thorough code review.
You will be given:
1. A code file with line numbers
2. Static analysis findings already detected by automated tools

Your job is to find ADDITIONAL issues the static tools missed, focusing on:
- Code quality and readability (confusing logic, poor naming, magic numbers)
- Performance issues (N+1 queries, unnecessary loops, missing caching)
- Security issues not caught by static tools (business logic flaws, auth gaps)
- Missing error handling and edge cases
- Documentation gaps on complex logic

RESPONSE FORMAT — respond ONLY with valid JSON, no markdown, no explanation:
{
  "findings": [
    {
      "line": 42,
      "severity": "high",
      "category": "security",
      "title": "Short title of the issue",
      "description": "Clear explanation of why this is a problem",
      "suggested_fix": "The corrected code as a snippet"
    }
  ],
  "summary": "One sentence summary of the file's overall quality"
}

severity must be one of: critical, high, medium, low
category must be one of: security, quality, performance, documentation

Only include real issues. Do not repeat issues already in the static findings.
If the code is clean, return an empty findings array."""

        human_prompt = f"""FILE: {file.path}
LANGUAGE: {file.language.value}

STATIC ANALYSIS FINDINGS ALREADY DETECTED:
{static_context if static_context else "None"}

CODE TO REVIEW:
{code_context}

Find additional issues the static tools missed. Return JSON only."""

        try:
            response = await self.llm.ainvoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=human_prompt),
            ])

            return self._parse_llm_response(response.content, file.path)

        except Exception as e:
            print(f"[CodeReviewer] LLM error for {file.path}: {e}")
            return [], ""

    async def _generate_overall_summary(
        self,
        fetched: FetchedCode,
        all_findings: list[LLMFinding],
        file_reviews: list[str],
    ) -> str:
        """Asks the LLM to write an executive summary of all findings"""

        if not all_findings and not file_reviews:
            return "No significant issues found. Code looks clean."

        findings_summary = "\n".join([
            f"- [{f.severity.upper()}] {f.file_path}:{f.line or '?'} — {f.title}"
            for f in all_findings[:20]  # cap at 20 for token limit
        ])

        prompt = f"""You reviewed {fetched.files_reviewed if hasattr(fetched, 'files_reviewed') else len(fetched.files)} files in {fetched.repo_full_name}.

Here are the key findings:
{findings_summary}

Write a concise executive summary (3-5 sentences) for the PR description.
Cover: overall code quality, most critical issues, and what the developer should prioritize fixing.
Be direct and specific. No fluff."""

        try:
            response = await self.llm.ainvoke([
                HumanMessage(content=prompt)
            ])
            return response.content.strip()
        except Exception as e:
            print(f"[CodeReviewer] Summary generation error: {e}")
            return f"Review complete. Found {len(all_findings)} issues across {len(fetched.files)} files."

    def _parse_llm_response(
        self, content: str, file_path: str
    ) -> tuple[list[LLMFinding], str]:
        """
        Parses the LLM's JSON response into LLMFinding objects.
        Handles cases where the LLM adds markdown or extra text.
        """
        import json
        import re

        # Strip markdown code blocks if LLM added them despite instructions
        content = re.sub(r"```json\s*", "", content)
        content = re.sub(r"```\s*", "", content)
        content = content.strip()

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            # Try to extract JSON from within the response
            match = re.search(r"\{.*\}", content, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group())
                except json.JSONDecodeError:
                    print(f"[CodeReviewer] Could not parse LLM JSON for {file_path}")
                    return [], ""
            else:
                return [], ""

        findings = []
        for item in data.get("findings", []):
            findings.append(LLMFinding(
                file_path=file_path,
                line=item.get("line"),
                severity=item.get("severity", "low"),
                category=item.get("category", "quality"),
                title=item.get("title", "Issue"),
                description=item.get("description", ""),
                suggested_fix=item.get("suggested_fix", ""),
            ))

        summary = data.get("summary", "")
        return findings, summary


# ── Helpers ──────────────────────────────────────────────────────────────────

def _group_by_file(findings: list, attr: str) -> dict[str, list]:
    result = {}
    for f in findings:
        key = getattr(f, attr, "")
        result.setdefault(key, []).append(f)
    return result


def _format_static_findings(findings: list) -> str:
    """Formats static findings as a numbered list for the LLM prompt"""
    if not findings:
        return ""
    lines = []
    for i, f in enumerate(findings[:10], 1):  # cap at 10 to save tokens
        line_no = getattr(f, "line", None) or getattr(f, "line_start", "?")
        severity = getattr(f, "severity", "?")
        title = getattr(f, "title", "?")
        desc = getattr(f, "description", "")
        lines.append(f"{i}. [Line {line_no}] [{severity.upper()}] {title}: {desc[:150]}")
    return "\n".join(lines)