# agents/auto_fix.py
from dataclasses import dataclass, field
from typing import Optional
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from agents.models import FetchedCode, FileInfo
from agents.code_reviewer import ReviewReport, LLMFinding
from core.config import settings


@dataclass
class FixedFile:
    """One file after the AutoFixAgent has applied fixes"""
    original_path: str
    fixed_content: str
    original_content: str
    fixes_applied: list[str]    # human-readable list of what was fixed
    language: str


@dataclass
class FixResult:
    """Complete output of AutoFixAgent"""
    fixed_files: list[FixedFile] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)   # files with no fixable issues
    total_fixes: int = 0


class AutoFixAgent:
    """
    Takes the ReviewReport and generates fixed versions of each flagged file.

    Strategy:
    - For each file that has LLM findings with suggested_fix snippets,
      ask the LLM to rewrite the complete file with ALL fixes applied.
    - We rewrite the whole file (not patch individual lines) because:
      a) Applying multiple overlapping patches is error-prone
      b) The LLM can also fix indirect issues caused by the primary ones
      c) It produces cleaner diffs in the PR

    Only files with HIGH or CRITICAL findings get auto-fixed.
    Low/medium findings are reported in the PR but not auto-patched
    (to avoid noise in the developer's codebase).
    """

    FIX_THRESHOLD = {"critical", "high"}   # severities that trigger auto-fix

    def __init__(self):
        self.llm = ChatGroq(
            api_key=settings.groq_api_key,
            model="llama-3.3-70b-versatile",
            temperature=0.05,   # very low — we want deterministic fixes, not creative rewrites
            max_tokens=8192,
        )

    async def fix(self, fetched: FetchedCode, report: ReviewReport) -> FixResult:
        """
        Main entry point. Returns a FixResult with all fixed files.
        """
        result = FixResult()

        # Group LLM findings by file
        findings_by_file: dict[str, list[LLMFinding]] = {}
        for finding in report.llm_findings:
            if finding.severity in self.FIX_THRESHOLD:
                findings_by_file.setdefault(finding.file_path, []).append(finding)

        # Also include AST/Bandit critical findings as context
        fixable_paths = set(findings_by_file.keys())

        if not fixable_paths:
            print("[AutoFix] No high/critical findings requiring auto-fix.")
            return result

        print(f"[AutoFix] Fixing {len(fixable_paths)} files...")

        # Build a path → FileInfo lookup
        file_map = {f.path: f for f in fetched.files}

        for file_path in fixable_paths:
            file_info = file_map.get(file_path)
            if not file_info:
                result.skipped_files.append(file_path)
                continue

            findings = findings_by_file[file_path]
            fixed = await self._fix_single_file(file_info, findings, report)

            if fixed:
                result.fixed_files.append(fixed)
                result.total_fixes += len(fixed.fixes_applied)
                print(f"[AutoFix] Fixed {file_path} — {len(fixed.fixes_applied)} issues resolved")
            else:
                result.skipped_files.append(file_path)

        print(f"[AutoFix] Complete: {result.total_fixes} fixes across {len(result.fixed_files)} files")
        return result

    async def _fix_single_file(
        self,
        file: FileInfo,
        findings: list[LLMFinding],
        report: ReviewReport,
    ) -> Optional[FixedFile]:
        """
        Rewrites one file with all fixes applied.
        Returns None if the LLM fails or produces no meaningful change.
        """

        # Format findings as a numbered instruction list for the LLM
        fix_instructions = "\n".join([
            f"{i}. [Line {f.line or '?'}] {f.title}\n"
            f"   Problem: {f.description}\n"
            f"   Fix: {f.suggested_fix}"
            for i, f in enumerate(findings, 1)
        ])

        system_prompt = """You are an expert software engineer applying security and quality fixes to code.

You will receive:
1. The complete original source file
2. A numbered list of issues and their fixes

Your task: Return the COMPLETE fixed file with ALL issues resolved.

STRICT RULES:
- Return ONLY the raw source code — no markdown, no backticks, no explanations
- Apply every fix listed
- Do not change any code that is not related to the listed issues
- Preserve all comments, imports, and overall structure
- The output must be valid, runnable code
- Do not add any text before or after the code"""

        human_prompt = f"""FILE: {file.path}
LANGUAGE: {file.language.value}

ISSUES TO FIX:
{fix_instructions}

ORIGINAL FILE:
{file.content}

Return the complete fixed file now:"""

        try:
            response = await self.llm.ainvoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=human_prompt),
            ])

            fixed_content = response.content.strip()

            # Sanity checks — make sure the LLM didn't return garbage
            if not fixed_content:
                return None
            if len(fixed_content) < len(file.content) * 0.5:
                # Fixed version is less than half the original size — likely truncated
                print(f"[AutoFix] Warning: fixed content suspiciously short for {file.path}")
                return None
            if fixed_content == file.content:
                # No changes made
                print(f"[AutoFix] No changes made to {file.path}")
                return None

            return FixedFile(
                original_path=file.path,
                fixed_content=fixed_content,
                original_content=file.content,
                fixes_applied=[f"{f.title} (line {f.line})" for f in findings],
                language=file.language.value,
            )

        except Exception as e:
            print(f"[AutoFix] LLM error fixing {file.path}: {e}")
            return None