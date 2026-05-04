# agents/vuln_scanner.py
import asyncio
from agents.models import FetchedCode
from agents.code_reviewer import CodeReviewerAgent, ReviewReport, LLMFinding
from tools.ast_scanner import ASTFinding, run_ast_scan
from tools.bandit_scanner import BanditFinding, run_bandit_scan
from tools.semgrep_scanner import SemgrepFinding, run_semgrep_scan


class VulnScannerAgent:
    """
    Orchestrates all scanners and the LLM reviewer.

    Running order:
    1. AST + Bandit + Semgrep all run in PARALLEL (they're independent)
    2. LLM reviewer runs AFTER — it gets all scanner results as context

    Parallel execution matters: if each scanner takes 5s,
    sequential = 15s, parallel = 5s.
    """

    def __init__(self):
        self.reviewer = CodeReviewerAgent()

    async def scan(self, fetched: FetchedCode) -> ReviewReport:
        """
        Main entry point. Runs all scanners and returns a ReviewReport.
        """
        print(f"[VulnScanner] Starting scan of {len(fetched.files)} files...")

        # ── Step 1: Run static scanners in parallel ───────────────────────────
        # asyncio.gather() runs all coroutines at the same time
        # and waits for all of them to finish before continuing

        ast_task     = asyncio.create_task(self._run_ast_all(fetched))
        bandit_task  = asyncio.create_task(self._run_bandit_all(fetched))
        semgrep_task = asyncio.create_task(self._run_semgrep_all(fetched))

        ast_findings, bandit_findings, semgrep_findings = await asyncio.gather(
            ast_task, bandit_task, semgrep_task
        )

        print(f"[VulnScanner] Static scan complete:")
        print(f"  AST:     {len(ast_findings)} findings")
        print(f"  Bandit:  {len(bandit_findings)} findings")
        print(f"  Semgrep: {len(semgrep_findings)} findings")

        # ── Step 2: LLM review (uses static findings as context) ─────────────
        print(f"[VulnScanner] Running LLM review...")
        llm_findings, overall_summary = await self.reviewer.review(
            fetched, ast_findings, bandit_findings, semgrep_findings
        )
        print(f"  LLM:     {len(llm_findings)} additional findings")

        # ── Step 3: Build the final report ────────────────────────────────────
        report = ReviewReport(
            repo_full_name=fetched.repo_full_name,
            commit_sha=fetched.commit_sha,
            files_reviewed=len(fetched.files),
            ast_findings=ast_findings,
            bandit_findings=bandit_findings,
            semgrep_findings=semgrep_findings,
            llm_findings=llm_findings,
            overall_summary=overall_summary,
        )
        report.compute_severity_counts()

        self._print_report_summary(report)
        return report

    # ── Scanner runners (these are async wrappers around sync functions) ──────

    async def _run_ast_all(self, fetched: FetchedCode) -> list[ASTFinding]:
        """Runs AST scanner on all files"""
        findings = []
        for file in fetched.files:
            # run_in_executor runs synchronous code in a thread pool
            # so it doesn't block the async event loop
            loop = asyncio.get_event_loop()
            file_findings = await loop.run_in_executor(None, run_ast_scan, file)
            findings.extend(file_findings)
        return findings

    async def _run_bandit_all(self, fetched: FetchedCode) -> list[BanditFinding]:
        """Runs Bandit scanner on all Python files"""
        findings = []
        loop = asyncio.get_event_loop()
        for file in fetched.files:
            file_findings = await loop.run_in_executor(None, run_bandit_scan, file)
            findings.extend(file_findings)
        return findings

    async def _run_semgrep_all(self, fetched: FetchedCode) -> list[SemgrepFinding]:
        """Runs Semgrep on all supported files"""
        findings = []
        loop = asyncio.get_event_loop()
        for file in fetched.files:
            file_findings = await loop.run_in_executor(None, run_semgrep_scan, file)
            findings.extend(file_findings)
        return findings

    def _print_report_summary(self, report: ReviewReport):
        """Prints a formatted summary to the terminal"""
        sep = "═" * 56
        print(f"\n{sep}")
        print(f"  SCAN REPORT — {report.repo_full_name}")
        print(f"  Files reviewed: {report.files_reviewed}")
        print(f"  Total findings: {report.total_findings}")
        print(f"  ├─ Critical: {report.critical_count}")
        print(f"  ├─ High:     {report.high_count}")
        print(f"  ├─ Medium:   {report.medium_count}")
        print(f"  └─ Low:      {report.low_count}")
        print(sep)
        if report.overall_summary:
            print(f"\n  SUMMARY:\n  {report.overall_summary}")
        print(f"{sep}\n")