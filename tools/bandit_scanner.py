# tools/bandit_scanner.py
import json
import subprocess
import tempfile
import os
from dataclasses import dataclass
from agents.models import FileInfo, SupportedLanguage


@dataclass
class BanditFinding:
    """One issue found by Bandit"""
    file_path: str
    line: int
    rule_id: str        # Bandit's ID e.g. "B105"
    severity: str       # "critical" | "high" | "medium" | "low"
    confidence: str     # "high" | "medium" | "low" — how sure Bandit is
    title: str
    description: str
    snippet: str = ""


# Map Bandit's severity strings to ours
SEVERITY_MAP = {
    "HIGH":   "high",
    "MEDIUM": "medium",
    "LOW":    "low",
}

CONFIDENCE_MAP = {
    "HIGH":   "high",
    "MEDIUM": "medium",
    "LOW":    "low",
}


def run_bandit_scan(file: FileInfo) -> list[BanditFinding]:
    """
    Runs Bandit on a single Python file and returns structured findings.

    How it works:
    1. Write the file content to a temp file on disk
    2. Run: bandit -f json -q <tempfile>
    3. Parse the JSON output
    4. Map results into BanditFinding objects
    5. Delete the temp file

    Why a temp file? Bandit only accepts file paths, not stdin.
    We use tempfile so we don't pollute the real workspace.
    """
    if file.language != SupportedLanguage.PYTHON:
        return []

    findings: list[BanditFinding] = []

    # Write content to a named temp file
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".py",
        delete=False,
        encoding="utf-8"
    ) as tmp:
        tmp.write(file.content)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            [
                "bandit",
                "-f", "json",    # output as JSON so we can parse it
                "-q",            # quiet mode (suppress progress output)
                "--severity-level", "low",    # catch everything
                "--confidence-level", "low",  # catch everything
                tmp_path,
            ],
            capture_output=True,
            text=True,
            timeout=30,          # never hang forever
        )

        # Bandit exits with code 1 if it finds issues — that's normal, not an error
        # Code 2+ means something actually went wrong
        if result.returncode > 1 and not result.stdout:
            print(f"[Bandit] Error scanning {file.path}: {result.stderr[:200]}")
            return []

        if not result.stdout.strip():
            return []

        # Parse the JSON output
        output = json.loads(result.stdout)
        raw_results = output.get("results", [])

        for issue in raw_results:
            severity_raw = issue.get("issue_severity", "LOW")
            confidence_raw = issue.get("issue_confidence", "LOW")

            findings.append(BanditFinding(
                file_path=file.path,            # use our path, not the temp path
                line=issue.get("line_number", 0),
                rule_id=issue.get("test_id", "B000"),
                severity=SEVERITY_MAP.get(severity_raw, "low"),
                confidence=CONFIDENCE_MAP.get(confidence_raw, "low"),
                title=issue.get("test_name", "Unknown issue").replace("_", " ").title(),
                description=issue.get("issue_text", ""),
                snippet=issue.get("code", "").strip(),
            ))

    except subprocess.TimeoutExpired:
        print(f"[Bandit] Timeout scanning {file.path} — skipping")
    except json.JSONDecodeError as e:
        print(f"[Bandit] Could not parse output for {file.path}: {e}")
    except FileNotFoundError:
        print("[Bandit] bandit not found. Run: pip install bandit")
    finally:
        # Always delete the temp file — even if something crashed above
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    return findings