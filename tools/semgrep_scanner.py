# tools/semgrep_scanner.py
import json
import subprocess
import tempfile
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from agents.models import FileInfo, SupportedLanguage


@dataclass
class SemgrepFinding:
    """One issue found by Semgrep"""
    file_path: str
    line_start: int
    line_end: int
    rule_id: str          # e.g. "python.lang.security.audit.eval-detected"
    severity: str
    title: str
    description: str
    snippet: str = ""
    fix_suggestion: str = ""   # Semgrep sometimes provides an autofix


# Semgrep rule packs per language — these are free community rules
# See: https://semgrep.dev/explore
RULESET_BY_LANGUAGE = {
    SupportedLanguage.PYTHON:     [
        "p/python",           # general Python rules
        "p/security-audit",   # security-focused
        "p/owasp-top-ten",    # OWASP top 10 vulnerabilities
    ],
    SupportedLanguage.JAVASCRIPT: [
        "p/javascript",
        "p/nodejs",
        "p/react",
        "p/owasp-top-ten",
    ],
    SupportedLanguage.TYPESCRIPT: [
        "p/typescript",
        "p/react",
        "p/owasp-top-ten",
    ],
    SupportedLanguage.GO:         ["p/golang", "p/security-audit"],
    SupportedLanguage.JAVA:       ["p/java", "p/owasp-top-ten"],
    SupportedLanguage.RUBY:       ["p/ruby"],
}

SEVERITY_MAP = {
    "ERROR":   "high",
    "WARNING": "medium",
    "INFO":    "low",
}


def run_semgrep_scan(file: FileInfo) -> list[SemgrepFinding]:
    """
    Runs Semgrep on a single file and returns structured findings.

    Strategy:
    - Write the file to a temp directory (Semgrep needs a directory, not a single file)
    - Run semgrep with the appropriate rule pack for the file's language
    - Parse JSON output
    - Map results into SemgrepFinding objects
    """
    if file.language == SupportedLanguage.UNKNOWN:
        return []

    rulesets = RULESET_BY_LANGUAGE.get(file.language, [])
    if not rulesets:
        return []

    findings: list[SemgrepFinding] = []

    # Create a temp directory with the file inside
    # Semgrep scans directories, so we give it a folder containing our one file
    tmp_dir = tempfile.mkdtemp()
    ext = _get_extension(file.language)
    tmp_file = os.path.join(tmp_dir, f"target{ext}")

    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            f.write(file.content)

        # Build the semgrep command
        # We run each ruleset separately and merge results
        for ruleset in rulesets:
            ruleset_findings = _run_single_ruleset(
                tmp_dir, tmp_file, file, ruleset
            )
            findings.extend(ruleset_findings)

        # Deduplicate by (line, rule_id)
        seen = set()
        unique = []
        for f in findings:
            key = (f.line_start, f.rule_id)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    except FileNotFoundError:
        print("[Semgrep] semgrep not found. Install: pip install semgrep")
        return []
    finally:
        # Always cleanup the temp directory
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _run_single_ruleset(
    tmp_dir: str,
    tmp_file: str,
    file: FileInfo,
    ruleset: str,
) -> list[SemgrepFinding]:
    """Runs semgrep with one specific ruleset and returns its findings"""
    try:
        result = subprocess.run(
            [
                "semgrep",
                "--config", ruleset,
                "--json",              # output as JSON
                "--quiet",             # no progress messages
                "--no-git-ignore",     # scan even if in .gitignore
                "--timeout", "20",     # per-file timeout
                tmp_dir,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if not result.stdout.strip():
            return []

        output = json.loads(result.stdout)
        raw = output.get("results", [])

        findings = []
        for item in raw:
            check_id = item.get("check_id", "")
            meta = item.get("extra", {})
            message = meta.get("message", "")
            severity_raw = meta.get("severity", "INFO")

            # Get fix suggestion if Semgrep provides one
            fix = meta.get("fix", "") or ""

            findings.append(SemgrepFinding(
                file_path=file.path,        # use our real path, not temp path
                line_start=item.get("start", {}).get("line", 0),
                line_end=item.get("end", {}).get("line", 0),
                rule_id=check_id,
                severity=SEVERITY_MAP.get(severity_raw, "low"),
                title=_rule_id_to_title(check_id),
                description=message,
                snippet=meta.get("lines", "").strip(),
                fix_suggestion=fix,
            ))

        return findings

    except subprocess.TimeoutExpired:
        print(f"[Semgrep] Timeout on ruleset {ruleset} for {file.path}")
        return []
    except json.JSONDecodeError:
        return []
    except Exception as e:
        print(f"[Semgrep] Error with ruleset {ruleset}: {e}")
        return []


def _rule_id_to_title(rule_id: str) -> str:
    """
    Converts a dotted rule ID into a readable title.
    "python.lang.security.audit.eval-detected" → "Eval Detected"
    """
    last_part = rule_id.split(".")[-1]
    return last_part.replace("-", " ").replace("_", " ").title()


def _get_extension(language: SupportedLanguage) -> str:
    ext_map = {
        SupportedLanguage.PYTHON:     ".py",
        SupportedLanguage.JAVASCRIPT: ".js",
        SupportedLanguage.TYPESCRIPT: ".ts",
        SupportedLanguage.JAVA:       ".java",
        SupportedLanguage.GO:         ".go",
        SupportedLanguage.RUBY:       ".rb",
    }
    return ext_map.get(language, ".txt")