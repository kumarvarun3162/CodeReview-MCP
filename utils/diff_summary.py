# utils/diff_summary.py
from agents.models import FetchedCode, FileInfo


def build_diff_summary(fetched: FetchedCode) -> str:
    """
    Creates a compact text summary of the fetched code.
    Used as context when sending code to the LLM for review.

    Example output:
    ─────────────────────────────────────
    Repo: owner/repo  |  Branch: main
    Mode: Diff-only (3 changed files)
    Total lines: 142
    ─────────────────────────────────────
    [1] src/auth/login.py (python) — 42 lines, 8 changed lines
        Changed at lines: 12, 13, 14, 38, 39, 40, 41, 42
    [2] src/db/queries.py (python) — 67 lines, 3 changed lines
    [3] tests/test_auth.py (python) — 33 lines, NEW FILE
    ─────────────────────────────────────
    """
    sep = "─" * 50
    lines = [
        sep,
        f"Repo: {fetched.repo_full_name}  |  Branch: {fetched.branch}",
    ]

    if fetched.commit_sha:
        lines.append(f"Commit: {fetched.commit_sha[:10]}")

    mode = "Full scan" if fetched.is_full_scan else f"Diff-only"
    lines.append(f"Mode: {mode} ({len(fetched.files)} files)")
    lines.append(f"Total lines: {fetched.total_lines_analyzed:,}")
    lines.append(sep)

    for i, f in enumerate(fetched.files, start=1):
        file_lines = len(f.content.splitlines())
        changed = f"  {len(f.changed_lines)} changed lines" if f.changed_lines else ""
        new_tag = "  NEW FILE" if f.is_new_file else ""
        lines.append(
            f"[{i}] {f.path} ({f.language.value}) — {file_lines} lines{changed}{new_tag}"
        )
        if f.changed_lines:
            # Show first 10 changed line numbers to keep it compact
            shown = f.changed_lines[:10]
            suffix = f" ... +{len(f.changed_lines) - 10} more" if len(f.changed_lines) > 10 else ""
            lines.append(f"     Changed at lines: {', '.join(str(l) for l in shown)}{suffix}")

    lines.append(sep)
    return "\n".join(lines)


def build_file_context_for_llm(file: FileInfo, max_lines: int = 200) -> str:
    """
    Formats a single file for inclusion in an LLM prompt.
    If the file has changed_lines, highlights those sections.
    Truncates very long files to keep within LLM context limits.
    """
    content_lines = file.content.splitlines()
    total = len(content_lines)

    if file.changed_lines and not file.is_new_file:
        # For diff mode: extract a window around changed lines
        # so the LLM has context but not the entire file
        relevant_lines = _extract_relevant_window(content_lines, file.changed_lines)
        header = f"# {file.path} ({file.language.value}) — showing changed sections\n"
    else:
        # For full scan or new files: include everything (up to max_lines)
        if total > max_lines:
            relevant_lines = content_lines[:max_lines]
            header = f"# {file.path} ({file.language.value}) — first {max_lines} of {total} lines\n"
        else:
            relevant_lines = content_lines
            header = f"# {file.path} ({file.language.value})\n"

    return header + "\n".join(relevant_lines)


def _extract_relevant_window(
    lines: list[str],
    changed_line_numbers: list[int],
    context: int = 5,   # lines of context above/below each change
) -> list[str]:
    """
    Extracts lines around changed areas with context.
    Adds markers to show where code was omitted.
    """
    total = len(lines)
    include = set()

    for ln in changed_line_numbers:
        idx = ln - 1  # convert to 0-indexed
        for i in range(max(0, idx - context), min(total, idx + context + 1)):
            include.add(i)

    result = []
    prev_included = False

    for i, line in enumerate(lines):
        if i in include:
            if not prev_included and result:
                result.append("... (lines omitted) ...")
            result.append(f"{i + 1:4d} | {line}")
            prev_included = True
        else:
            prev_included = False

    return result