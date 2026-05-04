# tools/ast_scanner.py
import ast
from dataclasses import dataclass, field
from typing import Optional
from agents.models import FileInfo, SupportedLanguage


@dataclass
class ASTFinding:
    """One issue found by the AST scanner"""
    file_path: str
    line: int
    col: int
    rule_id: str          # e.g. "AST001"
    severity: str         # "critical" | "high" | "medium" | "low"
    title: str            # short name: "Use of eval()"
    description: str      # what's wrong and why it matters
    snippet: str = ""     # the actual line of code


# ── Rules registry ────────────────────────────────────────────────────────────
# Each rule is a visitor method on the ASTScanner class below.
# Rule IDs follow: AST + 3 digit number
# ─────────────────────────────────────────────────────────────────────────────

# Variable names that suggest hardcoded secrets
SECRET_NAMES = {
    "password", "passwd", "secret", "api_key", "apikey",
    "token", "access_token", "auth_token", "private_key",
    "client_secret", "db_password", "database_password",
}

# Dangerous built-in function calls
DANGEROUS_CALLS = {
    "eval":    ("AST001", "critical", "Use of eval()",
                "eval() executes arbitrary Python code. Attackers can inject malicious "
                "code through user input. Use ast.literal_eval() for safe expression parsing."),
    "exec":    ("AST002", "critical", "Use of exec()",
                "exec() executes arbitrary Python code strings. This is almost always "
                "avoidable and creates severe code injection risk."),
    "compile": ("AST003", "high", "Use of compile()",
                "compile() can be used to execute dynamic code. Verify this is intentional "
                "and the input is never user-controlled."),
    "__import__": ("AST004", "high", "Dynamic import via __import__()",
                   "__import__() with dynamic arguments can load arbitrary modules. "
                   "Use importlib.import_module() with a whitelist instead."),
    "pickle.loads": ("AST005", "critical", "Use of pickle.loads()",
                     "Unpickling untrusted data executes arbitrary code. "
                     "Use JSON or another safe serialization format."),
}

# Imports that indicate dangerous usage
DANGEROUS_IMPORTS = {
    "pickle":   ("AST006", "high", "pickle module imported",
                 "The pickle module is insecure when loading untrusted data. "
                 "Prefer json, msgpack, or protobuf for serialization."),
    "marshal":  ("AST007", "high", "marshal module imported",
                 "marshal is insecure for untrusted input — like pickle but lower-level."),
    "shelve":   ("AST008", "medium", "shelve module imported",
                 "shelve uses pickle internally. Insecure for untrusted input."),
    "subprocess": ("AST009", "medium", "subprocess module imported",
                   "subprocess usage — verify shell=False and inputs are sanitized."),
    "os.system": ("AST010", "high", "os.system usage detected",
                  "os.system() runs shell commands. Use subprocess.run() with a list "
                  "of arguments and shell=False instead."),
    "tempfile":  None,   # allowed, just noted
}


class ASTScanner(ast.NodeVisitor):
    """
    Walks a Python AST tree and collects security/quality findings.

    How AST visiting works:
    - ast.NodeVisitor has a visit() method that routes to visit_<NodeType>()
    - We override specific visit_* methods to inspect nodes we care about
    - self.generic_visit(node) continues walking into child nodes
    """

    def __init__(self, file_path: str, source_lines: list[str]):
        self.file_path = file_path
        self.source_lines = source_lines
        self.findings: list[ASTFinding] = []

    def _get_snippet(self, line_no: int) -> str:
        """Returns the actual source line (1-indexed), stripped of whitespace"""
        if 1 <= line_no <= len(self.source_lines):
            return self.source_lines[line_no - 1].strip()
        return ""

    def _add(self, node: ast.AST, rule_id: str, severity: str,
             title: str, description: str):
        """Helper to add a finding with location info"""
        line = getattr(node, "lineno", 0)
        col = getattr(node, "col_offset", 0)
        self.findings.append(ASTFinding(
            file_path=self.file_path,
            line=line,
            col=col,
            rule_id=rule_id,
            severity=severity,
            title=title,
            description=description,
            snippet=self._get_snippet(line),
        ))

    # ── Visitor: Function calls ───────────────────────────────────────────────

    def visit_Call(self, node: ast.Call):
        """
        Visits every function call in the code.
        Checks for dangerous built-ins like eval(), exec(), etc.
        """
        func_name = self._get_call_name(node)

        if func_name in DANGEROUS_CALLS:
            rule_id, severity, title, desc = DANGEROUS_CALLS[func_name]
            self._add(node, rule_id, severity, title, desc)

        # Check for os.system() specifically
        if func_name in ("os.system", "os.popen"):
            self._add(node, "AST010", "high",
                      f"Use of {func_name}()",
                      f"{func_name}() runs shell commands. Use subprocess.run() "
                      f"with a list argument and shell=False instead.")

        self.generic_visit(node)  # continue walking into arguments

    def _get_call_name(self, node: ast.Call) -> str:
        """Extracts the function name from a Call node as a string"""
        if isinstance(node.func, ast.Name):
            return node.func.id   # simple name: eval(...)
        elif isinstance(node.func, ast.Attribute):
            # attribute access: pickle.loads(...)
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        return ""

    # ── Visitor: Assignments (hardcoded secrets) ──────────────────────────────

    def visit_Assign(self, node: ast.Assign):
        """
        Visits every assignment statement.
        Looks for: secret_key = "actual_secret_value_here"
        """
        for target in node.targets:
            name = ""
            if isinstance(target, ast.Name):
                name = target.id.lower()
            elif isinstance(target, ast.Attribute):
                name = target.attr.lower()

            if any(secret in name for secret in SECRET_NAMES):
                # Check if the value is a non-empty string literal
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val = node.value.value
                    # Skip obvious placeholders
                    if len(val) > 4 and val not in ("", "changeme", "your_key_here", "xxx"):
                        self._add(node, "AST011", "critical",
                                  "Hardcoded secret in source code",
                                  f"The variable '{name}' appears to contain a hardcoded "
                                  f"secret. Store secrets in environment variables and load "
                                  f"them with os.environ or python-dotenv. Never commit secrets.")

        self.generic_visit(node)

    # ── Visitor: Exception handlers (bare except) ─────────────────────────────

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        """
        Visits every except: clause.
        Bare except: catches SystemExit and KeyboardInterrupt — almost always a bug.
        """
        if node.type is None:
            self._add(node, "AST012", "medium",
                      "Bare except: clause",
                      "bare except: catches ALL exceptions including SystemExit and "
                      "KeyboardInterrupt. Specify the exception type: except ValueError: "
                      "or at minimum except Exception:")

        self.generic_visit(node)

    # ── Visitor: Imports ──────────────────────────────────────────────────────

    def visit_Import(self, node: ast.Import):
        """Checks top-level imports: import pickle"""
        for alias in node.names:
            module = alias.name.split(".")[0]
            if module in DANGEROUS_IMPORTS and DANGEROUS_IMPORTS[module]:
                rule_id, severity, title, desc = DANGEROUS_IMPORTS[module]
                self._add(node, rule_id, severity, title, desc)

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Checks from-imports: from pickle import loads"""
        module = (node.module or "").split(".")[0]
        if module in DANGEROUS_IMPORTS and DANGEROUS_IMPORTS[module]:
            rule_id, severity, title, desc = DANGEROUS_IMPORTS[module]
            self._add(node, rule_id, severity, title, desc)

        self.generic_visit(node)

    # ── Visitor: Function definitions (complexity + docs) ────────────────────

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """
        Visits every function definition.
        Checks for: missing docstrings on public functions,
        functions that are too long (complexity smell).
        """
        # Check for missing docstring on public functions (not starting with _)
        if not node.name.startswith("_"):
            has_docstring = (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            )
            if not has_docstring:
                self._add(node, "AST013", "low",
                          f"Public function '{node.name}' missing docstring",
                          f"Add a docstring to '{node.name}' explaining what it does, "
                          f"its parameters, and what it returns.")

        # Check for overly long functions (> 50 lines is a complexity smell)
        if hasattr(node, "end_lineno") and node.end_lineno:
            func_length = node.end_lineno - node.lineno
            if func_length > 50:
                self._add(node, "AST014", "low",
                          f"Function '{node.name}' is too long ({func_length} lines)",
                          f"Functions over 50 lines are hard to test and understand. "
                          f"Break '{node.name}' into smaller, single-purpose functions.")

        self.generic_visit(node)

    # Also apply to async def
    visit_AsyncFunctionDef = visit_FunctionDef


def run_ast_scan(file: FileInfo) -> list[ASTFinding]:
    """
    Entry point: scans one FileInfo object and returns a list of findings.
    Only runs on Python files — other languages handled by Semgrep.
    """
    if file.language != SupportedLanguage.PYTHON:
        return []

    try:
        tree = ast.parse(file.content)
    except SyntaxError as e:
        # File has a syntax error — report it as a finding
        return [ASTFinding(
            file_path=file.path,
            line=e.lineno or 0,
            col=e.offset or 0,
            rule_id="AST000",
            severity="high",
            title="Syntax error in file",
            description=f"Python could not parse this file: {e.msg}. "
                        f"Fix the syntax error before other rules can run.",
            snippet=e.text.strip() if e.text else "",
        )]

    source_lines = file.content.splitlines()
    scanner = ASTScanner(file.path, source_lines)
    scanner.visit(tree)
    return scanner.findings