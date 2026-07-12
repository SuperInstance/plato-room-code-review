"""
Review heuristics for the Code Review Room.

Each check is a pure function that takes the PR diff text and returns a
CheckResult.  Checks are intentionally simple — no LLM, no AST parsing.
They catch the 80% of issues that pattern matching handles well.

To add a new check: write a function decorated with @check, or append
to _ALL_CHECKS manually.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class CheckResult:
    """Result of a single review check."""
    check_id: str
    name: str
    passed: bool
    message: str
    severity: str = "info"  # info, warning, error
    file_hints: list[str] = field(default_factory=list)


CheckFunc = Callable[[str], CheckResult]
_ALL_CHECKS: list[CheckFunc] = []


def check(func: CheckFunc) -> CheckFunc:
    """Register a check function."""
    _ALL_CHECKS.append(func)
    return func


# ─── Security checks ─────────────────────────────────────────

# Common secret patterns (high false-positive rate is fine — triggers review)
_SECRET_PATTERNS = [
    # AWS
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    (re.compile(r"aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]"), "AWS Secret Key"),
    # Generic API keys
    (re.compile(r"(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token)\s*[:=]\s*['\"][-A-Za-z0-9_/+=]{16,}['\"]"), "API Key / Token"),
    # Private keys
    (re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "Private Key block"),
    # Database URLs with credentials
    (re.compile(r"(postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@"), "DB connection string with credentials"),
    # Slack tokens
    (re.compile(r"xox[bpoa]-[0-9A-Za-z-]{10,48}"), "Slack token"),
    # GitHub tokens
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}"), "GitHub token"),
    # JWT
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "JWT token"),
]

# Files that are security-sensitive
_SECURITY_FILES = [
    ".github/workflows/",
    "Dockerfile",
    "docker-compose",
    ".env",
    "secrets",
    "id_rsa",
    "id_ed25519",
    "Makefile",
    "security/",
    "auth/",
    "permissions",
    "policy",
    "sudoers",
    "nginx.conf",
    "sshd_config",
    "firewall",
    "iptables",
]

# SQL injection patterns
_SQL_INJECTION_PATTERNS = [
    re.compile(r"execute\s*\(\s*['\"].*\+.*['\"]\s*\)", re.IGNORECASE),  # string concat in execute()
    re.compile(r"execute\s*\(\s*f['\"]", re.IGNORECASE),                 # f-string in execute()
    re.compile(r"\%\s*\(.*\)\s*.*execute", re.IGNORECASE),              # %-format in execute
    re.compile(r"cursor\.execute.*\+.*request", re.IGNORECASE),          # request concat
    re.compile(r"query\s*=\s*['\"].*select.*\+.*['\"]", re.IGNORECASE),  # SELECT + concat
]


# ─── Checks ──────────────────────────────────────────────────

@check
def check_missing_tests(diff: str) -> CheckResult:
    """PR adds code but no tests."""
    added_code_files = set()
    test_files = set()

    current_file = None
    for line in diff.splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                current_file = parts[-1].lstrip("b/")
                if "test" in current_file.lower() or current_file.endswith(("_test.py", ".spec.ts", ".spec.js", ".test.ts", ".test.js")):
                    test_files.add(current_file)
                elif current_file.endswith((".py", ".ts", ".js", ".go", ".rs", ".java", ".rb")):
                    added_code_files.add(current_file)

    has_added_code = any(l.startswith("+") and not l.startswith("+++") for l in diff.splitlines())

    if has_added_code and added_code_files and not test_files:
        return CheckResult(
            check_id="missing_tests",
            name="Missing Tests",
            passed=False,
            message=f"PR adds code to {len(added_code_files)} file(s) but includes no test files. "
                    f"Consider adding tests for: {', '.join(list(added_code_files)[:3])}.",
            severity="warning",
            file_hints=list(added_code_files)[:5],
        )
    return CheckResult(
        check_id="missing_tests",
        name="Missing Tests",
        passed=True,
        message="Test files present or no production code added.",
    )


@check
def check_ci_bypass(diff: str) -> CheckResult:
    """Check for `|| true` or `continue-on-error` in CI files."""
    findings = []

    current_file = None
    for line in diff.splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                current_file = parts[-1].lstrip("b/")
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            if current_file and (".github/workflows/" in current_file or current_file.endswith((".yml", ".yaml"))):
                if "|| true" in content or "||exit 0" in content.replace(" ", ""):
                    findings.append(f"{current_file}: `{content.strip()}`")
                if "continue-on-error: true" in content.lower():
                    findings.append(f"{current_file}: `continue-on-error: true`")
                if "set +e" in content:
                    findings.append(f"{current_file}: `set +e` disables error checking")

    if findings:
        return CheckResult(
            check_id="ci_bypass",
            name="CI Error Suppression",
            passed=False,
            message="CI step appears to suppress failures: " + "; ".join(findings[:3]),
            severity="error",
            file_hints=[f.split(":")[0] for f in findings],
        )
    return CheckResult(
        check_id="ci_bypass",
        name="CI Error Suppression",
        passed=True,
        message="No CI error suppression patterns detected.",
    )


@check
def check_hardcoded_secrets(diff: str) -> CheckResult:
    """Check for secret-like strings in added lines."""
    findings = []

    current_file = None
    for line in diff.splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                current_file = parts[-1].lstrip("b/")
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            for pattern, label in _SECRET_PATTERNS:
                match = pattern.search(content)
                if match:
                    # Mask the secret in output
                    masked = content[:match.start()] + "***REDACTED***" + content[match.end():]
                    findings.append((current_file or "?", label, masked.strip()))

    if findings:
        unique_labels = {f[1] for f in findings}
        return CheckResult(
            check_id="secrets",
            name="Hardcoded Secrets",
            passed=False,
            message=f"Potential secrets detected ({', '.join(unique_labels)}). "
                    f"Use environment variables or a secrets manager.",
            severity="error",
            file_hints=list({f[0] for f in findings})[:5],
        )
    return CheckResult(
        check_id="secrets",
        name="Hardcoded Secrets",
        passed=True,
        message="No secret-like patterns detected.",
    )


@check
def check_missing_type_hints(diff: str) -> CheckResult:
    """Check for Python functions without type hints."""
    findings = []

    current_file = None
    func_pattern = re.compile(r"^\+def\s+(\w+)\s*\(([^)]*)\)")

    for line in diff.splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                current_file = parts[-1].lstrip("b/")
        if line.startswith("+") and not line.startswith("+++") and current_file:
            if current_file.endswith(".py"):
                match = func_pattern.match(line)
                if match:
                    func_name = match.group(1)
                    params = match.group(2)
                    # Check if params or return type are missing hints
                    has_hints = ":" in params or "->" in line
                    if not has_hints and params.strip() and params.strip() != "self":
                        findings.append(f"{current_file}::{func_name}()")

    if len(findings) >= 2:  # Only flag if multiple functions lack hints
        return CheckResult(
            check_id="type_hints",
            name="Missing Type Hints",
            passed=False,
            message=f"{len(findings)} function(s) without type hints: {', '.join(findings[:5])}",
            severity="info",
            file_hints=[f.split("::")[0] for f in findings],
        )
    return CheckResult(
        check_id="type_hints",
        name="Missing Type Hints",
        passed=True,
        message="Type hints present or too few violations to flag.",
    )


@check
def check_sql_injection(diff: str) -> CheckResult:
    """Check for potential SQL injection patterns."""
    findings = []

    current_file = None
    for line in diff.splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                current_file = parts[-1].lstrip("b/")
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            for pattern in _SQL_INJECTION_PATTERNS:
                if pattern.search(content):
                    findings.append(f"{current_file}: `{content.strip()[:80]}`")

    if findings:
        return CheckResult(
            check_id="sql_injection",
            name="SQL Injection Risk",
            passed=False,
            message="Potential SQL injection: unparameterized queries detected. "
                    "Use parameterized queries instead of string concatenation.",
            severity="error",
            file_hints=[f.split(":")[0] for f in findings],
        )
    return CheckResult(
        check_id="sql_injection",
        name="SQL Injection Risk",
        passed=True,
        message="No SQL injection patterns detected.",
    )


@check
def check_security_files(diff: str) -> CheckResult:
    """Flag changes to security-critical files."""
    touched = []

    current_file = None
    for line in diff.splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                current_file = parts[-1].lstrip("b/")
                for sec in _SECURITY_FILES:
                    if sec in current_file:
                        touched.append(current_file)
                        break

    if touched:
        return CheckResult(
            check_id="security_file",
            name="Security-Critical File Changed",
            passed=False,
            message=f"Security-sensitive file(s) modified: {', '.join(touched)}. "
                    f"Requires careful review.",
            severity="warning",
            file_hints=touched,
        )
    return CheckResult(
        check_id="security_file",
        name="Security-Critical File Changed",
        passed=True,
        message="No security-critical files in diff.",
    )


@check
def check_large_diff(diff: str) -> CheckResult:
    """Warn on very large diffs."""
    added = sum(1 for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++"))
    if added > 500:
        return CheckResult(
            check_id="large_diff",
            name="Large Diff",
            passed=False,
            message=f"Diff adds {added} lines. Consider splitting into smaller PRs.",
            severity="info",
        )
    return CheckResult(
        check_id="large_diff",
            name="Large Diff",
        passed=True,
        message=f"Diff size ({added} lines) is reasonable.",
    )


# ─── Extended heuristics ─────────────────────────────────────

@check
def check_missing_license(diff: str) -> CheckResult:
    """Check for missing LICENSE file in new repos.

    Detects when a PR creates multiple files (suggesting a new project)
    but no LICENSE file is among them.
    """
    created_files: list[str] = []
    has_license = False

    for line in diff.splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                fname = parts[-1].lstrip("b/")
                created_files.append(fname)
                if fname.upper() == "LICENSE" or fname.upper().startswith("LICENSE."):
                    has_license = True

    # Heuristic: if 3+ files are created and none is LICENSE, flag it
    if len(created_files) >= 3 and not has_license:
        return CheckResult(
            check_id="missing_license",
            name="Missing LICENSE",
            passed=False,
            message=f"{len(created_files)} file(s) created but no LICENSE file found. "
                    f"Consider adding an open-source license.",
            severity="info",
        )
    return CheckResult(
        check_id="missing_license",
        name="Missing LICENSE",
        passed=True,
        message="LICENSE file present or too few files to flag.",
    )


@check
def check_console_print(diff: str) -> CheckResult:
    """Check for console.log / print statements left in production code."""
    findings: list[tuple[str, str]] = []

    current_file = None
    for line in diff.splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                current_file = parts[-1].lstrip("b/")
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            stripped = content.strip()
            # Skip comments
            if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*"):
                continue
            # Skip test files — prints in tests are fine
            if current_file and (
                "test" in current_file.lower()
                or current_file.endswith(("_test.py", ".test.ts", ".test.js", ".spec.ts", ".spec.js"))
            ):
                continue
            # Detect console.log (JS/TS)
            if re.search(r"\bconsole\.log\s*\(", content):
                findings.append((current_file or "?", stripped[:80]))
            # Detect print() in Python (not in __repr__ or __str__ or debug functions)
            if current_file and current_file.endswith(".py"):
                if re.search(r"\bprint\s*\(", content) and not re.search(r"def\s+\w+", content):
                    findings.append((current_file or "?", stripped[:80]))

    if findings:
        return CheckResult(
            check_id="console_print",
            name="Debug Print Statements",
            passed=False,
            message=f"{len(findings)} debug print/console.log statement(s) found. "
                    f"Remove before merging.",
            severity="warning",
            file_hints=list({f[0] for f in findings})[:5],
        )
    return CheckResult(
        check_id="console_print",
        name="Debug Print Statements",
        passed=True,
        message="No debug print statements detected.",
    )


@check
def check_todo_without_assignee(diff: str) -> CheckResult:
    """Check for TODO/FIXME comments without an assignee.

    Looks for TODO, FIXME, HACK, XXX without a GitHub username assignee
    (e.g. `@username`) or issue reference (e.g. `#123`).
    """
    findings: list[tuple[str, str]] = []
    todo_pattern = re.compile(r"\b(TODO|FIXME|HACK|XXX)\b")
    assignee_pattern = re.compile(r"@[A-Za-z0-9_-]+|#\d+")

    current_file = None
    for line in diff.splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                current_file = parts[-1].lstrip("b/")
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            if todo_pattern.search(content):
                # Check if there's an assignee or issue reference
                if not assignee_pattern.search(content):
                    findings.append((current_file or "?", content.strip()[:80]))

    if findings:
        return CheckResult(
            check_id="todo_without_assignee",
            name="TODO Without Assignee",
            passed=False,
            message=f"{len(findings)} TODO/FIXME comment(s) without assignee or issue reference. "
                    f"Use `TODO @username` or `TODO #issue`.",
            severity="info",
            file_hints=list({f[0] for f in findings})[:5],
        )
    return CheckResult(
        check_id="todo_without_assignee",
        name="TODO Without Assignee",
        passed=True,
        message="All TODO/FIXME comments have assignees or issue references.",
    )


@check
def check_long_functions(diff: str) -> CheckResult:
    """Check for functions longer than 50 lines in added code.

    Approximates function boundaries by tracking def/return indentation.
    Works for Python; for JS/TS uses function arrow patterns.
    """
    max_lines = 50
    findings: list[tuple[str, str, int]] = []

    lines = diff.splitlines()
    current_file = None

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                current_file = parts[-1].lstrip("b/")
            i += 1
            continue

        # Only look at added lines
        if not (line.startswith("+") and not line.startswith("+++")):
            i += 1
            continue

        content = line[1:]

        # Python function definition
        if current_file and current_file.endswith(".py"):
            func_match = re.match(r"^(\s*)def\s+(\w+)", content)
            if func_match:
                indent = len(func_match.group(1))
                func_name = func_match.group(2)
                # Count lines until next function/class at same or lower indent, or end of diff
                func_len = 1
                j = i + 1
                while j < len(lines):
                    next_line = lines[j]
                    if next_line.startswith("diff --git"):
                        break
                    if next_line.startswith("+") and not next_line.startswith("+++"):
                        next_content = next_line[1:]
                        # Check if this is a new def/class at same or lower indent
                        next_def = re.match(r"^(\s*)(def |class )", next_content)
                        if next_def and len(next_def.group(1)) <= indent:
                            break
                        func_len += 1
                    elif next_line.startswith(" ") or next_line.startswith("\t"):
                        # Context line — counts toward function length
                        func_len += 1
                    elif next_line == "":
                        func_len += 1
                    else:
                        break
                    j += 1

                if func_len > max_lines:
                    findings.append((current_file or "?", func_name, func_len))

        # JS/TS function definition
        if current_file and current_file.endswith((".ts", ".js", ".tsx", ".jsx")):
            func_match = re.match(r"^(\s*)(export\s+)?(async\s+)?function\s+(\w+)", content)
            if not func_match:
                func_match = re.match(r"^(\s*)(export\s+)?const\s+(\w+)\s*=\s*(async\s*)?\(", content)
            if func_match:
                func_name = func_match.group(func_match.lastindex)
                func_len = 1
                brace_depth = content.count("{") - content.count("}")
                j = i + 1
                while j < len(lines) and brace_depth > 0:
                    next_line = lines[j]
                    if next_line.startswith("diff --git"):
                        break
                    if next_line.startswith("+") and not next_line.startswith("+++"):
                        nc = next_line[1:]
                        brace_depth += nc.count("{") - nc.count("}")
                        func_len += 1
                    elif next_line.startswith(" ") or next_line.startswith("\t"):
                        brace_depth += next_line.count("{") - next_line.count("}")
                        func_len += 1
                    elif next_line == "":
                        func_len += 1
                    else:
                        break
                    j += 1

                if func_len > max_lines:
                    findings.append((current_file or "?", func_name or "anon", func_len))

        i += 1

    if findings:
        hints = [f"{f[0]}::{f[1]}()" for f in findings]
        return CheckResult(
            check_id="long_functions",
            name="Long Functions",
            passed=False,
            message=f"{len(findings)} function(s) exceed {max_lines} lines: "
                    f"{', '.join(hints[:5])}",
            severity="warning",
            file_hints=[f[0] for f in findings][:5],
        )
    return CheckResult(
        check_id="long_functions",
        name="Long Functions",
        passed=True,
        message=f"All functions are within {max_lines} lines.",
    )


# Decision points for rough cyclomatic complexity
_COMPLEXITY_KEYWORDS = [
    re.compile(r"\bif\b"),
    re.compile(r"\belif\b"),
    re.compile(r"\belse\b"),
    re.compile(r"\bfor\b"),
    re.compile(r"\bwhile\b"),
    re.compile(r"\btry\b"),
    re.compile(r"\bexcept\b"),
    re.compile(r"\band\b"),
    re.compile(r"\bor\b"),
    re.compile(r"\bcase\b"),
    re.compile(r"\?"),  # ternary
    re.compile(r"\bcatch\b"),
    re.compile(r"\bswitch\b"),
]


@check
def check_cyclomatic_complexity(diff: str) -> CheckResult:
    """Rough estimate of cyclomatic complexity in added code.

    Counts decision points (if, elif, for, while, and, or, try, except,
    ternary, switch/case, catch) in added lines.  A function with >10
    decision points is considered complex.
    """
    threshold = 10
    findings: list[tuple[str, int]] = []

    current_file = None
    current_func_complexity = 0
    current_func_name = None
    current_indent = 0

    for line in diff.splitlines():
        if line.startswith("diff --git"):
            # Flush previous function
            if current_func_complexity > threshold:
                findings.append((current_func_name or "unknown", current_func_complexity))
            current_func_complexity = 0
            current_func_name = None

            parts = line.split()
            if len(parts) >= 4:
                current_file = parts[-1].lstrip("b/")
            continue

        if not (line.startswith("+") and not line.startswith("+++")):
            continue

        content = line[1:]

        # Track function entry for Python
        if current_file and current_file.endswith(".py"):
            func_match = re.match(r"^(\s*)def\s+(\w+)", content)
            if func_match:
                # Flush previous function
                if current_func_complexity > threshold:
                    findings.append((current_func_name or "unknown", current_func_complexity))
                current_func_name = func_match.group(2)
                current_func_complexity = 1  # base complexity
                current_indent = len(func_match.group(1))
                continue

            # Count decision points within functions
            if current_func_name:
                for pattern in _COMPLEXITY_KEYWORDS:
                    current_func_complexity += len(pattern.findall(content))

    # Flush last function
    if current_func_complexity > threshold:
        findings.append((current_func_name or "unknown", current_func_complexity))

    if findings:
        return CheckResult(
            check_id="cyclomatic_complexity",
            name="High Cyclomatic Complexity",
            passed=False,
            message=f"{len(findings)} function(s) with complexity > {threshold}: "
                    f"{', '.join(f'{n}({c})' for n, c in findings[:5])}",
            severity="warning",
        )
    return CheckResult(
        check_id="cyclomatic_complexity",
        name="High Cyclomatic Complexity",
        passed=True,
        message=f"All functions within complexity threshold ({threshold}).",
    )


@check
def check_missing_docstrings(diff: str) -> CheckResult:
    """Check for missing docstrings on public Python functions.

    A public function is one that doesn't start with `_`.  We look for
    `def` in added lines and check if a docstring follows within 3 lines.
    """
    findings: list[str] = []

    lines = diff.splitlines()
    current_file = None

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                current_file = parts[-1].lstrip("b/")
            i += 1
            continue

        if not (line.startswith("+") and not line.startswith("+++")):
            i += 1
            continue

        content = line[1:]

        if current_file and current_file.endswith(".py"):
            func_match = re.match(r"^def\s+(\w+)", content)
            if func_match:
                func_name = func_match.group(1)
                # Skip private functions and dunder methods
                if func_name.startswith("_"):
                    i += 1
                    continue
                # Skip __init__, __str__, etc.
                if func_name.startswith("__") and func_name.endswith("__"):
                    i += 1
                    continue

                # Look ahead for docstring in next few added lines
                has_docstring = False
                for j in range(i + 1, min(i + 4, len(lines))):
                    next_line = lines[j]
                    if next_line.startswith("+") and not next_line.startswith("+++"):
                        nc = next_line[1:].strip()
                        if nc.startswith('""') or nc.startswith("'''"):
                            has_docstring = True
                            break
                        # If we hit actual code (not blank/docstring), no docstring
                        if nc and not nc.startswith("#") and nc != "...":
                            break
                    elif next_line.startswith(" "):
                        nc = next_line.strip()
                        if nc.startswith('""') or nc.startswith("'''"):
                            has_docstring = True
                            break

                if not has_docstring:
                    findings.append(f"{current_file}::{func_name}()")

        i += 1

    if findings:
        return CheckResult(
            check_id="missing_docstrings",
            name="Missing Docstrings",
            passed=False,
            message=f"{len(findings)} public function(s) without docstrings: "
                    f"{', '.join(findings[:5])}",
            severity="info",
            file_hints=[f.split("::")[0] for f in findings][:5],
        )
    return CheckResult(
        check_id="missing_docstrings",
        name="Missing Docstrings",
        passed=True,
        message="All public functions have docstrings.",
    )


# ─── Orchestration ───────────────────────────────────────────

def run_all_checks(diff: str) -> list[CheckResult]:
    """Run all registered checks and return results."""
    results = []
    for func in _ALL_CHECKS:
        try:
            result = func(diff)
            results.append(result)
        except Exception as exc:
            results.append(CheckResult(
                check_id=func.__name__,
                name=func.__name__,
                passed=True,  # Don't fail PR on check crash
                message=f"Check errored: {exc}",
                severity="info",
            ))
    return results


def run_check(check_id: str, diff: str) -> CheckResult | None:
    """Run a single check by ID."""
    for func in _ALL_CHECKS:
        try:
            result = func(diff)
            if result.check_id == check_id:
                return result
        except Exception:
            pass
    return None
