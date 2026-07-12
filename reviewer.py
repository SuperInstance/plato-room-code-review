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
