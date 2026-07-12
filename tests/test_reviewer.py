"""
Tests for the Code Review Room's reviewer heuristics.

Run: python -m pytest tests/test_reviewer.py -v
"""

import sys
import os

# Allow running without install
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reviewer import (
    run_all_checks,
    check_missing_tests,
    check_ci_bypass,
    check_hardcoded_secrets,
    check_missing_type_hints,
    check_sql_injection,
    check_security_files,
    check_large_diff,
)


# ─── Sample diffs ────────────────────────────────────────────

CLEAN_DIFF = """\
diff --git a/src/utils.py b/src/utils.py
index 1111111..2222222 100644
--- a/src/utils.py
+++ b/src/utils.py
@@ -10,6 +10,9 @@ def helper(x: int) -> str:
+def format_name(name: str) -> str:
+    return name.strip().title()
+
diff --git a/tests/test_utils.py b/tests/test_utils.py
new file mode 100644
--- /dev/null
+++ b/tests/test_utils.py
@@ -0,0 +1,5 @@
+def test_format_name():
+    assert format_name("  hello  ") == "Hello"
"""

BAD_DIFF = """\
diff --git a/app/auth.py b/app/auth.py
new file mode 100644
--- /dev/null
+++ b/app/auth.py
@@ -0,0 +1,20 @@
+import sqlite3
+
+def login(username, password):
+    conn = sqlite3.connect("users.db")
+    cursor = conn.cursor()
+    query = "SELECT * FROM users WHERE username='" + username + "'"
+    cursor.execute(query)
+    return cursor.fetchone()
+
+API_KEY = "sk-1234567890abcdef1234567890abcdef"
+
+def get_user(user_id):
+    conn = sqlite3.connect("users.db")
+    cursor = conn.cursor()
+    cursor.execute("SELECT * FROM users WHERE id=" + str(user_id))
+    return cursor.fetchone()
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
new file mode 100644
--- /dev/null
+++ b/.github/workflows/ci.yml
@@ -0,0 +1,5 @@
+name: CI
+on: [push]
+jobs:
+  test:
+    steps:
+      - run: ./test.sh || true
"""

EMPTY_DIFF = ""


# ─── Tests ───────────────────────────────────────────────────

class TestMissingTests:
    def test_clean_diff_passes(self):
        result = check_missing_tests(CLEAN_DIFF)
        assert result.passed, f"Expected pass but: {result.message}"

    def test_bad_diff_fails(self):
        result = check_missing_tests(BAD_DIFF)
        assert not result.passed
        assert "auth.py" in result.message or "ci.yml" in result.message

    def test_empty_diff_passes(self):
        result = check_missing_tests(EMPTY_DIFF)
        assert result.passed


class TestCIBypass:
    def test_detects_pipe_true(self):
        result = check_ci_bypass(BAD_DIFF)
        assert not result.passed
        assert any("ci.yml" in f for f in result.file_hints)

    def test_clean_diff_ok(self):
        result = check_ci_bypass(CLEAN_DIFF)
        assert result.passed


class TestHardcodedSecrets:
    def test_detects_api_key(self):
        result = check_hardcoded_secrets(BAD_DIFF)
        assert not result.passed
        assert "API Key" in result.message or "Token" in result.message

    def test_clean_diff_ok(self):
        result = check_hardcoded_secrets(CLEAN_DIFF)
        assert result.passed

    def test_detects_aws_key(self):
        diff = "+AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        result = check_hardcoded_secrets(diff)
        assert not result.passed

    def test_detects_private_key(self):
        diff = "+-----BEGIN RSA PRIVATE KEY-----\n+MIIEpAIBAAKCAQEA...\n"
        result = check_hardcoded_secrets(diff)
        assert not result.passed


class TestTypeHints:
    def test_detects_missing_hints(self):
        result = check_missing_type_hints(BAD_DIFF)
        assert not result.passed
        assert "login" in result.message or "get_user" in result.message

    def test_clean_diff_ok(self):
        result = check_missing_type_hints(CLEAN_DIFF)
        assert result.passed


class TestSQLInjection:
    def test_detects_string_concat(self):
        result = check_sql_injection(BAD_DIFF)
        assert not result.passed

    def test_clean_diff_ok(self):
        result = check_sql_injection(CLEAN_DIFF)
        assert result.passed


class TestSecurityFiles:
    def test_detects_workflow_file(self):
        result = check_security_files(BAD_DIFF)
        assert not result.passed
        assert any("ci.yml" in f or ".github" in f for f in result.file_hints)

    def test_clean_diff_ok(self):
        result = check_security_files(CLEAN_DIFF)
        assert result.passed


class TestLargeDiff:
    def test_small_diff_ok(self):
        result = check_large_diff(CLEAN_DIFF)
        assert result.passed

    def test_large_diff_warns(self):
        big = "+line\n" * 600
        result = check_large_diff(big)
        assert not result.passed


class TestRunAllChecks:
    def test_returns_results_for_all_checks(self):
        results = run_all_checks(BAD_DIFF)
        check_ids = {r.check_id for r in results}
        assert "missing_tests" in check_ids
        assert "ci_bypass" in check_ids
        assert "secrets" in check_ids
        assert "sql_injection" in check_ids
        assert "security_file" in check_ids

    def test_clean_diff_mostly_passes(self):
        results = run_all_checks(CLEAN_DIFF)
        failed = [r for r in results if not r.passed]
        # Clean diff might still fail type hints (format_name has hints, so should pass)
        assert len(failed) == 0, f"Unexpected failures: {[r.name for r in failed]}"

    def test_bad_diff_has_multiple_failures(self):
        results = run_all_checks(BAD_DIFF)
        failed = [r for r in results if not r.passed]
        assert len(failed) >= 4, f"Expected >= 4 failures, got {len(failed)}: {[r.name for r in failed]}"

    def test_empty_diff_doesnt_crash(self):
        results = run_all_checks(EMPTY_DIFF)
        assert len(results) > 0
