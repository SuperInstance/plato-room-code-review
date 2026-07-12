"""
Tests for the Code Review Room's reviewer heuristics.

Run: python -m pytest tests/test_reviewer.py -v
"""

import sys
import os

# Allow running without install
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plato_room_code_review.reviewer import (
    run_all_checks,
    check_missing_tests,
    check_ci_bypass,
    check_hardcoded_secrets,
    check_missing_type_hints,
    check_sql_injection,
    check_security_files,
    check_large_diff,
    check_missing_license,
    check_console_print,
    check_todo_without_assignee,
    check_long_functions,
    check_cyclomatic_complexity,
    check_missing_docstrings,
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
        # Allow info-severity failures (e.g. missing_docstrings is advisory)
        non_info_failures = [r for r in failed if r.severity != "info"]
        assert len(non_info_failures) == 0, f"Unexpected non-info failures: {[r.name for r in non_info_failures]}"

    def test_bad_diff_has_multiple_failures(self):
        results = run_all_checks(BAD_DIFF)
        failed = [r for r in results if not r.passed]
        assert len(failed) >= 4, f"Expected >= 4 failures, got {len(failed)}: {[r.name for r in failed]}"

    def test_empty_diff_doesnt_crash(self):
        results = run_all_checks(EMPTY_DIFF)
        assert len(results) > 0

    def test_all_new_checks_registered(self):
        """Verify all new checks are in _ALL_CHECKS."""
        results = run_all_checks(BAD_DIFF)
        check_ids = {r.check_id for r in results}
        assert "missing_license" in check_ids
        assert "console_print" in check_ids
        assert "todo_without_assignee" in check_ids
        assert "long_functions" in check_ids
        assert "cyclomatic_complexity" in check_ids
        assert "missing_docstrings" in check_ids


# ─── New heuristic tests ─────────────────────────────────────

# Diffs specifically targeting new checks

NO_LICENSE_DIFF = """\
diff --git a/src/main.py b/src/main.py
new file mode 100644
--- /dev/null
+++ b/src/main.py
@@ -0,0 +1,3 @@
+print("hello")
+
+import os
@@ -0,0 +1,3 @@
+def run():
+    pass
+
diff --git a/src/utils.py b/src/utils.py
new file mode 100644
--- /dev/null
+++ b/src/utils.py
@@ -0,0 +1,3 @@
+def helper():
+    pass
+
diff --git a/README.md b/README.md
new file mode 100644
--- /dev/null
+++ b/README.md
@@ -0,0 +1,1 @@
+# My Project
"""

WITH_LICENSE_DIFF = """\
diff --git a/LICENSE b/LICENSE
new file mode 100644
--- /dev/null
+++ b/LICENSE
@@ -0,0 +1,1 @@
+MIT License
+Copyright (c) 2024
diff --git a/src/main.py b/src/main.py
new file mode 100644
--- /dev/null
+++ b/src/main.py
@@ -0,0 +1,3 @@
+def run():
+    pass
+
diff --git a/src/utils.py b/src/utils.py
new file mode 100644
--- /dev/null
+++ b/src/utils.py
@@ -0,0 +1,3 @@
+def helper():
+    pass
+"""

CONSOLE_PRINT_DIFF = """\
diff --git a/src/app.py b/src/app.py
index 111..222 100644
--- a/src/app.py
+++ b/src/app.py
@@ -5,6 +5,12 @@ def compute(x: int) -> int:
+    print("debug: computing", x)
+    result = x * 2
+    print("result:", result)
+    return result
diff --git a/src/frontend.ts b/src/frontend.ts
index 111..222 100644
--- a/src/frontend.ts
+++ b/src/frontend.ts
@@ -3,6 +3,8 @@ export function greet(): void {
+    console.log("hello from frontend");
+    return;
"""

TODO_DIFF = """\
diff --git a/src/handlers.py b/src/handlers.py
index 111..222 100644
--- a/src/handlers.py
+++ b/src/handlers.py
@@ -1,3 +1,10 @@
+def process(data):
+    # TODO: implement this properly
+    pass
+
+def fix_later(data):
+    # FIXME: this is broken
+    pass
+
+def ok(data):
+    # TODO @alice: review this
+    pass
+"""

TODO_CLEAN_DIFF = """\
diff --git a/src/handlers.py b/src/handlers.py
index 111..222 100644
--- a/src/handlers.py
+++ b/src/handlers.py
@@ -1,3 +1,5 @@
+def process(data):
+    # TODO @alice: implement this
+    pass
+"""

LONG_FUNCTION_DIFF = """\
diff --git a/src/big.py b/src/big.py
new file mode 100644
--- /dev/null
+++ b/src/big.py
@@ -0,0 +1,60 @@
+def huge_function(data):
+    x = 1
+    y = 2
+    z = 3
+    a = 4
+    b = 5
+    c = 6
+    d = 7
+    e = 8
+    f = 9
+    g = 10
+    h = 11
+    i = 12
+    j = 13
+    k = 14
+    l = 15
+    m = 16
+    n = 17
+    o = 18
+    p = 19
+    q = 20
+    r = 21
+    s = 22
+    t = 23
+    u = 24
+    v = 25
+    w = 26
+    aa = 27
+    bb = 28
+    cc = 29
+    dd = 30
+    ee = 31
+    ff = 32
+    gg = 33
+    hh = 34
+    ii = 35
+    jj = 36
+    kk = 37
+    ll = 38
+    mm = 39
+    nn = 40
+    oo = 41
+    pp = 42
+    qq = 43
+    rr = 44
+    ss = 45
+    tt = 46
+    uu = 47
+    vv = 48
+    ww = 49
+    xx = 50
+    yy = 51
+    zz = 52
+    return zz
+
+def small_function():
+    return 42
+"""

COMPLEX_FUNCTION_DIFF = """\
diff --git a/src/complex.py b/src/complex.py
new file mode 100644
--- /dev/null
+++ b/src/complex.py
@@ -0,0 +1,20 @@
+def complex_logic(data, mode, flag):
+    if mode == 1:
+        if flag and data:
+            for item in data:
+                if item > 0:
+                    if item % 2 == 0:
+                        pass
+    elif mode == 2:
+        while flag:
+            try:
+                if data or flag:
+                    pass
+            except Exception:
+                if data:
+                    pass
+    return data
+"""

DOCSTRING_DIFF = (
    'diff --git a/src/clean.py b/src/clean.py\n'
    'new file mode 100644\n'
    '--- /dev/null\n'
    '+++ b/src/clean.py\n'
    '@@ -0,0 +1,10 @@\n'
    '+def documented_function(x: int) -> int:\n'
    '+    """Compute the square of x."""\n'
    '+    return x * x\n'
    '+\n'
    '+def undocumented_function(y: int) -> int:\n'
    '+    return y * y\n'
    '+\n'
    '+def _private_function(z: int) -> int:\n'
    '+    return z * z\n'
)


class TestMissingLicense:
    def test_missing_license_detected(self):
        result = check_missing_license(NO_LICENSE_DIFF)
        assert not result.passed
        assert "LICENSE" in result.message

    def test_with_license_passes(self):
        result = check_missing_license(WITH_LICENSE_DIFF)
        assert result.passed

    def test_clean_diff_passes(self):
        result = check_missing_license(CLEAN_DIFF)
        assert result.passed

    def test_empty_diff_passes(self):
        result = check_missing_license(EMPTY_DIFF)
        assert result.passed


class TestConsolePrint:
    def test_detects_python_print(self):
        result = check_console_print(CONSOLE_PRINT_DIFF)
        assert not result.passed
        assert any("app.py" in f for f in result.file_hints) or any("frontend.ts" in f for f in result.file_hints)

    def test_detects_console_log(self):
        result = check_console_print(CONSOLE_PRINT_DIFF)
        assert not result.passed
        assert "print" in result.message.lower() or "console" in result.message.lower()

    def test_clean_diff_ok(self):
        result = check_console_print(CLEAN_DIFF)
        assert result.passed

    def test_empty_diff_ok(self):
        result = check_console_print(EMPTY_DIFF)
        assert result.passed

    def test_ignores_test_files(self):
        diff = """\
diff --git a/tests/test_app.py b/tests/test_app.py
new file mode 100644
--- /dev/null
+++ b/tests/test_app.py
@@ -0,0 +1,3 @@
+def test_thing():
+    print("testing")
+    assert True
+"""
        result = check_console_print(diff)
        assert result.passed

    def test_ignores_comments(self):
        diff = "+# print('this is a comment')\n"
        result = check_console_print(diff)
        assert result.passed


class TestTodoWithoutAssignee:
    def test_detects_unassigned_todo(self):
        result = check_todo_without_assignee(TODO_DIFF)
        assert not result.passed
        assert "TODO" in result.message or "FIXME" in result.message

    def test_assigned_todo_passes(self):
        result = check_todo_without_assignee(TODO_CLEAN_DIFF)
        assert result.passed

    def test_clean_diff_ok(self):
        result = check_todo_without_assignee(CLEAN_DIFF)
        assert result.passed

    def test_empty_diff_ok(self):
        result = check_todo_without_assignee(EMPTY_DIFF)
        assert result.passed


class TestLongFunctions:
    def test_detects_long_function(self):
        result = check_long_functions(LONG_FUNCTION_DIFF)
        assert not result.passed
        assert "huge_function" in result.message

    def test_short_functions_ok(self):
        result = check_long_functions(CLEAN_DIFF)
        assert result.passed

    def test_empty_diff_ok(self):
        result = check_long_functions(EMPTY_DIFF)
        assert result.passed


class TestCyclomaticComplexity:
    def test_detects_complex_function(self):
        result = check_cyclomatic_complexity(COMPLEX_FUNCTION_DIFF)
        assert not result.passed
        assert "complex_logic" in result.message

    def test_simple_function_ok(self):
        result = check_cyclomatic_complexity(CLEAN_DIFF)
        assert result.passed

    def test_empty_diff_ok(self):
        result = check_cyclomatic_complexity(EMPTY_DIFF)
        assert result.passed


class TestMissingDocstrings:
    def test_detects_missing_docstring(self):
        result = check_missing_docstrings(DOCSTRING_DIFF)
        assert not result.passed
        assert "undocumented_function" in result.message

    def test_documented_function_not_flagged(self):
        result = check_missing_docstrings(DOCSTRING_DIFF)
        # documented_function should NOT be in the failing list; only undocumented_function should
        if not result.passed:
            assert "::documented_function" not in result.message

    def test_private_function_not_flagged(self):
        result = check_missing_docstrings(DOCSTRING_DIFF)
        assert "_private_function" not in result.message

    def test_clean_diff_with_docstrings_ok(self):
        diff = (
            'diff --git a/src/utils.py b/src/utils.py\n'
            'index 111..222 100644\n'
            '--- a/src/utils.py\n'
            '+++ b/src/utils.py\n'
            '@@ -1,1 +1,4 @@\n'
            '+def format_name(name: str) -> str:\n'
            '+    """Format a name by stripping and titling."""\n'
            '+    return name.strip().title()\n'
        )
        result = check_missing_docstrings(diff)
        assert result.passed

    def test_empty_diff_ok(self):
        result = check_missing_docstrings(EMPTY_DIFF)
        assert result.passed
