"""
GitHub API client for the Code Review Room.

Fetches PR data (diff, metadata, CI status) and posts reviews/comments/labels.
Uses the REST API directly — no PyGithub dependency.

Works against the real GitHub API when GITHUB_TOKEN is set, and falls back
to returning empty/placeholder data when not configured, so the room can
run in test/simulation mode.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

logger = logging.getLogger("plato.room.github")

GITHUB_API = "https://api.github.com"

# Files that count as test files
_TEST_FILE_RE = re.compile(
    r"(test|spec|_test\.|\.test\.|\.spec\.|tests/|__tests__/|test_)",
    re.IGNORECASE,
)

# Security-sensitive file patterns
_SECURITY_PATH_RE = re.compile(
    r"(\.github/workflows/|Dockerfile|docker-compose|\.env|secret|id_rsa|"
    r"id_ed25519|Makefile|security/|auth/|permission|policy|sudoers|"
    r"nginx\.conf|sshd_config|firewall|iptables)",
    re.IGNORECASE,
)


class GitHubClient:
    """Minimal GitHub REST API client."""

    def __init__(self, token: str = "", rate_limit_per_hour: int = 5000):
        self.token = token
        self._rate_limit_remaining = rate_limit_per_hour
        self._last_request_time = 0.0

    @property
    def configured(self) -> bool:
        return bool(self.token)

    def _headers(self, accept: str = "application/vnd.github+json") -> dict[str, str]:
        h = {"Accept": accept, "User-Agent": "plato-room-code-review/1.0"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[dict] = None,
        accept: str = "application/vnd.github+json",
    ) -> Any:
        """Make an authenticated GitHub API request."""
        # Rate limiting — 1 req/sec max as a safety net
        elapsed = time.time() - self._last_request_time
        if elapsed < 1.0:
            time.sleep(1.0 - elapsed)
        self._last_request_time = time.time()

        url = f"{GITHUB_API}{path}"
        data = json.dumps(body).encode() if body else None
        req = Request(url, data=data, headers=self._headers(accept), method=method)

        try:
            with urlopen(req) as resp:
                self._rate_limit_remaining = int(
                    resp.headers.get("X-RateLimit-Remaining", self._rate_limit_remaining)
                )
                if resp.status == 204:
                    return {}
                raw = resp.read()
                # The Accept header decides the body format. A request for
                # "application/vnd.github.v3.diff" comes back as a RAW DIFF,
                # not as JSON -- so parsing it as JSON raised
                # "Expecting value: line 1 column 1" on every real pull
                # request, and the detector had never once run against a
                # real PR. The `isinstance(data, str)` check downstream was
                # dead code: _request could never return a str.
                if accept and "diff" in accept:
                    return raw.decode("utf-8", "replace")
                return json.loads(raw)
        except HTTPError as exc:
            logger.error("GitHub API %s %s → %d: %s", method, path, exc.code, exc.read()[:200])
            raise
        except URLError as exc:
            logger.error("GitHub API %s %s → %s", method, path, exc.reason)
            raise

    # ── PR data ───────────────────────────────────────────

    def fetch_pr_diff(self, owner: str, repo: str, pr_number: int) -> str:
        """Fetch the raw diff for a PR."""
        if not self.configured:
            return _SAMPLE_DIFF
        path = f"/repos/{owner}/{repo}/pulls/{pr_number}"
        data = self._request("GET", path, accept="application/vnd.github.v3.diff")
        return data if isinstance(data, str) else str(data)

    def fetch_pr_metadata(self, owner: str, repo: str, pr_number: int) -> dict[str, Any]:
        """Fetch PR metadata including file counts."""
        if not self.configured:
            return _SAMPLE_METADATA

        path = f"/repos/{owner}/{repo}/pulls/{pr_number}"
        pr = self._request("GET", path)

        # Fetch changed files (paginated)
        files_path = f"/repos/{owner}/{repo}/pulls/{pr_number}/files"
        files = self._paginated_get(files_path)

        changed_files = len(files)
        test_files = sum(1 for f in files if _TEST_FILE_RE.search(f.get("filename", "")))

        return {
            "number": pr.get("number", pr_number),
            "title": pr.get("title", ""),
            "state": pr.get("state", "open"),
            "draft": pr.get("draft", False),
            "author": pr.get("user", {}).get("login", ""),
            "changed_files": changed_files,
            "test_files": test_files,
            "additions": pr.get("additions", 0),
            "deletions": pr.get("deletions", 0),
            "mergeable": pr.get("mergeable"),
            "base_sha": pr.get("base", {}).get("sha", ""),
            "head_sha": pr.get("head", {}).get("sha", ""),
        }

    def fetch_ci_status(self, owner: str, repo: str, pr_number: int) -> dict[str, int]:
        """Fetch CI check run summary for a PR."""
        if not self.configured:
            return {"passed": 3, "failed": 0, "pending": 0}

        # Get the head SHA from the PR
        pr_path = f"/repos/{owner}/{repo}/pulls/{pr_number}"
        pr_data = self._request("GET", pr_path)
        head_sha = pr_data.get("head", {}).get("sha", "")

        if not head_sha:
            return {"passed": 0, "failed": 0, "pending": 0}

        # Check runs
        cr_path = f"/repos/{owner}/{repo}/commits/{head_sha}/check-runs"
        cr_data = self._request("GET", cr_path)

        passed = failed = pending = 0
        for run in cr_data.get("check_runs", []):
            status = run.get("status", "")
            conclusion = run.get("conclusion", "")
            if status != "completed":
                pending += 1
            elif conclusion == "success":
                passed += 1
            elif conclusion in ("failure", "cancelled", "timed_out", "action_required"):
                failed += 1
            else:
                pending += 1  # neutral / skipped → pending

        return {"passed": passed, "failed": failed, "pending": pending}

    # ── PR actions ────────────────────────────────────────

    def post_review(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str,
        event: str = "COMMENT",
    ) -> dict:
        """Post a PR review. event: APPROVE | REQUEST_CHANGES | COMMENT."""
        if not self.configured:
            logger.info("[simulated] Would post %s review: %s", event, body[:100])
            return {"simulated": True, "event": event}

        path = f"/repos/{owner}/{repo}/pulls/{pr_number}/reviews"
        review_body = {"body": body, "event": event}
        return self._request("POST", path, body=review_body)

    def post_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str,
    ) -> dict:
        """Post a general PR comment."""
        if not self.configured:
            logger.info("[simulated] Would post comment: %s", body[:100])
            return {"simulated": True}

        path = f"/repos/{owner}/{repo}/issues/{pr_number}/comments"
        return self._request("POST", path, body={"body": body})

    def apply_label(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        label: str,
    ) -> dict:
        """Apply a label to a PR."""
        if not self.configured:
            logger.info("[simulated] Would apply label: %s", label)
            return {"simulated": True}

        path = f"/repos/{owner}/{repo}/issues/{pr_number}/labels"
        return self._request("POST", path, body={"labels": [label]})

    # ── Helpers ───────────────────────────────────────────

    def _paginated_get(self, path: str, per_page: int = 100) -> list[dict]:
        """Fetch all pages of a paginated resource."""
        results: list[dict] = []
        page = 1
        while True:
            sep = "&" if "?" in path else "?"
            paged = f"{path}{sep}per_page={per_page}&page={page}"
            data = self._request("GET", paged)
            if not data:
                break
            results.extend(data)
            if len(data) < per_page:
                break
            page += 1
        return results


# ─── Sample data (for simulation/testing) ─────────────────────

_SAMPLE_DIFF = """\
diff --git a/app/auth.py b/app/auth.py
new file mode 100644
index 0000000..e69de29
--- /dev/null
+++ b/app/auth.py
@@ -0,0 +1,15 @@
+import sqlite3
+
+def login(username, password):
+    conn = sqlite3.connect("users.db")
+    cursor = conn.cursor()
+    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
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
index 0000000..e69de29
--- /dev/null
+++ b/.github/workflows/ci.yml
@@ -0,0 +1,8 @@
+name: CI
+on: [push, pull_request]
+jobs:
+  test:
+    runs-on: ubuntu-latest
+    steps:
+      - run: ./run_tests.sh || true
+      - run: echo "Tests passed"
"""

_SAMPLE_METADATA = {
    "number": 42,
    "title": "Add authentication module",
    "state": "open",
    "draft": False,
    "author": "developer",
    "changed_files": 2,
    "test_files": 0,
    "additions": 23,
    "deletions": 0,
    "mergeable": True,
    "base_sha": "abc123",
    "head_sha": "def456",
}
