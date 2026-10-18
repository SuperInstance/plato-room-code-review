"""Regression tests for two defects that made the detector useless.

1. THE DIFF WAS PARSED AS JSON. `fetch_pr_diff` requests
   `Accept: application/vnd.github.v3.diff`, which returns a RAW DIFF.
   `_request` then did `json.loads(resp.read())` on it, which raises
   "Expecting value: line 1 column 1" for every real pull request. The
   detector had therefore never once run against a real PR, and the
   `isinstance(data, str)` check downstream was dead code.

2. COMMENTS WERE FLAGGED AS CI BYPASSES. The detector's own workflow
   names the very shapes it looks for -- "|| true", "continue-on-error:
   true", "set +e" -- inside a COMMENT explaining what it detects. So it
   flagged its own comment, and the job failed on the pull request that
   introduced the detector.

A gate that cannot run is not a gate, and a gate that fires on its own
documentation is worse than no gate: it teaches people to ignore it.
"""
import unittest

from plato_room_code_review import reviewer
from plato_room_code_review.github_client import GitHubClient


def _diff_with(lines):
    body = "\n".join(lines)
    return "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n" + body + "\n"


class TestDiffIsNotParsedAsJson(unittest.TestCase):
    def test_a_raw_diff_body_is_returned_as_text(self):
        client = GitHubClient(token="t")
        raw = "diff --git a/x b/x\n-old\n+new\n"

        class _Resp:
            status = 200
            headers = {"X-RateLimit-Remaining": "4999"}

            def read(self):
                return raw.encode()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        import plato_room_code_review.github_client as gc
        orig = gc.urlopen
        gc.urlopen = lambda *a, **k: _Resp()
        try:
            out = client._request("GET", "/repos/o/r/pulls/1",
                                  accept="application/vnd.github.v3.diff")
        finally:
            gc.urlopen = orig
        self.assertEqual(out, raw)
        self.assertIsInstance(out, str)


class TestCommentsAreNotFlagged(unittest.TestCase):
    def _check(self, diff):
        res = reviewer.check_ci_bypass(diff) if hasattr(reviewer, "_check_ci_bypass") else None
        return res

    def test_a_comment_naming_the_shapes_is_not_a_finding(self):
        diff = _diff_with([
            "+        # the shapes this detects: `|| true`, `continue-on-error: true`, `set +e`",
        ])
        res = reviewer.check_ci_bypass(diff)
        self.assertTrue(res.passed, "a COMMENT is documentation, not a step")
        self.assertIn("ci_bypass", res.check_id)

    def test_a_real_bypass_is_still_found(self):
        diff = _diff_with([
            "+        - run: npm test",
            "+          continue-on-error: true",
        ])
        res = reviewer.check_ci_bypass(diff)
        self.assertFalse(res.passed, "a real bypass must still be found")
        self.assertIn("continue-on-error", res.message)

    def test_set_plus_e_is_still_found(self):
        diff = _diff_with(["+        set +e", "+        npm test"])
        res = reviewer.check_ci_bypass(diff)
        self.assertFalse(res.passed)
        self.assertIn("set +e", res.message)

    def test_or_true_is_still_found(self):
        diff = _diff_with(["+        - run: npm test || true"])
        res = reviewer.check_ci_bypass(diff)
        self.assertFalse(res.passed)


if __name__ == "__main__":
    unittest.main()
