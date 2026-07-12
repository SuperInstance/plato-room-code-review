"""
Tests for the Conservation Enforcer integration with the Code Review Room.

Run: python -m pytest tests/test_enforcer_integration.py -v
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Also add src/ to path for the new module
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from plato_room_code_review.reviewer import CheckResult, run_all_checks
from plato_room_code_review.github_client import GitHubClient
from plato_room_code_review.report import generate_report
from plato_room_code_review.enforcer_integration import (
    ConservationEnforcer,
    ConservationLaw,
    ConservationResult,
    EnforcerMetrics,
    EnforcedReviewRoom,
    Verdict,
    DEFAULT_LAWS,
    _law_no_empty_review,
    _law_no_suppressed_findings,
    _law_must_include_remediation,
    _law_severity_honesty,
    _law_no_secret_leakage,
)


# ─── Fixtures ────────────────────────────────────────────────

PASSING_RESULTS = [
    CheckResult("a", "Check A", True, "OK", "info"),
    CheckResult("b", "Check B", True, "OK", "warning"),
]

FAILING_RESULTS = [
    CheckResult("secrets", "Hardcoded Secrets", False, "Found keys.", "error"),
    CheckResult("missing_tests", "Missing Tests", False, "No test files.", "warning"),
    CheckResult("type_hints", "Type Hints", True, "Fine.", "info"),
]

ALL_PASS_RESULTS = [
    CheckResult("a", "Check A", True, "All good.", "info"),
    CheckResult("b", "Check B", True, "All good.", "warning"),
    CheckResult("c", "Check C", True, "All good.", "error"),
]


# ─── Individual law tests ────────────────────────────────────

class TestNoEmptyReview:
    def test_blocks_empty_body(self):
        ok, msg, _ = _law_no_empty_review("", PASSING_RESULTS)
        assert not ok
        assert "empty" in msg.lower()

    def test_blocks_whitespace_only(self):
        ok, msg, _ = _law_no_empty_review("   \n\n  ", PASSING_RESULTS)
        assert not ok

    def test_passes_non_empty(self):
        ok, _, _ = _law_no_empty_review("## Review\nLGTM", PASSING_RESULTS)
        assert ok


class TestNoSuppressedFindings:
    def test_blocks_false_success_claim(self):
        body = "All automated checks passed. ✅\n"
        ok, msg, _ = _law_no_suppressed_findings(body, FAILING_RESULTS)
        assert not ok
        assert "suppress" in msg.lower() or "failing" in msg.lower()

    def test_passes_honest_review(self):
        body = "## Review\n2 checks need attention."
        ok, _, _ = _law_no_suppressed_findings(body, FAILING_RESULTS)
        assert ok

    def test_passes_when_no_failures(self):
        body = "All automated checks passed. ✅\n"
        ok, _, _ = _law_no_suppressed_findings(body, ALL_PASS_RESULTS)
        assert ok


class TestSeverityHonesty:
    def test_blocks_approve_with_errors(self):
        body = "✅ Approved — all checks passed."
        ok, msg, _ = _law_severity_honesty(body, FAILING_RESULTS)
        assert not ok
        assert "approve" in msg.lower()

    def test_passes_request_changes_with_errors(self):
        body = "⚠️ Changes requested due to critical findings."
        ok, _, _ = _law_severity_honesty(body, FAILING_RESULTS)
        assert ok

    def test_passes_approve_when_no_errors(self):
        body = "✅ Approved — all checks passed."
        ok, _, _ = _law_severity_honesty(body, ALL_PASS_RESULTS)
        assert ok


class TestNoSecretLeakage:
    def test_detects_aws_key_in_body(self):
        body = "Found key: AKIAABCDEFGHIJKLMNOP\n"
        ok, msg, replacement = _law_no_secret_leakage(body, PASSING_RESULTS)
        assert not ok
        assert "redacted" in msg.lower()
        assert replacement is not None
        assert "AKIAABCDEFGHIJKLMNOP" not in replacement
        assert "***REDACTED***" in replacement

    def test_detects_github_token(self):
        body = "Token leaked: ghp_1234567890abcdefghijklmnopqrstuvwxyz1234\n"
        ok, msg, replacement = _law_no_secret_leakage(body, PASSING_RESULTS)
        assert not ok
        assert "REDACTED" in (replacement or "")

    def test_passes_clean_body(self):
        body = "## Review\nNo issues found."
        ok, _, _ = _law_no_secret_leakage(body, PASSING_RESULTS)
        assert ok


class TestMustIncludeRemediation:
    def test_appends_remediation_when_missing(self):
        body = "## Review\nFound issues.\n"
        ok, msg, replacement = _law_must_include_remediation(body, FAILING_RESULTS)
        assert not ok
        assert "remediation" in msg.lower()
        assert replacement is not None
        assert "Recommended Remediation" in replacement
        assert "secrets" in replacement.lower()

    def test_passes_when_actions_present(self):
        body = "## Review\nUse environment variables for secrets.\n"
        ok, _, _ = _law_must_include_remediation(body, FAILING_RESULTS)
        assert ok

    def test_passes_when_no_failures(self):
        body = "## Review\nAll good.\n"
        ok, _, _ = _law_must_include_remediation(body, ALL_PASS_RESULTS)
        assert ok


# ─── Enforcer integration tests ──────────────────────────────

class TestConservationEnforcer:
    def test_default_laws_registered(self):
        enforcer = ConservationEnforcer()
        ids = [l.law_id for l in enforcer.laws]
        assert "no-empty-review" in ids
        assert "no-suppressed-findings" in ids
        assert "severity-honesty" in ids
        assert "no-secret-leakage" in ids
        assert "must-include-remediation" in ids

    def test_passes_clean_review(self):
        enforcer = ConservationEnforcer()
        body = "## Review\nNo issues. Use parameterized queries.\n"
        result = enforcer.enforce(body, ALL_PASS_RESULTS)
        assert result.verdict == Verdict.PASS
        assert result.violations == []
        assert result.enforced_body == body

    def test_blocks_empty_review(self):
        enforcer = ConservationEnforcer()
        result = enforcer.enforce("", ALL_PASS_RESULTS)
        assert result.verdict == Verdict.BLOCK
        assert any("empty" in v for v in result.violations)

    def test_blocks_suppressed_findings(self):
        enforcer = ConservationEnforcer()
        body = "All automated checks passed. ✅\n"
        result = enforcer.enforce(body, FAILING_RESULTS)
        assert result.verdict == Verdict.BLOCK

    def test_blocks_approve_with_errors(self):
        enforcer = ConservationEnforcer()
        body = "✅ Approved — all checks passed."
        result = enforcer.enforce(body, FAILING_RESULTS)
        assert result.verdict == Verdict.BLOCK

    def test_transforms_to_add_remediation(self):
        enforcer = ConservationEnforcer()
        body = "## Review\n2 checks failing.\n"
        result = enforcer.enforce(body, FAILING_RESULTS)
        assert result.verdict == Verdict.TRANSFORM
        assert result.was_modified
        assert "Recommended Remediation" in result.enforced_body
        assert result.original_body != result.enforced_body

    def test_transforms_to_redact_secrets(self):
        enforcer = ConservationEnforcer()
        body = "## Review\nFound: AKIAABCDEFGHIJKLMNOP\n"
        result = enforcer.enforce(body, FAILING_RESULTS)
        # Secret leakage is a hard law, so it blocks
        assert result.verdict == Verdict.BLOCK
        assert "REDACTED" not in result.enforced_body  # blocked, not transformed

    def test_hard_law_takes_precedence_over_soft(self):
        enforcer = ConservationEnforcer()
        # Both empty (hard) and missing remediation (soft) would fire
        body = ""
        result = enforcer.enforce(body, FAILING_RESULTS)
        assert result.verdict == Verdict.BLOCK
        # Should have stopped at the first hard law
        assert len([v for v in result.violations]) >= 1

    def test_custom_laws(self):
        custom = ConservationLaw(
            law_id="custom-test",
            description="Test law that always passes.",
            evaluate=lambda body, results: (True, "OK", None),
        )
        enforcer = ConservationEnforcer(laws=[custom])
        result = enforcer.enforce("body", FAILING_RESULTS)
        assert result.verdict == Verdict.PASS
        assert "custom-test" in result.law_ids


# ─── Metrics tests ───────────────────────────────────────────

class TestEnforcerMetrics:
    def test_records_pass(self):
        m = EnforcerMetrics()
        result = ConservationResult(
            verdict=Verdict.PASS,
            original_body="x",
            enforced_body="x",
        )
        m.record(result)
        assert m.total_reviews == 1
        assert m.passed == 1
        assert m.blocked == 0

    def test_records_block(self):
        m = EnforcerMetrics()
        result = ConservationResult(
            verdict=Verdict.BLOCK,
            original_body="x",
            enforced_body="x",
            violations=["[no-empty] empty body"],
        )
        m.record(result)
        assert m.blocked == 1
        assert m.violations_by_law.get("no-empty") == 1

    def test_records_transform(self):
        m = EnforcerMetrics()
        result = ConservationResult(
            verdict=Verdict.TRANSFORM,
            original_body="x",
            enforced_body="y",
            transforms_applied=["[remediation] appended"],
        )
        m.record(result)
        assert m.transformed == 1
        assert m.transforms_by_law.get("remediation") == 1

    def test_block_rate(self):
        m = EnforcerMetrics()
        for _ in range(8):
            m.record(ConservationResult(
                verdict=Verdict.PASS,
                original_body="x",
                enforced_body="x",
            ))
        for _ in range(2):
            m.record(ConservationResult(
                verdict=Verdict.BLOCK,
                original_body="",
                enforced_body="",
                violations=["[x] y"],
            ))
        assert m.total_reviews == 10
        assert m.block_rate == 0.2

    def test_summary(self):
        m = EnforcerMetrics()
        m.record(ConservationResult(
            verdict=Verdict.PASS,
            original_body="x",
            enforced_body="x",
        ))
        s = m.summary()
        assert s["total_reviews"] == 1
        assert s["passed"] == 1
        assert "block_rate" in s


# ─── EnforcedReviewRoom tests ────────────────────────────────

class TestEnforcedReviewRoom:
    def test_room_id(self):
        gh = GitHubClient(token="")
        room = EnforcedReviewRoom(gh, "owner", "repo", 1, port=0)
        assert room.room_id == "enforced-code-review-room"

    def test_has_enforcer(self):
        gh = GitHubClient(token="")
        room = EnforcedReviewRoom(gh, "owner", "repo", 1, port=0)
        assert room.enforcer is not None
        assert len(room.enforcer.laws) >= 5

    def test_has_metrics(self):
        gh = GitHubClient(token="")
        room = EnforcedReviewRoom(gh, "owner", "repo", 1, port=0)
        assert room.metrics is not None
        assert room.metrics.total_reviews == 0

    def test_registers_enforcer_sensor(self):
        gh = GitHubClient(token="")
        room = EnforcedReviewRoom(gh, "owner", "repo", 1, port=0)
        assert "enforcer_state" in room._sensors

    def test_registers_enforcer_alarm(self):
        gh = GitHubClient(token="")
        room = EnforcedReviewRoom(gh, "owner", "repo", 1, port=0)
        assert "enforcer_block_spike" in room._alarms

    def test_enforcer_sensor_reports_initial_state(self):
        gh = GitHubClient(token="")
        room = EnforcedReviewRoom(gh, "owner", "repo", 1, port=0)
        data = room.tick()
        assert data["enforcer_total"] == 0.0
        assert data["enforcer_block_rate"] == 0.0

    def test_enforce_before_post_records_metrics(self):
        gh = GitHubClient(token="")
        room = EnforcedReviewRoom(gh, "owner", "repo", 1, port=0)
        body = "## Review\nNo issues.\n"
        result = room._enforce_before_post(body, ALL_PASS_RESULTS)
        assert room.metrics.total_reviews == 1
        assert room.metrics.passed == 1

    def test_enforce_before_post_blocks_bad_review(self):
        gh = GitHubClient(token="")
        room = EnforcedReviewRoom(gh, "owner", "repo", 1, port=0)
        body = "All automated checks passed. ✅\n"
        result = room._enforce_before_post(body, FAILING_RESULTS)
        assert result.verdict == Verdict.BLOCK
        assert room.metrics.blocked == 1

    def test_post_enforced_review_without_pr(self):
        gh = GitHubClient(token="")
        room = EnforcedReviewRoom(gh, "owner", "repo", 0, port=0)
        result = room.post_enforced_review(ALL_PASS_RESULTS)
        assert result is None

    def test_post_enforced_review_with_sample_diff(self):
        gh = GitHubClient(token="")
        room = EnforcedReviewRoom(gh, "owner", "repo", 42, port=0)
        diff = gh.fetch_pr_diff("owner", "repo", 42)
        results = run_all_checks(diff)
        # Sample diff has secrets, missing tests, etc.
        result = room.post_enforced_review(results, "COMMENT")
        assert result is not None
        assert room.metrics.total_reviews >= 1

    def test_custom_laws_override(self):
        custom_law = ConservationLaw(
            law_id="always-block",
            description="Blocks everything for testing.",
            evaluate=lambda body, results: (False, "Blocked.", None),
            severity="hard",
        )
        gh = GitHubClient(token="")
        room = EnforcedReviewRoom(
            gh, "owner", "repo", 1, port=0,
            custom_laws=[custom_law],
        )
        result = room._enforce_before_post("body", ALL_PASS_RESULTS)
        assert result.verdict == Verdict.BLOCK

    def test_enforcer_alarm_fires_on_block_spike(self):
        gh = GitHubClient(token="")
        room = EnforcedReviewRoom(gh, "owner", "repo", 1, port=0)
        # Inject enough blocked reviews to spike the rate
        for _ in range(10):
            room.metrics.record(ConservationResult(
                verdict=Verdict.BLOCK,
                original_body="",
                enforced_body="",
                violations=["[test] blocked"],
            ))
        data = room.tick()
        # Block rate should be 1.0 → alarm should trigger
        assert data["enforcer_block_rate"] > 0.25
        assert room._alarms["enforcer_block_spike"].state == "triggered"
