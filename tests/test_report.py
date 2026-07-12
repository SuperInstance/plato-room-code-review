"""
Tests for the review report generator.

Run: python -m pytest tests/test_report.py -v
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plato_room_code_review.reviewer import CheckResult, run_all_checks
from plato_room_code_review.report import generate_report, generate_short_summary
from plato_room_code_review.github_client import GitHubClient


# ─── Fixtures ────────────────────────────────────────────────

SAMPLE_RESULTS_ALL_PASS = [
    CheckResult(check_id="test_check", name="Test Check", passed=True,
                message="All good", severity="info"),
    CheckResult(check_id="another", name="Another", passed=True,
                message="Fine", severity="info"),
]

SAMPLE_RESULTS_WITH_FAILURES = [
    CheckResult(check_id="secrets", name="Hardcoded Secrets", passed=False,
                message="AWS key found", severity="error",
                file_hints=["app/config.py"]),
    CheckResult(check_id="tests", name="Missing Tests", passed=False,
                message="No test files", severity="warning",
                file_hints=["app/main.py"]),
    CheckResult(check_id="types", name="Type Hints", passed=True,
                message="OK", severity="info"),
]

SAMPLE_FROM_BAD_DIFF = run_all_checks(
    GitHubClient(token="").fetch_pr_diff("owner", "repo", 1)
)


# ─── Tests ───────────────────────────────────────────────────

class TestGenerateReport:
    def test_returns_string(self):
        report = generate_report(SAMPLE_RESULTS_ALL_PASS)
        assert isinstance(report, str)

    def test_contains_header(self):
        report = generate_report(SAMPLE_RESULTS_ALL_PASS)
        assert "PLATO Code Review Report" in report

    def test_contains_summary_section(self):
        report = generate_report(SAMPLE_RESULTS_ALL_PASS)
        assert "Summary" in report
        assert "Checks Run" in report

    def test_correct_pass_fail_counts(self):
        report = generate_report(SAMPLE_RESULTS_WITH_FAILURES)
        assert "3" in report  # total
        assert "1" in report  # passed
        assert "2" in report  # failed

    def test_contains_detailed_results(self):
        report = generate_report(SAMPLE_RESULTS_WITH_FAILURES)
        assert "Detailed Results" in report
        assert "Hardcoded Secrets" in report
        assert "Missing Tests" in report

    def test_includes_file_hints(self):
        report = generate_report(SAMPLE_RESULTS_WITH_FAILURES)
        assert "app/config.py" in report
        assert "app/main.py" in report

    def test_recommendation_approve_when_all_pass(self):
        report = generate_report(SAMPLE_RESULTS_ALL_PASS)
        assert "APPROVE" in report

    def test_recommendation_request_changes_on_error(self):
        report = generate_report(SAMPLE_RESULTS_WITH_FAILURES)
        assert "REQUEST_CHANGES" in report

    def test_recommendation_comment_on_warnings_only(self):
        results = [
            CheckResult(check_id="w1", name="Warning Check", passed=False,
                        message="Minor issue", severity="warning"),
            CheckResult(check_id="p1", name="Pass Check", passed=True,
                        message="OK", severity="info"),
        ]
        report = generate_report(results)
        assert "COMMENT" in report

    def test_includes_repo_and_pr_info(self):
        report = generate_report(
            SAMPLE_RESULTS_ALL_PASS,
            repo="owner/repo",
            pr_number=42,
            author="alice",
        )
        assert "owner/repo" in report
        assert "#42" in report
        assert "@alice" in report

    def test_works_with_bad_diff_results(self):
        """Report should work with real check results from a bad diff."""
        report = generate_report(SAMPLE_FROM_BAD_DIFF)
        assert "PLATO Code Review Report" in report
        assert "Summary" in report

    def test_empty_results_dont_crash(self):
        report = generate_report([])
        assert isinstance(report, str)
        assert "0" in report  # 0 checks

    def test_failing_checks_sorted_before_passing(self):
        report = generate_report(SAMPLE_RESULTS_WITH_FAILURES)
        # The failing "Hardcoded Secrets" (error) should appear before passing "Type Hints"
        pos_secrets = report.find("Hardcoded Secrets")
        pos_types = report.find("Type Hints")
        assert pos_secrets < pos_types

    def test_contains_footer(self):
        report = generate_report(SAMPLE_RESULTS_ALL_PASS)
        assert "PLATO Code Review Room" in report
        assert "github.com/SuperInstance" in report


class TestGenerateShortSummary:
    def test_all_passed_summary(self):
        summary = generate_short_summary(SAMPLE_RESULTS_ALL_PASS)
        assert "2/2" in summary
        assert "APPROVE" in summary

    def test_with_failures_summary(self):
        summary = generate_short_summary(SAMPLE_RESULTS_WITH_FAILURES)
        assert "1/3" in summary
        assert "REQUEST_CHANGES" in summary

    def test_empty_results(self):
        summary = generate_short_summary([])
        assert "0/0" in summary
