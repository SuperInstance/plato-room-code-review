"""
Conservation Enforcer integration with the PLATO Code Review Room.

The ``EnforcedReviewRoom`` wraps every review output through a
``ConservationEnforcer`` before it reaches GitHub.  This creates a
two-layer governance model:

    ┌─────────────────────┐        ┌──────────────────────┐
    │   CodeReviewRoom    │───────▶│  ConservationEnforcer │
    │  (room-level rules) │        │  (conservation laws)  │
    └─────────────────────┘        └──────────┬───────────┘
                                              │
                                              ▼
                                     GitHub API (post)

The room catches *domain* violations (secrets, missing tests, CI bypass).
The enforcer catches *meta* violations — information loss, tone drift,
incomplete remediation guidance, or findings that violate conservation
policies (e.g. a review that approves while suppressing critical findings).

Together they form a defence-in-depth governance pipeline.
"""

from __future__ import annotations

import logging
import re
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional, Sequence

# Support both package-relative and standalone imports
try:
    from ..plato_room_code_review.reviewer import CheckResult, run_all_checks
    from ..plato_room_code_review.room import CodeReviewRoom
    from ..plato_room_code_review.report import generate_report, generate_short_summary
    from ..plato_room_code_review.github_client import GitHubClient
except ImportError:
    try:
        from .reviewer import CheckResult, run_all_checks
        from .room import CodeReviewRoom
        from .report import generate_report, generate_short_summary
        from .github_client import GitHubClient
    except ImportError:
        from plato_room_code_review.reviewer import CheckResult, run_all_checks
        from plato_room_code_review.room import CodeReviewRoom
        from plato_room_code_review.report import generate_report, generate_short_summary
        from plato_room_code_review.github_client import GitHubClient

logger = logging.getLogger("plato.room.enforcer")


# ─── Conservation verdicts ───────────────────────────────────

class Verdict(Enum):
    """What the enforcer decided about a review payload."""
    PASS = "pass"           # review satisfies all conservation laws
    TRANSFORM = "transform"  # review was rewritten to satisfy laws
    BLOCK = "block"          # review violates a hard law — must not post
    DEFER = "defer"          # review needs human escalation


@dataclass
class ConservationResult:
    """Outcome of enforcing conservation laws on a review payload."""
    verdict: Verdict
    original_body: str
    enforced_body: str
    violations: list[str] = field(default_factory=list)
    transforms_applied: list[str] = field(default_factory=list)
    law_ids: list[str] = field(default_factory=list)
    ts: float = field(default_factory=time.time)

    @property
    def was_modified(self) -> bool:
        return self.verdict == Verdict.TRANSFORM and self.original_body != self.enforced_body


# ─── Conservation laws ───────────────────────────────────────

@dataclass
class ConservationLaw:
    """A single conservation law evaluated against review output."""
    law_id: str
    description: str
    evaluate: Callable[[str, list[CheckResult]], tuple[bool, str, Optional[str]]]
    severity: str = "hard"  # "hard" → BLOCK, "soft" → TRANSFORM

    def check(
        self, body: str, results: list[CheckResult]
    ) -> tuple[bool, str, Optional[str]]:
        """Return (satisfied, message, replacement_body_or_None)."""
        return self.evaluate(body, results)


def _law_no_suppressed_findings(
    body: str, results: list[CheckResult]
) -> tuple[bool, str, Optional[str]]:
    """Hard law: a review must not suppress or omit failing checks.

    If any CheckResult has ``passed=False`` but the review body contains
    'APPROVE' or 'all checks passed', the law is violated.
    """
    failing = [r for r in results if not r.passed]
    if not failing:
        return True, "No failing checks to suppress.", None

    body_lower = body.lower()
    suppressive_phrases = [
        "all automated checks passed",
        "all checks passed",
        "approved — all checks passed",
    ]
    for phrase in suppressive_phrases:
        if phrase in body_lower:
            return (
                False,
                f"Review claims success but {len(failing)} check(s) are failing. "
                f"Suppressed: {[r.check_id for r in failing]}",
                None,
            )
    return True, "No suppressed findings detected.", None


def _law_must_include_remediation(
    body: str, results: list[CheckResult]
) -> tuple[bool, str, Optional[str]]:
    """Soft law: failing checks must include actionable remediation.

    If the review mentions a failing check but doesn't include any
    suggested action (e.g. 'use environment variables', 'add tests'),
    append a remediation hint.
    """
    failing = [r for r in results if not r.passed]
    if not failing:
        return True, "No failing checks need remediation.", None

    action_keywords = [
        "use ", "add ", "remove ", "consider", "replace", "fix",
        "should ", "must ", "update", "refactor", "split",
        "environment variable", "secrets manager", "parameterized",
    ]
    has_action = any(kw in body.lower() for kw in action_keywords)
    if has_action:
        return True, "Remediation guidance present.", None

    # Build a replacement that appends remediation hints
    hints: list[str] = []
    for r in failing:
        if r.check_id == "secrets":
            hints.append(f"- **{r.name}**: Use environment variables or a secrets manager.")
        elif r.check_id == "missing_tests":
            hints.append(f"- **{r.name}**: Add test files covering the new code paths.")
        elif r.check_id == "ci_bypass":
            hints.append(f"- **{r.name}**: Remove `|| true` / `continue-on-error` from CI steps.")
        elif r.check_id == "sql_injection":
            hints.append(f"- **{r.name}**: Switch to parameterized queries.")
        elif r.check_id == "long_functions":
            hints.append(f"- **{r.name}**: Split into smaller functions.")
        else:
            hints.append(f"- **{r.name}**: Review and address the finding above.")

    remediation_block = (
        "\n\n### 🔧 Recommended Remediation\n\n" + "\n".join(hints)
    )
    replacement = body.rstrip() + remediation_block
    return (
        False,
        "Review lacked remediation guidance — appended recommended actions.",
        replacement,
    )


def _law_no_empty_review(
    body: str, results: list[CheckResult]
) -> tuple[bool, str, Optional[str]]:
    """Hard law: a review body must not be empty or whitespace-only."""
    if not body or not body.strip():
        return False, "Review body is empty.", None
    return True, "Review body is non-empty.", None


def _law_severity_honesty(
    body: str, results: list[CheckResult]
) -> tuple[bool, str, Optional[str]]:
    """Hard law: review recommendation must match the worst severity.

    If any check has severity 'error' and is failing, the review must
    not say APPROVE.
    """
    has_error = any(not r.passed and r.severity == "error" for r in results)
    if has_error and "approve" in body.lower():
        return (
            False,
            "Review says APPROVE but has failing error-severity checks.",
            None,
        )
    return True, "Severity honesty maintained.", None


def _law_no_secret_leakage(
    body: str, results: list[CheckResult]
) -> tuple[bool, str, Optional[str]]:
    """Hard law: review body must not contain raw secrets from the diff.

    Scans for the same secret patterns used in the reviewer and redacts
    them if found in the review body.
    """
    secret_patterns = [
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}"),
        re.compile(r"xox[bpoa]-[0-9A-Za-z-]{10,48}"),
        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        re.compile(r"(api[_-]?key|secret[_-]?key)\s*[:=]\s*['\"][-A-Za-z0-9_/+=]{16,}['\"]", re.IGNORECASE),
    ]
    for pattern in secret_patterns:
        match = pattern.search(body)
        if match:
            redacted = pattern.sub("***REDACTED***", body)
            return (
                False,
                f"Review body contained a secret-like string ({match.group()[:20]}...). Redacted.",
                redacted,
            )
    return True, "No secret leakage in review body.", None


# ─── Default law registry ────────────────────────────────────

DEFAULT_LAWS: list[ConservationLaw] = [
    ConservationLaw(
        law_id="no-empty-review",
        description="Review body must not be empty.",
        evaluate=_law_no_empty_review,
        severity="hard",
    ),
    ConservationLaw(
        law_id="no-suppressed-findings",
        description="Review must not claim success while checks are failing.",
        evaluate=_law_no_suppressed_findings,
        severity="hard",
    ),
    ConservationLaw(
        law_id="severity-honesty",
        description="Recommendation must match worst failing severity.",
        evaluate=_law_severity_honesty,
        severity="hard",
    ),
    ConservationLaw(
        law_id="no-secret-leakage",
        description="Review body must not contain raw secrets from the diff.",
        evaluate=_law_no_secret_leakage,
        severity="hard",
    ),
    ConservationLaw(
        law_id="must-include-remediation",
        description="Failing checks must include actionable remediation.",
        evaluate=_law_must_include_remediation,
        severity="soft",
    ),
]


# ─── Conservation Enforcer ───────────────────────────────────

class ConservationEnforcer:
    """Enforces conservation laws on review payloads before posting.

    Usage::

        enforcer = ConservationEnforcer()
        result = enforcer.enforce(review_body, check_results)
        if result.verdict == Verdict.BLOCK:
            # Don't post — escalate
            ...
        elif result.was_modified:
            post(result.enforced_body)
        else:
            post(result.original_body)
    """

    def __init__(self, laws: Optional[list[ConservationLaw]] = None):
        self.laws = laws or list(DEFAULT_LAWS)

    def enforce(
        self,
        body: str,
        results: list[CheckResult],
    ) -> ConservationResult:
        """Run all conservation laws against a review body.

        Returns a :class:`ConservationResult` describing the verdict,
        any violations, and (if applicable) the transformed body.
        """
        violations: list[str] = []
        transforms: list[str] = []
        law_ids: list[str] = []
        current_body = body

        for law in self.laws:
            satisfied, message, replacement = law.check(current_body, results)
            law_ids.append(law.law_id)

            if satisfied:
                continue

            violations.append(f"[{law.law_id}] {message}")

            if law.severity == "hard":
                return ConservationResult(
                    verdict=Verdict.BLOCK,
                    original_body=body,
                    enforced_body=current_body,
                    violations=violations,
                    transforms_applied=transforms,
                    law_ids=law_ids,
                )

            # Soft law — apply transform
            if replacement is not None:
                current_body = replacement
                transforms.append(f"[{law.law_id}] {message}")
            else:
                # Soft law with no replacement — just log
                transforms.append(f"[{law.law_id}] {message}")

        # If we applied transforms but no hard law blocked, verdict is TRANSFORM
        if transforms:
            return ConservationResult(
                verdict=Verdict.TRANSFORM,
                original_body=body,
                enforced_body=current_body,
                violations=violations,
                transforms_applied=transforms,
                law_ids=law_ids,
            )

        return ConservationResult(
            verdict=Verdict.PASS,
            original_body=body,
            enforced_body=body,
            violations=[],
            transforms_applied=[],
            law_ids=law_ids,
        )


# ─── Metrics ─────────────────────────────────────────────────

@dataclass
class EnforcerMetrics:
    """Tracks enforcement outcomes over time."""
    total_reviews: int = 0
    passed: int = 0
    transformed: int = 0
    blocked: int = 0
    deferred: int = 0
    violations_by_law: dict[str, int] = field(default_factory=dict)
    transforms_by_law: dict[str, int] = field(default_factory=dict)
    _history: deque = field(default_factory=lambda: deque(maxlen=500))

    def record(self, result: ConservationResult) -> None:
        self.total_reviews += 1
        self._history.append({
            "ts": result.ts,
            "verdict": result.verdict.value,
            "violations": len(result.violations),
            "transforms": len(result.transforms_applied),
        })
        for v in result.violations:
            law_id = v.split("]")[0].lstrip("[")
            self.violations_by_law[law_id] = self.violations_by_law.get(law_id, 0) + 1
        for t in result.transforms_applied:
            law_id = t.split("]")[0].lstrip("[")
            self.transforms_by_law[law_id] = self.transforms_by_law.get(law_id, 0) + 1

        if result.verdict == Verdict.PASS:
            self.passed += 1
        elif result.verdict == Verdict.TRANSFORM:
            self.transformed += 1
        elif result.verdict == Verdict.BLOCK:
            self.blocked += 1
        elif result.verdict == Verdict.DEFER:
            self.deferred += 1

    @property
    def block_rate(self) -> float:
        return self.blocked / max(self.total_reviews, 1)

    @property
    def transform_rate(self) -> float:
        return self.transformed / max(self.total_reviews, 1)

    def summary(self) -> dict[str, Any]:
        return {
            "total_reviews": self.total_reviews,
            "passed": self.passed,
            "transformed": self.transformed,
            "blocked": self.blocked,
            "deferred": self.deferred,
            "block_rate": round(self.block_rate, 4),
            "transform_rate": round(self.transform_rate, 4),
            "violations_by_law": dict(self.violations_by_law),
            "transforms_by_law": dict(self.transforms_by_law),
        }


# ─── Enforced Review Room ────────────────────────────────────

class EnforcedReviewRoom(CodeReviewRoom):
    """A Code Review Room that pipes all review output through a
    ConservationEnforcer before posting to GitHub.

    This is the primary integration point between the PLATO room
    governance layer and the Conservation Enforcer meta-governance
    layer.

    Additional sensors:

        enforcer_state — counts of blocked / transformed / passed reviews

    Additional alarms:

        enforcer_block_spike — fires when block rate exceeds 25% in
        the last 20 reviews, suggesting a systemic issue with review
        quality.

    Usage::

        gh = GitHubClient(token)
        room = EnforcedReviewRoom(gh, "owner", "repo", pr_number=42)
        room.serve()  # or room.tick()
    """

    room_id = "enforced-code-review-room"

    def __init__(
        self,
        github_client: GitHubClient,
        owner: str,
        repo: str,
        pr_number: int = 0,
        host: str = "0.0.0.0",
        port: int = 1234,
        enforcer: Optional[ConservationEnforcer] = None,
        custom_laws: Optional[list[ConservationLaw]] = None,
    ):
        if enforcer is None:
            enforcer = ConservationEnforcer(
                laws=custom_laws or list(DEFAULT_LAWS)
            )
        self.enforcer = enforcer
        self.metrics = EnforcerMetrics()
        self._last_enforcement: Optional[ConservationResult] = None
        super().__init__(github_client, owner, repo, pr_number, host, port)

    def setup(self) -> None:
        """Register base sensors/actuators/alarms, then add enforcer ones."""
        super().setup()

        # ── Enforcer sensor ──────────────────────────────────
        self.register_sensor("enforcer_state", _sensor_enforcer_state)

        # ── Enforcer alarm ───────────────────────────────────
        self.register_alarm(
            "enforcer_block_spike",
            sensor="enforcer_block_rate",
            operator=">",
            threshold=0.25,
            cooldown_sec=600,
        )

    def _enforce_before_post(
        self, body: str, results: list[CheckResult]
    ) -> ConservationResult:
        """Run the enforcer on a review body and record metrics.

        If the verdict is BLOCK, the review is not posted and an
        escalation comment is posted instead.  If TRANSFORM, the
        enforced body replaces the original.
        """
        result = self.enforcer.enforce(body, results)
        self.metrics.record(result)
        self._last_enforcement = result

        if result.verdict == Verdict.BLOCK:
            logger.warning(
                "Review BLOCKED by enforcer: %s", result.violations
            )
            # Post an escalation notice instead of the suppressed review
            escalation = (
                "## ⚠️ Review Escalated by Conservation Enforcer\n\n"
                "The automated review was blocked from posting because it "
                "violated one or more conservation laws:\n\n"
                + "\n".join(f"- {v}" for v in result.violations)
                + "\n\nA human reviewer should inspect this PR manually."
            )
            self.gh.post_review(
                self.owner, self.repo, self.pr_number,
                escalation, "COMMENT",
            )
        elif result.verdict == Verdict.TRANSFORM and result.was_modified:
            logger.info(
                "Review TRANSFORMED by enforcer: %s",
                result.transforms_applied,
            )

        return result

    def post_enforced_review(
        self,
        results: list[CheckResult],
        event: str = "COMMENT",
    ) -> ConservationResult | None:
        """Generate, enforce, and post a review in one call.

        This is the main entry point for enforced reviews.  It:
        1. Generates a report from check results.
        2. Runs the conservation enforcer on the report.
        3. Posts the enforced (or escalation) body to GitHub.
        4. Records metrics.

        Returns the ConservationResult, or None if no PR is configured.
        """
        if not self.pr_number:
            return None

        body = generate_report(
            results,
            repo=f"{self.owner}/{self.repo}",
            pr_number=self.pr_number,
        )
        result = self._enforce_before_post(body, results)

        if result.verdict == Verdict.BLOCK:
            return result  # escalation already posted in _enforce_before_post

        # Post the (possibly transformed) body
        post_body = result.enforced_body if result.was_modified else result.original_body
        self.gh.post_review(self.owner, self.repo, self.pr_number, post_body, event)
        return result

    def _on_alarm(self, alarm, data, ts):
        """Extended alarm handler — routes enforcer alarms separately."""
        if alarm.alarm_id == "enforcer_block_spike":
            logger.error(
                "Enforcer block spike! Rate=%.1f%% (threshold=25%%)",
                data.get("enforcer_block_rate", 0) * 100,
            )
            self.actuate("apply_label", 4.0)  # security-review label
            return
        super()._on_alarm(alarm, data, ts)


# ─── Sensor functions ────────────────────────────────────────

def _sensor_enforcer_state(room: EnforcedReviewRoom) -> dict[str, float]:
    """Expose enforcer metrics as sensor values."""
    m = room.metrics
    recent = list(m._history)[-20:]
    recent_blocks = sum(1 for r in recent if r["verdict"] == "block")
    block_rate = recent_blocks / max(len(recent), 1)
    return {
        "enforcer_total": float(m.total_reviews),
        "enforcer_passed": float(m.passed),
        "enforcer_transformed": float(m.transformed),
        "enforcer_blocked": float(m.blocked),
        "enforcer_block_rate": block_rate,
    }
