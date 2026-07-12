"""
PLATO Room Code Review — package init.
"""

# Support both package-relative and standalone imports
try:
    from .room import CodeReviewRoom, BaseRoom
    from .reviewer import run_all_checks, CheckResult
    from .github_client import GitHubClient
    from .report import generate_report, generate_short_summary
except ImportError:
    from room import CodeReviewRoom, BaseRoom
    from reviewer import run_all_checks, CheckResult
    from github_client import GitHubClient
    from report import generate_report, generate_short_summary

# Conservation Enforcer integration (optional — requires src/ layout)
try:
    from .enforcer_integration import (
        ConservationEnforcer,
        ConservationLaw,
        ConservationResult,
        EnforcerMetrics,
        EnforcedReviewRoom,
        Verdict,
    )
    _HAS_ENFORCER = True
except ImportError:
    _HAS_ENFORCER = False

__version__ = "0.3.0"
__all__ = [
    "CodeReviewRoom",
    "BaseRoom",
    "run_all_checks",
    "CheckResult",
    "GitHubClient",
    "generate_report",
    "generate_short_summary",
    # Enforcer integration
    "ConservationEnforcer",
    "ConservationLaw",
    "ConservationResult",
    "EnforcerMetrics",
    "EnforcedReviewRoom",
    "Verdict",
]
