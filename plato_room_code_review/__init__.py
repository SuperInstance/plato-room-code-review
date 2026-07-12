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

__version__ = "0.2.0"
__all__ = [
    "CodeReviewRoom",
    "BaseRoom",
    "run_all_checks",
    "CheckResult",
    "GitHubClient",
    "generate_report",
    "generate_short_summary",
]
