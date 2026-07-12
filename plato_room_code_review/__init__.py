"""
PLATO Room Code Review — package init.
"""

# Support both package-relative and standalone imports
try:
    from .room import CodeReviewRoom, BaseRoom
    from .reviewer import run_all_checks, CheckResult
    from .github_client import GitHubClient
except ImportError:
    from room import CodeReviewRoom, BaseRoom
    from reviewer import run_all_checks, CheckResult
    from github_client import GitHubClient

__version__ = "0.1.0"
__all__ = [
    "CodeReviewRoom",
    "BaseRoom",
    "run_all_checks",
    "CheckResult",
    "GitHubClient",
]
