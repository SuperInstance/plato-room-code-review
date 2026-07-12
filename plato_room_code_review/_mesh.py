"""
Mesh registration for PLATO plugin discovery.
"""

def register(registry):
    """Register the code review room with the PLATO mesh."""
    from .room import CodeReviewRoom

    registry.register("rooms", "code_review", lambda: CodeReviewRoom)
