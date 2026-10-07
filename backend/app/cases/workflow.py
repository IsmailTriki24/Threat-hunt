"""Case state machine. Pure and exhaustively tested; the API never sets `status` any other way."""

from app.core.errors import AppError

STATUSES = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE", "CLOSED"]
TERMINAL_REQUIRES_RESOLUTION = {"RESOLVED", "FALSE_POSITIVE", "CLOSED"}
REOPEN_TARGETS = {"OPEN", "INVESTIGATING"}

TRANSITIONS: dict[str, set[str]] = {
    "OPEN": {"INVESTIGATING", "FALSE_POSITIVE", "CLOSED"},
    "INVESTIGATING": {"OPEN", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"},
    "CONTAINED": {"INVESTIGATING", "RESOLVED"},
    "RESOLVED": {"CLOSED", "INVESTIGATING"},
    "FALSE_POSITIVE": {"CLOSED", "OPEN"},
    "CLOSED": {"INVESTIGATING"},  # reopen
}


class InvalidTransition(AppError):
    status_code = 409
    code = "invalid_transition"


def check_transition(current: str, target: str, comment: str) -> None:
    if target == current:
        raise InvalidTransition(f"Case is already {current}")
    if target not in TRANSITIONS.get(current, set()):
        allowed = ", ".join(sorted(TRANSITIONS.get(current, set()))) or "none"
        raise InvalidTransition(f"Cannot move from {current} to {target} (allowed: {allowed})")
    if (target in TERMINAL_REQUIRES_RESOLUTION or current == "CLOSED") and not comment.strip():
        raise InvalidTransition(
            f"A resolution/comment is required to move to {target}"
            if current != "CLOSED"
            else "A comment is required to reopen a closed case"
        )


def is_locked(status: str) -> bool:
    """Closed cases accept no evidence/IOC/asset changes until reopened."""
    return status == "CLOSED"
