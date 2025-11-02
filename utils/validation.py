"""
Input validation utilities
"""

import re


def validate_email(email: str) -> bool:
    """
    Validate email format using RFC 5322 compliant regex

    Args:
        email: Email address to validate

    Returns:
        bool: True if email format is valid
    """
    if not email or not isinstance(email, str):
        return False

    # RFC 5322 compliant email regex (simplified)
    # Allows most valid email formats while preventing common invalid ones
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    # Check basic format
    if not re.match(email_pattern, email):
        return False

    # Additional checks
    if len(email) > 254:  # RFC 5321 max email length
        return False

    # Check for consecutive dots
    if ".." in email:
        return False

    # Check for leading/trailing dots in local or domain part
    local, domain = email.rsplit("@", 1)
    if local.startswith(".") or local.endswith("."):
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False

    return True
