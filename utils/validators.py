"""
PrivacyGuard X - Input Validators
Enforces safe boundary constraints on inputs to prevent crashes and denial of service.
"""

import re
from typing import Tuple, Optional

MAX_TEXT_LENGTH = 1_000_000  # 1 MB of characters
MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024  # 25 MB


def validate_text_input(text: Optional[str]) -> Tuple[bool, str]:
    """Validates raw text input."""
    if text is None or not text.strip():
        return False, "Input text is empty. Please enter or paste content to analyze."
    if len(text) > MAX_TEXT_LENGTH:
        return False, f"Input is too large ({len(text):,} chars). Maximum limit is {MAX_TEXT_LENGTH:,} characters."
    return True, ""


def validate_file_size(size_bytes: int) -> Tuple[bool, str]:
    """Validates uploaded file size."""
    if size_bytes <= 0:
        return False, "File appears to be empty (0 bytes)."
    if size_bytes > MAX_FILE_SIZE_BYTES:
        mb_size = size_bytes / (1024 * 1024)
        return False, f"File exceeds maximum allowed size ({mb_size:.1f} MB > 25 MB). Please select a smaller file."
    return True, ""


def validate_url_syntax(url_str: str) -> Tuple[bool, str]:
    """Validates basic URL syntax."""
    if not url_str or not url_str.strip():
        return False, "URL cannot be blank."
    url_clean = url_str.strip()
    if len(url_clean) > 2048:
        return False, "URL exceeds the maximum acceptable length of 2048 characters."
    return True, ""
