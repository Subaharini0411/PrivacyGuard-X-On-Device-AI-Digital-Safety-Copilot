"""
PrivacyGuard X - Security & Zero-Knowledge Enforcement
Enforces permission checks, safe clipboard operations, and zero-knowledge scrubbing.
"""

from typing import Dict, Any, Optional
from database.database import get_permissions, get_setting


def check_permission(permission_key: str) -> bool:
    """Verifies if a specific permission is granted by the user."""
    perms = get_permissions()
    for p in perms:
        if p["permission_key"] == permission_key:
            return bool(p["granted"])
    return False


def get_clipboard_text_safely() -> Optional[str]:
    """
    Safely retrieves clipboard content if clipboard permission is granted.
    Never accesses clipboard without user permission.
    """
    if not check_permission("clipboard"):
        return None

    try:
        # Standard cross-platform or Windows clipboard reading
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()
        clipboard_content = root.clipboard_get()
        root.destroy()
        return clipboard_content
    except Exception:
        # If tkinter or clipboard access is unavailable
        return None
