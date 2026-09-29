"""
PrivacyGuard X - Database Layer
Thread-safe SQLite storage for scan metadata, metrics, and user preferences.
Zero retention of raw sensitive payloads ensures zero-knowledge privacy architecture.
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_PATH = os.path.join(DB_DIR, "privacyguard.db")


def get_db_connection() -> sqlite3.Connection:
    """Creates directory if needed and returns SQLite connection."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes tables for scans and user configuration settings."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT UNIQUE NOT NULL,
        timestamp DATETIME NOT NULL,
        file_name TEXT NOT NULL,
        file_type TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        findings_count INTEGER DEFAULT 0,
        high_risk_count INTEGER DEFAULT 0,
        med_risk_count INTEGER DEFAULT 0,
        low_risk_count INTEGER DEFAULT 0,
        risk_score INTEGER DEFAULT 0,
        risk_level TEXT NOT NULL,
        action_taken TEXT DEFAULT 'Reviewed',
        summary_reasons TEXT DEFAULT '',
        details_json TEXT DEFAULT '[]'
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS permissions (
        permission_key TEXT PRIMARY KEY,
        granted INTEGER DEFAULT 0,
        description TEXT NOT NULL,
        last_updated DATETIME NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        full_name TEXT DEFAULT '',
        created_at DATETIME NOT NULL
    )
    """)

    # Seed default settings if empty
    default_settings = {
        "dark_mode": "true",
        "local_processing_only": "true",
        "scan_sensitivity": "Balanced",  # Strict, Balanced, Permissive
        "auto_mask_preview": "true",
        "history_retention_days": "30",
        "telemetry_enabled": "false",
        "snapdragon_npu_acceleration": "auto"
    }

    for key, val in default_settings.items():
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, val))

    # Seed default permissions
    default_permissions = [
        ("file_system", 1, "Local file reading and sanitized copy exports", datetime.now().isoformat()),
        ("clipboard", 1, "Reading clipboard text on user demand", datetime.now().isoformat()),
        ("camera_screenshots", 0, "Direct screen capture ingestion", datetime.now().isoformat()),
        ("network_url_check", 1, "Non-invasive safe URL reachability checks", datetime.now().isoformat()),
    ]

    for p_key, granted, desc, updated in default_permissions:
        cursor.execute("""
            INSERT OR IGNORE INTO permissions (permission_key, granted, description, last_updated)
            VALUES (?, ?, ?, ?)
        """, (p_key, granted, desc, updated))

    conn.commit()
    conn.close()


def save_scan(scan_data: Dict[str, Any]) -> str:
    """Saves scan record metadata and returns scan_id."""
    conn = get_db_connection()
    cursor = conn.cursor()

    scan_id = scan_data.get("scan_id", f"SCN-{datetime.now().strftime('%Y%m%d%H%M%S%f')[:17]}")
    timestamp = scan_data.get("timestamp", datetime.now().isoformat())
    file_name = scan_data.get("file_name", "Unknown")
    file_type = scan_data.get("file_type", "text")
    scan_type = scan_data.get("scan_type", "Quick Scan")
    findings_count = int(scan_data.get("findings_count", 0))
    high_risk_count = int(scan_data.get("high_risk_count", 0))
    med_risk_count = int(scan_data.get("med_risk_count", 0))
    low_risk_count = int(scan_data.get("low_risk_count", 0))
    risk_score = int(scan_data.get("risk_score", 0))
    risk_level = scan_data.get("risk_level", "LOW")
    action_taken = scan_data.get("action_taken", "Reviewed")
    summary_reasons = scan_data.get("summary_reasons", "")
    
    # Store sanitized metadata (never raw credentials)
    details = scan_data.get("details_json", [])
    if isinstance(details, (list, dict)):
        details_str = json.dumps(details)
    else:
        details_str = str(details)

    cursor.execute("""
        INSERT INTO scans (
            scan_id, timestamp, file_name, file_type, scan_type,
            findings_count, high_risk_count, med_risk_count, low_risk_count,
            risk_score, risk_level, action_taken, summary_reasons, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id, timestamp, file_name, file_type, scan_type,
        findings_count, high_risk_count, med_risk_count, low_risk_count,
        risk_score, risk_level, action_taken, summary_reasons, details_str
    ))

    conn.commit()
    conn.close()
    return scan_id


def update_scan_action(scan_id: str, action: str):
    """Updates the action taken for a specific scan."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE scans SET action_taken = ? WHERE scan_id = ?", (action, scan_id))
    conn.commit()
    conn.close()


def get_recent_scans(limit: int = 15) -> List[Dict[str, Any]]:
    """Retrieves recent scans ordered by timestamp descending."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    result = [dict(row) for row in rows]
    conn.close()
    return result


def get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single scan by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def delete_scan(scan_id: str) -> bool:
    """Deletes a single scan record."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def clear_all_scans():
    """Wipes all scan history."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans")
    conn.commit()
    conn.close()


def get_metrics() -> Dict[str, Any]:
    """Computes real metrics from the scans table."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT SUM(findings_count), SUM(high_risk_count), SUM(med_risk_count), SUM(low_risk_count) FROM scans")
    row = cursor.fetchone()
    total_findings = row[0] or 0
    high_risks = row[1] or 0
    med_risks = row[2] or 0
    low_risks = row[3] or 0

    cursor.execute("SELECT COUNT(*) FROM scans WHERE action_taken IN ('Masked', 'Blurred', 'Protected Export', 'Safe Copied')")
    protected_items = cursor.fetchone()[0]

    # Scans by file_type
    cursor.execute("SELECT file_type, COUNT(*) FROM scans GROUP BY file_type")
    scans_by_type = {r[0]: r[1] for r in cursor.fetchall()}

    # Scans by risk_level
    cursor.execute("SELECT risk_level, COUNT(*) FROM scans GROUP BY risk_level")
    scans_by_risk = {r[0]: r[1] for r in cursor.fetchall()}

    # Findings category breakdown from details_json
    cursor.execute("SELECT details_json FROM scans WHERE findings_count > 0")
    details_rows = cursor.fetchall()
    category_counts: Dict[str, int] = {}
    for d_row in details_rows:
        try:
            items = json.loads(d_row[0])
            if isinstance(items, list):
                for item in items:
                    cat = item.get("category", "Other")
                    category_counts[cat] = category_counts.get(cat, 0) + 1
        except Exception:
            pass

    conn.close()

    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "high_risk_findings": high_risks,
        "medium_risk_findings": med_risks,
        "low_risk_findings": low_risks,
        "protected_items": protected_items,
        "scans_by_type": scans_by_type,
        "scans_by_risk": scans_by_risk,
        "category_counts": category_counts
    }


def get_setting(key: str, default: str = "") -> str:
    """Retrieves a configuration setting."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else default


def set_setting(key: str, value: str):
    """Sets a configuration setting."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()
    conn.close()


def get_all_settings() -> Dict[str, str]:
    """Retrieves all settings as a key-value dictionary."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM settings")
    settings = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()
    return settings


def get_permissions() -> List[Dict[str, Any]]:
    """Retrieves all system permission states."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM permissions")
    rows = cursor.fetchall()
    perms = [dict(r) for r in rows]
    conn.close()
    return perms


def set_permission(permission_key: str, granted: bool):
    """Toggles a permission state."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE permissions
        SET granted = ?, last_updated = ?
        WHERE permission_key = ?
    """, (1 if granted else 0, datetime.now().isoformat(), permission_key))
    conn.commit()
    conn.close()


# ==========================================
# USER AUTHENTICATION & ACCOUNT SYSTEM
# ==========================================
import hashlib
import secrets
from typing import Tuple


def hash_password(password: str, salt_hex: Optional[str] = None) -> Tuple[str, str]:
    """Hashes a password with PBKDF2 HMAC SHA-256 and unique salt."""
    if salt_hex is None:
        salt_bytes = secrets.token_bytes(16)
        salt_hex = salt_bytes.hex()
    else:
        salt_bytes = bytes.fromhex(salt_hex)

    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt_bytes,
        100_000
    ).hex()
    return pwd_hash, salt_hex


def verify_password(password: str, salt_hex: str, expected_hash: str) -> bool:
    """Verifies a plain password against the stored salt and hash."""
    calc_hash, _ = hash_password(password, salt_hex)
    return secrets.compare_digest(calc_hash, expected_hash)


def create_user(username: str, email: str, password: str, full_name: str = "") -> Tuple[bool, str]:
    """Registers a new user account with validated constraints."""
    username = username.strip().lower()
    email = email.strip().lower()

    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters long."
    if not email or "@" not in email or "." not in email:
        return False, "Please provide a valid email address."
    if not password or len(password) < 6:
        return False, "Password must be at least 6 characters long."

    pwd_hash, salt_hex = hash_password(password)
    now_iso = datetime.now().isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, salt, full_name, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username, email, pwd_hash, salt_hex, full_name.strip(), now_iso))
        conn.commit()
        conn.close()
        return True, "Account created successfully! You can now log in."
    except sqlite3.IntegrityError as e:
        conn.close()
        err_msg = str(e).lower()
        if "username" in err_msg:
            return False, "Username is already taken. Please choose another."
        elif "email" in err_msg:
            return False, "An account with this email already exists. Please log in."
        return False, "User with these credentials already exists."
    except Exception as e:
        conn.close()
        return False, f"Failed to register user: {str(e)}"


def authenticate_user(username_or_email: str, password: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """Authenticates a user via username or email."""
    identifier = username_or_email.strip().lower()
    if not identifier or not password:
        return False, None, "Please provide both identifier and password."

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM users WHERE username = ? OR email = ?
    """, (identifier, identifier))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return False, None, "Invalid username or password."

    user_dict = dict(row)
    if verify_password(password, user_dict["salt"], user_dict["password_hash"]):
        # Do not leak hash and salt
        safe_user = {
            "id": user_dict["id"],
            "username": user_dict["username"],
            "email": user_dict["email"],
            "full_name": user_dict["full_name"],
            "created_at": user_dict["created_at"]
        }
        return True, safe_user, "Authentication successful."
    else:
        return False, None, "Invalid username or password."


# Auto-initialize database on import
init_db()
