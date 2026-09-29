"""Database package for PrivacyGuard X."""
from .database import (
    init_db,
    save_scan,
    get_recent_scans,
    get_scan_by_id,
    delete_scan,
    clear_all_scans,
    get_metrics,
    get_setting,
    set_setting,
    get_all_settings,
    get_permissions,
    set_permission,
    update_scan_action,
    create_user,
    authenticate_user,
    hash_password,
    verify_password
)
