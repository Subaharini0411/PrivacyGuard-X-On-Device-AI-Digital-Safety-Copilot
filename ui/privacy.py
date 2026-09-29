"""
PrivacyGuard X - Privacy Center Page
Transparency, user permissions, zero-knowledge architecture, and local data destruction controls.
"""

import streamlit as st
from database.database import (
    get_setting, set_setting, get_permissions, set_permission,
    clear_all_scans, get_metrics
)
from utils.file_utils import clear_temp_directory, generate_audit_report_json


def render_privacy_center():
    """Renders the Privacy Center page."""
    st.markdown("## 🛡️ Privacy Center")
    st.caption("Inspect and govern your on-device data sovereignty, permissions, and zero-knowledge posture.")

    # Top Status Banner
    local_only = get_setting("local_processing_only", "true") == "true"
    st.markdown(f"""
    <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.4); border-radius: 10px; padding: 18px 22px; margin-bottom: 24px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h3 style="margin: 0; color: #10b981;">🔒 Zero-Knowledge Privacy Architecture</h3>
                <p style="margin: 6px 0 0 0; color: #94a3b8; font-size: 0.92rem;">
                    PrivacyGuard X never stores raw passwords, API keys, or decrypted documents. Only anonymized metadata is held locally on your device.
                </p>
            </div>
            <div>
                <span class="risk-badge-clean">LOCAL ONLY</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Section 1: Processing Mode & Data Retention
    st.subheader("⚙️ Processing Mode & Data Retention")
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Processing Mode Selection**")
        mode_val = st.radio(
            "Select AI execution boundary:",
            ["Strictly Local (On-Device Snapdragon Execution)", "Hybrid (Permit Optional Connectivity Checks)"],
            index=0 if local_only else 1,
            key="rad_privacy_mode"
        )
        is_strict = "Strictly Local" in mode_val
        set_setting("local_processing_only", "true" if is_strict else "false")
        if is_strict:
            st.success("All scans run strictly inside local device memory.")
        else:
            st.warning("Permits optional non-invasive external HEAD requests for URL reachability tests.")

    with col2:
        st.markdown("**Data Retention Rules**")
        st.markdown("""
        - **Uploaded Files:** Stored only in RAM during active analysis; flushed immediately on session end.
        - **Raw Sensitive Secrets:** **NEVER PERSISTED**. Database stores only masked fragments (e.g. `sk-...890`).
        - **Telemetry / Tracking:** Completely disabled. No phone-home beacons or cloud analytics.
        """)

    st.write("")
    st.markdown("---")

    # Section 2: Permission Controls
    st.subheader("🔑 Application Permission Management")
    st.write("PrivacyGuard X honors explicit user permissions before touching any local resources.")

    permissions = get_permissions()
    for p in permissions:
        p_col1, p_col2 = st.columns([3, 1])
        with p_col1:
            st.markdown(f"**{p['permission_key'].replace('_', ' ').title()}**")
            st.caption(f"{p['description']} (Updated: {p['last_updated'][:10]})")
        with p_col2:
            is_granted = bool(p['granted'])
            new_val = st.toggle("Granted", value=is_granted, key=f"perm_toggle_{p['permission_key']}")
            if new_val != is_granted:
                set_permission(p['permission_key'], new_val)
                st.rerun()

    st.write("")
    st.markdown("---")

    # Section 3: Data Destruction & Audit Export
    st.subheader("🧹 User-Controlled Data Erasure")

    d_col1, d_col2, d_col3 = st.columns(3)

    with d_col1:
        if st.button("🗑️ Clear All Scan History", type="secondary", use_container_width=True):
            clear_all_scans()
            st.success("All local scan history and audit entries wiped!")
            st.rerun()

    with d_col2:
        if st.button("🧼 Clear Temporary Files", type="secondary", use_container_width=True):
            cleaned = clear_temp_directory()
            st.success(f"Cleared {cleaned} temporary files from local storage.")

    with d_col3:
        metrics = get_metrics()
        report_json = generate_audit_report_json({
            "scan_id": "GLOBAL-PRIVACY-EXPORT",
            "file_name": "Full Privacy Audit Export",
            "file_type": "audit_snapshot",
            "risk_score": 0,
            "risk_level": "CLEAN",
            "action_taken": "Privacy Center Export",
            "findings_count": metrics["total_findings"],
            "reasons": ["User requested global privacy audit report export."],
            "findings": []
        })
        st.download_button(
            label="📄 Export Privacy Report (JSON)",
            data=report_json,
            file_name="privacyguard_audit_export.json",
            mime="application/json",
            use_container_width=True
        )
