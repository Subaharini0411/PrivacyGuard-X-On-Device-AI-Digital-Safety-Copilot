"""
PrivacyGuard X - Settings Page
Configurable operational preferences persisted in SQLite.
Every setting actively governs application runtime behavior.
"""

import streamlit as st
from database.database import (
    get_setting, set_setting, get_all_settings, clear_all_scans
)


def render_settings():
    """Renders the settings configuration page."""
    st.markdown("## ⚙️ Settings & Configuration")
    st.caption("Customize scan heuristics, privacy thresholds, and UI theme. All settings persist locally.")

    # Section 1: Appearance & Theme
    st.subheader("🎨 Appearance")
    dark_mode_val = get_setting("dark_mode", "true") == "true"
    new_theme = st.toggle("Dark Obsidian Theme (Snapdragon / HP PC Optimized)", value=dark_mode_val, key="toggle_dark_theme")
    if new_theme != dark_mode_val:
        set_setting("dark_mode", "true" if new_theme else "false")
        st.success("Theme preference saved. Refresh to apply changes.")
        st.rerun()

    st.write("")
    st.markdown("---")

    # Section 2: AI & Processing Bounds
    st.subheader("🧠 On-Device AI & Processing")
    local_val = get_setting("local_processing_only", "true") == "true"
    new_local = st.toggle(
        "Enforce Strictly Local On-Device AI (Zero Cloud Egress)",
        value=local_val,
        help="When enabled, blocks all non-local connections and ensures 100% processing on Snapdragon hardware.",
        key="toggle_local_proc"
    )
    if new_local != local_val:
        set_setting("local_processing_only", "true" if new_local else "false")
        st.success("Local processing preference updated.")
        st.rerun()

    # Section 3: Detection Sensitivity
    st.subheader("🎯 Risk Engine Sensitivity")
    current_sens = get_setting("scan_sensitivity", "Balanced")
    sens_options = ["Strict", "Balanced", "Permissive"]
    sens_index = sens_options.index(current_sens) if current_sens in sens_options else 1

    selected_sens = st.select_slider(
        "Detection Sensitivity Level:",
        options=sens_options,
        value=sens_options[sens_index],
        help="Strict: flags all suspicious entropy and informational patterns (+25% weight). Balanced: calibrated defaults. Permissive: credentials and verified cards only.",
        key="slider_sensitivity"
    )
    if selected_sens != current_sens:
        set_setting("scan_sensitivity", selected_sens)
        st.success(f"Scan sensitivity adjusted to '{selected_sens}'.")
        st.rerun()

    # Section 4: Auto-Masking Preferences
    st.subheader("🛡️ Protection & Masking")
    auto_mask_val = get_setting("auto_mask_preview", "true") == "true"
    new_auto_mask = st.toggle(
        "Enable Automatic Masking in Previews & Safe Share",
        value=auto_mask_val,
        help="Automatically obscures detected secrets and PII in preview widgets.",
        key="toggle_auto_mask"
    )
    if new_auto_mask != auto_mask_val:
        set_setting("auto_mask_preview", "true" if new_auto_mask else "false")
        st.success("Auto-masking preference saved.")
        st.rerun()

    # Section 5: History Retention Policy
    st.subheader("🕒 Audit History Retention")
    retention_options = ["7 Days", "30 Days", "90 Days", "Keep Indefinitely"]
    current_ret = get_setting("history_retention_days", "30")
    ret_map = {"7": "7 Days", "30": "30 Days", "90": "90 Days", "0": "Keep Indefinitely"}
    rev_ret_map = {"7 Days": "7", "30 Days": "30", "90 Days": "90", "Keep Indefinitely": "0"}

    curr_ret_label = ret_map.get(current_ret, "30 Days")
    sel_ret_label = st.selectbox(
        "Purge audit history records older than:",
        options=retention_options,
        index=retention_options.index(curr_ret_label) if curr_ret_label in retention_options else 1,
        key="select_history_retention"
    )
    if rev_ret_map[sel_ret_label] != current_ret:
        set_setting("history_retention_days", rev_ret_map[sel_ret_label])
        st.success(f"History retention set to {sel_ret_label}.")
        st.rerun()

    if st.button("🗑️ Purge All History Now", key="btn_purge_hist_settings"):
        clear_all_scans()
        st.success("History database wiped cleanly.")
        st.rerun()

    st.write("")
    st.markdown("---")

    # Section 6: About PrivacyGuard X
    st.subheader("ℹ️ About PrivacyGuard X")
    st.markdown("""
    - **Product:** PrivacyGuard X — On-Device AI Digital Safety Copilot
    - **Version:** `1.0.0-production-prototype`
    - **Target Platform:** HP Laptops powered by Qualcomm Snapdragon X Elite / Plus
    - **Engine:** Qualcomm AI Hub Optimized On-Device Risk Architecture
    - **License:** Open Source MIT
    - **Design Principle:** *Detect → Understand → Explain → Risk Score → User Decision → Protect*
    """)
