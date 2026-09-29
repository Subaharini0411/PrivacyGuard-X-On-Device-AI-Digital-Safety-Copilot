"""
PrivacyGuard X — On-Device AI Digital Safety Copilot
Production Prototype designed for Snapdragon-powered HP PCs.
Zero Cloud Egress | Local On-Device AI | Explainable Risk Engine
"""

import sys
import os

# Ensure project root is in Python sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st
from database.database import init_db, get_setting
from ui.styles import get_custom_css
from ui.dashboard import render_dashboard
from ui.scanner import render_scanner
from ui.safe_share_ui import render_safe_share
from ui.snapdragon import render_snapdragon_page
from ui.privacy import render_privacy_center
from ui.reports import render_reports
from ui.history import render_history
from ui.settings import render_settings
from ui.guidelines import render_guidelines
from ui.challenge import render_challenge


def main():
    # Streamlit page setup
    st.set_page_config(
        page_title="PrivacyGuard X — On-Device AI Digital Safety Copilot",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Initialize Database tables if not already present
    init_db()

    # Load UI preferences
    dark_mode = get_setting("dark_mode", "true") == "true"
    st.markdown(get_custom_css(dark_mode=dark_mode), unsafe_allow_html=True)

    # Sidebar Navigation
    with st.sidebar:
        st.markdown("""
        <div style="padding: 10px 0 16px 0; border-bottom: 1px solid #243247; margin-bottom: 16px;">
            <div style="font-size: 1.5rem; font-weight: 800; letter-spacing: -0.02em;">
                🛡️ PrivacyGuard <span style="color: #ff2a5f;">X</span>
            </div>
            <div style="font-size: 0.8rem; color: #94a3b8; font-weight: 500;">
                On-Device AI Digital Safety Copilot
            </div>
            <div style="margin-top: 8px;">
                <span class="snapdragon-badge">⚡ Snapdragon X Elite NPU</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        pages = [
            "Dashboard",
            "Scan Center",
            "Safe Share",
            "Built for Snapdragon",
            "Privacy Center",
            "Reports & Analytics",
            "Scan History",
            "Challenge Overview",
            "Security & AI Guidelines",
            "Settings"
        ]

        if "current_page" not in st.session_state:
            st.session_state.current_page = "Dashboard"

        current_idx = pages.index(st.session_state.current_page) if st.session_state.current_page in pages else 0

        selected_page = st.radio(
            "Navigation",
            options=pages,
            index=current_idx,
            label_visibility="collapsed",
            key="nav_radio"
        )

        if selected_page != st.session_state.current_page:
            st.session_state.current_page = selected_page
            st.rerun()

        st.markdown("---")
        st.caption("⚡ **Target Snapdragon Deployment**")
        st.caption("🔒 **Zero Cloud Egress Active**")
        st.caption("HP PC AI Innovation Edition 2026")

    # Safe execution with graceful error boundary (No raw stack traces)
    try:
        active_page = st.session_state.current_page

        if active_page == "Dashboard":
            render_dashboard()
        elif active_page == "Scan Center":
            render_scanner()
        elif active_page == "Safe Share":
            render_safe_share()
        elif active_page == "Built for Snapdragon":
            render_snapdragon_page()
        elif active_page == "Privacy Center":
            render_privacy_center()
        elif active_page == "Reports & Analytics":
            render_reports()
        elif active_page == "Scan History":
            render_history()
        elif active_page == "Challenge Overview":
            render_challenge()
        elif active_page == "Security & AI Guidelines":
            render_guidelines()
        elif active_page == "Settings":
            render_settings()
        else:
            render_dashboard()

    except Exception as e:
        st.markdown("""
        <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid #ef4444; border-radius: 10px; padding: 20px; margin: 20px 0;">
            <h3 style="color: #ef4444; margin: 0 0 8px 0;">⚠️ An unexpected error occurred while processing</h3>
            <p style="color: #fca5a5; margin: 0; font-size: 0.95rem;">
                PrivacyGuard X caught an error and prevented an unhandled crash. No user data was compromised.
            </p>
        </div>
        """, unsafe_allow_html=True)
        st.info(f"Details: {type(e).__name__} — {str(e)}")
        if st.button("🔄 Reload Dashboard"):
            st.session_state.current_page = "Dashboard"
            st.rerun()


if __name__ == "__main__":
    main()
