"""
PrivacyGuard X - Dashboard Page
Main executive overview displaying metrics, system protection status,
quick launch buttons for all scan modalities, and recent scan audits.
"""

import streamlit as st
from database.database import get_metrics, get_recent_scans, get_setting
from ai.model_manager import SnapdragonModelManager


def render_dashboard():
    """Renders the executive dashboard page."""
    model_mgr = SnapdragonModelManager()
    metrics = get_metrics()
    recent_scans = get_recent_scans(limit=8)
    local_only = get_setting("local_processing_only", "true") == "true"

    # Hero Banner
    st.markdown("""
    <div class="brand-hero">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px;">
            <div>
                <h1 style="margin: 0; font-size: 2.2rem; font-weight: 800; letter-spacing: -0.03em;">
                    🛡️ PrivacyGuard <span style="color: #ff2a5f;">X</span>
                </h1>
                <p style="margin: 6px 0 0 0; font-size: 1.05rem; color: #94a3b8; font-weight: 500;">
                    Check before you share.
                </p>
                <div style="margin-top: 10px; display: flex; gap: 10px; flex-wrap: wrap;">
                    <span class="snapdragon-badge">⚡ Snapdragon X Elite NPU Optimized</span>
                    <span style="background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.4); padding: 3px 10px; border-radius: 6px; font-size: 0.78rem; font-weight: 600;">
                        🔒 Zero Cloud Egress (On-Device)
                    </span>
                </div>
            </div>
            <div style="text-align: right;">
                <span style="font-size: 0.8rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600;">Protection Status</span>
                <div style="font-size: 1.1rem; font-weight: 700; color: #10b981; display: flex; align-items: center; justify-content: flex-end; gap: 6px; margin-top: 2px;">
                    <span style="height: 10px; width: 10px; background-color: #10b981; border-radius: 50%; display: inline-block;"></span>
                    Active & Shielding
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Metric Cards Row
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #38bdf8;">{metrics['total_scans']:,}</div>
            <div class="metric-label">Total Scans</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #f59e0b;">{metrics['total_findings']:,}</div>
            <div class="metric-label">Risks Detected</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #ef4444;">{metrics['high_risk_findings']:,}</div>
            <div class="metric-label">High-Risk Findings</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #10b981;">{metrics['protected_items']:,}</div>
            <div class="metric-label">Protected Items</div>
        </div>
        """, unsafe_allow_html=True)

    st.write("")

    # Quick Launch Navigation Section
    st.subheader("⚡ Quick Launch Scanners")
    btn_cols = st.columns(7)

    with btn_cols[0]:
        if st.button("📷 Scan Image", use_container_width=True, key="btn_dash_img"):
            st.session_state.current_page = "Scan Center"
            st.session_state.scanner_tab = 0
            st.rerun()

    with btn_cols[1]:
        if st.button("📄 Document", use_container_width=True, key="btn_dash_doc"):
            st.session_state.current_page = "Scan Center"
            st.session_state.scanner_tab = 1
            st.rerun()

    with btn_cols[2]:
        if st.button("📝 Scan Text", use_container_width=True, key="btn_dash_txt"):
            st.session_state.current_page = "Scan Center"
            st.session_state.scanner_tab = 2
            st.rerun()

    with btn_cols[3]:
        if st.button("💻 Scan Code", use_container_width=True, key="btn_dash_code"):
            st.session_state.current_page = "Scan Center"
            st.session_state.scanner_tab = 3
            st.rerun()

    with btn_cols[4]:
        if st.button("🌐 Analyze URL", use_container_width=True, key="btn_dash_url"):
            st.session_state.current_page = "Scan Center"
            st.session_state.scanner_tab = 4
            st.rerun()

    with btn_cols[5]:
        if st.button("📊 View Reports", use_container_width=True, key="btn_dash_rep"):
            st.session_state.current_page = "Reports & Analytics"
            st.rerun()

    with btn_cols[6]:
        if st.button("⚙️ Settings", use_container_width=True, key="btn_dash_set"):
            st.session_state.current_page = "Settings"
            st.rerun()

    st.write("")
    st.markdown("---")

    # Protection Status & Snapdragon Telemetry Row
    status_col1, status_col2 = st.columns([1, 1])

    with status_col1:
        st.subheader("🛡️ Current Protection Status")
        st.markdown(f"""
        - **Inference Mode:** `{'Local On-Device (Zero Egress)' if local_only else 'Hybrid Mode'}`
        - **Hardware Tier:** `{model_mgr.host_info['hardware_tier']}`
        - **Active Accelerator:** `{model_mgr.host_info['current_mode']}`
        - **Qualcomm AI Hub Target:** `MobileNetV4-OCR + Llama-3.2-1B-Instruct (INT4 QNN)`
        - **Data Retention:** `Zero raw credentials persisted (Metadata only)`
        - **Network Transmission:** `Disabled for scans`
        """)

    with status_col2:
        st.subheader("🎯 Safe Share Fast Action")
        st.markdown(
            "Use **Safe Share Mode** for a high-priority pre-transmission check. "
            "Guarantees that files or snippets are thoroughly vetted and masked before sharing."
        )
        if st.button("🚀 Launch Safe Share Assistant", type="primary", use_container_width=True):
            st.session_state.current_page = "Safe Share"
            st.rerun()

    st.write("")
    st.markdown("---")

    # Recent Scans Table
    st.subheader("🕒 Recent Scan Activity")
    if not recent_scans:
        st.info("No scan history yet. Try scanning an image, document, text snippet, or code file above!")
    else:
        # Render clean interactive table
        table_rows = []
        for s in recent_scans:
            table_rows.append({
                "Date / Time": s["timestamp"][:19].replace("T", " "),
                "Target / File": s["file_name"],
                "Type": s["file_type"].upper(),
                "Risk Level": s["risk_level"],
                "Score": f"{s['risk_score']}/100",
                "Findings": s["findings_count"],
                "Action Taken": s["action_taken"]
            })
        st.dataframe(table_rows, use_container_width=True)
