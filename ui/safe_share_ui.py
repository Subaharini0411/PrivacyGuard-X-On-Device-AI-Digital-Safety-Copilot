"""
PrivacyGuard X - Safe Share Mode Page
Gatekeeper pre-transmission checklist for sensitive materials.
Enforces user autonomy and zero unauthorized transmission.
"""

import streamlit as st
from core.safe_share import SafeShareGatekeeper
from ai.model_manager import SnapdragonModelManager
from database.database import save_scan, get_setting
from demo.demo_data import DEMO_TEXT, DEMO_CODE, DEMO_CLEAN_TEXT


def render_safe_share():
    """Renders the interactive Safe Share workflow."""
    model_mgr = SnapdragonModelManager()
    sensitivity = get_setting("scan_sensitivity", "Balanced")

    st.markdown("## 🛡️ Safe Share Assistant")
    st.caption("Pre-flight safety inspection: Ensure no private credentials or confidential data leave your device.")

    st.write("Select or paste the content you are preparing to share with colleagues, clients, or public channels:")

    col_btn1, col_btn2, col_btn3 = st.columns(3)
    with col_btn1:
        if st.button("🧪 Sample with Secrets", key="ss_demo_secret"):
            st.session_state.ss_input = DEMO_CODE
    with col_btn2:
        if st.button("🧪 Sample with PII", key="ss_demo_pii"):
            st.session_state.ss_input = DEMO_TEXT
    with col_btn3:
        if st.button("✅ Clean Sample", key="ss_demo_clean"):
            st.session_state.ss_input = DEMO_CLEAN_TEXT

    default_val = st.session_state.get("ss_input", "")
    content = st.text_area("Content to verify:", value=default_val, height=180, key="ss_content_area")

    if st.button("🔍 Run Safe Share Check", type="primary", use_container_width=True, key="btn_run_safe_share"):
        if not content.strip():
            st.warning("⚠️ Please provide content to evaluate.")
        else:
            gatekeeper = SafeShareGatekeeper()
            result = gatekeeper.evaluate(content, sensitivity=sensitivity)
            st.session_state.ss_result = result
            st.session_state.ss_evaluated_content = content

    if "ss_result" in st.session_state and st.session_state.get("ss_evaluated_content") == content:
        res = st.session_state.ss_result
        assessment = res["assessment"]
        findings = res["findings"]
        status = res["status"]

        st.write("")
        st.markdown("---")
        st.markdown("### 📋 SAFE SHARE CHECK VERDICT")

        if status == "HIGH":
            badge_html = '<div style="background: rgba(239, 68, 68, 0.15); border: 2px solid #ef4444; border-radius: 10px; padding: 20px; text-align: center;"><h2 style="color: #ef4444; margin: 0;">🔴 SENSITIVE INFORMATION DETECTED</h2><p style="color: #fca5a5; margin: 8px 0 0 0; font-size: 1.05rem;">Critical security risk: Do NOT share this content in its current form.</p></div>'
        elif status == "MEDIUM":
            badge_html = '<div style="background: rgba(245, 158, 11, 0.15); border: 2px solid #f59e0b; border-radius: 10px; padding: 20px; text-align: center;"><h2 style="color: #f59e0b; margin: 0;">⚠️ REVIEW RECOMMENDED</h2><p style="color: #fcd34d; margin: 8px 0 0 0; font-size: 1.05rem;">Personal identifiers or internal technical details found.</p></div>'
        elif status == "LOW":
            badge_html = '<div style="background: rgba(59, 130, 246, 0.15); border: 2px solid #3b82f6; border-radius: 10px; padding: 20px; text-align: center;"><h2 style="color: #3b82f6; margin: 0;">🟡 MINOR EXPOSURE DETECTED</h2><p style="color: #93c5fd; margin: 8px 0 0 0; font-size: 1.05rem;">Low-sensitivity informational references detected.</p></div>'
        else:
            badge_html = '<div style="background: rgba(16, 185, 129, 0.15); border: 2px solid #10b981; border-radius: 10px; padding: 20px; text-align: center;"><h2 style="color: #10b981; margin: 0;">🟢 NO OBVIOUS SENSITIVE INFORMATION DETECTED</h2><p style="color: #6ee7b7; margin: 8px 0 0 0; font-size: 1.05rem;">Content passed on-device security checks.</p></div>'

        st.markdown(badge_html, unsafe_allow_html=True)
        st.write("")

        # Action Buttons
        act_col1, act_col2, act_col3, act_col4 = st.columns(4)

        with act_col1:
            show_findings = st.button("🔎 View Findings", use_container_width=True, key="ss_view_findings")

        with act_col2:
            protect_clicked = st.button("🛡️ Protect Content", type="primary", use_container_width=True, key="ss_protect_content")

        with act_col3:
            continue_clicked = st.button("⚠️ Continue Anyway", use_container_width=True, key="ss_continue_anyway")

        with act_col4:
            cancel_clicked = st.button("❌ Cancel", use_container_width=True, key="ss_cancel")

        if cancel_clicked:
            st.session_state.pop("ss_result", None)
            st.info("Safe Share session cancelled. Content remains private.")
            st.rerun()

        if continue_clicked:
            save_scan({
                "file_name": "Safe Share Bypassed",
                "file_type": "text",
                "scan_type": "Safe Share",
                "findings_count": len(findings),
                "high_risk_count": assessment.high_risk_count if assessment else 0,
                "med_risk_count": assessment.med_risk_count if assessment else 0,
                "low_risk_count": assessment.low_risk_count if assessment else 0,
                "risk_score": assessment.score if assessment else 0,
                "risk_level": status,
                "action_taken": "Ignored",
                "summary_reasons": "; ".join(assessment.reasons) if assessment else "User chose to continue without redaction",
                "details_json": [f.to_dict() for f in findings]
            })
            st.warning("⚠️ You chose to continue anyway. The decision was logged locally in your audit history.")

        if protect_clicked or st.session_state.get("ss_protected", False):
            st.session_state.ss_protected = True
            safe_text = content
            for f in findings:
                if f.matched_text in safe_text:
                    safe_text = safe_text.replace(f.matched_text, f.masked_text)

            st.write("")
            st.subheader("🛡️ Protected Content Ready to Share")
            st.code(safe_text, language="text")

            dl_c1, dl_c2 = st.columns(2)
            with dl_c1:
                st.download_button(
                    label="📋 Download Sanitized Text",
                    data=safe_text,
                    file_name="safe_share_protected.txt",
                    mime="text/plain",
                    use_container_width=True
                )
            with dl_c2:
                if st.button("✅ Mark as Protected & Log", use_container_width=True):
                    save_scan({
                        "file_name": "Safe Share Protected Content",
                        "file_type": "text",
                        "scan_type": "Safe Share",
                        "findings_count": len(findings),
                        "high_risk_count": assessment.high_risk_count if assessment else 0,
                        "med_risk_count": assessment.med_risk_count if assessment else 0,
                        "low_risk_count": assessment.low_risk_count if assessment else 0,
                        "risk_score": assessment.score if assessment else 0,
                        "risk_level": status,
                        "action_taken": "Protected Export",
                        "summary_reasons": "; ".join(assessment.reasons) if assessment else "",
                        "details_json": [f.to_dict() for f in findings]
                    })
                    st.success("Protected action logged in audit history!")

        if show_findings or not findings:
            st.write("")
            st.subheader(f"🔍 Findings Audit Details ({len(findings)})")
            if not findings:
                st.success("Zero security or privacy concerns were detected.")
            else:
                for idx, f in enumerate(findings, start=1):
                    ai_exp = model_mgr.generate_ai_explanation(f.category, f.matched_text)
                    st.markdown(f"""
                    - **Finding #{idx} ({f.category}):** Matched `<code>{f.masked_text}</code>` at {f.location}.
                      - *Why it matters:* {ai_exp['why']}
                      - *Remedy:* {ai_exp['action']}
                    """, unsafe_allow_html=True)
