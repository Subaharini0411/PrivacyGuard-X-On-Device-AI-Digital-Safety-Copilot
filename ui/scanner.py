"""
PrivacyGuard X - Scan Center Page
Unified hub for Image, Document, Text, Code, and URL risk analysis.
Every tab is fully functional with on-device evaluation and zero external transmission.
"""

import io
import streamlit as st
from PIL import Image
from core.pii_detector import PIIDetector
from core.secret_detector import SecretDetector
from core.document_scanner import DocumentScanner
from core.url_analyzer import URLAnalyzer
from core.risk_engine import calculate_risk_score, Finding
from ai.ocr import LocalOCREngine
from ai.model_manager import SnapdragonModelManager
from database.database import save_scan, get_setting
from utils.file_utils import generate_audit_report_json, generate_audit_report_markdown
from utils.validators import validate_text_input, validate_file_size, validate_url_syntax
from demo.demo_data import (
    DEMO_CODE, DEMO_TEXT, DEMO_DOCUMENT, DEMO_URL, DEMO_CLEAN_TEXT,
    DEMO_DISCLAIMER, generate_demo_image
)


def render_finding_card(finding: Finding, idx: int, model_mgr: SnapdragonModelManager):
    """Renders an explainable finding card with full 5-point AI breakdown."""
    risk_class = (
        "finding-card-high" if finding.risk_level == "HIGH"
        else "finding-card-med" if finding.risk_level == "MEDIUM"
        else "finding-card-low"
    )
    badge_class = (
        "risk-badge-high" if finding.risk_level == "HIGH"
        else "risk-badge-med" if finding.risk_level == "MEDIUM"
        else "risk-badge-low"
    )

    ai_exp = model_mgr.generate_ai_explanation(finding.category, finding.matched_text)

    st.markdown(f"""
    <div class="finding-card {risk_class}">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <div style="font-weight: 700; font-size: 1.05rem;">
                ⚠️ #{idx} — {finding.category}
            </div>
            <div>
                <span class="{badge_class}">{finding.risk_level} RISK</span>
            </div>
        </div>
        <div style="font-size: 0.9rem; color: #94a3b8; margin-bottom: 6px;">
            <strong>📍 Location:</strong> <code>{finding.location}</code> &nbsp;|&nbsp; 
            <strong>Matched Pattern:</strong> <code>{finding.masked_text}</code>
        </div>
        <div style="margin-top: 10px; font-size: 0.92rem; line-height: 1.5;">
            <div style="margin-bottom: 4px;"><strong>1. What was detected:</strong> {ai_exp['what']}</div>
            <div style="margin-bottom: 4px;"><strong>2. Why it may be risky:</strong> {ai_exp['why']}</div>
            <div style="margin-bottom: 4px;"><strong>3. Where it was detected:</strong> {finding.location}</div>
            <div style="margin-bottom: 4px; color: #f87171;"><strong>4. What could happen if shared:</strong> {ai_exp['consequences']}</div>
            <div style="margin-top: 6px; padding: 6px 10px; background: rgba(0, 150, 214, 0.1); border-left: 3px solid #0096d6; border-radius: 4px;">
                <strong>💡 Recommended Action:</strong> {ai_exp['action']}
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_scanner():
    """Renders the comprehensive Scan Center with 5 active tabs."""
    model_mgr = SnapdragonModelManager()
    sensitivity = get_setting("scan_sensitivity", "Balanced")

    st.markdown("## 🔍 Scan Center")
    st.caption("On-device privacy & security analysis across screenshots, documents, text, source code, and URLs.")

    # Tab selection index preserved in session state
    default_tab = st.session_state.get("scanner_tab", 0)
    tabs = st.tabs(["📷 Image Scan", "📄 Document Scan", "📝 Text Scan", "💻 Code Scan", "🌐 URL Safety"])

    # ==========================================
    # TAB 1: IMAGE SCAN
    # ==========================================
    with tabs[0]:
        st.subheader("📷 Screenshot & Image Safety Scanner")
        st.write("Upload a screenshot or photo to detect exposed credentials, PII, and sensitive visible data.")

        img_col1, img_col2 = st.columns([3, 1])
        with img_col1:
            uploaded_img = st.file_uploader(
                "Upload Image (PNG, JPG, JPEG, WEBP)",
                type=["png", "jpg", "jpeg", "webp"],
                key="uploader_img"
            )
        with img_col2:
            st.write("")
            st.write("")
            load_demo_img = st.button("🧪 Load Demo Screenshot", key="btn_load_demo_img")

        img_bytes = None
        img_name = "uploaded_image.png"

        if load_demo_img:
            img_bytes = generate_demo_image()
            img_name = "demo_screenshot.png"
            st.session_state.current_image_bytes = img_bytes
            st.session_state.current_image_name = img_name
            st.info(f"Loaded synthetic demo screenshot. {DEMO_DISCLAIMER}")
        elif uploaded_img:
            img_bytes = uploaded_img.read()
            img_name = uploaded_img.name
            st.session_state.current_image_bytes = img_bytes
            st.session_state.current_image_name = img_name
        elif "current_image_bytes" in st.session_state:
            img_bytes = st.session_state.current_image_bytes
            img_name = st.session_state.current_image_name

        if img_bytes:
            ocr_engine = LocalOCREngine()
            with st.spinner("Analyzing image on-device..."):
                scan_res = ocr_engine.scan_image(img_bytes, img_name, sensitivity=sensitivity)

            if not scan_res["success"]:
                st.error(f"⚠️ {scan_res['error']}")
            else:
                assessment = scan_res["assessment"]
                findings = scan_res["findings"]
                original_img = scan_res["image"]
                boxes = scan_res["boxes"]

                # Assessment Summary Banner
                score = assessment.score
                level = assessment.risk_level
                badge_class = (
                    "risk-badge-high" if level == "HIGH"
                    else "risk-badge-med" if level == "MEDIUM"
                    else "risk-badge-low" if level == "LOW"
                    else "risk-badge-clean"
                )

                st.markdown(f"""
                <div style="background: #161f30; padding: 16px 20px; border-radius: 10px; margin: 16px 0; border: 1px solid #243247; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="font-size: 1.25rem; font-weight: 700;">Risk Score: {score}/100</div>
                        <div style="color: #94a3b8; font-size: 0.88rem; margin-top: 4px;">{assessment.summary}</div>
                    </div>
                    <div>
                        <span class="{badge_class}">{level} RISK</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                # Redaction Options
                st.markdown("### 🛡️ Visual Redaction Controls")
                redact_mode = st.radio(
                    "Choose Redaction Mode for Protected Export:",
                    ["Mask (Solid Privacy Bars)", "Blur (Gaussian Blur)", "Ignore (No Redaction)"],
                    horizontal=True,
                    key="img_redact_radio"
                )

                mode_key = "mask" if "Mask" in redact_mode else "blur" if "Blur" in redact_mode else "ignore"
                protected_img = ocr_engine.redact_image(original_img, boxes, findings, mode=mode_key)

                # Side-by-side image comparison
                img_view_col1, img_view_col2 = st.columns(2)
                with img_view_col1:
                    st.markdown("**Original Image (Unmodified)**")
                    st.image(original_img, use_container_width=True)

                with img_view_col2:
                    st.markdown(f"**Protected Image ({redact_mode})**")
                    st.image(protected_img, use_container_width=True)

                # Export Protected Image Button
                buf = io.BytesIO()
                protected_img.save(buf, format="PNG")
                prot_bytes = buf.getvalue()

                exp_col1, exp_col2, exp_col3 = st.columns([1, 1, 1])
                with exp_col1:
                    if st.download_button(
                        label="💾 Export Protected Image",
                        data=prot_bytes,
                        file_name="screenshot_protected.png",
                        mime="image/png",
                        use_container_width=True,
                        key="btn_dl_prot_img"
                    ):
                        # Save audit record in DB
                        save_scan({
                            "file_name": img_name,
                            "file_type": "image",
                            "scan_type": "Image OCR Scan",
                            "findings_count": len(findings),
                            "high_risk_count": assessment.high_risk_count,
                            "med_risk_count": assessment.med_risk_count,
                            "low_risk_count": assessment.low_risk_count,
                            "risk_score": score,
                            "risk_level": level,
                            "action_taken": "Protected Export",
                            "summary_reasons": "; ".join(assessment.reasons),
                            "details_json": [f.to_dict() for f in findings]
                        })
                        st.success("Protected image exported and logged locally!")

                with exp_col2:
                    if st.button("🔄 Rescan Image", use_container_width=True, key="btn_rescan_img"):
                        st.rerun()

                with exp_col3:
                    report_md = generate_audit_report_markdown({
                        "file_name": img_name,
                        "file_type": "image",
                        "scan_type": "Image OCR Scan",
                        "risk_score": score,
                        "risk_level": level,
                        "action_taken": redact_mode,
                        "findings_count": len(findings),
                        "summary": assessment.summary,
                        "reasons": assessment.reasons,
                        "findings": [f.to_dict() for f in findings]
                    })
                    st.download_button(
                        label="📄 Export Audit Report (MD)",
                        data=report_md,
                        file_name="audit_report.md",
                        mime="text/markdown",
                        use_container_width=True
                    )

                # Detailed Findings Breakdown
                st.write("")
                st.subheader(f"📋 Detected Findings ({len(findings)})")
                if not findings:
                    st.success("✅ No sensitive information or secrets were detected in this image.")
                else:
                    for i, f in enumerate(findings, start=1):
                        render_finding_card(f, i, model_mgr)

    # ==========================================
    # TAB 2: DOCUMENT SCAN
    # ==========================================
    with tabs[1]:
        st.subheader("📄 Document Safety Scanner")
        st.write("Upload PDF or text documents (txt, md, json, csv, log, env, py) for deep page-by-page risk inspection.")

        doc_col1, doc_col2 = st.columns([3, 1])
        with doc_col1:
            uploaded_doc = st.file_uploader(
                "Upload Document File",
                type=["pdf", "txt", "md", "json", "csv", "log", "env", "py"],
                key="uploader_doc"
            )
        with doc_col2:
            st.write("")
            st.write("")
            load_demo_doc = st.button("🧪 Load Demo Document", key="btn_load_demo_doc")

        doc_bytes = None
        doc_name = "uploaded_doc.txt"

        if load_demo_doc:
            doc_bytes = DEMO_DOCUMENT.encode("utf-8")
            doc_name = "demo_audit_report.txt"
            st.session_state.current_doc_bytes = doc_bytes
            st.session_state.current_doc_name = doc_name
            st.info(f"Loaded synthetic demo document. {DEMO_DISCLAIMER}")
        elif uploaded_doc:
            doc_bytes = uploaded_doc.read()
            doc_name = uploaded_doc.name
            st.session_state.current_doc_bytes = doc_bytes
            st.session_state.current_doc_name = doc_name
        elif "current_doc_bytes" in st.session_state:
            doc_bytes = st.session_state.current_doc_bytes
            doc_name = st.session_state.current_doc_name

        if doc_bytes:
            doc_scanner = DocumentScanner()
            with st.spinner("Extracting text and scanning pages locally..."):
                doc_res = doc_scanner.scan_document(doc_bytes, doc_name, sensitivity=sensitivity)

            if not doc_res["success"]:
                st.error(f"⚠️ {doc_res['error']}")
            else:
                assessment = doc_res["assessment"]
                findings = doc_res["findings"]
                pages = doc_res["pages"]
                score = assessment.score
                level = assessment.risk_level

                badge_class = (
                    "risk-badge-high" if level == "HIGH"
                    else "risk-badge-med" if level == "MEDIUM"
                    else "risk-badge-low" if level == "LOW"
                    else "risk-badge-clean"
                )

                # Document Overview Card
                st.markdown(f"""
                <div style="background: #161f30; padding: 16px 20px; border-radius: 10px; margin: 16px 0; border: 1px solid #243247;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <div style="font-size: 1.2rem; font-weight: 700;">Document: <code>{doc_name}</code></div>
                            <div style="color: #94a3b8; font-size: 0.88rem; margin-top: 4px;">
                                Pages: {doc_res['page_count']} | Findings: {len(findings)} | Score: {score}/100
                            </div>
                        </div>
                        <div>
                            <span class="{badge_class}">{level} RISK</span>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                # Action Controls
                sanitized_bytes, sanitized_fname = doc_scanner.create_sanitized_copy(pages, findings, doc_name)

                doc_act1, doc_act2 = st.columns(2)
                with doc_act1:
                    if st.download_button(
                        label=f"💾 Download Sanitized Copy ({sanitized_fname})",
                        data=sanitized_bytes,
                        file_name=sanitized_fname,
                        mime="text/plain",
                        use_container_width=True,
                        key="btn_dl_sanitized_doc"
                    ):
                        save_scan({
                            "file_name": doc_name,
                            "file_type": "document",
                            "scan_type": "Document Scan",
                            "findings_count": len(findings),
                            "high_risk_count": assessment.high_risk_count,
                            "med_risk_count": assessment.med_risk_count,
                            "low_risk_count": assessment.low_risk_count,
                            "risk_score": score,
                            "risk_level": level,
                            "action_taken": "Protected Export",
                            "summary_reasons": "; ".join(assessment.reasons),
                            "details_json": [f.to_dict() for f in findings]
                        })
                        st.success("Sanitized document downloaded! Original file preserved.")

                with doc_act2:
                    report_json = generate_audit_report_json({
                        "file_name": doc_name,
                        "file_type": "document",
                        "scan_type": "Document Scan",
                        "risk_score": score,
                        "risk_level": level,
                        "action_taken": "Audit Report",
                        "findings_count": len(findings),
                        "reasons": assessment.reasons,
                        "findings": [f.to_dict() for f in findings]
                    })
                    st.download_button(
                        label="📄 Export Document Audit Report (JSON)",
                        data=report_json,
                        file_name="document_audit.json",
                        mime="application/json",
                        use_container_width=True
                    )

                # Findings List
                st.write("")
                st.subheader(f"📋 Document Findings ({len(findings)})")
                if not findings:
                    st.success("✅ No sensitive information or secrets were detected in this document.")
                else:
                    for i, f in enumerate(findings, start=1):
                        render_finding_card(f, i, model_mgr)

    # ==========================================
    # TAB 3: TEXT SCAN
    # ==========================================
    with tabs[2]:
        st.subheader("📝 Text Safety Scanner")
        st.write("Paste emails, memos, chat transcripts, or notes to inspect for accidental exposure.")

        txt_btn_c1, txt_btn_c2 = st.columns([1, 1])
        with txt_btn_c1:
            if st.button("🧪 Paste Demo Text (PII Sample)", key="btn_paste_demo_txt"):
                st.session_state.text_to_scan = DEMO_TEXT
        with txt_btn_c2:
            if st.button("✅ Paste Clean Text Sample", key="btn_paste_clean_txt"):
                st.session_state.text_to_scan = DEMO_CLEAN_TEXT

        default_input = st.session_state.get("text_to_scan", "")
        user_text = st.text_area("Paste text here...", value=default_input, height=180, key="txt_input_area")

        if st.button("🔍 Analyze Text", type="primary", key="btn_analyze_txt"):
            is_valid, err = validate_text_input(user_text)
            if not is_valid:
                st.warning(f"⚠️ {err}")
            else:
                pii_detector = PIIDetector()
                secret_detector = SecretDetector()
                pii_findings = pii_detector.scan_text(user_text)
                sec_findings = secret_detector.scan_text(user_text)
                all_findings = pii_findings + sec_findings
                assessment = calculate_risk_score(all_findings, sensitivity=sensitivity)

                score = assessment.score
                level = assessment.risk_level

                badge_class = (
                    "risk-badge-high" if level == "HIGH"
                    else "risk-badge-med" if level == "MEDIUM"
                    else "risk-badge-low" if level == "LOW"
                    else "risk-badge-clean"
                )

                st.markdown(f"""
                <div style="background: #161f30; padding: 16px 20px; border-radius: 10px; margin: 16px 0; border: 1px solid #243247; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="font-size: 1.25rem; font-weight: 700;">Risk Score: {score}/100</div>
                        <div style="color: #94a3b8; font-size: 0.88rem; margin-top: 4px;">{assessment.summary}</div>
                    </div>
                    <div>
                        <span class="{badge_class}">{level} RISK</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                # Safe Version Generation
                safe_text = user_text
                for f in all_findings:
                    if f.matched_text in safe_text:
                        safe_text = safe_text.replace(f.matched_text, f.masked_text)

                safe_col1, safe_col2 = st.columns(2)
                with safe_col1:
                    st.markdown("**Original Content Preview**")
                    st.code(user_text[:500] + ("..." if len(user_text) > 500 else ""), language="text")

                with safe_col2:
                    st.markdown("**Safe Sanitized Version**")
                    st.code(safe_text[:500] + ("..." if len(safe_text) > 500 else ""), language="text")

                # Copy Safe Version button
                st.download_button(
                    label="📋 Download / Copy Safe Version",
                    data=safe_text,
                    file_name="safe_text.txt",
                    mime="text/plain",
                    use_container_width=True,
                    key="btn_dl_safe_txt"
                )

                # Save record to DB
                save_scan({
                    "file_name": "Pasted Text Snippet",
                    "file_type": "text",
                    "scan_type": "Text Scan",
                    "findings_count": len(all_findings),
                    "high_risk_count": assessment.high_risk_count,
                    "med_risk_count": assessment.med_risk_count,
                    "low_risk_count": assessment.low_risk_count,
                    "risk_score": score,
                    "risk_level": level,
                    "action_taken": "Safe Copied" if all_findings else "Reviewed",
                    "summary_reasons": "; ".join(assessment.reasons),
                    "details_json": [f.to_dict() for f in all_findings]
                })

                st.write("")
                st.subheader(f"📋 Detected Findings ({len(all_findings)})")
                if not all_findings:
                    st.success("✅ Clean content. No sensitive identifiers found.")
                else:
                    for i, f in enumerate(all_findings, start=1):
                        render_finding_card(f, i, model_mgr)

    # ==========================================
    # TAB 4: CODE SCAN
    # ==========================================
    with tabs[3]:
        st.subheader("💻 Developer Source Code Scanner")
        st.write("Scan scripts, config files, or environment files before git commits or public sharing.")

        code_btn_c1, code_btn_c2 = st.columns([1, 1])
        with code_btn_c1:
            if st.button("🧪 Paste Demo Code (Secrets Sample)", key="btn_paste_demo_code"):
                st.session_state.code_to_scan = DEMO_CODE

        default_code = st.session_state.get("code_to_scan", "")
        user_code = st.text_area("Paste source code or config here...", value=default_code, height=220, key="code_input_area")

        if st.button("🔍 Scan Code for Secrets", type="primary", key="btn_analyze_code"):
            is_valid, err = validate_text_input(user_code)
            if not is_valid:
                st.warning(f"⚠️ {err}")
            else:
                secret_detector = SecretDetector()
                pii_detector = PIIDetector()
                code_findings = secret_detector.scan_text(user_code) + pii_detector.scan_text(user_code)
                assessment = calculate_risk_score(code_findings, sensitivity=sensitivity)

                score = assessment.score
                level = assessment.risk_level

                badge_class = (
                    "risk-badge-high" if level == "HIGH"
                    else "risk-badge-med" if level == "MEDIUM"
                    else "risk-badge-low" if level == "LOW"
                    else "risk-badge-clean"
                )

                st.markdown(f"""
                <div style="background: #161f30; padding: 16px 20px; border-radius: 10px; margin: 16px 0; border: 1px solid #243247; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="font-size: 1.25rem; font-weight: 700;">Code Risk Score: {score}/100</div>
                        <div style="color: #94a3b8; font-size: 0.88rem; margin-top: 4px;">{assessment.summary}</div>
                    </div>
                    <div>
                        <span class="{badge_class}">{level} RISK</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                # Sanitized Code
                sanitized_code = user_code
                for f in code_findings:
                    if f.matched_text in sanitized_code:
                        sanitized_code = sanitized_code.replace(f.matched_text, f'"{f.masked_text}"')

                st.markdown("**Sanitized Code Preview (Secrets Masked)**")
                st.code(sanitized_code, language="python")

                code_act1, code_act2 = st.columns(2)
                with code_act1:
                    st.download_button(
                        label="📋 Download Sanitized Code",
                        data=sanitized_code,
                        file_name="sanitized_script.py",
                        mime="text/plain",
                        use_container_width=True
                    )
                with code_act2:
                    if st.button("🚫 Ignore All & Keep Original", use_container_width=True):
                        st.info("Marked findings as ignored by user discretion.")

                save_scan({
                    "file_name": "Source Code Snippet",
                    "file_type": "code",
                    "scan_type": "Code Secret Scan",
                    "findings_count": len(code_findings),
                    "high_risk_count": assessment.high_risk_count,
                    "med_risk_count": assessment.med_risk_count,
                    "low_risk_count": assessment.low_risk_count,
                    "risk_score": score,
                    "risk_level": level,
                    "action_taken": "Safe Copied" if code_findings else "Reviewed",
                    "summary_reasons": "; ".join(assessment.reasons),
                    "details_json": [f.to_dict() for f in code_findings]
                })

                st.write("")
                st.subheader(f"📋 Detected Secrets ({len(code_findings)})")
                if not code_findings:
                    st.success("✅ Clean code. No hardcoded secrets or credentials detected.")
                else:
                    for i, f in enumerate(code_findings, start=1):
                        render_finding_card(f, i, model_mgr)

    # ==========================================
    # TAB 5: URL SAFETY ANALYSIS
    # ==========================================
    with tabs[4]:
        st.subheader("🌐 URL Safety Analysis")
        st.write("Safe, non-invasive static URL risk inspection without aggressive network probing.")

        url_btn_c1, url_btn_c2 = st.columns([1, 1])
        with url_btn_c1:
            if st.button("🧪 Paste Demo Suspicious URL", key="btn_paste_demo_url"):
                st.session_state.url_to_scan = DEMO_URL
        with url_btn_c2:
            if st.button("✅ Paste Standard HTTPS URL", key="btn_paste_safe_url"):
                st.session_state.url_to_scan = "https://www.qualcomm.com/products/mobile/snapdragon"

        default_url = st.session_state.get("url_to_scan", "")
        user_url = st.text_input("Enter URL to inspect:", value=default_url, placeholder="https://example.com/portal", key="url_input_field")

        check_conn = st.checkbox("Perform non-invasive safe HEAD ping (2.5s timeout)", value=False)

        if st.button("🔍 Inspect URL Safety", type="primary", key="btn_analyze_url"):
            analyzer = URLAnalyzer()
            with st.spinner("Analyzing URL structure locally..."):
                res = analyzer.analyze(user_url, check_connectivity=check_conn)

            if not res["valid"]:
                st.error(f"⚠️ {res.get('error', 'Invalid URL')}")
            else:
                assessment = res["assessment"]
                findings = res["findings"]
                score = assessment.score
                level = assessment.risk_level

                badge_class = (
                    "risk-badge-high" if level == "HIGH"
                    else "risk-badge-med" if level == "MEDIUM"
                    else "risk-badge-low" if level == "LOW"
                    else "risk-badge-clean"
                )

                st.markdown(f"""
                <div style="background: #161f30; padding: 16px 20px; border-radius: 10px; margin: 16px 0; border: 1px solid #243247; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="font-size: 1.25rem; font-weight: 700;">URL Risk Score: {score}/100</div>
                        <div style="color: #94a3b8; font-size: 0.88rem; margin-top: 4px;">Host: <code>{res['hostname']}</code> | Protocol: <code>{res['scheme'].upper()}</code></div>
                    </div>
                    <div>
                        <span class="{badge_class}">{level} RISK</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                st.info(f"ℹ️ **Status Check:** {res['connectivity_status']}")
                st.caption(f"🛡️ **Disclaimer:** *{res['disclaimer']}*")

                save_scan({
                    "file_name": user_url[:50],
                    "file_type": "url",
                    "scan_type": "URL Safety Scan",
                    "findings_count": len(findings),
                    "high_risk_count": assessment.high_risk_count,
                    "med_risk_count": assessment.med_risk_count,
                    "low_risk_count": assessment.low_risk_count,
                    "risk_score": score,
                    "risk_level": level,
                    "action_taken": "Reviewed",
                    "summary_reasons": "; ".join(assessment.reasons),
                    "details_json": [f.to_dict() for f in findings]
                })

                st.write("")
                st.subheader(f"📋 URL Findings ({len(findings)})")
                if not findings:
                    st.success("✅ Standard HTTPS URL structure. No obvious deception patterns or credentials found.")
                else:
                    for i, f in enumerate(findings, start=1):
                        render_finding_card(f, i, model_mgr)
