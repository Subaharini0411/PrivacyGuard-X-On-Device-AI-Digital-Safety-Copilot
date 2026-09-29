"""
PrivacyGuard X - Security Guidelines & Responsible AI
Explicit principles for safe digital practices, human-in-the-loop decisions,
and ethical, transparent artificial intelligence.
"""

import streamlit as st


def render_guidelines():
    """Renders the Security Guidelines and Responsible AI commitments."""
    st.markdown("## 🛡️ Guidelines & Responsible AI Governance")
    st.caption("Ethical guidelines, security best practices, and AI advisory frameworks.")

    tab1, tab2 = st.tabs(["🔒 Security & Privacy Guidelines", "🤖 Responsible AI Framework"])

    with tab1:
        st.subheader("📋 10-Point Digital Safety & Security Checklist")
        st.markdown("""
        1. **Never upload passwords or credentials unnecessarily:** Avoid entering sensitive login secrets into web browsers or third-party cloud tools.
        2. **Do not share API keys publicly:** Treat API keys, access tokens, and bearer credentials as sensitive bearer assets.
        3. **Use environment variables for application secrets:** Never hardcode secret keys directly into client or server source code files.
        4. **Do not commit `.env` files containing real credentials:** Always ensure `.env` and credential files are added to your `.gitignore` configuration.
        5. **Review screenshots before posting them online:** Crop or blur desktop window titles, taskbars, background tabs, and contact lists before publishing.
        6. **Use HTTPS websites whenever possible:** Unencrypted HTTP connections expose browsing sessions and payloads to network eavesdroppers.
        7. **Keep sensitive documents private:** Store PDFs, tax records, identification cards, and financial spreadsheets in encrypted local containers.
        8. **Rotate credentials if accidentally exposed:** If a key or token is leaked, immediately revoke it in the provider dashboard and regenerate a new token.
        9. **Advisory Assistance Disclaimer:** PrivacyGuard X provides automated heuristic assistance and does not replace professional manual security auditing.
        10. **Always verify important security decisions manually:** Maintain human oversight and never rely exclusively on automated tools for compliance.
        """)

    with tab2:
        st.subheader("⚖️ Responsible AI Principles")
        st.markdown("""
        PrivacyGuard X is built upon DeepMind and Qualcomm Responsible AI tenets:

        - **Advisory Risk Scoring:** Risk scores (0-100) are advisory indicators designed to aid human review. Detection does not constitute definitive proof of malicious or fraudulent intent.
        - **Uncertainty Calibration:** The engine uses cautious language ("Potential secret detected", "Possible credential pattern", "Review recommended") rather than claiming absolute certainty without sufficient evidence.
        - **Zero-Knowledge Privacy:** Detected secrets are masked in memory and logs. No unencrypted secrets or documents are stored in the local SQLite database.
        - **Minimal Data Collection:** The application collects only anonymous metadata necessary for reporting (e.g. timestamp, finding count, category).
        - **Human-in-the-Loop Autonomy:** PrivacyGuard X never automatically deletes files, modifies user code without consent, or transmits content over the network.
        - **AI Fallibility Transparency:** Pattern recognition models and OCR can experience false positives or false negatives. Users are encouraged to manually inspect highlighted locations.
        """)
