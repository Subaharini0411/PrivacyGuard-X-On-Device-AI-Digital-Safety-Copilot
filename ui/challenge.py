"""
PrivacyGuard X - Challenge Overview Page
Presentation deck summary for the AI Innovation Challenge.
Explains Problem, Solution, Innovation, Snapdragon Advantage, and Societal Impact.
"""

import streamlit as st


def render_challenge():
    """Renders the competition challenge presentation overview."""
    st.markdown("""
    <div style="background: linear-gradient(135deg, rgba(22, 31, 48, 0.95) 0%, rgba(15, 23, 42, 0.98) 100%); border-left: 5px solid #ff2a5f; border-radius: 12px; padding: 24px 28px; margin-bottom: 24px;">
        <h1 style="margin: 0; font-size: 2rem; font-weight: 800;">
            🏆 Challenge Overview & Innovation
        </h1>
        <p style="margin: 6px 0 0 0; color: #94a3b8; font-size: 1.05rem;">
            Snapdragon-Powered HP PCs: On-Device AI Digital Safety Copilot
        </p>
    </div>
    """, unsafe_allow_html=True)

    # 5 Pillars
    c1, c2 = st.columns(2)

    with c1:
        st.markdown("""
        ### 🚨 The Problem
        Every day, millions of digital files, screenshots, code snippets, and PDFs are shared across Discord, Slack, GitHub, email, and social media.
        Users routinely expose:
        - **API keys and AWS credentials** in terminal screenshots or test scripts
        - **Personal phone numbers, home addresses, and emails** in receipts or presentation slides
        - **Credit card numbers and government IDs** in uploaded scan batches
        - **Database connection URIs** in shared config snippets
        Traditional tools are either simplistic cloud APIs that leak your data to analyze it, or basic regex that generates meaningless alerts without explaining why it matters.
        """)

    with c2:
        st.markdown("""
        ### 💡 The Solution: PrivacyGuard X
        PrivacyGuard X is a **zero-cloud, on-device digital safety assistant** designed for Snapdragon-powered HP PCs.
        It intercepts content *before* you share it, explains why an element is risky in simple language, computes a transparent 0-100 risk score, and gives the user one-click remediation (Mask, Blur, or Redact).
        - **On-Device:** 100% of OCR, NLP explanation, and entropy analysis runs locally.
        - **Zero Cloud Dependence:** Works offline, anywhere.
        - **User in Control:** Never automatically modifies or uploads files.
        """)

    st.write("")
    st.markdown("---")

    # Innovation & Snapdragon Advantage
    i1, i2 = st.columns(2)

    with i1:
        st.markdown("""
        ### 🚀 Main Innovation
        **The 6-Step Safety Pipeline:**
        $$\\text{Detect} \\longrightarrow \\text{Understand} \\longrightarrow \\text{Explain} \\longrightarrow \\text{Risk Score} \\longrightarrow \\text{User Decision} \\longrightarrow \\text{Protect}$$

        1. **Multi-Format Ingestion:** Screenshots, PDFs, text, code, and URLs in one unified copilot.
        2. **Explainable AI:** Answers: What was found? Why is it risky? Where was it found? What could happen? What action to take?
        3. **Luhn & Entropy Validation:** Mathematical verification prevents false alarms on random numbers.
        4. **Zero-Knowledge Sanitization:** Emits `screenshot_protected.png` and `doc_protected.txt` while preserving originals untouched.
        """)

    with i2:
        st.markdown("""
        ### ⚡ Snapdragon Advantage on HP PCs
        - **Qualcomm Hexagon™ NPU (45 TOPS):** Offloads quantized Small Language Models (SLMs) and OCR embeddings without taxing the main CPU.
        - **Qualcomm Oryon™ CPU:** Ultra-fast deterministic regex matching and Shannon entropy computation.
        - **All-Day Battery Life:** NPU efficiency ensures continuous digital safety monitoring without battery penalty.
        - **Qualcomm AI Hub Optimization:** Models aligned with Qualcomm QNN Execution Provider standards for direct ONNX Runtime acceleration.
        """)

    st.write("")
    st.markdown("---")

    # Impact
    st.markdown("""
    ### 🌍 Real-World Impact
    - **Students & Academics:** Safely share lab assignments, research PDFs, and project screenshots without leaking student IDs or passwords.
    - **Developers & Engineers:** Prevent accidental git commits of live API keys, JWTs, and AWS tokens.
    - **Remote Professionals & Healthcare:** Protect patient data, invoices, and internal company network addresses from accidental email distribution.
    - **Everyday Consumers:** Share payment receipts and photos with friends after automatically blurring bank card and address details.
    """)
