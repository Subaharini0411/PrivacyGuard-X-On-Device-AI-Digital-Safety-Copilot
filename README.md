# 🛡️ PrivacyGuard X — On-Device AI Digital Safety Copilot

> **"Check before you share."**  
> An on-device AI digital safety copilot architected for **Snapdragon-powered HP PCs**. Evaluates digital material (screenshots, documents, code, text, URLs) before online transmission with zero cloud data egress.

[![Platform](https://img.shields.io/badge/Platform-Snapdragon%20X%20Elite%20%7C%20HP%20PCs-crimson.svg)](https://www.qualcomm.com/products/mobile/snapdragon)
[![Privacy](https://img.shields.io/badge/Privacy-Zero--Knowledge%20On--Device-10b981.svg)]()
[![License](https://img.shields.io/badge/License-MIT-blue.svg)]()
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)]()

---

## 1. Project Title
**PrivacyGuard X: On-Device AI Digital Safety Copilot for Snapdragon-Powered HP PCs**

---

## 2. Problem Statement
Every day, developers, students, and professionals accidentally expose sensitive information when sharing screenshots, presentations, code snippets, logs, and documents across Discord, Slack, Teams, GitHub, and social channels:
- Hardcoded API keys (`sk-...`, `AKIA...`, GitHub tokens) and database connection strings
- Personal identifiers: emails, phone numbers, home addresses, employee/student IDs
- Financial and government data: payment card numbers, SSNs, national identity IDs
- Private infrastructure topologies: internal RFC1918 IPs, staging URLs, unencrypted HTTP links

Existing cloud-based checkers paradoxically violate user privacy by sending user payloads to remote servers. Meanwhile, standard regex tools lack explainability, fail to calculate deterministic risk scores, and offer no integrated remediation.

---

## 3. Solution
PrivacyGuard X is a **zero-cloud digital safety copilot** that runs completely on-device on Snapdragon-powered HP PCs. It analyzes five modalities of digital material, derives an explainable **0–100 risk score**, explains the real-world danger in beginner-friendly language, and enables one-click redaction (masking, blurring, or safe copy) before transmission.

---

## 4. Target Users
- **Developers & Engineers:** Screen code and configuration files before committing to Git or sharing in chat.
- **Students & Academics:** Inspect assignments, slides, and screenshots to avoid leaking student IDs, credentials, or personal numbers.
- **Enterprise & Remote Professionals:** Ensure contracts, invoices, and internal infrastructure URLs are sanitized before client distribution.
- **Everyday Consumers:** Automatically blur payment card numbers and home addresses on receipts and photos.

---

## 5. Key Features
1. **Multi-Modal Scan Center:**
   - **Image Scan:** Visual OCR text extraction, visual bounding boxes, interactive Mask / Blur / Ignore, and export to `screenshot_protected.png`.
   - **Document Scan:** Multi-page PDF, Markdown, TXT, CSV, and code file extraction with automated generation of sanitized copies (`document_protected.txt`) preserving the original file.
   - **Text Scan:** Immediate triage of memos and emails with "Copy Safe Version" masking.
   - **Code Scan:** Developer scanner identifying cloud credentials, tokens, passwords, and connection strings with line-number locations.
   - **URL Safety Analysis:** Safe, non-invasive static check for HTTP vs HTTPS, raw IP hosts, embedded credentials, homograph punycode patterns, and suspicious parameters.
2. **Safe Share Mode:** High-priority pre-flight triage workflow with clear verdicts:
   - 🟢 *No obvious sensitive information detected*
   - ⚠️ *Review recommended*
   - 🔴 *Sensitive information detected*
3. **5-Point Explainable AI:**
   - What was detected
   - Why it may be risky
   - Where it was detected
   - What could happen if shared
   - Recommended remediation
4. **Interactive Reports & Analytics:** Live metrics, risk distribution charts, and category breakdowns driven strictly by SQLite metadata.
5. **Zero-Knowledge Privacy Center:** Explicit user permission controls (Files, Clipboard, Screenshots, Network), temp file clearing, and instant history wiping.

---

## 6. Main Innovation
$$\text{Detect} \longrightarrow \text{Understand} \longrightarrow \text{Explain} \longrightarrow \text{Risk Score} \longrightarrow \text{User Decision} \longrightarrow \text{Protect}$$

PrivacyGuard X goes beyond simple redaction:
- **Mathematical Validation:** Uses the Luhn algorithm to verify payment card authenticity, eliminating false positives.
- **Shannon Entropy Analysis:** Identifies unlabelled cryptographic secrets and API keys via informational randomness ($H \ge 4.2$).
- **Calibrated Explainability:** Scores (0–100) are accompanied by human-readable justification bullet points.
- **Human Autonomy:** The user retains full control; PrivacyGuard X never automatically deletes or uploads data.

---

## 7. Snapdragon Relevance & Hardware Advantage
Designed specifically for **HP PCs powered by Snapdragon X Elite and Snapdragon X Plus**:
- **Qualcomm Hexagon™ NPU (45 TOPS):** Offloads quantized Small Language Models (SLMs) and OCR embeddings without taxing the main CPU.
- **Qualcomm Oryon™ CPU:** Delivers ultra-low latency execution of regex compilation and Shannon entropy calculations.
- **Qualcomm Adreno™ GPU:** Accelerates visual canvas rendering and Gaussian blur filters.
- **All-Day Battery Life:** Ultra-efficient NPU execution enables continuous background safety checks without battery drain.
- **Zero Cloud Dependence:** Works offline on planes, remote offices, and disconnected networks.

---

## 8. Architecture

```text
PrivacyGuardX/
│
├── app.py                      # Streamlit application entry point & error boundary
├── requirements.txt            # Python dependencies
├── README.md                   # Comprehensive documentation
│
├── ui/                         # User Interface Layer (Streamlit + CSS Design Tokens)
│   ├── dashboard.py            # Page 1: Executive metrics & quick launch
│   ├── scanner.py              # Page 2: Multi-modal Scan Center (Image, Doc, Text, Code, URL)
│   ├── safe_share_ui.py        # Page 3: Safe Share triage workflow
│   ├── snapdragon.py           # Page 4: Built for Snapdragon AI PCs
│   ├── privacy.py              # Page 5: Privacy Center & permission governance
│   ├── reports.py              # Page 6: Reports & analytics dashboard
│   ├── history.py              # Page 7: Scan history audit trail
│   ├── challenge.py            # Page 8: Challenge Overview & deck summary
│   ├── guidelines.py           # Page 9: Security & Responsible AI guidelines
│   ├── settings.py             # Page 10: Persistent configuration & sensitivity sliders
│   └── styles.py               # Custom HP Snapdragon dark obsidian styling
│
├── core/                       # Core Logic & Risk Engines
│   ├── risk_engine.py          # Unified 0-100 explainable scoring & Finding dataclass
│   ├── pii_detector.py         # Emails, phones, SSNs, Luhn card check, addresses, IPs
│   ├── secret_detector.py      # OpenAI, AWS, GitHub, tokens, DB URIs, Shannon entropy
│   ├── url_analyzer.py         # Non-invasive URL static risk analyzer
│   ├── document_scanner.py     # PDF & text document parser & sanitizer
│   └── safe_share.py           # Pre-flight gatekeeper evaluator
│
├── ai/                         # On-Device AI & Hardware Abstraction
│   ├── model_manager.py        # Snapdragon telemetry & Qualcomm AI Hub catalog
│   └── ocr.py                  # Local optical character extractor & visual redactor
│
├── database/                   # SQLite Storage Layer
│   └── database.py             # Zero-knowledge metadata persistence & metrics
│
├── utils/                      # Helper Utilities
│   ├── file_utils.py           # Path sanitization, report exporters, temp cleaner
│   ├── security.py             # Permission checkers & safe clipboard reader
│   └── validators.py           # Bounds, size, and URL syntax validators
│
├── demo/                       # Synthetic Demonstration Suite
│   └── demo_data.py            # Synthetic samples & in-memory screenshot generator
│
└── tests/                      # Automated Unit Test Suite
    ├── test_risk_engine.py     # Scoring calibration & sensitivity tests
    ├── test_detectors.py       # PII, Luhn card verification, and secret tests
    └── test_validators.py      # Input boundary & path sanitization tests
```

---

## 9. AI Models & Qualcomm AI Hub Targets
| Component | Runtime Engine | Active Execution | Qualcomm AI Hub Target | Quantization |
| :--- | :--- | :--- | :--- | :--- |
| **Pattern & Entropy Engine** | Native Python / C | Oryon CPU Core | Rule-Engine-Accelerated | Native FP32 |
| **PII & Luhn Validator** | Deterministic Checksum | Oryon CPU Core | PII-Extraction-Heuristics-v1 | Native |
| **Vision & OCR Extractor** | Pillow / Optical Bounding | Host CPU / Adreno GPU | `qualcomm/MobileNetV4-OCR` | INT8 (QNN EP) |
| **Risk Explanation SLM** | Explainability Engine | Hexagon NPU Target | `qualcomm/Llama-3.2-1B-Instruct` | W4A16 / INT4 |
| **URL Deception Heuristics** | Structural Inspector | Oryon CPU Core | URL-Safety-Heuristics-v1 | Native |

*Platform Honesty Notice:* Hardware execution is dynamically probed. When deployed on non-Snapdragon host systems, execution is clearly designated as **"Target Snapdragon Deployment"** without fabricating synthetic benchmark numbers.

---

## 10. Tech Stack
- **Frontend / UI:** Python 3.10+, Streamlit, Custom CSS (Snapdragon Crimson & HP Cyber Blue design tokens)
- **Backend / Core:** Python, SQLite3 (check_same_thread=False)
- **Imaging & Redaction:** Pillow (PIL.Image, PIL.ImageFilter, PIL.ImageDraw)
- **Document Processing:** pypdf
- **Data Visualization:** Pandas, Altair
- **Verification & Testing:** PyTest

---

## 11. Installation

```bash
# 1. Clone repository
git clone https://github.com/Subaharini0411/PrivacyGuard-X-On-Device-AI-Digital-Safety-Copilot.git
cd PrivacyGuard-X-On-Device-AI-Digital-Safety-Copilot

# 2. Create and activate a Python virtual environment (recommended)
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 12. Running Instructions

```bash
# Launch PrivacyGuard X
streamlit run app.py
```
The application will open in your default browser at `http://localhost:8501`.

---

## 13. Configuration
Preferences can be configured through the **Settings** page or programmatically via SQLite:
- **Theme:** Dark Obsidian Theme (default) / Light Mode
- **Processing Boundary:** Strictly Local On-Device (default) / Hybrid
- **Scan Sensitivity:** Strict (+25% score weight) / Balanced (default) / Permissive
- **Auto-Masking:** Automatically mask secrets in preview panes (default: True)
- **History Retention:** 7 Days / 30 Days (default) / 90 Days / Keep Indefinitely

---

## 14. Privacy Architecture
- **Zero Cloud Transmission:** Zero file bytes leave the device.
- **Zero Raw Credential Storage:** The SQLite database stores only sanitized snippets (e.g. `sk-...890`).
- **RAM-Only Analysis:** Uploaded documents are processed in volatile memory and purged immediately.
- **User Permission Gates:** Local files, clipboard, and screenshots require explicit permission toggles.

---

## 15. Security Guidelines
1. Never enter passwords or master keys into online web forms unnecessarily.
2. Always store API keys in `.env` files and add `.env` to `.gitignore`.
3. Review screenshots before posting to public forums or social platforms.
4. Ensure target endpoints support HTTPS before sharing URLs.
5. In the event of an accidental credential leak, immediately revoke and rotate the secret in the vendor console.
6. PrivacyGuard X provides automated guidance; always verify critical security decisions.

---

## 16. Testing
Execute the complete automated test suite with PyTest:

```bash
python -m pytest tests/
```
Output:
```text
tests/test_detectors.py ....
tests/test_risk_engine.py ....
tests/test_validators.py ....
============================== 12 passed in 0.10s ==============================
```

---

## 17. Limitations
- **Image OCR Dependency:** In environments without native compiled OCR binaries (e.g. Tesseract or EasyOCR), the engine falls back to heuristic and template extraction.
- **Encrypted PDFs:** Password-protected PDFs cannot be inspected without user decryption credentials.
- **Heuristic Nature:** Shannon entropy flags high-randomness strings; developers should verify whether a flagged string is an active credential or a harmless random hash.

---

## 18. Future Improvements
- Direct integration with Qualcomm AI Hub API for automated one-click model quantization.
- Real-time Windows clipboard background monitor running on the Hexagon NPU.
- Visual QR code and barcode redaction engine.
- Chrome and Edge browser extensions for pre-upload form field safety checks.

---

## 19. Snapdragon Optimization Plan
1. **Model Quantization:** Quantize `Llama-3.2-1B-Instruct` to INT4 using the Qualcomm AI Hub Python SDK.
2. **ONNX Runtime QNN Provider:** Build ONNX Runtime execution pipelines utilizing `QNNExecutionProvider` targeting the Snapdragon Hexagon HTP (Hexagon Tensor Processor).
3. **Power Telemetry:** Measure active milliwatt consumption on HP Snapdragon PCs to demonstrate 80%+ energy reduction compared to CPU/GPU execution.

---

## 20. Demo Instructions
PrivacyGuard X includes built-in synthetic test data for instant evaluation without requiring real secrets:
1. Navigate to **Scan Center**.
2. Click **"Load Demo Screenshot"** in Image Scan to see visual masking on a synthetic screenshot.
3. Click **"Load Demo Document"** in Document Scan to inspect multi-page PII and export a sanitized copy.
4. Click **"Paste Demo Code"** in Code Scan to detect API keys and database credentials.
5. Click **"Safe Share"** in the sidebar to run pre-flight transmission verification on sample text.
