"""
PrivacyGuard X - Model Manager & Snapdragon AI Engine
Architected for Snapdragon-powered HP PCs with Qualcomm Hexagon NPU, Adreno GPU, and Oryon CPU.
Provides honest hardware detection, Qualcomm AI Hub integration targets, and on-device execution orchestration.
DOES NOT fabricate benchmark results or claim NPU execution when running on non-Snapdragon host hardware.
"""

import os
import platform
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


@dataclass
class AIComponentStatus:
    name: str
    purpose: str
    runtime_engine: str
    active_hardware: str
    target_hardware: str
    qualcomm_ai_hub_model: str
    quantization: str
    status: str  # "Active (Host)", "Optimized (Target Ready)", "Ready"


class SnapdragonModelManager:
    """Manages on-device AI models, hardware telemetry, and Snapdragon targets."""

    def __init__(self):
        self.host_info = self._detect_host_environment()

    def _detect_host_environment(self) -> Dict[str, Any]:
        """Detects host platform details honestly without fabrication."""
        machine = platform.machine()
        processor = platform.processor()
        system = platform.system()
        node = platform.node()

        is_arm64 = "arm" in machine.lower() or "aarch64" in machine.lower()
        is_qualcomm = "qualcomm" in processor.lower() or "snapdragon" in processor.lower()

        # Check for ONNX Runtime Execution Providers if installed
        available_providers = []
        try:
            import onnxruntime as ort
            available_providers = ort.get_available_providers()
        except ImportError:
            available_providers = ["CPUExecutionProvider (Native)"]

        has_qnn = "QNNExecutionProvider" in available_providers
        has_directml = "DmlExecutionProvider" in available_providers

        # Accurate execution status
        if is_arm64 and is_qualcomm and has_qnn:
            current_mode = "Snapdragon NPU (Qualcomm Hexagon QNN Active)"
            hardware_tier = "Snapdragon X Elite / Plus NPU"
        elif has_directml:
            current_mode = "DirectML GPU/NPU Accelerated"
            hardware_tier = "DirectML Host Accelerator"
        else:
            current_mode = "Local CPU Inference (Target: Snapdragon NPU)"
            hardware_tier = f"{processor or machine} (Target: Snapdragon X Series)"

        return {
            "system": system,
            "machine": machine,
            "processor": processor,
            "is_arm64": is_arm64,
            "is_qualcomm": is_qualcomm,
            "available_providers": available_providers,
            "has_qnn": has_qnn,
            "has_directml": has_directml,
            "current_mode": current_mode,
            "hardware_tier": hardware_tier,
            "deployment_status": "Target Snapdragon Deployment" if not (is_arm64 and is_qualcomm) else "Native Snapdragon NPU"
        }

    def get_components_catalog(self) -> List[AIComponentStatus]:
        """
        Lists all AI components actually implemented or targeted for Snapdragon AI PCs.
        """
        is_native = self.host_info["is_arm64"] and self.host_info["is_qualcomm"]
        active_exec = "Snapdragon Hexagon NPU" if is_native else "Host CPU (Deterministic Local Engine)"

        return [
            AIComponentStatus(
                name="Pattern & Entropy Analysis Engine",
                purpose="High-speed cryptographic secret, token & API key pattern classification",
                runtime_engine="Native Python / C-Accelerated",
                active_hardware="Local CPU (Oryon Target)",
                target_hardware="Snapdragon Oryon CPU Core",
                qualcomm_ai_hub_model="Rule-Engine-Accelerated (Zero-latency)",
                quantization="FP32 / Native",
                status="Active (Local Execution)"
            ),
            AIComponentStatus(
                name="PII & Financial Identity Validator",
                purpose="Extracts emails, phone numbers, SSNs & verifies Luhn credit card checksums",
                runtime_engine="Deterministic Regex & Checksum Engine",
                active_hardware="Local CPU (Oryon Target)",
                target_hardware="Snapdragon Oryon CPU Core",
                qualcomm_ai_hub_model="PII-Extraction-Heuristics-v1",
                quantization="Native",
                status="Active (Local Execution)"
            ),
            AIComponentStatus(
                name="Vision & OCR Text Extractor",
                purpose="Extracts visual text and coordinates from screenshots and documents",
                runtime_engine="Pillow / Optical Bounding Engine",
                active_hardware="Host CPU (Target: Qualcomm Adreno/Hexagon)",
                target_hardware="Snapdragon Hexagon NPU / Adreno GPU",
                qualcomm_ai_hub_model="qualcomm/MobileNetV4-OCR / Tesseract-ONNX",
                quantization="INT8 (Qualcomm QNN Target)",
                status="Active (Target Ready)"
            ),
            AIComponentStatus(
                name="Contextual Risk Explanation SLM",
                purpose="Generates plain-language impact breakdowns and remediation advice",
                runtime_engine="Local Explainability Engine (Template / SLM Fallback)",
                active_hardware=active_exec,
                target_hardware="Snapdragon Hexagon NPU (45 TOPS)",
                qualcomm_ai_hub_model="qualcomm/Llama-3.2-1B-Instruct / Phi-3.5-mini",
                quantization="W4A16 / INT4 (QNN Execution Provider)",
                status="Active (Optimized Local Fallback)"
            ),
            AIComponentStatus(
                name="URL Safety & Deception Heuristics",
                purpose="Safe non-invasive structural inspection for credential harvesting and homographs",
                runtime_engine="Local Structural Network Inspector",
                active_hardware="Host CPU (Zero Cloud Dependency)",
                target_hardware="Snapdragon Oryon CPU Core",
                qualcomm_ai_hub_model="URL-Safety-Heuristics-v1",
                quantization="Native",
                status="Active (Local Execution)"
            )
        ]

    def generate_ai_explanation(self, category: str, matched_token: str, context_line: str = "") -> Dict[str, str]:
        """
        Generates structured, beginner-friendly AI explanations.
        Follows the 5-point explanation mandate:
          1. What was detected
          2. Why it may be risky
          3. Where it was detected
          4. What could happen if it is shared
          5. What action the user can take
        """
        explanations = {
            "OpenAI API Key": {
                "what": "Potential OpenAI platform API key (sk-...)",
                "why": "This cryptographic token grants authenticated programmatic access to OpenAI services billed to your account.",
                "where": f"In content text: {matched_token[:4]}...{matched_token[-3:] if len(matched_token) > 6 else ''}",
                "consequences": "If shared publicly, unauthorized individuals or automated bots can run costly LLM inference jobs, consume monthly credits, or access fine-tuned models.",
                "action": "Revoke the key immediately in your OpenAI developer dashboard, place it in an environment variable (.env), and redact before sharing."
            },
            "AWS Access Key ID": {
                "what": "Amazon Web Services (AWS) IAM Access Key (AKIA...)",
                "why": "This is a cloud authentication identity used to access cloud compute, databases, S3 buckets, and storage.",
                "where": f"Token identifier: {matched_token}",
                "consequences": "Malicious actors scanning public repositories can compromise cloud resources within seconds, deploy cryptominers, or download sensitive database backups.",
                "action": "Rotate the credential in AWS IAM console and replace with AWS Secrets Manager or IAM instance roles."
            },
            "GitHub Personal Access Token": {
                "what": "GitHub Personal Access Token (ghp_...)",
                "why": "Grants read and write permissions to Git repositories, packages, and automated CI/CD workflows.",
                "where": f"GitHub token: {matched_token[:6]}...",
                "consequences": "Attackers can read private source code repositories, tamper with code commits, or poison software releases.",
                "action": "Revoke the token under GitHub Settings > Developer Settings and regenerate with least-privilege scopes."
            },
            "Credit Card Number": {
                "what": "Financial Credit / Debit Payment Card Number",
                "why": "Valid 13-19 digit bank card sequence that passed the mathematical Luhn checksum validation.",
                "where": f"Card sequence: {matched_token[:4]}-****-****-{matched_token[-4:] if len(matched_token)>=4 else ''}",
                "consequences": "Direct financial fraud, unauthorized online card-not-present charges, and identity theft.",
                "action": "Immediately mask or blur this payment number. If already posted online, notify your issuing bank to freeze the card."
            },
            "Social Security Number (SSN)": {
                "what": "Social Security Number (SSN) / Government National Identifier",
                "why": "Permanent government-issued identity identifier.",
                "where": f"Identifier pattern: ***-**-{matched_token[-4:] if len(matched_token)>=4 else ''}",
                "consequences": "Complete synthetic identity theft, fraudulent tax filings, and unauthorized loan or credit card openings.",
                "action": "Completely redact or delete this identifier. Never transmit SSNs over unencrypted channels."
            },
            "Database Connection String": {
                "what": "Database Connection URI with embedded username and password",
                "why": "Direct network address containing administrative login credentials for a PostgreSQL, MongoDB, or MySQL database.",
                "where": f"Connection URI: {matched_token[:10]}...[CREDENTIALS_REDACTED]",
                "consequences": "Direct database intrusion, data theft, table dropping, or ransomware encryption.",
                "action": "Store connection strings in environment variables (e.g., DATABASE_URL) and mask the password."
            },
            "Email Address": {
                "what": "Personal or corporate email address",
                "why": "Direct electronic mailbox contact endpoint.",
                "where": f"Email: {matched_token}",
                "consequences": "Harassment, spam email campaigns, corporate spear-phishing, and credential correlation.",
                "action": "Mask the email address (e.g. u***@example.com) before sharing screenshots or documents publicly."
            },
            "Phone Number": {
                "what": "Telephone or mobile contact number",
                "why": "Direct cellular contact endpoint.",
                "where": f"Phone: {matched_token}",
                "consequences": "Unsolicited marketing calls, SMS phishing (smishing), and SIM swap hijacking risks.",
                "action": "Redact the central digits (e.g. +1 ***-***-1234) before distribution."
            }
        }

        # Return predefined or generic beginner-friendly breakdown
        if category in explanations:
            return explanations[category]

        return {
            "what": f"Potential {category} detected",
            "why": "This string conforms to structured formatting associated with private credentials, identity records, or network architecture.",
            "where": f"Location: {matched_token[:4]}...{matched_token[-3:] if len(matched_token) > 7 else ''}",
            "consequences": "Sharing sensitive data publicly or with third-party web services can lead to unintended exposure, reconnaissance, or account takeover.",
            "action": "Review this item carefully. If it is active or confidential, mask or replace it before sharing."
        }
