"""
PrivacyGuard X - Secret & Credential Detector
Analyzes text, configuration, and source code for exposed API keys, access tokens,
cryptographic private keys, database connection strings, passwords, and cloud secrets.
Includes Shannon entropy computation for anomaly detection.
"""

import math
import re
from typing import List
from .risk_engine import Finding


def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def mask_secret(secret: str) -> str:
    """Provides safe masking for detected secrets."""
    if len(secret) <= 6:
        return "[REDACTED_SECRET]"
    return secret[:3] + "..." + secret[-3:]


class SecretDetector:
    """Detector for credentials, tokens, and high-entropy secrets."""

    def __init__(self):
        # Known structured API keys & tokens
        self.signatures = [
            {
                "name": "OpenAI API Key",
                "pattern": re.compile(r'\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,80})\b'),
                "weight": 50,
                "why": "Potential OpenAI platform API key detected.",
                "consequence": "Unauthorized AI API quota consumption, model invocation abuse, and bill accrual."
            },
            {
                "name": "AWS Access Key ID",
                "pattern": re.compile(r'\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b'),
                "weight": 50,
                "why": "Standard AWS IAM or STS identity key identifier.",
                "consequence": "Direct unauthorized access to AWS Cloud infrastructure (S3, EC2, IAM)."
            },
            {
                "name": "GitHub Personal Access Token",
                "pattern": re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{36,40}|github_pat_[A-Za-z0-9_]{82})\b'),
                "weight": 50,
                "why": "GitHub developer personal or organization access token.",
                "consequence": "Source code repository exfiltration, pipeline tampering, and unauthorized commits."
            },
            {
                "name": "Google / Firebase API Key",
                "pattern": re.compile(r'\b(AIza[0-9A-Za-z\-_]{35})\b'),
                "weight": 45,
                "why": "Google Cloud Platform or Firebase developer API key.",
                "consequence": "GCP resource quota depletion, Firebase database reads/writes."
            },
            {
                "name": "Slack Token",
                "pattern": re.compile(r'\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b'),
                "weight": 45,
                "why": "Slack workspace bot or user OAuth token.",
                "consequence": "Internal workplace chat surveillance and message injection."
            },
            {
                "name": "Stripe Live Secret Key",
                "pattern": re.compile(r'\b(sk_live_[0-9a-zA-Z]{24,34}|rk_live_[0-9a-zA-Z]{24,34})\b'),
                "weight": 50,
                "why": "Stripe financial payment gateway live secret key.",
                "consequence": "Direct manipulation of real payment charges, refunds, and customer card data."
            },
            {
                "name": "Hugging Face Access Token",
                "pattern": re.compile(r'\b(hf_[A-Za-z0-9]{34,40})\b'),
                "weight": 40,
                "why": "Hugging Face model repository access token.",
                "consequence": "Unauthorized model downloads, fine-tuning compute usage, and model tampering."
            },
            {
                "name": "JSON Web Token (JWT)",
                "pattern": re.compile(r'\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b'),
                "weight": 45,
                "why": "Signed JSON Web Token for authentication session or authorization claims.",
                "consequence": "Session hijacking, administrative privilege escalation, or user impersonation."
            },
            {
                "name": "Private Cryptographic Key",
                "pattern": re.compile(r'(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)'),
                "weight": 50,
                "why": "Asymmetric private encryption/signing key.",
                "consequence": "TLS decryption, server SSH access breach, and code signing forgery."
            },
            {
                "name": "Database Connection String",
                "pattern": re.compile(r'\b((?:postgres|postgresql|mongodb|mongodb\+srv|mysql|redis|mssql):\/\/[A-Za-z0-9_-]+:[^\s@]+@[A-Za-z0-9.-]+(?::[0-9]+)?(?:\/[^\s]*)?)\b'),
                "weight": 50,
                "why": "Direct database credentials embedded in connection URI.",
                "consequence": "Direct remote database breach, data ransomware, and sensitive table theft."
            }
        ]

        # Password / secret assignments in code or configs
        self.assignment_pattern = re.compile(
            r'(?i)\b(?:api_key|apikey|secret_key|secret|password|passwd|pwd|db_pass|db_password|access_token|auth_token|client_secret)\s*[:=]\s*["\']([^"\'\s]{6,80})["\']'
        )

        # Private internal URLs
        self.internal_url_pattern = re.compile(
            r'\b(https?:\/\/(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9-]+\.(?:internal|local|lan|corp))(?::\d+)?(?:\/[^\s"\'<>]*)?)\b'
        )

    def scan_text(self, text: str) -> List[Finding]:
        """Scans code or text for credentials and secrets."""
        if not text or not isinstance(text, str):
            return []

        findings: List[Finding] = []

        # Check full text for multiline private keys
        for sig in self.signatures:
            if "Private Cryptographic Key" in sig["name"]:
                for match in sig["pattern"].finditer(text):
                    matched = match.group(1)
                    findings.append(Finding(
                        category="Private Key",
                        matched_text=matched,
                        masked_text="-----BEGIN PRIVATE KEY-----\n[REDACTED_RSA_BODY]\n-----END PRIVATE KEY-----",
                        risk_level="HIGH",
                        score_weight=sig["weight"],
                        location="Document Body",
                        why_it_matters=sig["why"],
                        potential_consequence=sig["consequence"],
                        recommended_action="Immediately revoke and rotate this cryptographic key. Never commit to public storage."
                    ))

        lines = text.split("\n")
        for line_idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            # 1. Match specific token signatures
            for sig in self.signatures:
                if "Private Cryptographic Key" in sig["name"]:
                    continue  # Handled above
                for match in sig["pattern"].finditer(line):
                    matched = match.group(1)
                    findings.append(Finding(
                        category=sig["name"],
                        matched_text=matched,
                        masked_text=mask_secret(matched),
                        risk_level="HIGH",
                        score_weight=sig["weight"],
                        location=f"Line {line_idx}",
                        line_number=line_idx,
                        why_it_matters=sig["why"],
                        potential_consequence=sig["consequence"],
                        recommended_action="Store credentials in environment variables or hardware key vaults, not in cleartext."
                    ))

            # 2. Assignment patterns (e.g. password = "...", api_key = "...")
            for match in self.assignment_pattern.finditer(line):
                full_matched = match.group(0)
                secret_val = match.group(1)
                
                # Check if already caught by structured signature
                if not any(f.matched_text in secret_val or secret_val in f.matched_text for f in findings):
                    # Exclude common placeholders like "your_password_here" or "********"
                    lowered = secret_val.lower()
                    if any(ph in lowered for ph in ["your_", "example", "placeholder", "xxx", "todo", "change_me"]):
                        # Low risk placeholder
                        continue

                    findings.append(Finding(
                        category="Password / Credential",
                        matched_text=full_matched,
                        masked_text=full_matched.replace(secret_val, mask_secret(secret_val)),
                        risk_level="HIGH",
                        score_weight=45,
                        location=f"Line {line_idx}",
                        line_number=line_idx,
                        why_it_matters="Possible authentication credential assigned in code/configuration.",
                        potential_consequence="Direct credential compromise and unauthorized system sign-in.",
                        recommended_action="Externalize secrets to a secure .env file excluded from version control."
                    ))

            # 3. Private / Internal URLs
            for match in self.internal_url_pattern.finditer(line):
                matched = match.group(1)
                findings.append(Finding(
                    category="Internal Infrastructure URL",
                    matched_text=matched,
                    masked_text="http://[INTERNAL_HOST_REDACTED]",
                    risk_level="MEDIUM",
                    score_weight=25,
                    location=f"Line {line_idx}",
                    line_number=line_idx,
                    why_it_matters="Reference to private intranet host or local service endpoint.",
                    potential_consequence="Exposes internal service names, architecture layout, and port numbers to attackers.",
                    recommended_action="Replace internal hostnames with example.corp or localhost before sharing."
                ))

            # 4. Entropy-based high-randomness string detection
            # Look for isolated alphanumeric strings of length 20-64 with high entropy
            tokens = re.findall(r'\b[A-Za-z0-9_\-+/]{20,64}\b', line)
            for token in tokens:
                # Avoid standard base64/hex long numbers that are common in code unless high entropy
                if any(f.matched_text in token for f in findings):
                    continue
                entropy = calculate_shannon_entropy(token)
                # Shannon entropy > 4.2 for 20+ chars indicates high randomness typical of secrets
                if entropy >= 4.2 and not token.lower().startswith("http"):
                    findings.append(Finding(
                        category="High-Entropy Secret String",
                        matched_text=token,
                        masked_text=mask_secret(token),
                        risk_level="HIGH",
                        score_weight=35,
                        location=f"Line {line_idx}",
                        line_number=line_idx,
                        why_it_matters=f"High Shannon entropy ({entropy:.2f} bits/symbol) indicates cryptographic randomness.",
                        potential_consequence="Could be an unlabelled API key, secret salt, or encrypted token.",
                        recommended_action="Review this token. If it is an active secret, remove or mask it."
                    ))

        return findings
