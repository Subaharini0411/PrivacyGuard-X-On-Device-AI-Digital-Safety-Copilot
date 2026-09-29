"""
PrivacyGuard X - PII Detector
Detects Personally Identifiable Information (PII) including emails, phone numbers,
government IDs, employee/student IDs, credit card numbers, and physical addresses.
Includes Luhn algorithm verification for financial cards.
"""

import re
import ipaddress
from typing import List
from .risk_engine import Finding


def verify_luhn(card_number_str: str) -> bool:
    """Verifies standard Luhn checksum for credit/debit card numbers."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


def mask_string(val: str, category: str) -> str:
    """Returns privacy-masked representation of the sensitive token."""
    if category == "Email Address":
        parts = val.split("@")
        if len(parts) == 2 and len(parts[0]) > 2:
            return f"{parts[0][0]}***{parts[0][-1]}@{parts[1]}"
        return "[REDACTED_EMAIL]"

    if category == "Phone Number":
        digits_only = re.sub(r"\D", "", val)
        if len(digits_only) >= 4:
            return f"***-***-{digits_only[-4:]}"
        return "[REDACTED_PHONE]"

    if category == "Credit Card Number":
        digits_only = re.sub(r"\D", "", val)
        if len(digits_only) >= 4:
            return f"****-****-****-{digits_only[-4:]}"
        return "[REDACTED_CARD]"

    if category == "Social Security Number (SSN)":
        return "***-**-" + val[-4:]

    if category == "National Identity ID":
        return "****-****-" + val[-4:]

    if len(val) > 6:
        return val[:2] + "****" + val[-2:]
    return "[REDACTED]"


class PIIDetector:
    """Rule and regex-based local PII detector."""

    def __init__(self):
        # Email pattern
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
            re.IGNORECASE
        )

        # Phone numbers: US, international (+XX), Indian (10-digit starting with 6-9), and dashed
        self.phone_pattern = re.compile(
            r'(?:(?:\+|00)\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}\b'
        )

        # SSN (US): XXX-XX-XXXX
        self.ssn_pattern = re.compile(
            r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'
        )

        # National ID / Aadhaar-like 12-digit format: XXXX XXXX XXXX
        self.national_id_pattern = re.compile(
            r'\b[2-9]\d{3}\s\d{4}\s\d{4}\b'
        )

        # Employee / Student ID patterns (e.g. EMP-12345, STU98765, ID: A123456)
        self.id_pattern = re.compile(
            r'\b(?:EMP|STU|ID|EMPLOYEE|STUDENT|STAFF)[-_:\s#]?([A-Z0-9]{4,10})\b',
            re.IGNORECASE
        )

        # Credit / Debit Cards (Visa, Mastercard, Amex, Discover)
        self.card_pattern = re.compile(
            r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b|'
            r'\b(?:\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4})\b'
        )

        # IPv4 addresses
        self.ipv4_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )

        # Physical street addresses (common English indicators)
        self.address_pattern = re.compile(
            r'\b\d{1,5}\s+[A-Za-z0-9\s,.-]{2,35}\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Circle|Cir)\b',
            re.IGNORECASE
        )

    def scan_text(self, text: str) -> List[Finding]:
        """Scans input string and returns detected PII findings."""
        if not text or not isinstance(text, str):
            return []

        findings: List[Finding] = []
        lines = text.split("\n")

        for line_idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            # 1. Emails
            for match in self.email_pattern.finditer(line):
                matched = match.group(0)
                # Filter out obvious false positives like example.com or domain.ext
                if not matched.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg")):
                    findings.append(Finding(
                        category="Email Address",
                        matched_text=matched,
                        masked_text=mask_string(matched, "Email Address"),
                        risk_level="MEDIUM",
                        score_weight=25,
                        location=f"Line {line_idx}",
                        line_number=line_idx,
                        why_it_matters="Direct personal contact email exposed to public scrutiny.",
                        potential_consequence="Spam campaigns, credential stuffing correlation, and targeted phishing.",
                        recommended_action="Mask the email address before sharing."
                    ))

            # 2. Credit Card check with Luhn validation
            for match in self.card_pattern.finditer(line):
                matched = match.group(0)
                cleaned_num = re.sub(r"\D", "", matched)
                if verify_luhn(cleaned_num):
                    findings.append(Finding(
                        category="Credit Card Number",
                        matched_text=matched,
                        masked_text=mask_string(matched, "Credit Card Number"),
                        risk_level="HIGH",
                        score_weight=50,
                        location=f"Line {line_idx}",
                        line_number=line_idx,
                        why_it_matters="Valid payment card number with verified Luhn checksum.",
                        potential_consequence="Unauthorized transactions, banking fraud, and identity theft.",
                        recommended_action="Redact all payment card details immediately."
                    ))

            # 3. SSN
            for match in self.ssn_pattern.finditer(line):
                matched = match.group(0)
                findings.append(Finding(
                    category="Social Security Number (SSN)",
                    matched_text=matched,
                    masked_text=mask_string(matched, "Social Security Number (SSN)"),
                    risk_level="HIGH",
                    score_weight=50,
                    location=f"Line {line_idx}",
                    line_number=line_idx,
                    why_it_matters="Government-issued social identifier.",
                    potential_consequence="Severe identity theft, tax fraud, and unauthorized credit applications.",
                    recommended_action="Completely remove or redact this identifier."
                ))

            # 4. National ID / Aadhaar
            for match in self.national_id_pattern.finditer(line):
                matched = match.group(0)
                findings.append(Finding(
                    category="National Identity ID",
                    matched_text=matched,
                    masked_text=mask_string(matched, "National Identity ID"),
                    risk_level="HIGH",
                    score_weight=45,
                    location=f"Line {line_idx}",
                    line_number=line_idx,
                    why_it_matters="National identity number format detected.",
                    potential_consequence="Government impersonation and biometric record linkage risk.",
                    recommended_action="Remove or mask the 12-digit number."
                ))

            # 5. Phone numbers
            for match in self.phone_pattern.finditer(line):
                matched = match.group(0).strip()
                digits = re.sub(r"\D", "", matched)
                # Only accept legitimate phone length (10-15 digits) and avoid common numbers/dates
                if 10 <= len(digits) <= 15 and not matched.startswith("202") and not matched.startswith("199"):
                    # Check if already caught by credit card
                    if not any(f.matched_text in matched for f in findings if f.category == "Credit Card Number"):
                        findings.append(Finding(
                            category="Phone Number",
                            matched_text=matched,
                            masked_text=mask_string(matched, "Phone Number"),
                            risk_level="MEDIUM",
                            score_weight=20,
                            location=f"Line {line_idx}",
                            line_number=line_idx,
                            why_it_matters="Direct telephone or SMS communication endpoint.",
                            potential_consequence="Unsolicited telemarketing, SIM swapping, and smishing attacks.",
                            recommended_action="Redact telephone digits before distributing."
                        ))

            # 6. Employee or Student IDs
            for match in self.id_pattern.finditer(line):
                matched = match.group(0)
                findings.append(Finding(
                    category="Student/Employee ID",
                    matched_text=matched,
                    masked_text=mask_string(matched, "Student/Employee ID"),
                    risk_level="MEDIUM",
                    score_weight=20,
                    location=f"Line {line_idx}",
                    line_number=line_idx,
                    why_it_matters="Internal institutional or corporate identifier.",
                    potential_consequence="Internal system impersonation and targeted corporate reconnaissance.",
                    recommended_action="Mask internal employee or student badge numbers."
                ))

            # 7. IP Addresses
            for match in self.ipv4_pattern.finditer(line):
                matched = match.group(0)
                try:
                    ip_obj = ipaddress.ip_address(matched)
                    is_private = ip_obj.is_private or ip_obj.is_loopback
                    is_special = ip_obj.is_reserved or ip_obj.is_multicast
                    
                    # Avoid flagging version numbers like 1.0.0.1 or 0.0.0.0 unnecessarily unless context suggests network
                    if matched in ["0.0.0.0", "255.255.255.255"]:
                        continue

                    if is_private:
                        findings.append(Finding(
                            category="Private/Internal IP Address",
                            matched_text=matched,
                            masked_text=mask_string(matched, "IP Address"),
                            risk_level="MEDIUM",
                            score_weight=20,
                            location=f"Line {line_idx}",
                            line_number=line_idx,
                            why_it_matters="Internal subnet or loopback IP address exposed.",
                            potential_consequence="Reveals internal network topology and LAN routing structure to adversaries.",
                            recommended_action="Replace private IP addresses with generic placeholders (e.g., 192.168.X.X)."
                        ))
                    else:
                        findings.append(Finding(
                            category="Public IP Address",
                            matched_text=matched,
                            masked_text=mask_string(matched, "IP Address"),
                            risk_level="LOW",
                            score_weight=10,
                            location=f"Line {line_idx}",
                            line_number=line_idx,
                            why_it_matters="Publicly routable IP address visible in content.",
                            potential_consequence="Port scanning, DDoS targeting, or geolocation mapping.",
                            recommended_action="Verify if this server IP is intended to be public."
                        ))
                except ValueError:
                    pass

            # 8. Physical street addresses
            for match in self.address_pattern.finditer(line):
                matched = match.group(0)
                findings.append(Finding(
                    category="Physical Address",
                    matched_text=matched,
                    masked_text=mask_string(matched, "Physical Address"),
                    risk_level="MEDIUM",
                    score_weight=25,
                    location=f"Line {line_idx}",
                    line_number=line_idx,
                    why_it_matters="Physical residential or commercial geographic location.",
                    potential_consequence="Stalking, physical security compromise, and real-world harassment.",
                    recommended_action="Blur or remove physical street addresses."
                ))

        return findings
