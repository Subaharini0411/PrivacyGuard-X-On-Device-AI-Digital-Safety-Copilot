"""Unit tests for PrivacyGuard X PII & Secret Detectors."""
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.pii_detector import PIIDetector, verify_luhn
from core.secret_detector import SecretDetector, calculate_shannon_entropy


def test_verify_luhn():
    # Known valid test card numbers (Luhn checksum verified)
    assert verify_luhn("4532015012345671") is True
    # Known invalid number
    assert verify_luhn("4532015012345674") is False


def test_pii_detection():
    detector = PIIDetector()
    text = (
        "Hello, my email is alice@company.com and my phone number is +1 415-555-0199.\n"
        "My SSN is 123-45-6789 and my employee ID is EMP-99882.\n"
        "Internal router is at 192.168.1.1."
    )
    findings = detector.scan_text(text)
    categories = [f.category for f in findings]

    assert "Email Address" in categories
    assert "Phone Number" in categories
    assert "Social Security Number (SSN)" in categories
    assert "Student/Employee ID" in categories
    assert "Private/Internal IP Address" in categories


def test_secret_detection():
    detector = SecretDetector()
    text = (
        'OPENAI_API_KEY = "sk-proj-demo987349182347192847129384712398demo"\n'
        'AWS_ACCESS_KEY_ID = "AKIA12345678EXAMPLE0"\n'
        'DB_PASS = "super_secret_db_pass_2026"\n'
        'DATABASE_URL = "postgres://admin:pass123@localhost:5432/my_db"'
    )
    findings = detector.scan_text(text)
    categories = [f.category for f in findings]

    assert "OpenAI API Key" in categories
    assert "AWS Access Key ID" in categories
    assert "Password / Credential" in categories
    assert "Database Connection String" in categories


def test_shannon_entropy():
    # Low entropy repeating string
    low = calculate_shannon_entropy("aaaaaaaaaaaaaaaa")
    # High entropy random string
    high = calculate_shannon_entropy("4fK9!xQ7z$pL2#vB9@mN")
    assert high > low
    assert low == 0.0
