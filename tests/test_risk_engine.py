"""Unit tests for PrivacyGuard X Risk Engine."""
import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.risk_engine import Finding, calculate_risk_score, RiskLevel


def test_clean_content_score():
    assessment = calculate_risk_score([])
    assert assessment.score == 0
    assert assessment.risk_level == RiskLevel.CLEAN.value
    assert len(assessment.reasons) > 0
    assert assessment.high_risk_count == 0


def test_high_risk_credential_score():
    findings = [
        Finding(
            category="OpenAI API Key",
            matched_text="sk-proj-demo12345678901234567890",
            masked_text="sk-...890",
            risk_level="HIGH",
            score_weight=50,
            location="Line 1",
            why_it_matters="API key exposure",
            potential_consequence="Financial billing abuse",
            recommended_action="Rotate immediately"
        )
    ]
    assessment = calculate_risk_score(findings, sensitivity="Balanced")
    assert assessment.score >= 70
    assert assessment.risk_level == RiskLevel.HIGH.value
    assert assessment.high_risk_count == 1
    assert any("API" in r for r in assessment.reasons)


def test_medium_risk_pii_score():
    findings = [
        Finding(
            category="Email Address",
            matched_text="test@example.com",
            masked_text="t***t@example.com",
            risk_level="MEDIUM",
            score_weight=25,
            location="Line 4",
            why_it_matters="Direct email",
            potential_consequence="Spam",
            recommended_action="Mask email"
        )
    ]
    assessment = calculate_risk_score(findings, sensitivity="Balanced")
    assert 40 <= assessment.score < 70
    assert assessment.risk_level == RiskLevel.MEDIUM.value
    assert assessment.med_risk_count == 1


def test_sensitivity_adjustments():
    findings = [
        Finding(
            category="Public IP Address",
            matched_text="8.8.8.8",
            masked_text="8.8.8.8",
            risk_level="LOW",
            score_weight=15,
            location="Line 1",
            why_it_matters="Public IP",
            potential_consequence="Recon",
            recommended_action="Verify"
        )
    ]
    strict = calculate_risk_score(findings, sensitivity="Strict")
    permissive = calculate_risk_score(findings, sensitivity="Permissive")
    assert strict.score >= permissive.score
