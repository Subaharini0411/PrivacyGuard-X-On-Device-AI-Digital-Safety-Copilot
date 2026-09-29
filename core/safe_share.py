"""
PrivacyGuard X - Safe Share Mode
Gatekeeper workflow that performs an immediate on-device safety triage check
before digital material is transmitted, copied, or uploaded.
Enforces zero-upload policies and guarantees user autonomy.
"""

from typing import Dict, Any, List
from .risk_engine import Finding, calculate_risk_score, RiskAssessment, RiskLevel
from .pii_detector import PIIDetector
from .secret_detector import SecretDetector


class SafeShareGatekeeper:
    """Triage gatekeeper for preemptive pre-sharing safety checks."""

    def __init__(self):
        self.pii_detector = PIIDetector()
        self.secret_detector = SecretDetector()

    def evaluate(self, content: str, content_type: str = "text", sensitivity: str = "Balanced") -> Dict[str, Any]:
        """
        Runs comprehensive scan and produces Safe Share Check status.
        """
        if not content or not content.strip():
            return {
                "status": "EMPTY",
                "verdict_badge": "⚪ Empty Content",
                "verdict_message": "No content provided to evaluate.",
                "assessment": None,
                "findings": [],
                "can_proceed": False
            }

        pii_findings = self.pii_detector.scan_text(content)
        secret_findings = self.secret_detector.scan_text(content)
        all_findings: List[Finding] = pii_findings + secret_findings

        assessment: RiskAssessment = calculate_risk_score(all_findings, sensitivity=sensitivity)

        if assessment.risk_level == RiskLevel.HIGH.value:
            verdict_badge = "🔴 Sensitive Information Detected"
            verdict_color = "red"
            verdict_message = (
                "CRITICAL WARNING: High-risk secrets, authentication tokens, or sensitive credentials "
                "were detected in this content. Sharing this could compromise accounts, private data, or infrastructure."
            )
            recommendation = "Protect content immediately (Mask / Redact) before sharing."
        elif assessment.risk_level == RiskLevel.MEDIUM.value:
            verdict_badge = "⚠️ Review Recommended"
            verdict_color = "amber"
            verdict_message = (
                "ATTENTION: Personally identifiable information (PII) or internal networking items "
                "were found. We recommend reviewing these before sending."
            )
            recommendation = "Review the highlighted items and mask personal contact information."
        elif assessment.risk_level == RiskLevel.LOW.value:
            verdict_badge = "🟡 Minor Exposure Detected"
            verdict_color = "yellow"
            verdict_message = (
                "LOW RISK: Minor exposure patterns found. Review recommended if sharing in public forums."
            )
            recommendation = "Inspect details to ensure informational patterns are safe for your audience."
        else:
            verdict_badge = "🟢 No Obvious Sensitive Information Detected"
            verdict_color = "green"
            verdict_message = (
                "CLEAR: Local safety patterns found no credentials, passwords, or personal identity identifiers."
            )
            recommendation = "Safe to share based on local rules."

        return {
            "status": assessment.risk_level,
            "verdict_badge": verdict_badge,
            "verdict_color": verdict_color,
            "verdict_message": verdict_message,
            "recommendation": recommendation,
            "assessment": assessment,
            "findings": all_findings,
            "can_proceed": True
        }
