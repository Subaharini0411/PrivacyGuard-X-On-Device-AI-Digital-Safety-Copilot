"""
PrivacyGuard X - Risk Engine
Unified Explainable Risk Classification & Scoring System.
Calculates transparent 0-100 risk scores with human-readable rationale.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional


class RiskLevel(str, Enum):
    CLEAN = "CLEAN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class Finding:
    category: str
    matched_text: str
    masked_text: str
    risk_level: str  # HIGH, MEDIUM, LOW
    score_weight: int
    location: str
    why_it_matters: str
    potential_consequence: str
    recommended_action: str
    line_number: Optional[int] = None
    extra_meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Avoid storing full raw matched secret in logs/persistence if high risk
        if self.risk_level == "HIGH" and len(self.matched_text) > 4:
            d["matched_snippet"] = self.matched_text[:2] + "..." + self.matched_text[-2:]
        else:
            d["matched_snippet"] = self.masked_text
        return d


@dataclass
class RiskAssessment:
    score: int  # 0 to 100
    risk_level: str  # CLEAN, LOW, MEDIUM, HIGH
    reasons: List[str]
    findings: List[Finding]
    summary: str
    action_advice: str

    @property
    def high_risk_count(self) -> int:
        return sum(1 for f in self.findings if f.risk_level == "HIGH")

    @property
    def med_risk_count(self) -> int:
        return sum(1 for f in self.findings if f.risk_level == "MEDIUM")

    @property
    def low_risk_count(self) -> int:
        return sum(1 for f in self.findings if f.risk_level == "LOW")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "risk_level": self.risk_level,
            "reasons": self.reasons,
            "findings_count": len(self.findings),
            "high_risk_count": self.high_risk_count,
            "med_risk_count": self.med_risk_count,
            "low_risk_count": self.low_risk_count,
            "summary": self.summary,
            "action_advice": self.action_advice,
            "findings": [f.to_dict() for f in self.findings]
        }


def calculate_risk_score(findings: List[Finding], sensitivity: str = "Balanced") -> RiskAssessment:
    """
    Computes deterministic, fully explainable risk scores from 0 to 100.
    Does NOT generate arbitrary or random numbers.
    
    Sensitivity factors:
      - Strict: Amplifies minor risk indicators (x1.25)
      - Balanced: Standard calibrated weights (x1.0)
      - Permissive: Focuses primarily on explicit credentials (x0.75)
    """
    if not findings:
        return RiskAssessment(
            score=0,
            risk_level=RiskLevel.CLEAN.value,
            reasons=["No obvious sensitive information or secrets were detected."],
            findings=[],
            summary="Content appears safe to share based on local safety patterns.",
            action_advice="Safe to share. No remediation required."
        )

    sensitivity_multipliers = {
        "Strict": 1.25,
        "Balanced": 1.0,
        "Permissive": 0.75
    }
    multiplier = sensitivity_multipliers.get(sensitivity, 1.0)

    raw_score = 0
    reasons: List[str] = []
    high_count = 0
    med_count = 0
    low_count = 0

    # Tally findings and derive explainable score
    for f in findings:
        weight = f.score_weight
        if f.risk_level == "HIGH":
            high_count += 1
            raw_score += int(weight * multiplier)
        elif f.risk_level == "MEDIUM":
            med_count += 1
            raw_score += int(weight * multiplier)
        else:
            low_count += 1
            raw_score += int(weight * multiplier)

    # Base minimum score floors if high or medium risk items exist
    if high_count > 0:
        raw_score = max(raw_score, 75 + min((high_count - 1) * 7, 25))
    elif med_count > 0:
        raw_score = max(raw_score, 45 + min((med_count - 1) * 5, 24))
    elif low_count > 0:
        raw_score = max(raw_score, 15 + min((low_count - 1) * 4, 20))

    final_score = min(max(raw_score, 0), 100)

    # Determine risk level
    if final_score >= 70:
        level = RiskLevel.HIGH.value
        summary = "Potential high-risk credentials, secrets, or identity records detected."
        advice = "DO NOT share publicly. Mask or remove all credentials before proceeding."
    elif final_score >= 40:
        level = RiskLevel.MEDIUM.value
        summary = "Personal identifiers or internal technical details detected."
        advice = "Review recommended. Consider redacting personal details or private IPs."
    else:
        level = RiskLevel.LOW.value
        summary = "Minor exposure or low-sensitivity informational patterns detected."
        advice = "Low safety impact, but verify that detected items are intended for sharing."

    # Construct explainable reasons
    if high_count > 0:
        reasons.append(f"Detected {high_count} potential credential or secret pattern(s) (API keys, tokens, or passwords).")
    if med_count > 0:
        reasons.append(f"Detected {med_count} personal identifier(s) or private networking reference(s) (emails, phone numbers, or private IPs).")
    if low_count > 0:
        reasons.append(f"Detected {low_count} informational or public pattern(s) that may provide contextual reconnaissance.")

    # Specific category highlights
    categories_present = set(f.category for f in findings)
    if "API Key" in categories_present or "Access Token" in categories_present:
        reasons.append("Authentication tokens detected: If active, these could grant unauthorized API access.")
    if "Database Credential" in categories_present:
        reasons.append("Database connection strings or passwords detected: Risk of unauthorized data access.")
    if "Private Key" in categories_present:
        reasons.append("Cryptographic private key detected: Severe risk of identity impersonation or decrypting secure sessions.")
    if "Credit Card Number" in categories_present:
        reasons.append("Payment card number detected with valid Luhn checksum: High financial fraud risk.")
    if "Email Address" in categories_present or "Phone Number" in categories_present:
        reasons.append("Direct contact PII detected: Risk of spam, phishing, or social engineering.")

    return RiskAssessment(
        score=final_score,
        risk_level=level,
        reasons=reasons,
        findings=findings,
        summary=summary,
        action_advice=advice
    )
