"""
PrivacyGuard X - File Utilities
Provides safe path handling, sanitization, report generation, and temporary storage management.
"""

import os
import re
import json
import shutil
from datetime import datetime
from typing import Dict, Any, List, Optional

TEMP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "temp")


def ensure_temp_dir() -> str:
    """Ensures temp directory exists."""
    os.makedirs(TEMP_DIR, exist_ok=True)
    return TEMP_DIR


def sanitize_filename(filename: str) -> str:
    """Sanitizes filename against path traversal and forbidden characters."""
    base = os.path.basename(filename)
    cleaned = re.sub(r'[\\/*?:"<>|]', "", base)
    cleaned = cleaned.replace("..", "").strip()
    return cleaned if cleaned else "safe_document.txt"


def clear_temp_directory() -> int:
    """Safely cleans all temporary files."""
    count = 0
    if os.path.exists(TEMP_DIR):
        for f in os.listdir(TEMP_DIR):
            fpath = os.path.join(TEMP_DIR, f)
            try:
                if os.path.isfile(fpath) or os.path.islink(fpath):
                    os.unlink(fpath)
                    count += 1
                elif os.path.isdir(fpath):
                    shutil.rmtree(fpath)
                    count += 1
            except Exception:
                pass
    return count


def generate_audit_report_json(scan_data: Dict[str, Any]) -> str:
    """Generates structured JSON audit report."""
    report = {
        "generator": "PrivacyGuard X — On-Device AI Digital Safety Copilot",
        "generated_at": datetime.now().isoformat(),
        "scan_metadata": {
            "scan_id": scan_data.get("scan_id"),
            "file_name": scan_data.get("file_name"),
            "file_type": scan_data.get("file_type"),
            "risk_score": scan_data.get("risk_score"),
            "risk_level": scan_data.get("risk_level"),
            "action_taken": scan_data.get("action_taken"),
            "findings_count": scan_data.get("findings_count")
        },
        "reasons": scan_data.get("reasons", []),
        "findings": scan_data.get("findings", [])
    }
    return json.dumps(report, indent=2)


def generate_audit_report_markdown(scan_data: Dict[str, Any]) -> str:
    """Generates a professional Markdown audit summary."""
    md = [
        "# PrivacyGuard X — Digital Safety Audit Report",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**File / Target:** `{scan_data.get('file_name', 'Untitled')}`",
        f"**Scan Type:** {scan_data.get('scan_type', 'Direct Analysis')}",
        f"**Risk Level:** **{scan_data.get('risk_level', 'LOW')}** (Score: {scan_data.get('risk_score', 0)}/100)",
        f"**Action Executed:** {scan_data.get('action_taken', 'Reviewed')}",
        "\n---\n",
        "## Executive Summary",
        scan_data.get("summary", "Analysis completed on-device."),
        "\n### Key Reasons & Observations:",
    ]
    for r in scan_data.get("reasons", []):
        md.append(f"- {r}")

    findings = scan_data.get("findings", [])
    if findings:
        md.append("\n## Detected Findings Breakdown\n")
        md.append("| # | Category | Location | Risk | Recommendation |")
        md.append("|---|---|---|---|---|")
        for idx, f in enumerate(findings, start=1):
            cat = f.get("category", "General")
            loc = f.get("location", "Body")
            lvl = f.get("risk_level", "LOW")
            rec = f.get("recommended_action", "Review")
            md.append(f"| {idx} | {cat} | {loc} | {lvl} | {rec} |")

    md.append("\n---\n*PrivacyGuard X processes content locally. No data was transmitted to external cloud services.*")
    return "\n".join(md)
