"""
PrivacyGuard X - Document Scanner
Extracts text from PDF and text-based documents (txt, md, json, csv, log, env, py, etc.),
analyzes each page/section for privacy and security risks, and exports sanitized copies.
Preserves original files without destructive modification.
"""

import os
import io
from typing import Dict, Any, List, Tuple
from .risk_engine import Finding, calculate_risk_score, RiskAssessment
from .pii_detector import PIIDetector
from .secret_detector import SecretDetector


class DocumentScanner:
    """Document risk analyzer and sanitizer for PDF and text files."""

    SUPPORTED_EXTENSIONS = {
        ".pdf", ".txt", ".md", ".json", ".csv", ".log",
        ".env", ".yaml", ".yml", ".xml", ".html", ".py", ".js", ".ts", ".sh"
    }

    def __init__(self):
        self.pii_detector = PIIDetector()
        self.secret_detector = SecretDetector()

    def extract_text_from_file(self, file_bytes: bytes, filename: str) -> List[Tuple[int, str]]:
        """
        Extracts pages of text from file bytes.
        Returns a list of tuples: [(page_number, text_content), ...]
        """
        ext = os.path.splitext(filename)[1].lower()
        pages: List[Tuple[int, str]] = []

        if ext == ".pdf":
            try:
                import pypdf
                reader = pypdf.PdfReader(io.BytesIO(file_bytes))
                if len(reader.pages) == 0:
                    return [(1, "")]
                for idx, page in enumerate(reader.pages, start=1):
                    extracted = page.extract_text() or ""
                    pages.append((idx, extracted))
            except Exception as e:
                # Fallback: attempt basic utf-8 / latin-1 stream decoding
                try:
                    raw_text = file_bytes.decode("utf-8", errors="ignore")
                    pages.append((1, raw_text))
                except Exception:
                    raise ValueError(f"Unable to parse PDF document ({str(e)}). File may be corrupted or encrypted.")
        else:
            # Plain text or code file
            try:
                text = file_bytes.decode("utf-8")
            except UnicodeDecodeError:
                text = file_bytes.decode("latin-1", errors="replace")
            pages.append((1, text))

        return pages

    def scan_document(self, file_bytes: bytes, filename: str, sensitivity: str = "Balanced") -> Dict[str, Any]:
        """
        Scans a document and generates detailed page-level and global findings.
        """
        if not file_bytes:
            return {
                "success": False,
                "error": "Document file is empty (0 bytes).",
                "filename": filename
            }

        ext = os.path.splitext(filename)[1].lower()
        if ext not in self.SUPPORTED_EXTENSIONS:
            return {
                "success": False,
                "error": f"Unsupported format '{ext}'. Supported formats: {', '.join(sorted(self.SUPPORTED_EXTENSIONS))}",
                "filename": filename
            }

        try:
            pages = self.extract_text_from_file(file_bytes, filename)
        except Exception as e:
            return {
                "success": False,
                "error": f"Unable to process this file: {str(e)}. Try another file.",
                "filename": filename
            }

        all_findings: List[Finding] = []
        page_summaries = []

        for page_num, page_text in pages:
            if not page_text.strip():
                continue

            pii_findings = self.pii_detector.scan_text(page_text)
            secret_findings = self.secret_detector.scan_text(page_text)

            page_findings = pii_findings + secret_findings

            # Enrich location with page number if multi-page
            for f in page_findings:
                if len(pages) > 1:
                    f.location = f"Page {page_num}, {f.location}"
                all_findings.append(f)

            page_assessment = calculate_risk_score(page_findings, sensitivity=sensitivity)
            page_summaries.append({
                "page_num": page_num,
                "findings_count": len(page_findings),
                "risk_level": page_assessment.risk_level,
                "preview": page_text[:200].strip() + ("..." if len(page_text) > 200 else "")
            })

        global_assessment = calculate_risk_score(all_findings, sensitivity=sensitivity)

        return {
            "success": True,
            "filename": filename,
            "page_count": len(pages),
            "findings_count": len(all_findings),
            "assessment": global_assessment,
            "findings": all_findings,
            "pages": pages,
            "page_summaries": page_summaries
        }

    def create_sanitized_copy(self, pages: List[Tuple[int, str]], findings: List[Finding], original_filename: str) -> Tuple[bytes, str]:
        """
        Creates a privacy-sanitized copy of the document text.
        Returns: (sanitized_bytes, new_filename)
        """
        name_part, ext = os.path.splitext(original_filename)
        sanitized_filename = f"{name_part}_protected.txt"

        sanitized_pages = []
        for page_num, text in pages:
            sanitized_text = text
            # Replace findings with their masked representation
            for f in findings:
                if f.matched_text in sanitized_text:
                    sanitized_text = sanitized_text.replace(f.matched_text, f"[{f.category.upper()}: REDACTED]")
            sanitized_pages.append(f"--- PAGE {page_num} ---\n{sanitized_text}\n")

        full_sanitized_doc = "\n".join(sanitized_pages)
        return full_sanitized_doc.encode("utf-8"), sanitized_filename
