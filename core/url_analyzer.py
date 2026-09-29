"""
PrivacyGuard X - Safe URL Analyzer
Performs safe, strictly non-invasive URL static inspection and structural risk assessment.
Does NOT perform intrusive scanning, penetration testing, fuzzing, or attacks against any server.
Advisory Disclaimer:
"This is a risk assessment, not a guarantee that a website is safe or malicious."
"""

import urllib.parse
import re
import ipaddress
from typing import Dict, Any, List
from .risk_engine import Finding, calculate_risk_score, RiskAssessment


class URLAnalyzer:
    """Safe, non-invasive risk analyzer for URLs."""

    SUSPICIOUS_TLDS = {
        ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".work",
        ".click", ".rest", ".fit", ".buzz", ".monster", ".bar"
    }

    RISKY_PARAMS = {
        "token", "apikey", "api_key", "secret", "auth", "access_token",
        "key", "password", "passwd", "session_id", "jwt", "bearer"
    }

    def analyze(self, raw_url: str, check_connectivity: bool = False) -> Dict[str, Any]:
        """
        Analyzes a URL for privacy, deception, and configuration risks.
        """
        raw_url = raw_url.strip() if raw_url else ""
        if not raw_url:
            return {
                "valid": False,
                "error": "URL cannot be empty.",
                "disclaimer": "This is a risk assessment, not a guarantee that a website is safe or malicious."
            }

        # Normalize prefix if scheme is missing
        parsed_test = urllib.parse.urlparse(raw_url)
        if not parsed_test.scheme:
            target_url = "https://" + raw_url
            has_explicit_scheme = False
        else:
            target_url = raw_url
            has_explicit_scheme = True

        try:
            parsed = urllib.parse.urlparse(target_url)
            hostname = parsed.hostname or ""
            scheme = parsed.scheme.lower()
            port = parsed.port
            query = parsed.query
            username = parsed.username
            password = parsed.password
        except Exception as e:
            return {
                "valid": False,
                "error": f"Invalid URL formatting: {str(e)}",
                "disclaimer": "This is a risk assessment, not a guarantee that a website is safe or malicious."
            }

        findings: List[Finding] = []

        # 1. Scheme Check (HTTP vs HTTPS)
        if scheme == "http":
            findings.append(Finding(
                category="Insecure Protocol (HTTP)",
                matched_text="http://",
                masked_text="http://",
                risk_level="MEDIUM",
                score_weight=30,
                location="URL Scheme",
                why_it_matters="Transfers data in cleartext without TLS cryptographic encryption.",
                potential_consequence="Vulnerable to Wi-Fi eavesdropping, man-in-the-middle (MitM) packet inspection, and packet tampering.",
                recommended_action="Ensure the target service supports HTTPS and update the link to https://"
            ))

        # 2. Embedded Credentials in URL
        if username or password:
            findings.append(Finding(
                category="Embedded Credentials in URL",
                matched_text=f"{username}:{password}@" if password else f"{username}@",
                masked_text="[USER:PASS_REDACTED]@",
                risk_level="HIGH",
                score_weight=50,
                location="URL Authority",
                why_it_matters="Cleartext username or password embedded directly in the URL address.",
                potential_consequence="Credentials are saved into browser histories, web server access logs, and referrer headers.",
                recommended_action="Never include authentication credentials in shareable URLs."
            ))

        # 3. Direct IP Address Hostname Check
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if ip_obj.is_private or ip_obj.is_loopback:
                findings.append(Finding(
                    category="Internal Subnet Address",
                    matched_text=hostname,
                    masked_text="192.168.X.X",
                    risk_level="MEDIUM",
                    score_weight=30,
                    location="URL Hostname",
                    why_it_matters="Points to a local intranet or loopback address (e.g., 127.0.0.1, 192.168.x.x, 10.x.x.x).",
                    potential_consequence="Accessible only inside your private network; sharing it with external parties will fail and leaks internal network topology.",
                    recommended_action="Replace with public domain name or remove."
                ))
            else:
                findings.append(Finding(
                    category="Direct IP Hostname",
                    matched_text=hostname,
                    masked_text="XXX.XXX.XXX.XXX",
                    risk_level="MEDIUM",
                    score_weight=25,
                    location="URL Hostname",
                    why_it_matters="URL uses a raw public IP address instead of a registered domain name.",
                    potential_consequence="Frequently associated with unverified infrastructure, phishing drops, or bypass of domain reputation checks.",
                    recommended_action="Verify domain ownership before accessing."
                ))
        except ValueError:
            # Hostname is a standard domain, check other attributes
            pass

        # 4. Punycode / Internationalized Domain Name (Homograph deception)
        if hostname.startswith("xn--") or ".xn--" in hostname:
            findings.append(Finding(
                category="Punycode / Homograph Pattern",
                matched_text=hostname,
                masked_text=hostname,
                risk_level="HIGH",
                score_weight=45,
                location="URL Hostname",
                why_it_matters="Domain uses Punycode encoding (xn--), which can visually mimic legitimate character glyphs.",
                potential_consequence="High risk of IDN homograph phishing (e.g., visually identical Cyrillic 'a' replacing Latin 'a').",
                recommended_action="Inspect the decoded unicode domain carefully before clicking."
            ))

        # 5. Suspicious TLD Check
        for tld in self.SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                findings.append(Finding(
                    category="Uncommon / High-Abuse TLD",
                    matched_text=tld,
                    masked_text=tld,
                    risk_level="LOW",
                    score_weight=15,
                    location="Domain Suffix",
                    why_it_matters=f"Domain ends in {tld}, a suffix with historically elevated spam and abuse rates.",
                    potential_consequence="Higher statistical incidence of short-lived malicious campaigns.",
                    recommended_action="Double-check the identity and reputation of the entity operating this site."
                ))
                break

        # 6. Sensitive / Credential Query Parameters
        if query:
            query_params = urllib.parse.parse_qs(query)
            for param, values in query_params.items():
                param_lower = param.lower()
                if param_lower in self.RISKY_PARAMS:
                    findings.append(Finding(
                        category="Authentication Parameter in Query",
                        matched_text=f"{param}={values[0] if values else ''}",
                        masked_text=f"{param}=[REDACTED_PARAM_VAL]",
                        risk_level="HIGH",
                        score_weight=40,
                        location="URL Query String",
                        why_it_matters=f"Query parameter '{param}' appears to carry an authentication token or secret key.",
                        potential_consequence="Exposes temporary login sessions or API authorizations in browser history and referral links.",
                        recommended_action=f"Strip the '{param}' parameter from the URL before sharing."
                    ))

        # 7. Non-standard HTTP ports
        if port and port not in [80, 443, 8080, 8443]:
            findings.append(Finding(
                category="Non-Standard Port",
                matched_text=f":{port}",
                masked_text=f":{port}",
                risk_level="LOW",
                score_weight=10,
                location="URL Port",
                why_it_matters=f"Service running on custom port :{port}.",
                potential_consequence="Often indicates development servers, internal admin panels, or atypical listening services.",
                recommended_action="Confirm if port is intended for public consumption."
            ))

        assessment = calculate_risk_score(findings)

        # Non-invasive HTTP status check (optional safe ping)
        connectivity_status = "Not probed (Safe static inspection only)"
        if check_connectivity:
            try:
                import requests
                # Safe non-invasive HEAD request with 2.5s timeout
                resp = requests.head(target_url, timeout=2.5, allow_redirects=True, headers={"User-Agent": "PrivacyGuardX-SafetyCopilot/1.0"})
                connectivity_status = f"Reachable (HTTP {resp.status_code})"
            except Exception as e:
                connectivity_status = f"Unreachable or blocked ({type(e).__name__})"

        return {
            "valid": True,
            "url": target_url,
            "hostname": hostname,
            "scheme": scheme,
            "assessment": assessment,
            "findings": findings,
            "connectivity_status": connectivity_status,
            "disclaimer": "This is a risk assessment, not a guarantee that a website is safe or malicious."
        }
