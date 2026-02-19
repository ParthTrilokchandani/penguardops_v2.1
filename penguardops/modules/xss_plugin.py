"""
Cross-Site Scripting (XSS) Scanner Module
Detects reflected and stored XSS via parameter injection and form fuzzing.
"""

import re
import hashlib
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.base_plugin import BasePlugin, Finding
from utils.logger import get_logger

logger = get_logger("xss")

# ── Payloads ─────────────────────────────────────────────────────────────────

# Canary-style: we'll look for these exact strings reflected back
XSS_CANARY = "VULNSCAN_XSS_"

XSS_PAYLOADS = [
    # Basic reflection test
    f'<{XSS_CANARY}TAG>',
    # Script injection
    f'<script>{XSS_CANARY}SCRIPT</script>',
    f'<ScRipT>{XSS_CANARY}MIXED</ScRipT>',
    # Event handlers
    f'" onmouseover="{XSS_CANARY}EVENT" x="',
    f"' onmouseover='{XSS_CANARY}EVENT' x='",
    f'"><img src=x onerror="{XSS_CANARY}IMG">',
    f"'><img src=x onerror='{XSS_CANARY}IMG'>",
    # Template injection markers
    f'{{{{7*7}}}}',
    # JS injection
    f'javascript:{XSS_CANARY}PROTO',
    # SVG
    f'<svg onload="{XSS_CANARY}SVG">',
    # Body injection
    f'</title><script>{XSS_CANARY}TITLE</script>',
    f'</textarea><script>{XSS_CANARY}TEXTAREA</script>',
    # Encoded
    f'%3Cscript%3E{XSS_CANARY}ENC%3C/script%3E',
    # HTML5
    f'<details open ontoggle="{XSS_CANARY}HTML5">',
    f'<video><source onerror="{XSS_CANARY}VIDEO">',
]

# WAF bypass XSS variants
XSS_BYPASS_PAYLOADS = [
    f'<ScRiPt sRc=data:,{XSS_CANARY}BYPASS>',
    f'<IMG SRC=# onmouseover="{XSS_CANARY}BYPASS">',
    f'<img src=1 href=1 onerror="{XSS_CANARY}BYPASS"></img>',
    f'<audio src=1 href=1 onerror="{XSS_CANARY}BYPASS"></audio>',
    f'<video src=1 href=1 onerror="{XSS_CANARY}BYPASS"></video>',
]

# DOM XSS source/sink patterns
DOM_XSS_SOURCES = [
    r"document\.location",
    r"document\.URL",
    r"document\.documentURI",
    r"window\.location",
    r"location\.search",
    r"location\.hash",
    r"document\.referrer",
]

DOM_XSS_SINKS = [
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"eval\s*\(",
    r"setTimeout\s*\(",
    r"setInterval\s*\(",
    r"new\s+Function\s*\(",
    r"\.html\s*\(",  # jQuery
    r"\.append\s*\(",
    r"\.prepend\s*\(",
    r"location\.href\s*=",
]

# Context detection patterns
CONTEXT_PATTERNS = {
    "html_attribute": re.compile(r'<[^>]+["\']?\s*=\s*["\']?' + re.escape(XSS_CANARY), re.IGNORECASE),
    "html_body":      re.compile(re.escape(XSS_CANARY), re.IGNORECASE),
    "script_context": re.compile(r'<script[^>]*>.*?' + re.escape(XSS_CANARY), re.IGNORECASE | re.DOTALL),
}


class XSSPlugin(BasePlugin):
    plugin_id = "xss"
    name = "Cross-Site Scripting"
    description = "Detects reflected XSS, DOM XSS patterns, and stored XSS indicators"
    owasp_category = "A03:2021"
    mitre_technique = "T1059.007"

    def run(self, crawl_results: Dict) -> List[Finding]:
        logger.info("Starting XSS scan")

        for url, result in crawl_results.items():
            # Test URL parameters
            if "?" in url:
                self._test_url_params(url)

            # Test forms
            for form in result.forms:
                self._test_form(form)

            # Check for DOM XSS indicators in scripts
            if result.scripts or result.url:
                self._check_dom_xss(url, result)

        logger.info(f"XSS scan complete: {len(self.findings)} findings")
        return self.findings

    def _test_url_params(self, url: str):
        """Test URL parameters for reflected XSS."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return

        for param_name in params:
            for payload in XSS_PAYLOADS:
                injected_url = self._inject_url_param(url, param_name, payload)
                resp = self.session.get(injected_url)

                if not resp:
                    continue

                reflected, context = self._is_reflected(payload, resp.text)
                if reflected:
                    sanitized = self._check_sanitization(payload, resp.text)
                    severity = "high" if not sanitized else "medium"
                    confidence = "high" if not sanitized else "medium"

                    self.add_finding(self._make_finding(
                        title=f"Reflected XSS — Parameter '{param_name}'",
                        severity=severity,
                        description=(
                            f"The parameter '{param_name}' reflects user input into the HTML response "
                            f"without adequate sanitization. Payload was reflected in context: {context}."
                        ),
                        url=url,
                        parameter=param_name,
                        method="GET",
                        payload=payload,
                        evidence=self._get_evidence_snippet(payload, resp.text),
                        cwe_id="CWE-79",
                        cvss_score=8.2 if severity == "high" else 6.1,
                        confidence=confidence,
                        remediation=self._remediation_reflected(),
                        references=self._references(),
                    ))
                    break  # One finding per param

    def _test_form(self, form):
        """Test form fields for reflected XSS."""
        from core.crawler import Form

        for field in form.fields:
            if field.field_type in ("hidden", "submit", "button", "image", "reset", "file", "select"):
                continue

            for payload in XSS_PAYLOADS[:8]:  # Limit payloads per field
                data = form.to_data()
                data[field.name] = payload

                if form.method == "POST":
                    resp = self.session.post(form.target_url, data=data)
                else:
                    from urllib.parse import urlencode
                    url = f"{form.target_url}?{urlencode(data)}"
                    resp = self.session.get(url)

                if not resp:
                    continue

                reflected, context = self._is_reflected(payload, resp.text)
                if reflected:
                    sanitized = self._check_sanitization(payload, resp.text)
                    severity = "high" if not sanitized else "medium"

                    self.add_finding(self._make_finding(
                        title=f"Reflected XSS via Form — Field '{field.name}'",
                        severity=severity,
                        description=(
                            f"Form field '{field.name}' at {form.url} reflects user input "
                            f"into the response without adequate encoding."
                        ),
                        url=form.url,
                        parameter=field.name,
                        method=form.method,
                        payload=payload,
                        evidence=self._get_evidence_snippet(payload, resp.text),
                        cwe_id="CWE-79",
                        cvss_score=8.2 if severity == "high" else 6.1,
                        confidence="high",
                        remediation=self._remediation_reflected(),
                        references=self._references(),
                    ))
                    break

    def _check_dom_xss(self, url: str, result):
        """Analyze JavaScript for DOM XSS source→sink flows."""
        resp = self.session.get(url)
        if not resp:
            return

        html = resp.text
        found_sources = []
        found_sinks = []

        for pattern in DOM_XSS_SOURCES:
            if re.search(pattern, html):
                found_sources.append(pattern)

        for pattern in DOM_XSS_SINKS:
            if re.search(pattern, html):
                found_sinks.append(pattern)

        if found_sources and found_sinks:
            self.add_finding(self._make_finding(
                title="DOM-Based XSS (Potential)",
                severity="medium",
                description=(
                    f"JavaScript code at this page reads from taint sources "
                    f"({', '.join(found_sources[:3])}) and writes to dangerous sinks "
                    f"({', '.join(found_sinks[:3])}), which may allow DOM-based XSS."
                ),
                url=url,
                method="GET",
                evidence=(
                    f"Sources: {found_sources[:3]}\nSinks: {found_sinks[:3]}"
                ),
                cwe_id="CWE-79",
                cvss_score=6.5,
                confidence="low",
                false_positive_risk="high",
                remediation=self._remediation_dom(),
                references=self._references(),
            ))

    def _is_reflected(self, payload: str, response_text: str) -> tuple:
        """Check if payload (or its canary) is reflected in response."""
        # Check for canary string (our unique marker)
        if XSS_CANARY in response_text:
            # Determine context
            for ctx_name, pattern in CONTEXT_PATTERNS.items():
                if pattern.search(response_text):
                    return True, ctx_name
            return True, "html_body"

        # Check for literal payload reflection
        if payload in response_text:
            return True, "literal"

        # Check if angle brackets survive
        if "<" in payload and ">" in payload:
            stripped_payload = payload.replace(XSS_CANARY, "")
            if stripped_payload in response_text:
                return True, "html_body"

        return False, None

    def _check_sanitization(self, payload: str, response_text: str) -> bool:
        """Check if the output appears to be HTML-encoded (reduced risk)."""
        encoded_indicators = [
            "&lt;", "&gt;", "&quot;", "&#x27;", "&amp;",
            "&#60;", "&#62;",
        ]
        for indicator in encoded_indicators:
            if indicator in response_text.lower():
                return True
        return False

    def _get_evidence_snippet(self, payload: str, response_text: str, ctx_chars: int = 200) -> str:
        """Get surrounding context of where the payload appears."""
        idx = response_text.find(XSS_CANARY)
        if idx == -1:
            idx = response_text.find(payload[:20])
        if idx == -1:
            return "Payload reflected in response"

        start = max(0, idx - ctx_chars // 2)
        end = min(len(response_text), idx + ctx_chars // 2)
        return response_text[start:end]

    def _inject_url_param(self, url: str, param_name: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _remediation_reflected(self) -> str:
        return (
            "Encode all user-controlled data before inserting into HTML output using context-aware encoding "
            "(HTML, JavaScript, CSS, URL). Implement a Content Security Policy (CSP) header. "
            "Use modern frameworks that auto-escape template variables. "
            "Validate and whitelist expected input on the server side. "
            "Set the HttpOnly and Secure flags on cookies."
        )

    def _remediation_dom(self) -> str:
        return (
            "Avoid using dangerous DOM sinks (innerHTML, document.write, eval). "
            "Use safe alternatives like textContent and createElement. "
            "Implement DOMPurify for HTML sanitization in the browser. "
            "Apply a strict Content Security Policy. "
            "Use modern JavaScript frameworks that safely handle data binding."
        )

    def _references(self) -> List[str]:
        return [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://portswigger.net/web-security/cross-site-scripting",
            "https://content-security-policy.com/",
        ]
