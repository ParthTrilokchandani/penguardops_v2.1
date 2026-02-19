"""
Base Plugin Interface — Phase 2: Plugin Architecture
All vulnerability modules implement this interface.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime


# OWASP Top 10 (2021) reference
OWASP_TOP10 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery (SSRF)",
}

# MITRE ATT&CK techniques
MITRE_ATTACK = {
    "T1190":     "Exploit Public-Facing Application",
    "T1059.007": "Command and Scripting Interpreter: JavaScript",
    "T1083":     "File and Directory Discovery",
    "T1534":     "Internal Spearphishing",
    "T1600":     "Weaken Encryption",
    "T1185":     "Browser Session Hijacking",
    "T1090":     "Proxy",
    "T1078":     "Valid Accounts",
    "T1005":     "Data from Local System",
    "T1552":     "Unsecured Credentials",
}

SEVERITY_WEIGHTS = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass
class Finding:
    """A single vulnerability finding."""
    # Core identification
    module: str
    title: str
    severity: str  # critical, high, medium, low, info
    description: str

    # Location
    url: str
    parameter: Optional[str] = None
    method: str = "GET"

    # Evidence
    payload: Optional[str] = None
    request: Optional[str] = None
    response_snippet: Optional[str] = None
    evidence: Optional[str] = None

    # Classification
    owasp_category: Optional[str] = None    # e.g. "A03:2021"
    mitre_technique: Optional[str] = None   # e.g. "T1190"
    cwe_id: Optional[str] = None            # e.g. "CWE-89"
    cvss_score: Optional[float] = None

    # Remediation
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)

    # Meta
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    confidence: str = "medium"  # high, medium, low
    false_positive_risk: str = "low"

    @property
    def severity_weight(self) -> int:
        return SEVERITY_WEIGHTS.get(self.severity, 99)

    @property
    def owasp_title(self) -> str:
        if self.owasp_category:
            return OWASP_TOP10.get(self.owasp_category, self.owasp_category)
        return ""

    @property
    def mitre_title(self) -> str:
        if self.mitre_technique:
            return MITRE_ATTACK.get(self.mitre_technique, self.mitre_technique)
        return ""

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "payload": self.payload,
            "evidence": self.evidence,
            "owasp_category": self.owasp_category,
            "owasp_title": self.owasp_title,
            "mitre_technique": self.mitre_technique,
            "mitre_title": self.mitre_title,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "remediation": self.remediation,
            "references": self.references,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }


class BasePlugin(ABC):
    """
    Abstract base for all vulnerability scanner modules.

    Every plugin must implement:
    - plugin_id: unique string identifier
    - name: human-readable name
    - description: what it tests
    - run(): main scanning method

    Plugins receive the HTTP session, config, and crawl results.
    They return a list of Finding objects.
    """

    plugin_id: str = "base"
    name: str = "Base Plugin"
    description: str = "Base vulnerability scanner plugin"
    owasp_category: str = ""
    mitre_technique: str = ""

    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.findings: List[Finding] = []

    @abstractmethod
    def run(self, crawl_results: Dict) -> List[Finding]:
        """
        Execute the scan module.

        Args:
            crawl_results: dict of url -> CrawlResult from the crawler

        Returns:
            List of Finding objects
        """
        pass

    def _make_finding(self, **kwargs) -> Finding:
        """Convenience factory that pre-fills module-level metadata."""
        kwargs.setdefault("module", self.plugin_id)
        kwargs.setdefault("owasp_category", self.owasp_category)
        kwargs.setdefault("mitre_technique", self.mitre_technique)
        return Finding(**kwargs)

    def _is_enabled(self) -> bool:
        return self.plugin_id in self.config.enabled_modules

    def _severity_passes_threshold(self, severity: str) -> bool:
        weight = SEVERITY_WEIGHTS.get(severity, 99)
        threshold = SEVERITY_WEIGHTS.get(self.config.min_severity, 4)
        return weight <= threshold

    def log_info(self, msg: str):
        from utils.logger import get_logger
        get_logger(self.plugin_id).info(msg)

    def log_debug(self, msg: str):
        from utils.logger import get_logger
        get_logger(self.plugin_id).debug(msg)

    def log_warning(self, msg: str):
        from utils.logger import get_logger
        get_logger(self.plugin_id).warning(msg)

    def add_finding(self, finding: Finding):
        if self._severity_passes_threshold(finding.severity):
            self.findings.append(finding)

    @property
    def finding_count(self) -> int:
        return len(self.findings)
