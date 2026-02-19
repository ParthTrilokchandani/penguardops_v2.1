"""
JSON Report Generator — Machine-readable output with full finding details.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict
from collections import Counter

from core.base_plugin import Finding
from core.config import ScanConfig


class JSONReporter:
    def __init__(self, config: ScanConfig):
        self.config = config

    def generate(self, findings: List[Finding], scan_meta: dict) -> str:
        """Generate JSON report file and return path."""
        by_severity = Counter(f.severity for f in findings)
        by_module = Counter(f.module for f in findings)
        by_owasp = Counter(f.owasp_category for f in findings if f.owasp_category)
        by_mitre = Counter(f.mitre_technique for f in findings if f.mitre_technique)

        report = {
            "report_metadata": {
                "tool": "PenguardOps",
                "version": "2.1.0",
                "generated_at": datetime.now().isoformat(),
                "report_format": "JSON",
            },
            "scan_summary": {
                **scan_meta,
                "total_findings": len(findings),
                "findings_by_severity": dict(by_severity),
                "findings_by_module": dict(by_module),
                "findings_by_owasp": dict(by_owasp),
                "findings_by_mitre": dict(by_mitre),
                "risk_score": self._calculate_risk_score(findings),
            },
            "findings": [f.to_dict() for f in findings],
            "owasp_coverage": self._owasp_coverage(findings),
            "mitre_coverage": self._mitre_coverage(findings),
        }

        filename = f"penguardops_{self.config.scan_id}.json"
        filepath = Path(self.config.output_dir) / filename

        with open(filepath, "w") as f:
            json.dump(report, f, indent=2, default=str)

        return str(filepath)

    def _calculate_risk_score(self, findings: List[Finding]) -> float:
        """Calculate 0-100 risk score based on findings."""
        weights = {"critical": 40, "high": 15, "medium": 5, "low": 1, "info": 0}
        score = sum(weights.get(f.severity, 0) for f in findings)
        return min(100.0, round(score, 1))

    def _owasp_coverage(self, findings: List[Finding]) -> List[dict]:
        from core.base_plugin import OWASP_TOP10
        covered = {f.owasp_category for f in findings if f.owasp_category}
        return [
            {
                "id": owasp_id,
                "title": title,
                "affected": owasp_id in covered,
                "finding_count": sum(1 for f in findings if f.owasp_category == owasp_id),
            }
            for owasp_id, title in OWASP_TOP10.items()
        ]

    def _mitre_coverage(self, findings: List[Finding]) -> List[dict]:
        from core.base_plugin import MITRE_ATTACK
        covered_techniques = {f.mitre_technique for f in findings if f.mitre_technique}
        return [
            {
                "technique_id": tid,
                "technique_name": tname,
                "detected": tid in covered_techniques,
            }
            for tid, tname in MITRE_ATTACK.items()
        ]
