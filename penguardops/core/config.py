"""
Scan configuration — single source of truth for all settings.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
import uuid


@dataclass
class ScanConfig:
    # Target
    target_url: str
    scope: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)

    # Crawl
    depth: int = 3
    max_urls: int = 200
    threads: int = 5
    delay: float = 0.5
    timeout: int = 10

    # Modules
    enabled_modules: List[str] = field(default_factory=lambda: [
        "sqli", "xss", "lfi", "open_redirect", "headers", "csrf", "xxe", "ssrf", "idor"
    ])

    # WAF
    detect_waf: bool = True
    waf_bypass: bool = False

    # HTTP
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    cookies: Dict[str, str] = field(default_factory=dict)
    custom_headers: Dict[str, str] = field(default_factory=dict)
    proxy: Optional[str] = None
    verify_ssl: bool = False

    # Auth
    auth_user: Optional[str] = None
    auth_pass: Optional[str] = None
    login_url: Optional[str] = None
    login_data: Optional[str] = None

    # Output
    report_format: str = "both"
    output_dir: str = "./reports"
    min_severity: str = "info"
    verbose: bool = False
    quiet: bool = False

    # Persistence
    scan_id: Optional[str] = None
    resume_scan_id: Optional[str] = None
    save_state: bool = True

    # Runtime (set automatically)
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())

    def __post_init__(self):
        if not self.scan_id:
            self.scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

    @property
    def severity_levels(self) -> List[str]:
        levels = ["critical", "high", "medium", "low", "info"]
        idx = levels.index(self.min_severity)
        return levels[:idx + 1]

    def to_dict(self) -> dict:
        return {
            k: v for k, v in self.__dict__.items()
        }
