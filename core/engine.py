"""
Scan Engine v5.0
Orchestrates: WAF detection → Crawl → Plugins → Reports
Real-time PhaseTracker updates for every stage.
"""

import sys, time, traceback, threading
from typing import List, Dict, Optional, Type
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from core.config import ScanConfig
from core.http_session import HttpSession
from core.crawler import Crawler
from core.base_plugin import BasePlugin, Finding
from persistence.scan_state import ScanState
from utils.logger import get_logger
from utils.progress import PhaseTracker, C

logger = get_logger("engine")

# ── Plugin Registry ───────────────────────────────────────────────────────────
def _load_plugins():
    from modules.sqli_plugin   import SQLiPlugin
    from modules.xss_plugin    import XSSPlugin
    from modules.other_plugins import (
        HeadersPlugin, LFIPlugin, OpenRedirectPlugin,
        CSRFPlugin, XXEPlugin, SSRFPlugin, IDORPlugin,
    )
    return {
        "sqli":          SQLiPlugin,
        "xss":           XSSPlugin,
        "headers":       HeadersPlugin,
        "lfi":           LFIPlugin,
        "open_redirect": OpenRedirectPlugin,
        "csrf":          CSRFPlugin,
        "xxe":           XXEPlugin,
        "ssrf":          SSRFPlugin,
        "idor":          IDORPlugin,
    }

PLUGIN_REGISTRY: Dict[str, Type[BasePlugin]] = _load_plugins()

MODULE_LABEL = {
    "sqli":          "SQL Injection",
    "xss":           "Cross-Site Scripting",
    "lfi":           "Local File Inclusion",
    "open_redirect": "Open Redirect",
    "headers":       "Security Headers",
    "csrf":          "CSRF Detection",
    "xxe":           "XXE Injection",
    "ssrf":          "SSRF",
    "idor":          "IDOR",
}


# ── Engine ────────────────────────────────────────────────────────────────────
class ScanEngine:

    def __init__(self, config: ScanConfig):
        self.config  = config
        self.session = HttpSession(config)
        self.findings: List[Finding]  = []
        self.crawl_results: Dict      = {}
        self.waf_info: Optional[str]  = None
        self._state: Optional[ScanState] = None

        if config.save_state:
            if config.resume_scan_id:
                self._state = ScanState.load(config.resume_scan_id)
                if not self._state:
                    logger.warning("Could not resume — starting fresh.")
                    self._state = ScanState(config.scan_id)
            else:
                self._state = ScanState(config.scan_id)

    # ── Main entry ────────────────────────────────────────────────────────────
    def run(self) -> dict:
        start = time.time()

        # Build phase list for the tracker
        phases = (
            ["WAF Detection", "Crawling"]
            + [MODULE_LABEL.get(m, m) for m in self.config.enabled_modules]
            + ["Generating Reports"]
        )

        tracker = PhaseTracker(phases)
        if not self.config.quiet:
            tracker.start()

        try:
            # ── WAF ───────────────────────────────────────────────────────────
            tracker.set_running("WAF Detection", "Probing target…")
            if self.config.detect_waf:
                self.waf_info = self.session.detect_waf(self.config.target_url)
                tracker.set_done("WAF Detection",
                                 self.waf_info or "None detected")
            else:
                tracker.set_skipped("WAF Detection", "Disabled (--no-waf)")

            # ── Crawl ─────────────────────────────────────────────────────────
            tracker.set_running("Crawling", f"depth={self.config.depth}")
            crawler = Crawler(self.config, self.session)
            if self._state and self._state.previously_visited:
                crawler.visited = self._state.previously_visited

            self.crawl_results = self._crawl_with_progress(crawler, tracker)
            atk = crawler.get_attack_surface()
            tracker.set_done("Crawling",
                             f"{len(self.crawl_results)} URLs · {atk['forms']} forms")

            if self._state:
                self._state.save(config=self.config,
                                 crawl_results=self.crawl_results,
                                 waf_detected=self.waf_info)

            # ── Plugins ───────────────────────────────────────────────────────
            mods_to_run = list(self.config.enabled_modules)
            if self._state:
                done_already = set(self._state.modules_already_run)
                for m in done_already:
                    lbl = MODULE_LABEL.get(m, m)
                    if lbl in phases:
                        tracker.set_skipped(lbl, "Resumed")
                mods_to_run = [m for m in mods_to_run if m not in done_already]

            self._run_plugins(mods_to_run, tracker)

            # ── Reports ───────────────────────────────────────────────────────
            tracker.set_running("Generating Reports", "Building HTML + JSON…")
            report_paths = self._generate_reports(atk, start)
            tracker.set_done("Generating Reports",
                             f"{len(report_paths)} file(s) written")

        finally:
            if not self.config.quiet:
                tracker.stop()

        # Persist
        if self._state:
            self._state.save(
                config=self.config,
                crawl_results=self.crawl_results,
                findings=self.findings,
                waf_detected=self.waf_info,
                modules_completed=self.config.enabled_modules,
            )
            self._state.mark_complete()

        by_sev = {}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

        return {
            "scan_id":        self.config.scan_id,
            "target":         self.config.target_url,
            "urls_scanned":   len(self.crawl_results),
            "total_findings": len(self.findings),
            "by_severity":    by_sev,
            "waf_detected":   self.waf_info,
            "report_paths":   report_paths,
            "duration":       time.time() - start,
        }

    # ── Crawl with simple progress ────────────────────────────────────────────
    def _crawl_with_progress(self, crawler: Crawler, tracker: PhaseTracker) -> Dict:
        """Run crawler without complex progress tracking."""
        try:
            return crawler.crawl()
        except Exception as e:
            tracker.set_error("Crawling", str(e)[:50])
            raise

    # ── Plugin execution ──────────────────────────────────────────────────────
    def _run_plugins(self, modules: List[str], tracker: PhaseTracker):
        sequential = ["headers"]
        concurrent = [m for m in modules if m not in sequential]

        for m in sequential:
            if m in modules:
                self.findings.extend(self._run_one(m, tracker))

        if not concurrent:
            return

        with ThreadPoolExecutor(max_workers=min(len(concurrent), 4)) as ex:
            fut_map = {ex.submit(self._run_one, m, tracker): m for m in concurrent}
            for fut in as_completed(fut_map):
                m = fut_map[fut]
                try:
                    self.findings.extend(fut.result())
                except Exception as e:
                    lbl = MODULE_LABEL.get(m, m)
                    tracker.set_error(lbl, str(e)[:40])
                    logger.error(f"[{m}] {e}")
                    if self.config.verbose:
                        traceback.print_exc()

        sev_ord = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self.findings.sort(key=lambda f: sev_ord.get(f.severity, 99))

    def _run_one(self, mod_id: str, tracker: PhaseTracker) -> List[Finding]:
        lbl   = MODULE_LABEL.get(mod_id, mod_id)
        klass = PLUGIN_REGISTRY.get(mod_id)
        if not klass:
            tracker.set_skipped(lbl, "Unknown module")
            return []

        tracker.set_running(lbl, "Scanning...")

        try:
            plugin = klass(self.session, self.config)
            findings = plugin.run(self.crawl_results)
            tracker.set_done(lbl, findings=len(findings))
            return findings
        except Exception as e:
            tracker.set_error(lbl, str(e)[:40])
            logger.error(f"[{mod_id}] {e}")
            if self.config.verbose:
                traceback.print_exc()
            return []

    # ── Reports ───────────────────────────────────────────────────────────────
    def _generate_reports(self, attack_surface: dict, start_time: float) -> List[str]:
        from reports.json_report import JSONReporter
        from reports.html_report import HTMLReporter
        import os

        os.makedirs(self.config.output_dir, exist_ok=True)

        scan_meta = {
            "scan_id":        self.config.scan_id,
            "target":         self.config.target_url,
            "start_time":     self.config.start_time,
            "end_time":       datetime.now().isoformat(),
            "duration":       time.time() - start_time,
            "waf_detected":   self.waf_info,
            "urls_scanned":   len(self.crawl_results),
            "attack_surface": attack_surface,
            "modules_run":    self.config.enabled_modules,
            "config":         self.config.to_dict(),
        }

        paths = []
        if self.config.report_format in ("json", "both"):
            paths.append(JSONReporter(self.config).generate(self.findings, scan_meta))
        if self.config.report_format in ("html", "both"):
            paths.append(HTMLReporter(self.config).generate(self.findings, scan_meta))
        return paths

    def save_state(self):
        if self._state:
            self._state.save(
                config=self.config,
                crawl_results=self.crawl_results,
                findings=self.findings,
                waf_detected=self.waf_info,
            )
            logger.info(f"State saved — resume with: --resume {self.config.scan_id}")
