"""
Scan Persistence — Save and resume scan state.
Stores crawl results, findings, and scan metadata to disk.
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any

from utils.logger import get_logger

logger = get_logger("persistence")

PERSISTENCE_DIR = Path(".vulnscan_state")


class ScanState:
    """Serializable scan state for persistence."""

    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.state_file = PERSISTENCE_DIR / f"{scan_id}.json"
        self.state: Dict[str, Any] = {
            "scan_id": scan_id,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "status": "running",
            "config": {},
            "visited_urls": [],
            "crawl_results": {},
            "findings": [],
            "waf_detected": None,
            "modules_completed": [],
            "stats": {},
        }

    def save(self, config=None, crawl_results=None, findings=None,
             waf_detected=None, modules_completed=None):
        """Save current state to disk."""
        PERSISTENCE_DIR.mkdir(exist_ok=True)

        self.state["updated_at"] = datetime.now().isoformat()

        if config:
            self.state["config"] = config.to_dict()

        if crawl_results:
            # Serialize crawl results (basic info only)
            self.state["visited_urls"] = list(crawl_results.keys())
            self.state["crawl_results"] = {
                url: {
                    "depth": r.depth,
                    "status_code": r.status_code,
                    "content_type": r.content_type,
                    "form_count": len(r.forms),
                    "parameter_count": len(r.parameters),
                }
                for url, r in crawl_results.items()
            }

        if findings:
            self.state["findings"] = [f.to_dict() for f in findings]

        if waf_detected is not None:
            self.state["waf_detected"] = waf_detected

        if modules_completed:
            self.state["modules_completed"] = modules_completed

        try:
            with open(self.state_file, "w") as f:
                json.dump(self.state, f, indent=2, default=str)
            logger.debug(f"State saved: {self.state_file}")
        except Exception as e:
            logger.warning(f"Failed to save state: {e}")

    def mark_complete(self):
        self.state["status"] = "complete"
        self.state["updated_at"] = datetime.now().isoformat()
        self._write()

    def _write(self):
        try:
            with open(self.state_file, "w") as f:
                json.dump(self.state, f, indent=2, default=str)
        except Exception as e:
            logger.warning(f"State write error: {e}")

    @classmethod
    def load(cls, scan_id: str) -> Optional["ScanState"]:
        """Load an existing scan state."""
        state_file = PERSISTENCE_DIR / f"{scan_id}.json"

        if not state_file.exists():
            logger.error(f"State file not found: {state_file}")
            return None

        try:
            with open(state_file) as f:
                data = json.load(f)

            state = cls(scan_id)
            state.state = data
            logger.info(f"Resumed scan state: {scan_id}")
            logger.info(f"  Previously visited {len(data.get('visited_urls', []))} URLs")
            logger.info(f"  Modules completed: {data.get('modules_completed', [])}")
            return state

        except Exception as e:
            logger.error(f"Failed to load state {scan_id}: {e}")
            return None

    @classmethod
    def list_scans(cls) -> List[Dict]:
        """List all saved scan states."""
        if not PERSISTENCE_DIR.exists():
            return []

        scans = []
        for state_file in PERSISTENCE_DIR.glob("*.json"):
            try:
                with open(state_file) as f:
                    data = json.load(f)
                scans.append({
                    "scan_id": data.get("scan_id"),
                    "target": data.get("config", {}).get("target_url"),
                    "status": data.get("status"),
                    "created_at": data.get("created_at"),
                    "updated_at": data.get("updated_at"),
                    "findings_count": len(data.get("findings", [])),
                    "urls_visited": len(data.get("visited_urls", [])),
                })
            except Exception:
                continue

        return sorted(scans, key=lambda x: x.get("updated_at", ""), reverse=True)

    @property
    def previously_visited(self) -> set:
        return set(self.state.get("visited_urls", []))

    @property
    def modules_already_run(self) -> List[str]:
        return self.state.get("modules_completed", [])
