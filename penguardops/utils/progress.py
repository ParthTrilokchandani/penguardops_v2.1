"""
Simple progress display - NO threading, NO complex terminal control
Just print status updates as they happen
"""

import sys
from typing import List, Optional


class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[91m"; YELLOW = "\033[93m"; GREEN = "\033[92m"
    BLUE = "\033[94m"; CYAN = "\033[96m"; MAGENTA = "\033[95m"
    WHITE = "\033[97m"; GRAY = "\033[90m"

SEV_COLOR = {
    "critical": C.RED, "high": C.YELLOW,
    "medium": C.MAGENTA, "low": C.BLUE, "info": C.GRAY,
}

ALL_MODULES = {
    "sqli": ("SQL Injection", "A03:2021", "T1190", "CRITICAL"),
    "xss": ("Cross-Site Scripting", "A03:2021", "T1059.007", "HIGH"),
    "lfi": ("Local File Inclusion", "A01:2021", "T1083", "CRITICAL"),
    "open_redirect": ("Open Redirect", "A01:2021", "T1534", "MEDIUM"),
    "headers": ("Security Headers Check", "A05:2021", "T1600", "MEDIUM"),
    "csrf": ("CSRF Token Detection", "A01:2021", "T1185", "MEDIUM"),
    "xxe": ("XML External Entity (XXE)", "A05:2021", "T1190", "HIGH"),
    "ssrf": ("Server-Side Request Forgery", "A10:2021", "T1090", "HIGH"),
    "idor": ("Insecure Direct Object Ref.", "A01:2021", "T1078", "MEDIUM"),
}


class PhaseTracker:
    """Simple print-only progress tracker."""
    
    def __init__(self, phases: List[str]):
        self._completed = set()
    
    def start(self):
        print()
    
    def stop(self):
        print()
    
    def set_running(self, phase: str, detail: str = "", total: int = 0):
        if phase in self._completed:
            return
        print(f"  {C.CYAN}▶ {phase:<22}{C.RESET} Starting... {C.DIM}{detail}{C.RESET}")
        sys.stdout.flush()
    
    def update(self, phase: str, done: int, total: int = None, detail: str = None):
        pass  # Skip intermediate updates to avoid spam
    
    def set_done(self, phase: str, detail: str = "", findings: int = -1):
        if phase in self._completed:
            return
        self._completed.add(phase)
        if findings >= 0:
            msg = f"{findings} finding{'s' if findings!=1 else ''}" if findings else "Clean ✓"
        else:
            msg = detail
        print(f"  {C.GREEN}✔ {phase:<22}{C.RESET} {msg}")
        sys.stdout.flush()
    
    def set_error(self, phase: str, detail: str = ""):
        if phase in self._completed:
            return
        self._completed.add(phase)
        print(f"  {C.RED}✘ {phase:<22}{C.RESET} Error: {detail}")
        sys.stdout.flush()
    
    def set_skipped(self, phase: str, detail: str = "Skipped"):
        if phase in self._completed:
            return
        self._completed.add(phase)
        print(f"  {C.DIM}— {phase:<22}{C.RESET} {detail}")
        sys.stdout.flush()


def interactive_module_select(preselected: Optional[List[str]] = None) -> List[str]:
    """Interactive module selection."""
    selected = set(preselected or ALL_MODULES.keys())
    print(f"\n{C.BOLD}{C.CYAN}Module Selection{C.RESET}")
    print(f"{C.DIM}Enter 'all' for all modules, or comma-separated list (e.g., sqli,xss,headers){C.RESET}\n")
    
    for i, (mid, (desc, owasp, _, risk)) in enumerate(ALL_MODULES.items(), 1):
        rc = {"CRITICAL":C.RED,"HIGH":C.YELLOW,"MEDIUM":C.MAGENTA,"LOW":C.BLUE}.get(risk, C.GRAY)
        print(f"  {i}. {C.BOLD}{mid:<17}{C.RESET} {desc:<35} {rc}{risk}{C.RESET}")
    
    print(f"\n  {C.DIM}Current selection: {', '.join(selected)}{C.RESET}")
    ans = input(f"  Modules to run (Enter for all): ").strip().lower()
    
    if not ans or ans == "all":
        return list(ALL_MODULES.keys())
    
    result = [m.strip() for m in ans.split(',') if m.strip() in ALL_MODULES]
    print(f"  {C.GREEN}✔ Selected: {', '.join(result)}{C.RESET}\n")
    return result


def print_banner():
    print(f"""{C.CYAN}
{'═'*80}

    ██████╗ ███████╗███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗  ██████╗ ██████╗ ███████╗
    ██╔══██╗██╔════╝████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
    ██████╔╝█████╗  ██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║   ██║██████╔╝███████╗
    ██╔═══╝ ██╔══╝  ██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║   ██║██╔═══╝ ╚════██║
    ██║     ███████╗██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝╚██████╔╝██║     ███████║
    ╚═╝     ╚══════╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝     ╚══════╝

    {C.BOLD}v2.1 - Elite Penetration Testing Framework{C.RESET}
    {C.DIM}OWASP Top 10 · MITRE ATT&CK · Professional Security Assessment{C.RESET}

{'═'*80}{C.RESET}
""")


def print_scan_start(target: str, modules: List[str], config):
    print(f"  {C.BOLD}Target:{C.RESET}   {C.CYAN}{target}{C.RESET}")
    print(f"  {C.BOLD}Modules:{C.RESET}  {C.GREEN}{', '.join(modules)}{C.RESET}")
    print(f"  {C.BOLD}Scan ID:{C.RESET}  {C.DIM}{config.scan_id}{C.RESET}\n")


def print_summary(results: dict):
    by_sev = results.get("by_severity", {})
    total = results.get("total_findings", 0)
    dur = results.get("duration", 0)
    urls = results.get("urls_scanned", 0)
    waf = results.get("waf_detected")
    paths = results.get("report_paths", [])

    print(f"\n{C.BOLD}{C.CYAN}{'═'*80}{C.RESET}")
    print(f"  {C.BOLD}✅ Scan Complete{C.RESET}  ({dur:.1f}s)")
    print(f"  {C.BOLD}Total Issues: {total}{C.RESET}")
    for sev in ["critical", "high", "medium", "low", "info"]:
        n = by_sev.get(sev, 0)
        if n:
            clr = SEV_COLOR.get(sev, C.GRAY)
            print(f"    {clr}▸ {sev.upper():<10}{C.RESET} {n}")
    if waf:
        print(f"  {C.YELLOW}WAF Detected: {waf}{C.RESET}")
    for p in paths:
        print(f"  {C.BLUE}Report: {p}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═'*80}{C.RESET}\n")
