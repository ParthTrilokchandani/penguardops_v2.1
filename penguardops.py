#!/usr/bin/env python3
"""
PenguardOps v2.1 — Elite Penetration Testing Framework
Real-time progress tracking • Interactive module selection
WAF detection & bypass • OWASP Top 10 • MITRE ATT&CK mapping
Hacker-grade reconnaissance suite
"""

import sys, argparse, time
from utils.progress import (
    print_banner, print_scan_start, print_summary,
    interactive_module_select, C, ALL_MODULES,
)
from utils.logger import get_logger

logger = get_logger("penguardops")
_ALL_IDS = list(ALL_MODULES.keys())


# ── Argument parser ───────────────────────────────────────────────────────────
def _build_parser():
    p = argparse.ArgumentParser(
        prog="penguardops",
        description="PenguardOps v2.1 — Elite Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python penguardops.py -u https://example.com
  python penguardops.py -u https://example.com --select-modules
  python penguardops.py -u https://example.com --modules sqli xss headers
  python penguardops.py -u https://example.com --waf-bypass --threads 10
  python penguardops.py -u https://example.com --resume scan_20260217_abc
  python penguardops.py --list-modules
  python penguardops.py --list-scans
""",
    )

    # ── Target ────────────────────────────────────────────────────────────────
    g = p.add_argument_group("Target")
    g.add_argument("-u","--url",   help="Target URL  (required unless --list-* used)")
    g.add_argument("--scope",      nargs="*", metavar="DOMAIN",  help="Extra in-scope domains")
    g.add_argument("--exclude",    nargs="*", metavar="PATTERN", help="URL regex patterns to skip")

    # ── Crawl ─────────────────────────────────────────────────────────────────
    g = p.add_argument_group("Crawl")
    g.add_argument("--depth",    type=int,   default=3,   help="Crawl depth (default: 3)")
    g.add_argument("--max-urls", type=int,   default=200, help="Max URLs (default: 200)")
    g.add_argument("--threads",  type=int,   default=5,   help="Threads (default: 5)")
    g.add_argument("--delay",    type=float, default=0.5, help="Delay between requests s (default: 0.5)")
    g.add_argument("--timeout",  type=int,   default=10,  help="Request timeout s (default: 10)")

    # ── Modules ───────────────────────────────────────────────────────────────
    g = p.add_argument_group("Modules")
    g.add_argument(
        "--modules", nargs="*",
        choices=_ALL_IDS + ["all"],
        default=["all"],
        metavar="MODULE",
        help="Modules to run (default: all).  Choices: " + ", ".join(_ALL_IDS),
    )
    g.add_argument("--skip-modules",    nargs="*", metavar="MODULE", help="Modules to skip")
    g.add_argument("--select-modules",  action="store_true",
                   help="Interactive yes/no prompt to choose modules before scanning")
    g.add_argument("--list-modules",    action="store_true", help="Print module catalogue and exit")
    g.add_argument("--list-scans",      action="store_true", help="Print saved scans and exit")

    # ── WAF / Evasion ─────────────────────────────────────────────────────────
    g = p.add_argument_group("WAF & Evasion")
    g.add_argument("--no-waf",     action="store_true", help="Skip WAF detection")
    g.add_argument("--waf-bypass", action="store_true", help="Enable WAF evasion techniques")
    g.add_argument("--user-agent", metavar="UA",        help="Custom User-Agent")
    g.add_argument("--cookies",    metavar="K=V;K=V",   help="Cookies to send")
    g.add_argument("--headers",    nargs="*", metavar="H:V", help="Extra HTTP headers")
    g.add_argument("--proxy",      metavar="URL",       help="HTTP proxy")

    # ── Auth ──────────────────────────────────────────────────────────────────
    g = p.add_argument_group("Authentication")
    g.add_argument("--auth-user",  metavar="USER")
    g.add_argument("--auth-pass",  metavar="PASS")
    g.add_argument("--login-url",  metavar="URL")
    g.add_argument("--login-data", metavar="DATA")

    # ── Persistence ───────────────────────────────────────────────────────────
    g = p.add_argument_group("Persistence")
    g.add_argument("--resume",  metavar="SCAN_ID", help="Resume an interrupted scan")
    g.add_argument("--scan-id", metavar="ID",      help="Custom scan ID")
    g.add_argument("--no-save", action="store_true", help="Don't persist scan state")

    # ── Output ────────────────────────────────────────────────────────────────
    g = p.add_argument_group("Output")
    g.add_argument("--report",     choices=["html","json","both"], default="both")
    g.add_argument("--output-dir", default="./reports", metavar="DIR")
    g.add_argument("--severity",   choices=["critical","high","medium","low","info"], default="info")
    g.add_argument("-v","--verbose", action="store_true")
    g.add_argument("-q","--quiet",   action="store_true")

    return p


# ── Helpers ───────────────────────────────────────────────────────────────────
def _parse_cookies(s):
    out = {}
    for part in (s or "").split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out

def _parse_headers(lst):
    out = {}
    for h in (lst or []):
        if ":" in h:
            k, v = h.split(":", 1)
            out[k.strip()] = v.strip()
    return out

def _list_modules():
    print(f"\n  {C.BOLD}{'#':<3} {'ID':<17} {'Description':<33} {'OWASP':<10} {'MITRE':<12} Risk{C.RESET}")
    print(f"  {'─'*88}")
    for i, (mid, (desc, owasp, mitre, risk)) in enumerate(ALL_MODULES.items(), 1):
        rc = {"CRITICAL":C.RED,"HIGH":C.YELLOW,"MEDIUM":C.MAGENTA}.get(risk, C.GRAY)
        print(f"  {C.DIM}{i:<3}{C.RESET}{C.BOLD}{mid:<17}{C.RESET}{desc:<33}"
              f"{C.CYAN}{owasp:<10}{C.RESET}{C.DIM}{mitre:<12}{C.RESET}{rc}{risk}{C.RESET}")
    print()

def _list_scans():
    from persistence.scan_state import ScanState
    scans = ScanState.list_scans()
    if not scans:
        print(f"\n  {C.YELLOW}No saved scans found.{C.RESET}\n")
        return
    print(f"\n  {C.BOLD}{'Scan ID':<42} {'Target':<30} {'Status':<10} {'Findings'} {C.RESET}")
    print(f"  {'─'*95}")
    for s in scans:
        sc = C.GREEN if s.get("status") == "complete" else C.YELLOW
        print(f"  {C.CYAN}{str(s.get('scan_id','')):<42}{C.RESET}"
              f" {str(s.get('target',''))[:28]:<30}"
              f" {sc}{str(s.get('status','')):<10}{C.RESET}"
              f" {s.get('findings_count',0)}")
    print()


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print_banner()
    parser = _build_parser()
    args   = parser.parse_args()

    # Utility exits
    if args.list_modules:
        _list_modules(); sys.exit(0)
    if getattr(args, "list_scans", False):
        _list_scans();   sys.exit(0)

    if not args.url:
        parser.print_help()
        print(f"\n  {C.RED}Error: -u / --url is required.{C.RESET}\n")
        sys.exit(1)

    # ── Resolve module list ───────────────────────────────────────────────────
    base = _ALL_IDS[:] if "all" in (args.modules or []) else [
        m for m in (args.modules or []) if m in _ALL_IDS
    ]
    if args.skip_modules:
        base = [m for m in base if m not in args.skip_modules]

    if args.select_modules:
        enabled_modules = interactive_module_select(base)
    else:
        enabled_modules = base
        if not args.quiet:
            print(f"  {C.DIM}Tip: use --select-modules for interactive module selection.{C.RESET}\n")

    if not enabled_modules:
        print(f"  {C.RED}No modules selected — nothing to scan.{C.RESET}\n")
        sys.exit(0)

    # ── Build config ──────────────────────────────────────────────────────────
    from core.config import ScanConfig
    config = ScanConfig(
        target_url       = args.url,
        depth            = args.depth,
        max_urls         = args.max_urls,
        threads          = args.threads,
        delay            = args.delay,
        timeout          = args.timeout,
        enabled_modules  = enabled_modules,
        detect_waf       = not args.no_waf,
        waf_bypass       = args.waf_bypass,
        user_agent       = args.user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        cookies          = _parse_cookies(args.cookies),
        custom_headers   = _parse_headers(args.headers),
        proxy            = args.proxy,
        auth_user        = args.auth_user,
        auth_pass        = args.auth_pass,
        report_format    = args.report,
        output_dir       = args.output_dir,
        min_severity     = args.severity,
        verbose          = args.verbose,
        quiet            = args.quiet,
        scope            = args.scope or [],
        exclude_patterns = args.exclude or [],
        scan_id          = args.scan_id,
        resume_scan_id   = args.resume,
        save_state       = not args.no_save,
    )

    if not args.quiet:
        print_scan_start(args.url, enabled_modules, config)

    # ── Run ───────────────────────────────────────────────────────────────────
    from core.engine import ScanEngine
    engine = ScanEngine(config)
    try:
        results = engine.run()
        if not args.quiet:
            print_summary(results)
    except KeyboardInterrupt:
        print(f"\n\n  {C.YELLOW}[!] Interrupted — saving state…{C.RESET}")
        engine.save_state()
        print(f"  {C.DIM}Resume with: --resume {config.scan_id}{C.RESET}\n")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal: {e}", exc_info=config.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()
