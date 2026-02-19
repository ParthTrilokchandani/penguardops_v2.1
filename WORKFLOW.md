# PenguardOps v2.1 — Complete Technical Documentation

**Professional Penetration Testing Framework**  
**Full Workflow, Architecture, and Implementation Guide**

---

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Complete Workflow](#complete-workflow)
4. [Module Deep Dive](#module-deep-dive)
5. [Progress Tracking System](#progress-tracking-system)
6. [Report Generation](#report-generation)
7. [Scan Persistence](#scan-persistence)
8. [WAF Detection & Bypass](#waf-detection--bypass)
9. [Configuration System](#configuration-system)
10. [Plugin Architecture](#plugin-architecture)
11. [HTTP Session Management](#http-session-management)
12. [Crawler Implementation](#crawler-implementation)
13. [Security Considerations](#security-considerations)
14. [Troubleshooting](#troubleshooting)

---

## Overview

### What is PenguardOps?

PenguardOps is an **elite penetration testing framework** designed for professional security assessments. It combines intelligent crawling, multi-threaded vulnerability scanning, real-time progress tracking, and comprehensive reporting into a single, powerful tool.

### Key Design Principles

1. **Modularity** — Plugin-based architecture for easy extensibility
2. **Concurrency** — Multi-threaded execution for speed
3. **Persistence** — Resume interrupted scans from saved state
4. **Transparency** — Real-time progress visibility at every phase
5. **Professionalism** — Production-grade reports with OWASP/MITRE mapping
6. **Stealth** — WAF detection and evasion capabilities

### Technology Stack

- **Language**: Python 3.8+
- **HTTP Client**: requests library with custom session management
- **HTML Parsing**: BeautifulSoup4 + lxml
- **Concurrency**: ThreadPoolExecutor from concurrent.futures
- **UI**: Pure stdlib ANSI terminal control (zero external UI deps)

---

## System Architecture

### High-Level Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      penguardops.py                         │
│                   (CLI Entry Point)                         │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    ScanEngine                               │
│  - Orchestrates entire scan workflow                        │
│  - Manages phase transitions                                │
│  - Coordinates crawler, plugins, reporters                  │
└─┬─────────┬─────────┬─────────┬──────────┬────────┬────────┘
  │         │         │         │          │        │
  ▼         ▼         ▼         ▼          ▼        ▼
┌──────┐ ┌────────┐ ┌──────┐ ┌────────┐ ┌──────┐ ┌───────┐
│HTTP  │ │Crawler │ │Plugin│ │Progress│ │Report│ │ State │
│Sess. │ │        │ │ Mgr  │ │Tracker │ │ Gen. │ │ Mgr.  │
└──────┘ └────────┘ └──────┘ └────────┘ └──────┘ └───────┘
```

### Core Components

#### 1. **ScanEngine** (`core/engine.py`)
**Responsibility**: Master orchestrator  
**Functions**:
- Initialize HTTP session
- Detect WAF (if enabled)
- Run crawler
- Execute plugins concurrently
- Generate reports
- Persist state

#### 2. **HttpSession** (`core/http_session.py`)
**Responsibility**: HTTP communication  
**Functions**:
- Manage requests session with retry logic
- WAF fingerprinting
- Baseline response comparison
- Request rate limiting with jitter
- Cookie/header/proxy management

#### 3. **Crawler** (`core/crawler.py`)
**Responsibility**: Target discovery  
**Functions**:
- Breadth-first multi-threaded crawling
- Form extraction and parsing
- URL parameter discovery
- JavaScript endpoint mining
- Scope enforcement

#### 4. **BasePlugin** (`core/base_plugin.py`)
**Responsibility**: Plugin interface  
**Functions**:
- Abstract base class for all modules
- Finding model with OWASP/MITRE metadata
- Severity filtering
- Common utilities

#### 5. **PhaseTracker** (`utils/progress.py`)
**Responsibility**: Live UI updates  
**Functions**:
- Multi-row progress table
- Real-time percentage updates
- State management (waiting → running → done/error/skipped)
- ANSI terminal control

#### 6. **Reporters** (`reports/`)
**Responsibility**: Output generation  
**Functions**:
- HTMLReporter: Dynamic report with interactive features
- JSONReporter: Machine-readable structured output

#### 7. **ScanState** (`persistence/scan_state.py`)
**Responsibility**: Scan persistence  
**Functions**:
- Save scan state to disk
- Resume from saved state
- Track visited URLs and completed modules

---

## Complete Workflow

### Phase 1: Initialization

```python
# User runs: python penguardops.py -u https://target.com

1. Parse command-line arguments
2. Build ScanConfig object
   - Target URL
   - Module selection (all or subset)
   - Crawl parameters (depth, threads, delay)
   - WAF settings
   - Output preferences
3. Initialize ScanEngine(config)
4. Check for resume scan (--resume SCAN_ID)
   - Load previous state if exists
   - Restore visited URLs
   - Identify completed modules
5. Display banner and scan configuration
```

### Phase 2: WAF Detection

```python
# If config.detect_waf == True

1. PhaseTracker.set_running("WAF Detection", "Probing target...")

2. Send test probe:
   GET /path?vulnscan_waf_probe=<script>alert(1)</script>

3. Analyze response:
   - Check headers for WAF signatures
   - Match response body against known WAF patterns
   - Store detected WAF name (or None)

4. WAF Signature Matching:
   - Cloudflare: cf-ray, __cfduid headers
   - AWS WAF: x-amzn-requestid
   - Akamai: akamai headers
   - ModSecurity: mod_security patterns
   - Imperva: x-iinfo, visid_incap
   - F5 BIG-IP: TS[a-zA-Z0-9]{8}
   - Barracuda: barra_counter_session
   - Sucuri: x-sucuri-id
   - Wordfence: generated by wordfence
   - Generic: "403 Forbidden", "Access Denied"

5. PhaseTracker.set_done("WAF Detection", waf_name or "None detected")

6. Log warning if WAF detected and bypass not enabled
```

### Phase 3: Crawling

```python
# Multi-threaded breadth-first crawl

1. PhaseTracker.set_running("Crawling", f"depth={config.depth}")

2. Initialize Crawler:
   - Create visited/queued sets
   - Set base domain for scope enforcement
   - Load previously visited URLs if resuming

3. Start crawl from target URL:
   queue = [(target_url, 0)]  # (url, depth)

4. For each URL in queue (concurrent):
   a. Check if in scope (domain matching)
   b. Check if excluded (regex patterns)
   c. HTTP GET request
   d. Parse HTML:
      - Extract links (<a>, <form>, <script src>, etc.)
      - Parse forms (fields, method, action)
      - Extract URL parameters
      - Mine JavaScript for API endpoints
      - Extract HTML comments
   e. Normalize and enqueue discovered URLs
   f. Update PhaseTracker:
      tracker.update("Crawling", 
                     done=len(visited), 
                     total=len(visited + queued),
                     detail=f"{len(visited)} visited · {len(queued)} queued")

5. Continue until:
   - Max depth reached
   - Max URLs limit hit
   - Queue empty

6. Build attack surface summary:
   - Total URLs discovered
   - Forms found (with fields)
   - Parameterized endpoints
   - JavaScript endpoints

7. PhaseTracker.set_done("Crawling", 
   f"{len(results)} URLs · {len(forms)} forms")

8. Save crawl state to disk (if persistence enabled)
```

### Phase 4: Plugin Execution

```python
# Concurrent vulnerability scanning

1. Determine modules to run:
   - Start with config.enabled_modules
   - Remove already-completed modules (if resuming)

2. For each module:
   PhaseTracker.set_running(module_label, "Starting...")

3. Sequential execution (headers module):
   - Run first to avoid interference
   - Check security headers on target
   - Validate cookie attributes
   - Detect information disclosure

4. Concurrent execution (all other modules):
   - Use ThreadPoolExecutor with max 4 workers
   - Each module runs independently

5. Per-module workflow:
   
   a. Instantiate plugin class:
      plugin = SQLiPlugin(session, config)
   
   b. Monkey-patch session.get/post to count requests:
      - Increment request counter
      - Update PhaseTracker with progress
      - Show current URL being tested
   
   c. Run plugin.run(crawl_results):
      - Iterate over all discovered URLs/forms
      - Apply test payloads
      - Detect vulnerabilities
      - Create Finding objects
   
   d. Restore original session methods
   
   e. PhaseTracker.set_done(module_label, 
      findings=len(plugin.findings))

6. Aggregate all findings:
   - Collect from all plugins
   - Sort by severity (critical → high → medium → low → info)

7. Log summary:
   - Total findings
   - Breakdown by severity
   - Breakdown by module
```

### Phase 5: Report Generation

```python
# Dual-format output

1. PhaseTracker.set_running("Generating Reports", 
   "Building HTML + JSON...")

2. Prepare scan metadata:
   scan_meta = {
     "scan_id": config.scan_id,
     "target": config.target_url,
     "start_time": scan_start_timestamp,
     "end_time": datetime.now().isoformat(),
     "duration": elapsed_seconds,
     "waf_detected": waf_name,
     "urls_scanned": len(crawl_results),
     "attack_surface": {...},
     "modules_run": enabled_modules,
     "config": config.to_dict()
   }

3. Calculate statistics:
   - Risk score (0-100 based on finding weights)
   - Risk level (CRITICAL/HIGH/MEDIUM/LOW/NONE)
   - Findings by severity
   - Findings by module
   - OWASP Top 10 coverage
   - MITRE ATT&CK technique detection

4. Generate JSON report:
   JSONReporter(config).generate(findings, scan_meta)
   → reports/penguardops_{scan_id}.json

5. Generate HTML report:
   HTMLReporter(config).generate(findings, scan_meta)
   → reports/penguardops_{scan_id}.html
   
   HTML includes:
   - Dynamic header with risk gauge
   - Module progress bars
   - Module toggle filters
   - Severity cards with animated counters
   - Bar charts (severity, module distribution)
   - OWASP Top 10 mapping
   - MITRE ATT&CK mapping
   - Advanced statistics
   - Scan timeline
   - Configuration table
   - Detailed findings (expandable cards)
   - Interactive search and filtering

6. PhaseTracker.set_done("Generating Reports", 
   f"{len(report_paths)} file(s) written")

7. Stop progress tracker (render final state)
```

### Phase 6: Finalization

```python
# Cleanup and summary

1. Save final scan state:
   - All findings
   - Completed modules
   - Mark status as "complete"

2. Display summary:
   print_summary(results)
   - Scan ID
   - Target URL
   - Duration
   - URLs scanned
   - Total findings
   - Breakdown by severity
   - WAF detected (if any)
   - Report file paths

3. Exit gracefully
```

---

## Module Deep Dive

### SQL Injection Module (`modules/sqli_plugin.py`)

**Detection Methods**:

1. **Error-Based Detection**
   ```python
   Payloads: ', '', ", \, ' OR '1'='1, etc.
   
   For each URL parameter and form field:
   - Inject payload
   - Check response for DB error patterns:
     * MySQL: "you have an error in your sql syntax"
     * MSSQL: "microsoft sql server", "unclosed quotation"
     * Oracle: "ORA-\d{4,5}", "quoted string not properly terminated"
     * PostgreSQL: "pg_query\(\): Query failed"
     * SQLite: "sqlite3.OperationalError"
   
   If error matched:
     - Create Finding (severity: critical, confidence: high)
     - Record DB type, payload, evidence snippet
   ```

2. **Boolean-Blind Detection**
   ```python
   Payload pairs:
   - True:  1 AND 1=1  or  ' AND '1'='1
   - False: 1 AND 1=2  or  ' AND '1'='2
   
   For each parameter:
   - Get baseline response
   - Inject true payload → response A
   - Inject false payload → response B
   
   If |len(A) - len(B)| > 50 AND status_A != status_B:
     - Create Finding (severity: high, confidence: medium)
     - Note: Higher false-positive risk
   ```

3. **Time-Based Blind Detection**
   ```python
   Payloads:
   - MySQL:  ' AND SLEEP(3)--
   - MSSQL:  '; WAITFOR DELAY '0:0:3'--
   - Oracle: ' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS',3)--
   - PgSQL:  '; SELECT pg_sleep(3)--
   
   For each parameter:
   - Record start time
   - Inject payload
   - Record end time
   
   If elapsed >= delay * 0.8:
     - Create Finding (severity: high, confidence: medium)
     - Evidence: response delay in seconds
   ```

**OWASP**: A03:2021 (Injection)  
**MITRE**: T1190 (Exploit Public-Facing Application)  
**CWE**: CWE-89  
**CVSS**: 9.8 (Critical) / 8.1-8.5 (High for blind)

---

### XSS Module (`modules/xss_plugin.py`)

**Detection Methods**:

1. **Reflected XSS**
   ```python
   Canary-based payloads with unique marker:
   XSS_CANARY = "VULNSCAN_XSS_"
   
   Payloads:
   - <VULNSCAN_XSS_TAG>
   - <script>VULNSCAN_XSS_SCRIPT</script>
   - "><img src=x onerror="VULNSCAN_XSS_IMG">
   - <svg onload="VULNSCAN_XSS_SVG">
   
   For each parameter:
   - Inject payload
   - Search response for canary marker
   - Determine reflection context:
     * HTML body
     * HTML attribute
     * Script block
     * HTML comment
   
   Check sanitization:
   - Look for HTML encoding (&lt;, &gt;, &quot;)
   - If NOT sanitized: severity = high, confidence = high
   - If sanitized: severity = medium, confidence = medium
   ```

2. **DOM-Based XSS** (Pattern Analysis)
   ```python
   Source patterns (taint sources):
   - document.location
   - document.URL
   - window.location
   - location.search / location.hash
   - document.referrer
   
   Sink patterns (dangerous sinks):
   - innerHTML =
   - outerHTML =
   - document.write(
   - eval(
   - setTimeout(
   - new Function(
   - location.href =
   
   Analysis:
   - Parse JavaScript in page
   - Match source patterns
   - Match sink patterns
   
   If sources AND sinks found:
     - Create Finding (severity: medium, confidence: low)
     - Note: High false-positive risk (manual verification needed)
   ```

**OWASP**: A03:2021 (Injection)  
**MITRE**: T1059.007 (JavaScript)  
**CWE**: CWE-79  
**CVSS**: 8.2 (High for reflected) / 6.5 (Medium for DOM)

---

### LFI Module (`modules/other_plugins.py` — LFIPlugin)

**Detection Method**:

```python
Path traversal payloads:
- ../etc/passwd
- ../../etc/passwd
- ../../../../../../../../etc/passwd
- ..%2Fetc%2Fpasswd
- ....//etc/passwd
- /etc/passwd
- C:\\Windows\\win.ini
- php://filter/convert.base64-encode/resource=index.php

Success patterns:
- root:x:0:0
- root:.*:/bin/
- daemon:x:
- \[boot loader\]  (Windows)

For parameters with file-related names (file, path, page, dir, include):
- Inject payload
- Check response body for success patterns

If matched:
  - Create Finding (severity: critical, confidence: high)
  - Evidence: matched pattern snippet
```

**OWASP**: A01:2021 (Broken Access Control)  
**MITRE**: T1083 (File and Directory Discovery)  
**CWE**: CWE-22  
**CVSS**: 9.1 (Critical)

---

### Security Headers Module

**Checks Performed**:

1. **Missing Security Headers**
   - Content-Security-Policy (High)
   - Strict-Transport-Security (High)
   - X-Frame-Options (Medium)
   - X-Content-Type-Options (Medium)
   - Referrer-Policy (Low)
   - Permissions-Policy (Low)

2. **Information Disclosure Headers**
   - Server (reveals version)
   - X-Powered-By (reveals tech stack)
   - X-AspNet-Version
   - X-AspNetMvc-Version

3. **Cookie Security**
   - HttpOnly flag missing (Medium)
   - Secure flag missing (Medium)
   - SameSite attribute missing (Low)

4. **HTTPS Enforcement**
   - Target using HTTP instead of HTTPS (High)

**OWASP**: A05:2021 (Security Misconfiguration)  
**MITRE**: T1600 (Weaken Encryption)

---

## Progress Tracking System

### Design Architecture

```python
# PhaseTracker manages a live table of scan phases

┌─────────────────────────────────────────────────────────┐
│  ○ WAF Detection       [░░░░░░░░░░░░░░]   0.0% Waiting │
│  ● Crawling            [████████░░░░░░]  50.0% 43 URLs  │
│  ○ SQL Injection       [░░░░░░░░░░░░░░]   0.0% Waiting │
│  ○ XSS                 [░░░░░░░░░░░░░░]   0.0% Waiting │
│  ✔ Security Headers    [██████████████] 100.0% 6 finds │
└─────────────────────────────────────────────────────────┘
```

### State Machine

```
Phase States:
- waiting  (○ gray)   → Not started yet
- running  (● cyan)   → Currently executing (animated spinner)
- done     (✔ green)  → Completed successfully (locked at 100%)
- error    (✘ red)    → Failed with error
- skipped  (— dim)    → Skipped (not enabled or resumed)
```

### Key Implementation Details

**Problem**: Progress bars showed duplicates and exceeded 100%  
**Root Cause**: 
1. No deduplication of phase names on init
2. `set_running()` overwrote "done" states
3. `update()` allowed done > total

**Solution v2.1**:

```python
class PhaseTracker:
    def __init__(self, phases):
        # DEDUPLICATE on initialization
        seen = set()
        unique = []
        for p in phases:
            if p not in seen:
                unique.append(p)
                seen.add(p)
        self._phases = unique
        
    def set_running(self, phase, detail="", total=0):
        with self._lock:
            # CRITICAL: Don't overwrite terminal states
            if self._state[phase] in ("done", "error", "skipped"):
                return
            self._state[phase] = "running"
            self._progress[phase] = (0, max(total, 1))
    
    def update(self, phase, done, total=None, detail=None):
        with self._lock:
            # CRITICAL: Don't update completed phases
            if self._state[phase] in ("done", "error", "skipped"):
                return
            new_done = min(done, new_total)  # CAP at total
            
    def set_done(self, phase, detail="", findings=-1):
        with self._lock:
            self._state[phase] = "done"
            _, t = self._progress[phase]
            # LOCK at 100%
            self._progress[phase] = (max(t,1), max(t,1))
    
    def _render(self, final=False):
        # FORCE 100% for done states
        if st == "done":
            bar = "[██████████████████] 100.0%"
```

### Background Rendering Thread

```python
def start(self):
    self._thread = threading.Thread(target=self._loop, daemon=True)
    self._thread.start()

def _loop(self):
    while not self._stop.is_set():
        self._render()
        time.sleep(0.15)  # Refresh every 150ms
        self._tick += 1

def _render(self):
    # Cursor control: move up, clear, redraw
    if self._drawn > 0:
        sys.stdout.write(f"\033[{self._drawn}A")  # Move up N lines
    sys.stdout.write(table_output)
    sys.stdout.flush()
```

---

## Report Generation

### HTML Report Architecture

**Dynamic Generation Principle**: Zero hardcoded values. Every number, chart width, color, and text is computed from actual `findings` + `scan_meta` at runtime.

**Structure**:

```html
<!DOCTYPE html>
<html>
<head>
  <style>
    /* 1200+ lines of embedded CSS */
    /* Dark theme, responsive grid, animated charts */
  </style>
</head>
<body>
  <!-- Header: Logo, metadata, risk gauge -->
  
  <!-- Module Progress Bars -->
  <div class="prow">
    <span>SQL Injection</span>
    <div class="ptrk">
      <div class="pfil" style="width:75%" data-w="75%"></div>
    </div>
    <span>3</span> <!-- Finding count -->
  </div>
  
  <!-- Module Toggle Cards -->
  <div class="tc" data-mod="sqli">
    <input type="checkbox" checked onchange="toggleMod('sqli',this.checked)">
  </div>
  
  <!-- Severity Cards (animated counters) -->
  <div class="sc">
    <div class="sc-n" data-n="5">0</div> <!-- Counts up to 5 -->
    <div class="sc-l">critical</div>
  </div>
  
  <!-- Bar Charts (severity, module distribution) -->
  
  <!-- OWASP Top 10 Mapping -->
  <div class="owrow">
    <div class="owdot" style="background:#ef4444"></div>
    <span>A03:2021</span>
    <span>Injection</span>
    <div class="owbf" style="width:65%"></div>
    <span>3</span>
  </div>
  
  <!-- MITRE ATT&CK Mapping -->
  
  <!-- Advanced Statistics -->
  
  <!-- Scan Timeline -->
  
  <!-- Configuration Tables -->
  
  <!-- Detailed Findings (expandable cards) -->
  <div class="fi" data-sev="critical" data-mod="sqli" data-search="...">
    <div class="fi-hdr" onclick="tog(this)">
      <span class="pill">🔴 CRITICAL</span>
      <div class="fi-title">SQL Injection (Error-Based)</div>
    </div>
    <div class="fi-body">
      <!-- Description, payload, evidence, remediation -->
    </div>
  </div>
  
  <!-- Footer -->
  
  <script>
    /* JavaScript for filtering, animations, interactions */
    var activeSev = 'all';
    var activeSearch = '';
    var activeMods = new Set(['sqli', 'xss', ...]);
    
    function applyFilters() {
      // Hide/show findings based on severity + module + search
    }
    
    function toggleMod(mod, checked) {
      // Update activeMods Set, apply filters
    }
    
    function animN(el, target) {
      // Animate number counter from 0 to target
    }
    
    window.addEventListener('DOMContentLoaded', () => {
      // Animate all counters and progress bars
      // Auto-expand first critical/high finding
    });
  </script>
</body>
</html>
```

### JSON Report Structure

```json
{
  "report_metadata": {
    "tool": "PenguardOps",
    "version": "2.1.0",
    "generated_at": "2026-02-18T05:20:15.123456",
    "report_format": "JSON"
  },
  "scan_summary": {
    "scan_id": "scan_20260218_052015_abc123",
    "target": "http://testphp.vulnweb.com",
    "start_time": "2026-02-18T05:12:00",
    "end_time": "2026-02-18T05:18:22",
    "duration": 382.4,
    "waf_detected": "Cloudflare",
    "urls_scanned": 127,
    "attack_surface": {
      "total_urls": 127,
      "forms": 18,
      "parameterized_urls": 45
    },
    "modules_run": ["sqli", "xss", "lfi", ...],
    "total_findings": 13,
    "findings_by_severity": {
      "critical": 3,
      "high": 4,
      "medium": 5,
      "low": 1
    },
    "findings_by_module": {
      "sqli": 2,
      "xss": 2,
      "headers": 5,
      ...
    },
    "risk_score": 87.5
  },
  "findings": [
    {
      "module": "sqli",
      "title": "SQL Injection (Error-Based) — MySQL",
      "severity": "critical",
      "description": "...",
      "url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
      "parameter": "cat",
      "method": "GET",
      "payload": "' OR 1=1--",
      "evidence": "MySQL error detected",
      "owasp_category": "A03:2021",
      "owasp_title": "Injection",
      "mitre_technique": "T1190",
      "mitre_title": "Exploit Public-Facing Application",
      "cwe_id": "CWE-89",
      "cvss_score": 9.8,
      "confidence": "high",
      "timestamp": "2026-02-18T05:15:32",
      "remediation": "...",
      "references": ["https://owasp.org/..."]
    }
  ],
  "owasp_coverage": [
    {
      "id": "A03:2021",
      "title": "Injection",
      "affected": true,
      "finding_count": 4
    }
  ],
  "mitre_coverage": [
    {
      "technique_id": "T1190",
      "technique_name": "Exploit Public-Facing Application",
      "detected": true
    }
  ]
}
```

---

## Scan Persistence

### File Structure

```
.vulnscan_state/
└── scan_20260218_052015_abc123.json
```

### State Schema

```json
{
  "scan_id": "scan_20260218_052015_abc123",
  "created_at": "2026-02-18T05:12:00",
  "updated_at": "2026-02-18T05:18:22",
  "status": "complete",
  "config": { ... },
  "visited_urls": ["http://...", "http://..."],
  "crawl_results": {
    "http://example.com": {
      "depth": 0,
      "status_code": 200,
      "content_type": "text/html",
      "form_count": 2,
      "parameter_count": 3
    }
  },
  "findings": [ ... ],
  "waf_detected": "Cloudflare",
  "modules_completed": ["sqli", "xss", "headers"]
}
```

### Resume Workflow

```python
1. User runs: python penguardops.py -u https://target.com --resume scan_20260218_abc123

2. Engine loads state file:
   state = ScanState.load("scan_20260218_abc123")

3. Restore crawler state:
   crawler.visited = state.previously_visited
   → Crawler skips all previously visited URLs

4. Identify remaining modules:
   modules_to_run = [m for m in enabled_modules 
                     if m not in state.modules_already_run]
   → Only run modules not yet completed

5. Run remaining modules

6. Append new findings to existing findings

7. Mark scan as complete

8. Generate reports with ALL findings (old + new)
```

---

## WAF Detection & Bypass

### Detection Algorithm

```python
def detect_waf(self, url):
    # Send probe with suspicious payload
    probe_url = url + "/?vulnscan_waf_probe=<script>alert(1)</script>"
    resp = self.session.get(probe_url)
    
    # Combine headers and body for analysis
    check_text = " ".join(resp.headers.values()) + " " + resp.text[:2000]
    check_text = check_text.lower()
    
    # Match against signature database
    for waf_name, patterns in WAF_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern.lower(), check_text):
                return waf_name
    
    return None
```

### Bypass Techniques

```python
WAF_BYPASS_TECHNIQUES = {
    "case_variation": lambda p: p.upper() if random.random() > 0.5 else p.lower(),
    # SELECT → SeLeCt
    
    "comment_insertion": lambda p: p.replace("SELECT", "SE/**/LECT"),
    # SELECT → SE/**/LECT
    
    "url_encoding": lambda p: p.replace("'", "%27").replace(" ", "%20"),
    # ' OR 1=1 → %27%20OR%201=1
    
    "double_encoding": lambda p: p.replace("%", "%25"),
    # %27 → %2527
    
    "whitespace_variation": lambda p: p.replace(" ", "\t"),
    # space → tab
}

# Apply during scan:
if self.config.waf_bypass:
    payload = self.session.apply_waf_bypass(payload)
```

---

## Configuration System

### ScanConfig Dataclass

```python
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
        "sqli", "xss", "lfi", "open_redirect", 
        "headers", "csrf", "xxe", "ssrf", "idor"
    ])
    
    # WAF
    detect_waf: bool = True
    waf_bypass: bool = False
    
    # HTTP
    user_agent: str = "Mozilla/5.0 ..."
    cookies: Dict[str, str] = field(default_factory=dict)
    custom_headers: Dict[str, str] = field(default_factory=dict)
    proxy: Optional[str] = None
    verify_ssl: bool = False
    
    # Auth
    auth_user: Optional[str] = None
    auth_pass: Optional[str] = None
    
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
```

---

## Plugin Architecture

### Plugin Lifecycle

```python
1. Engine loads plugin class:
   plugin_class = PLUGIN_REGISTRY["sqli"]
   # PLUGIN_REGISTRY = {"sqli": SQLiPlugin, "xss": XSSPlugin, ...}

2. Instantiate plugin:
   plugin = plugin_class(session, config)

3. Run plugin:
   findings = plugin.run(crawl_results)
   
4. Plugin processes all URLs/forms:
   for url, result in crawl_results.items():
       self._test_url(url)
       for form in result.forms:
           self._test_form(form)

5. Plugin creates findings:
   finding = self._make_finding(
       title="SQL Injection",
       severity="critical",
       description="...",
       url=url,
       parameter=param,
       payload=payload,
       evidence=evidence,
       cwe_id="CWE-89",
       cvss_score=9.8,
       ...
   )
   self.add_finding(finding)

6. Return findings to engine:
   return self.findings
```

### Creating a Custom Plugin

```python
from core.base_plugin import BasePlugin, Finding

class MyCustomPlugin(BasePlugin):
    plugin_id = "my_vuln"
    name = "My Vulnerability"
    description = "Tests for custom vulnerability"
    owasp_category = "A01:2021"
    mitre_technique = "T1190"
    
    def run(self, crawl_results: Dict) -> List[Finding]:
        self.log_info("Starting custom scan")
        
        for url, result in crawl_results.items():
            # Test URL
            resp = self.session.get(url + "?custom_param=test")
            if resp and "vulnerable_pattern" in resp.text:
                self.add_finding(self._make_finding(
                    title="Custom Vulnerability Found",
                    severity="high",
                    description="The application is vulnerable to...",
                    url=url,
                    cwe_id="CWE-XXX",
                    cvss_score=7.5,
                    confidence="high",
                    remediation="Fix by doing...",
                ))
        
        return self.findings

# Register in engine.py:
PLUGIN_REGISTRY["my_vuln"] = MyCustomPlugin
```

---

## HTTP Session Management

### Session Features

```python
class HttpSession:
    def __init__(self, config):
        self.session = requests.Session()
        
        # Retry strategy
        retry = Retry(total=2, backoff_factor=0.5, 
                      status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Default headers
        self.session.headers.update({
            "User-Agent": config.user_agent,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.5",
        })
        
        # Cookies, auth, proxy
        self.session.cookies.update(config.cookies)
        if config.auth_user:
            self.session.auth = (config.auth_user, config.auth_pass)
        if config.proxy:
            self.session.proxies = {"http": config.proxy, "https": config.proxy}
    
    def _request(self, method, url, **kwargs):
        # Rate limiting with jitter
        if self.config.delay > 0:
            jitter = random.uniform(0, self.config.delay * 0.5)
            time.sleep(self.config.delay + jitter)
        
        # Make request
        resp = self.session.request(method, url, **kwargs)
        self.request_count += 1
        
        return resp
```

### Baseline Comparison

```python
class BaselineResponse:
    def __init__(self, response):
        self.status_code = response.status_code
        self.content_length = len(response.content)
        self.content_hash = hashlib.md5(response.content).hexdigest()
        self.title = extract_title(response.text)
        self.error_indicators = check_errors(response.text)
    
    def differs_from(self, other, threshold=0.2):
        # Different status code
        if other.status_code != self.status_code:
            return True
        
        # Significant length difference
        if self.content_length > 0:
            diff_ratio = abs(other.content_length - self.content_length) / self.content_length
            if diff_ratio > threshold:
                return True
        
        # Different title
        if other.title != self.title:
            return True
        
        return False

# Usage in plugins:
baseline = self.session.get_baseline(url)
test_resp = self.session.get(test_url)
if self.session.response_differs_from_baseline(url, test_resp):
    # Potential vulnerability
```

---

## Crawler Implementation

### Multi-Threaded Architecture

```python
class Crawler:
    def crawl(self):
        queue = deque([(target_url, 0)])
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {}
            
            while queue or futures:
                # Submit work
                while queue and len(futures) < threads * 2:
                    url, depth = queue.popleft()
                    future = executor.submit(self._crawl_url, url, depth)
                    futures[future] = (url, depth)
                
                # Process completed
                done = {f for f in futures if f.done()}
                for future in done:
                    url, depth = futures.pop(future)
                    result = future.result()
                    
                    if result:
                        self.results[url] = result
                        
                        # Enqueue discovered links
                        if depth < max_depth:
                            for link in result.links:
                                if link not in visited and link not in queued:
                                    queue.append((link, depth + 1))
```

### Form Parsing

```python
def _extract_forms(self, soup, base_url):
    forms = []
    
    for form_tag in soup.find_all("form"):
        action = form_tag.get("action", "")
        method = form_tag.get("method", "GET").upper()
        
        # Resolve action URL
        if action:
            action = urljoin(base_url, action)
        else:
            action = base_url
        
        # Parse fields
        fields = []
        for inp in form_tag.find_all(["input", "textarea", "select"]):
            name = inp.get("name", "")
            if not name:
                continue
            
            field_type = inp.get("type", "text").lower()
            value = inp.get("value", "")
            
            # Handle select dropdowns
            if inp.name == "select":
                options = [opt.get("value", opt.text) 
                          for opt in inp.find_all("option")]
                value = options[0] if options else ""
                field_type = "select"
            
            fields.append(FormField(
                name=name,
                field_type=field_type,
                value=value,
                options=options
            ))
        
        forms.append(Form(
            url=base_url,
            action=action,
            method=method,
            fields=fields
        ))
    
    return forms
```

---

## Security Considerations

### Rate Limiting & Politeness

```python
# Configurable delay between requests
delay: float = 0.5  # seconds

# Jitter to avoid detection
jitter = random.uniform(0, delay * 0.5)
time.sleep(delay + jitter)

# Max URLs to prevent runaway crawls
max_urls: int = 200
```

### Scope Enforcement

```python
def _in_scope(self, url):
    parsed = urlparse(url)
    return parsed.netloc in self.scope_domains

# Only crawl in-scope domains
if not self._in_scope(discovered_url):
    continue  # Skip
```

### SSL/TLS Verification

```python
# Disabled by default for internal testing
verify_ssl: bool = False

# But can be enabled:
python penguardops.py -u https://target.com --verify-ssl
```

### Request Timeout

```python
# Prevent hanging on slow servers
timeout: int = 10  # seconds

resp = self.session.request(method, url, timeout=timeout)
```

---

## Troubleshooting

### Common Issues

**Issue**: Progress bars show duplicates  
**Solution**: Fixed in v2.1 — PhaseTracker deduplicates on init

**Issue**: Progress exceeds 100%  
**Solution**: Fixed in v2.1 — `update()` caps done ≤ total

**Issue**: Progress still running after completion  
**Solution**: Fixed in v2.1 — `set_running()` doesn't overwrite "done" state

**Issue**: "Connection refused" errors  
**Solution**: Check if target is accessible, verify URL format includes http:// or https://

**Issue**: "Too many redirects"  
**Solution**: Target might have redirect loop, check with browser first

**Issue**: No findings detected on known vulnerable target  
**Solution**: 
- Check if WAF is blocking requests (use --waf-bypass)
- Increase crawl depth (--depth 5)
- Check if target requires authentication (use --cookies or --auth-user)

**Issue**: Scan very slow  
**Solution**: 
- Increase threads (--threads 10)
- Reduce delay (--delay 0.1)
- Decrease max URLs (--max-urls 50)

**Issue**: Out of memory error  
**Solution**: Reduce --max-urls limit

---

## Performance Tuning

### Recommended Settings

**Fast scan** (60-120 seconds):
```bash
--depth 2 --max-urls 50 --threads 10 --delay 0.1
```

**Balanced scan** (5-10 minutes):
```bash
--depth 3 --max-urls 200 --threads 5 --delay 0.5
```

**Deep scan** (30-60 minutes):
```bash
--depth 5 --max-urls 1000 --threads 8 --delay 0.3
```

**Stealth scan** (slow, avoids detection):
```bash
--depth 3 --max-urls 100 --threads 2 --delay 2.0
```

---

## Conclusion

PenguardOps v2.1 is a production-grade penetration testing framework with enterprise-level features. This documentation covers the complete workflow, architecture, and implementation details needed to understand, use, extend, and troubleshoot the tool.

For questions, issues, or contributions, visit:
https://github.com/yourusername/penguardops

**Happy ethical hacking! 🐧🔒**
