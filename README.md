# 🐧 PenguardOps v2.1

**Elite Penetration Testing Framework** — Professional web vulnerability scanner with real-time progress tracking, interactive module selection, and comprehensive security reporting.

```

   ___                                     _   ___           
  / _ \___ _ __   __ _ _   _  __ _ _ __ __| | /___\_ __  ___ 
 / /_)/ _ \ '_ \ / _` | | | |/ _` | '__/ _` |//  // '_ \/ __|
/ ___/  __/ | | | (_| | |_| | (_| | | | (_| / \_//| |_) \__ \
\/    \___|_| |_|\__, |\__,_|\__,_|_|  \__,_\___/ | .__/|___/
                 |___/                            |_|        
             
```

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010-red.svg)](https://owasp.org/www-project-top-ten/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange.svg)](https://attack.mitre.org/)

---

## 🎯 Features

### Core Capabilities
- ✅ **9 Vulnerability Modules** — SQL Injection, XSS, LFI, Open Redirect, Security Headers, CSRF, XXE, SSRF, IDOR
- ✅ **Real-Time Progress Tracking** — Live multi-phase progress bars with ETA
- ✅ **Interactive Module Selection** — Yes/no prompt per module before scanning
- ✅ **WAF Detection & Bypass** — Identifies web application firewalls and applies evasion techniques
- ✅ **Intelligent Crawler** — Depth-controlled, scope-aware with form discovery
- ✅ **OWASP Top 10 Mapping** — Findings mapped to OWASP 2021 categories
- ✅ **MITRE ATT&CK Framework** — Techniques aligned with adversary tactics
- ✅ **Dual Report Format** — Professional HTML + machine-readable JSON
- ✅ **Scan Persistence** — Resume interrupted scans with `--resume`
- ✅ **Concurrent Scanning** — Multi-threaded plugin execution for speed

### Advanced Features
- 🔍 **Smart Detection**
  - Error-based SQL injection
  - Boolean-blind SQL injection
  - Time-based blind SQL injection
  - Reflected & DOM-based XSS
  - Path traversal / LFI
  - Open redirect vulnerabilities
  - Missing security headers
  - CSRF token validation
  - XXE injection
  - SSRF via metadata endpoints
  - IDOR with sequential IDs

- 🛡️ **Stealth & Evasion**
  - WAF fingerprinting (Cloudflare, AWS WAF, Akamai, ModSecurity, Imperva, F5, etc.)
  - Configurable request delays and jitter
  - Custom User-Agent strings
  - Cookie/header injection
  - HTTP proxy support

- 📊 **Professional Reporting**
  - Dynamic HTML reports with interactive filtering
  - Severity-based prioritization (Critical → Info)
  - CVSS scoring
  - Exploit likelihood meters
  - Module toggle filters
  - Real-time search
  - Responsive design

---

## 📦 Installation

### Requirements
- Python 3.8 or higher
- pip package manager

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/penguardops.git
cd penguardops

# Install dependencies
pip install -r requirements.txt

# Run your first scan
python penguardops.py -u https://example.com
```

### Dependencies
```
requests>=2.31.0
beautifulsoup4>=4.12.0
urllib3>=2.0.0
lxml>=4.9.0
```

---

## 🚀 Usage

### Basic Scan
```bash
python penguardops.py -u https://target.com
```

### Interactive Module Selection
```bash
python penguardops.py -u https://target.com --select-modules
```

### Specific Modules
```bash
python penguardops.py -u https://target.com --modules sqli xss headers
```

### Advanced Scan
```bash
python penguardops.py -u https://target.com \
  --depth 4 \
  --threads 10 \
  --max-urls 500 \
  --waf-bypass \
  --delay 0.3 \
  --report html \
  --output-dir ./my-reports
```

### Resume Interrupted Scan
```bash
python penguardops.py -u https://target.com --resume scan_20260218_abc123
```

### With Authentication
```bash
python penguardops.py -u https://target.com \
  --cookies "session=abc123; token=xyz789" \
  --headers "Authorization: Bearer TOKEN"
```

### Through Proxy
```bash
python penguardops.py -u https://target.com --proxy http://127.0.0.1:8080
```

---

## 📖 Command Reference

### Required Arguments
```
-u, --url URL              Target URL to scan
```

### Crawl Configuration
```
--depth INT                Crawl depth (default: 3)
--max-urls INT             Maximum URLs to crawl (default: 200)
--threads INT              Concurrent threads (default: 5)
--delay FLOAT              Delay between requests in seconds (default: 0.5)
--timeout INT              Request timeout in seconds (default: 10)
```

### Module Selection
```
--modules [MODULE ...]     Specific modules: sqli, xss, lfi, open_redirect,
                           headers, csrf, xxe, ssrf, idor, or 'all'
--skip-modules [MODULE]    Modules to exclude from scan
--select-modules           Interactive yes/no prompt per module
--list-modules             Display all available modules and exit
```

### WAF & Evasion
```
--no-waf                   Skip WAF detection
--waf-bypass               Enable WAF evasion techniques
--user-agent UA            Custom User-Agent string
--cookies COOKIES          Session cookies (key=value; key2=value2)
--headers [HEADER:VALUE]   Additional HTTP headers
--proxy URL                HTTP/HTTPS proxy
```

### Authentication
```
--auth-user USER           HTTP Basic auth username
--auth-pass PASS           HTTP Basic auth password
--login-url URL            Login form URL
--login-data DATA          Login POST data
```

### Persistence
```
--resume SCAN_ID           Resume previous scan
--scan-id ID               Custom scan identifier
--no-save                  Don't save scan state
--list-scans               List all saved scans and exit
```

### Output
```
--report {html,json,both}  Report format (default: both)
--output-dir DIR           Output directory (default: ./reports)
--severity {critical,high,medium,low,info}
                           Minimum severity to report (default: info)
-v, --verbose              Verbose output
-q, --quiet                Quiet mode (errors only)
```

---

## 🏗️ Architecture

```
penguardops/
├── core/
│   ├── base_plugin.py      # Plugin interface & Finding model
│   ├── config.py           # Scan configuration management
│   ├── crawler.py          # Intelligent web crawler
│   ├── engine.py           # Orchestration & workflow
│   └── http_session.py     # HTTP client with WAF detection
├── modules/
│   ├── sqli_plugin.py      # SQL injection scanner
│   ├── xss_plugin.py       # XSS detection
│   └── other_plugins.py    # LFI, headers, CSRF, XXE, SSRF, IDOR
├── reports/
│   ├── html_report.py      # Dynamic HTML generation
│   └── json_report.py      # JSON export
├── persistence/
│   └── scan_state.py       # Scan save/resume
├── utils/
│   ├── logger.py           # Colored logging
│   └── progress.py         # Real-time progress UI
├── penguardops.py          # Main CLI entry point
└── requirements.txt        # Python dependencies
```

---

## 🔍 Module Details

| Module | Severity | OWASP | MITRE | Description |
|--------|----------|-------|-------|-------------|
| **sqli** | CRITICAL | A03:2021 | T1190 | Error-based, boolean-blind, time-based SQL injection |
| **xss** | HIGH | A03:2021 | T1059.007 | Reflected, stored, DOM-based cross-site scripting |
| **lfi** | CRITICAL | A01:2021 | T1083 | Path traversal / local file inclusion |
| **open_redirect** | MEDIUM | A01:2021 | T1534 | Unvalidated URL redirects |
| **headers** | MEDIUM | A05:2021 | T1600 | Missing security headers (CSP, HSTS, etc.) |
| **csrf** | MEDIUM | A01:2021 | T1185 | Cross-site request forgery token validation |
| **xxe** | HIGH | A05:2021 | T1190 | XML external entity injection |
| **ssrf** | HIGH | A10:2021 | T1090 | Server-side request forgery |
| **idor** | MEDIUM | A01:2021 | T1078 | Insecure direct object references |

---

## 📊 Report Features

### HTML Report Highlights
- 🎨 **Professional Dark Theme** — Modern, responsive interface
- 📈 **Interactive Charts** — Severity distribution, module breakdown
- 🔍 **Live Filtering** — By severity, module, or search query
- 🎛️ **Module Toggles** — Enable/disable findings by module
- 📊 **Risk Gauge** — 0-100 risk score with visual indicator
- ⏱️ **Scan Timeline** — Visual event timeline
- 🗺️ **Framework Mapping** — OWASP Top 10 & MITRE ATT&CK coverage
- 📉 **Advanced Stats** — Exploit likelihood, CVSS scores, confidence levels
- 🔒 **Finding Details** — Payload, evidence, remediation, references

### JSON Report Structure
```json
{
  "report_metadata": { "tool": "PenguardOps", "version": "2.1.0" },
  "scan_summary": { "total_findings": 15, "risk_score": 87.5 },
  "findings": [ { "severity": "critical", "title": "...", ... } ],
  "owasp_coverage": [ { "id": "A03:2021", "affected": true } ],
  "mitre_coverage": [ { "technique_id": "T1190", "detected": true } ]
}
```

---

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

PenguardOps is designed for **authorized security assessments** and **penetration testing** of systems you own or have explicit permission to test.

### You are responsible for:
- ✅ Obtaining **written permission** before scanning any system
- ✅ Complying with all applicable **laws and regulations**
- ✅ Respecting **bug bounty program** rules and scope
- ✅ Following **responsible disclosure** practices

### Unauthorized use is illegal:
- ❌ Scanning systems without permission is **illegal** in most jurisdictions
- ❌ Violates Computer Fraud and Abuse Act (US) and similar laws worldwide
- ❌ May result in **criminal prosecution** and **civil liability**

**The authors assume no liability for misuse of this tool.**

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Setup
```bash
git clone https://github.com/yourusername/penguardops.git
cd penguardops
pip install -r requirements.txt -r requirements-dev.txt  # If dev deps exist
```

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **OWASP** — For the Top 10 framework and comprehensive security resources
- **MITRE** — For the ATT&CK framework mapping
- **PortSwigger** — For Web Security Academy and research
- **Security Community** — For vulnerability research and disclosure

---

## 📧 Contact

- **Issues**: [GitHub Issues](https://github.com/yourusername/penguardops/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/penguardops/discussions)

---

## 🔄 Version History

### v2.1 (Current)
- ✅ Fixed progress tracker duplicate phases
- ✅ Fixed progress bars exceeding 100%
- ✅ Improved state management for concurrent operations
- ✅ Shield icon restored in HTML reports
- ✅ Enhanced hacker penguin CLI banner

### v2.0
- ✨ Real-time multi-phase progress tracking
- ✨ Interactive module yes/no selection
- ✨ Dynamic HTML report generation (zero hardcoded values)
- ✨ Hacker-themed branding

### v1.0
- 🎉 Initial release
- 🎉 9 vulnerability detection modules
- 🎉 WAF detection and bypass
- 🎉 HTML + JSON reporting

---

**Made with 🐧 by security researchers, for security researchers**

⭐ **Star this repo if you find it useful!**
