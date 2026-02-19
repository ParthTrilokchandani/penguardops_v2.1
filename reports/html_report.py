"""
HTML Report Generator v5.0
100% dynamic — every number, chart, finding, and colour is generated
from the actual scan_meta + findings passed in at runtime.
No hardcoded values anywhere in the output.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List
from collections import Counter

from core.base_plugin import Finding, OWASP_TOP10, MITRE_ATTACK
from core.config import ScanConfig

# ── Severity palette ──────────────────────────────────────────────────────────
SEV_HEX   = {"critical":"#ef4444","high":"#f97316","medium":"#eab308","low":"#3b82f6","info":"#6b7280"}
SEV_ICON  = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","info":"⚪"}
SEV_ORDER = ["critical","high","medium","low","info"]

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

def _e(v) -> str:
    """HTML-escape a value."""
    if v is None: return ""
    return (str(v)
            .replace("&","&amp;").replace("<","&lt;")
            .replace(">","&gt;").replace('"',"&quot;")
            .replace("'","&#x27;"))


class HTMLReporter:
    def __init__(self, config: ScanConfig):
        self.config = config

    # ── Entry ─────────────────────────────────────────────────────────────────
    def generate(self, findings: List[Finding], scan_meta: dict) -> str:
        by_sev     = Counter(f.severity for f in findings)
        risk_score = min(100.0, round(
            sum({"critical":40,"high":15,"medium":5,"low":1,"info":0}.get(f.severity,0)
                for f in findings), 1))
        risk_level = ("CRITICAL" if risk_score>=80 else "HIGH" if risk_score>=50
                      else "MEDIUM" if risk_score>=25 else "LOW" if risk_score>0 else "NONE")
        risk_hex   = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308",
                      "LOW":"#3b82f6","NONE":"#22c55e"}.get(risk_level,"#6b7280")

        html = self._full_doc(findings, scan_meta, by_sev, risk_score, risk_level, risk_hex)

        out_dir  = Path(self.config.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        filepath = out_dir / f"penguardops_{self.config.scan_id}.html"
        filepath.write_text(html, encoding="utf-8")
        return str(filepath)

    # ── Document ──────────────────────────────────────────────────────────────
    def _full_doc(self, findings, meta, by_sev, risk_score, risk_level, risk_hex):
        total    = len(findings)
        target   = meta.get("target","N/A")
        sid      = meta.get("scan_id","N/A")
        waf      = meta.get("waf_detected") or "None detected"
        dur      = meta.get("duration",0)
        urls     = meta.get("urls_scanned",0)
        atk      = meta.get("attack_surface",{})
        forms    = atk.get("forms",0)
        params   = atk.get("parameterized_urls",0)
        mods     = meta.get("modules_run",[])
        cfg      = meta.get("config",{})
        start    = meta.get("start_time","")
        end      = meta.get("end_time","")

        owasp_counts   = Counter(f.owasp_category for f in findings if f.owasp_category)
        mitre_detected = {f.mitre_technique for f in findings if f.mitre_technique}
        mod_counts     = Counter(f.module for f in findings)

        # ── Safe JS payload (only IDs, no raw user data) ──────────────────────
        fi_js = json.dumps([{"id":i,"sev":f.severity,"mod":f.module}
                             for i,f in enumerate(findings)])
        mods_js = json.dumps(mods)

        # ── Gauge SVG ─────────────────────────────────────────────────────────
        r  = 36; circ = 2*3.14159*r; off = circ*(1-risk_score/100)
        gauge = (f'<svg width="86" height="86" viewBox="0 0 86 86">'
                 f'<circle cx="43" cy="43" r="{r}" fill="none" stroke="#1d2d40" stroke-width="8"/>'
                 f'<circle cx="43" cy="43" r="{r}" fill="none" stroke="{risk_hex}" stroke-width="8" '
                 f'stroke-dasharray="{circ:.1f}" stroke-dashoffset="{off:.1f}" stroke-linecap="round" '
                 f'transform="rotate(-90 43 43)"/></svg>')

        # ── Module progress rows ──────────────────────────────────────────────
        mod_progress = ""
        for m in mods:
            cnt   = mod_counts.get(m, 0)
            pct   = int(cnt/max(total,1)*100) if total else 0
            color = "#ef4444" if cnt>2 else "#f97316" if cnt>0 else "#22c55e"
            label = MODULE_LABEL.get(m, m)
            stat  = f'<span style="color:{"#f87171" if cnt else "#4ade80"}">{"⚠ Issues" if cnt else "✓ Clean"}</span>'
            mod_progress += f"""
<div class="prow">
  <span class="plbl">{_e(label)}</span>
  <div class="ptrk"><div class="pfil" style="background:{color}" data-w="{pct}%"></div></div>
  <span class="pcnt" style="color:{color}">{cnt}</span>
  <span class="pstat">{stat}</span>
</div>"""

        # ── Module toggle cards ───────────────────────────────────────────────
        toggle_cards = ""
        for m, mlabel in MODULE_LABEL.items():
            cnt   = mod_counts.get(m, 0)
            ran   = m in mods
            has_f = cnt > 0
            cls   = ("enabled " if ran else "") + ("has-fi" if has_f else "")
            sub   = (f"{cnt} issue{'s' if cnt!=1 else ''}" if has_f
                     else ("Ran — clean" if ran else "Not enabled"))
            sc    = "red" if has_f else ""
            toggle_cards += f"""
<div class="tc {cls}" data-mod="{_e(m)}">
  <div><div class="tc-n">{_e(mlabel)}</div><div class="tc-s {sc}">{sub}</div></div>
  <label class="sw">
    <input type="checkbox" {"checked" if ran else ""} onchange="toggleMod('{_e(m)}',this.checked)">
    <div class="sw-t"></div><div class="sw-k"></div>
  </label>
</div>"""

        # ── Severity cards ────────────────────────────────────────────────────
        max_n = max(by_sev.values(), default=1) or 1
        sev_cards = ""
        for sev in SEV_ORDER:
            n   = by_sev.get(sev, 0)
            clr = SEV_HEX[sev]
            pct = int(n/max_n*100)
            sev_cards += f"""
<div class="sc" onclick="filterSev('{sev}',this)" style="border-top:3px solid {clr}">
  <div>{SEV_ICON[sev]}</div>
  <div class="sc-n" style="color:{clr}" data-n="{n}">0</div>
  <div class="sc-l">{sev}</div>
  <div class="sc-b"><div class="sc-f" style="background:{clr}" data-w="{pct}%"></div></div>
</div>"""

        # ── Severity bar chart ────────────────────────────────────────────────
        sev_chart = ""
        for sev in SEV_ORDER:
            n   = by_sev.get(sev, 0)
            pct = int(n/max_n*100)
            clr = SEV_HEX[sev]
            sev_chart += f"""
<div class="bcr">
  <span class="bcl">{sev.capitalize()}</span>
  <div class="bct"><div class="bcf" style="background:{clr}" data-w="{pct}%">{n if n else ""}</div></div>
  <span class="bcv" style="color:{clr}">{n}</span>
</div>"""

        # ── Module bar chart ──────────────────────────────────────────────────
        mod_chart = ""
        if mod_counts:
            mx = max(mod_counts.values(), default=1) or 1
            for m, cnt in sorted(mod_counts.items(), key=lambda x:-x[1]):
                pct   = int(cnt/mx*100)
                label = MODULE_LABEL.get(m, m)
                mod_chart += f"""
<div class="bcr">
  <span class="bcl" title="{_e(label)}">{_e(label[:13])}</span>
  <div class="bct"><div class="bcf" style="background:var(--ac)" data-w="{pct}%">{cnt}</div></div>
  <span class="bcv">{cnt}</span>
</div>"""
        else:
            mod_chart = '<p class="dim">No findings.</p>'

        # ── OWASP rows ────────────────────────────────────────────────────────
        owasp_rows = ""
        max_o = max(owasp_counts.values(), default=1) or 1
        for oid, otitle in OWASP_TOP10.items():
            n   = owasp_counts.get(oid, 0)
            clr = "#ef4444" if n>2 else "#f97316" if n>0 else "#1d2d40"
            dot = "#ef4444" if n else "#1d2d40"
            pct = int(n/max_o*100)
            owasp_rows += f"""
<div class="owrow">
  <div class="owdot" style="background:{dot}"></div>
  <span class="owid">{_e(oid)}</span>
  <span class="own" title="{_e(otitle)}">{_e(otitle)}</span>
  <div class="owbw"><div class="owbf" style="background:{clr};width:{pct}%"></div></div>
  <span class="owcnt" style="color:{clr}">{n if n else "—"}</span>
</div>"""

        # ── MITRE rows ────────────────────────────────────────────────────────
        mitre_rows = ""
        for tid, tname in MITRE_ATTACK.items():
            hit = tid in mitre_detected
            cls = "mtrow hit" if hit else "mtrow"
            bdg = f'<span class="mbdg d">DETECTED</span>' if hit else f'<span class="mbdg c">Clean</span>'
            mitre_rows += f"""
<div class="{cls}">
  <span>{"🔴" if hit else "⚪"}</span>
  <span class="mtid">{_e(tid)}</span>
  <span class="mtn">{_e(tname)}</span>
  {bdg}
</div>"""

        # ── Advanced stats ────────────────────────────────────────────────────
        crit_high   = by_sev.get("critical",0)+by_sev.get("high",0)
        unique_urls = len({f.url for f in findings})
        hi_conf     = sum(1 for f in findings if getattr(f,"confidence","")=="high")
        cvss_l      = [f.cvss_score for f in findings if f.cvss_score]
        avg_cvss    = round(sum(cvss_l)/len(cvss_l),1) if cvss_l else 0
        exploitable = sum(1 for f in findings
                          if f.severity in ("critical","high") and
                          getattr(f,"confidence","")=="high")
        stats_html  = ""
        for t,v,s in [("Total Issues",total,"across all modules"),
                       ("Critical + High",crit_high,"require immediate action"),
                       ("Affected URLs",unique_urls,"unique endpoints"),
                       ("High Confidence",hi_conf,"low false-positive risk"),
                       (f"Avg CVSS",f"{avg_cvss}/10","severity score"),
                       ("Likely Exploitable",exploitable,"critical+high, hi-conf")]:
            stats_html += f'<div class="vs"><div class="vs-t">{t}</div><div class="vs-v">{v}</div><div class="vs-s">{s}</div></div>'

        # ── Timeline ─────────────────────────────────────────────────────────
        ts = start[:19].replace("T"," ") if start else ""
        te = end[:19].replace("T"," ")   if end   else ""
        tl_events = [
            (ts,  "var(--ac)",  f"🚀 Scan initiated — {_e(target)}"),
            ("",  "var(--ac2)", f"🕷️ Crawler launched — depth {cfg.get('depth',3)}, {cfg.get('threads',5)} threads"),
            ("",  "var(--ac3)", f"📋 Discovered {urls} URLs · {forms} forms · {params} param endpoints"),
            ("",  "#f97316",    f"⚙️ {len(mods)} module(s) executed: {_e(', '.join(mods))}"),
            ("",  "#ef4444" if findings else "#22c55e",
                                f"🔍 {total} finding(s) recorded" +
                                (" — remediation required" if findings else " — target appears clean")),
            (te,  "var(--ac3)", f"✅ Scan complete — {dur:.1f}s elapsed"),
        ]
        timeline_rows = "".join(f"""
<div class="tli">
  <div class="tldot" style="border-color:{c}"></div>
  <div class="tlts">{ts2}</div>
  <div class="tltx">{tx}</div>
</div>""" for ts2,c,tx in tl_events)

        # ── Config tables ─────────────────────────────────────────────────────
        cfg_rows_a = "".join(f'<tr><td>{k}</td><td><code>{_e(v)}</code></td></tr>' for k,v in [
            ("Target URL",   target),
            ("Scan ID",      sid),
            ("URLs Scanned", urls),
            ("Forms Found",  forms),
            ("Param URLs",   params),
            ("WAF Detected", waf),
            ("Duration",     f"{dur:.1f}s"),
            ("Start",        start[:19] if start else "N/A"),
        ])
        cfg_rows_b = "".join(f'<tr><td>{k}</td><td>{_e(v)}</td></tr>' for k,v in [
            ("Modules Run",   f"{len(mods)} / {len(MODULE_LABEL)}"),
            ("Threads",       cfg.get("threads",5)),
            ("Crawl Depth",   cfg.get("depth",3)),
            ("Max URLs",      cfg.get("max_urls",200)),
            ("Request Delay", f"{cfg.get('delay',0.5)}s"),
            ("Timeout",       f"{cfg.get('timeout',10)}s"),
            ("Report Format", cfg.get("report_format","both")),
            ("Min Severity",  cfg.get("min_severity","info")),
        ])

        # ── Filter buttons ────────────────────────────────────────────────────
        fbtns = "".join(
            f'<button class="fb" onclick="filterSev(\'{s}\',this)">'
            f'{SEV_ICON[s]} {s.capitalize()} ({n})</button>'
            for s in SEV_ORDER if (n:=by_sev.get(s,0))
        )

        # ── Findings list ─────────────────────────────────────────────────────
        findings_html = self._findings_list(findings) if findings else (
            '<div class="empty"><div>🎉</div>'
            '<h3>No vulnerabilities found!</h3>'
            '<p>The target appears clean for the modules that were run.</p></div>')

        gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PenguardOps Report — {_e(target)}</title>
{self._css()}
</head>
<body>

<!-- HEADER -->
<header>
<div class="wrap hdr">
  <div class="hdr-top">
    <div class="logo">
      <div class="logo-icon">🛡️</div>
      <div>
        <div class="logo-t">PenguardOps</div>
        <div class="logo-s">Professional Penetration Testing Suite</div>
        <div class="badges">
          <span class="bdg bdg-b">OWASP Top 10</span>
          <span class="bdg bdg-p">MITRE ATT&CK</span>
          <span class="bdg bdg-g">v2.1</span>
        </div>
      </div>
    </div>
    <div class="hdr-meta">
      <div><b>Scan ID:</b> {_e(sid)}</div>
      <div><b>Target:</b> {_e(target)}</div>
      <div><b>Generated:</b> {gen_time}</div>
      <div><b>Duration:</b> {dur:.1f}s &nbsp;|&nbsp; <b>WAF:</b> {_e(waf)}</div>
    </div>
  </div>
  <div class="risk-panel">
    <div class="rgauge">
      {gauge}
      <div class="rlbl">
        <span class="rnum" style="color:{risk_hex}">{risk_score:.0f}</span>
        <span class="rsub">/100</span>
      </div>
    </div>
    <div class="rtext">
      <h2 style="color:{risk_hex}">Risk: {risk_level}</h2>
      <p>{total} {"vulnerability" if total==1 else "vulnerabilities"} across
         {urls} URLs · {forms} forms · {params} param endpoints.</p>
    </div>
    <div class="qs-row">
      <div class="qs"><div>🌐</div><b>{urls}</b><span>URLs</span></div>
      <div class="qs"><div>📝</div><b>{forms}</b><span>Forms</span></div>
      <div class="qs"><div>🔗</div><b>{params}</b><span>Params</span></div>
      <div class="qs"><div>🔍</div><b>{total}</b><span>Issues</span></div>
    </div>
  </div>
</div>
</header>

<div class="wrap" style="padding:28px 26px">

<!-- PROGRESS -->
<section>
<div class="st">📡 Scan Progress — Module Results</div>
<div class="card">
  <div class="card-hdr"><h3>⚙️ Module Execution</h3>
    <span class="dim">✅ {len(mods)} module(s) completed</span></div>
  <div class="card-body">{mod_progress}</div>
</div>
</section>

<!-- MODULE TOGGLES -->
<section>
<div class="st">🔧 Module Configuration (Yes / No)</div>
<p class="dim" style="margin-bottom:12px">Toggle modules to filter findings below in real-time.</p>
<div class="tgl-grid">{toggle_cards}</div>
</section>

<!-- OVERVIEW -->
<section>
<div class="st">📊 Findings Overview</div>
<div class="sev-cards">{sev_cards}</div>
<div class="g2">
  <div class="card">
    <div class="card-hdr"><h3>📈 Severity Distribution</h3></div>
    <div class="card-body"><div class="bc">{sev_chart}</div></div>
  </div>
  <div class="card">
    <div class="card-hdr"><h3>🏷️ Module Breakdown</h3></div>
    <div class="card-body"><div class="bc">{mod_chart}</div></div>
  </div>
</div>
</section>

<!-- FRAMEWORK MAPPING -->
<section>
<div class="st">🗺️ Security Framework Mapping</div>
<div class="g2">
  <div class="card">
    <div class="card-hdr"><h3>📋 OWASP Top 10 (2021)</h3>
      <span class="dim">{sum(1 for k in OWASP_TOP10 if owasp_counts.get(k,0)>0)}/10 affected</span></div>
    <div class="card-body"><div class="owlist">{owasp_rows}</div></div>
  </div>
  <div class="card">
    <div class="card-hdr"><h3>⚔️ MITRE ATT&amp;CK</h3>
      <span class="dim">{len(mitre_detected)} detected</span></div>
    <div class="card-body"><div class="mtlist">{mitre_rows}</div></div>
  </div>
</div>
</section>

<!-- STATS -->
<section>
<div class="st">📉 Advanced Statistics</div>
<div class="vs-grid">{stats_html}</div>
</section>

<!-- TIMELINE -->
<section>
<div class="st">⏱️ Scan Timeline</div>
<div class="card"><div class="card-body"><div class="tl">{timeline_rows}</div></div></div>
</section>

<!-- CONFIG -->
<section>
<div class="st">⚙️ Scan Configuration</div>
<div class="g2">
  <div class="card">
    <div class="card-hdr"><h3>Target &amp; Discovery</h3></div>
    <div class="card-body"><table class="cfg"><tbody>{cfg_rows_a}</tbody></table></div>
  </div>
  <div class="card">
    <div class="card-hdr"><h3>Engine Settings</h3></div>
    <div class="card-body"><table class="cfg"><tbody>{cfg_rows_b}</tbody></table></div>
  </div>
</div>
</section>

<!-- FINDINGS -->
<section id="findings">
<div class="st">🔍 Detailed Findings
  <span class="dim" style="font-size:13px;font-weight:400">({total})</span>
</div>
<div class="fbar">
  <button class="fb on" onclick="filterSev('all',this)">All ({total})</button>
  {fbtns}
  <div class="srch"><input type="text" placeholder="Search…" oninput="doSearch(this.value)"></div>
</div>
<div id="fi-list">{findings_html}</div>
</section>

</div>

<!-- FOOTER -->
<footer>
<div class="wrap ft">
  <div class="ftb">
    <div class="fticon">🛡️</div>
    <div>
      <div class="ftn">PenguardOps v2.1</div>
      <div class="ftc">Professional Penetration Testing Suite · {datetime.now().year}</div>
    </div>
  </div>
  <div class="ftwarn">⚠️ For authorised security testing only. Unauthorised use is illegal.</div>
</div>
</footer>

{self._js(fi_js, mods_js)}
</body>
</html>"""

    # ── Findings ──────────────────────────────────────────────────────────────
    def _findings_list(self, findings: List[Finding]) -> str:
        html = ""
        for i, f in enumerate(findings):
            clr  = SEV_HEX.get(f.severity, "#6b7280")
            icon = SEV_ICON.get(f.severity, "⚪")
            expl = min(100, ({"critical":60,"high":40,"medium":20,"low":5,"info":0}.get(f.severity,0)
                             + (25 if getattr(f,"confidence","")=="high" else
                                10 if getattr(f,"confidence","")=="medium" else 0)
                             + (15 if getattr(f,"false_positive_risk","")=="low" else 0)))
            ec   = "#ef4444" if expl>70 else "#f97316" if expl>40 else "#eab308"
            stxt = f"{f.title} {f.url} {f.parameter or ''} {f.module} {f.severity} {f.description}".lower()

            pay  = (f'<div class="fb-s"><h4>Payload</h4>'
                    f'<div class="codebox">{_e(f.payload)}</div></div>') if f.payload else ""
            evi  = (f'<div class="fb-s"><h4>Evidence</h4>'
                    f'<div class="codebox">{_e(f.evidence)}</div></div>') if f.evidence else ""
            rem  = (f'<div class="remed"><strong>🛠️ Remediation</strong>{_e(f.remediation)}</div>'
                    ) if f.remediation else ""
            refs = ""
            if f.references:
                refs = '<div class="fb-s" style="margin-top:10px"><h4>References</h4><div>'
                refs += "".join(f'<a class="rl" href="{_e(r)}" target="_blank">{_e(r)}</a>'
                                for r in f.references)
                refs += '</div></div>'

            tags = []
            if f.owasp_category: tags.append(f.owasp_category)
            if f.mitre_technique: tags.append(f.mitre_technique)
            if f.cwe_id: tags.append(f.cwe_id)
            if f.cvss_score: tags.append(f"CVSS {f.cvss_score}")
            tags.append(f"Conf: {getattr(f,'confidence','?')}")
            tags_html = "".join(f'<span class="tag">{_e(t)}</span>' for t in tags)

            url_short = (_e(f.url[:65]) + ("…" if len(f.url)>65 else ""))
            html += f"""
<div class="fi" id="f{i}" data-sev="{_e(f.severity)}" data-mod="{_e(f.module)}"
     data-search="{_e(stxt)}" style="border-left:4px solid {clr}">
  <div class="fi-hdr" onclick="tog(this)">
    <span class="pill" style="background:{clr};color:#fff">{icon} {f.severity.upper()}</span>
    <div class="fi-main">
      <div class="fi-title">{_e(f.title)}</div>
      <div class="fi-meta">
        <span>📁 {_e(f.module)}</span>
        <span>🔗 <code>{url_short}</code></span>
        {"<span>⚙️ <code>" + _e(f.parameter) + "</code></span>" if f.parameter else ""}
        {"<span>" + _e(f.method) + "</span>" if f.method else ""}
        {"<span style='color:" + clr + "'>CVSS " + str(f.cvss_score) + "</span>" if f.cvss_score else ""}
      </div>
    </div>
    <div class="fi-tags">
      {"<span class='tag'>" + _e(f.owasp_category) + "</span>" if f.owasp_category else ""}
      {"<span class='tag'>" + _e(f.mitre_technique) + "</span>" if f.mitre_technique else ""}
    </div>
    <span class="expbtn">▼</span>
  </div>
  <div class="fi-body">
    <div class="fbg">
      <div>
        <div class="fb-s"><h4>Description</h4><p>{_e(f.description)}</p></div>
        {pay}
        <div style="margin-top:10px">
          <h4 class="dim-h4">Exploit Likelihood</h4>
          <div class="exbar"><div class="exfil" style="width:{expl}%;background:{ec}"></div></div>
          <div class="dim" style="font-size:10px;margin-top:3px">{expl}% — {"High risk" if expl>70 else "Moderate" if expl>40 else "Needs verification"}</div>
        </div>
        <div class="ctags" style="margin-top:8px">{tags_html}</div>
      </div>
      <div>
        {evi}
        {rem}
        {refs}
      </div>
    </div>
  </div>
</div>"""
        return html

    # ── CSS ───────────────────────────────────────────────────────────────────
    def _css(self):
        return """<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#080d14;--sur:#0f1923;--s2:#162030;--s3:#1d2d40;
  --bdr:#243447;--bdr2:#2e4058;
  --tx:#e8f0fe;--mu:#6b8aad;
  --ac:#4f8ef7;--ac2:#a78bfa;--ac3:#34d399;
  --r:8px;--r2:14px;
  --ff:'Segoe UI',system-ui,-apple-system,sans-serif;
  --mono:'Cascadia Code','Fira Code',Consolas,monospace;
}
html{scroll-behavior:smooth}
body{font-family:var(--ff);background:var(--bg);color:var(--tx);line-height:1.6;font-size:14px}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--bdr2);border-radius:3px}
.wrap{max-width:1360px;margin:0 auto;padding:0 26px}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:18px}
@media(max-width:860px){.g2{grid-template-columns:1fr}}
.dim{color:var(--mu)}
.dim-h4{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--mu);margin-bottom:5px}

/* Header */
header{background:linear-gradient(155deg,#05080f,#091524 45%,#0b1c30);
  border-bottom:1px solid var(--bdr);padding:30px 0 24px;position:relative;overflow:hidden}
header::before{content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse 55% 90% at 12% 50%,rgba(79,142,247,.08),transparent 65%),
             radial-gradient(ellipse 45% 70% at 88% 30%,rgba(167,139,250,.06),transparent 65%);
  pointer-events:none}
header::after{content:'';position:absolute;inset:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(255,255,255,.005) 3px,rgba(255,255,255,.005) 6px);
  pointer-events:none}
.hdr{position:relative;z-index:1}
.hdr-top{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;flex-wrap:wrap}
.logo{display:flex;align-items:center;gap:15px}
.logo-icon{width:52px;height:52px;flex-shrink:0;background:linear-gradient(135deg,#4f8ef7,#a78bfa);
  border-radius:13px;display:flex;align-items:center;justify-content:center;
  font-size:27px;box-shadow:0 0 22px rgba(79,142,247,.38)}
.logo-t{font-size:29px;font-weight:900;letter-spacing:-1px;line-height:1;
  background:linear-gradient(90deg,#4f8ef7,#a78bfa);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.logo-s{font-size:12px;color:var(--mu);margin-top:4px}
.badges{display:flex;gap:6px;margin-top:8px;flex-wrap:wrap}
.bdg{padding:2px 9px;border-radius:100px;font-size:10px;font-weight:600;letter-spacing:.4px;border:1px solid}
.bdg-b{color:#60a5fa;border-color:rgba(96,165,250,.3);background:rgba(96,165,250,.07)}
.bdg-p{color:#c4b5fd;border-color:rgba(196,181,253,.3);background:rgba(196,181,253,.07)}
.bdg-g{color:#6ee7b7;border-color:rgba(110,231,183,.3);background:rgba(110,231,183,.07)}
.hdr-meta{text-align:right;font-size:12px;color:var(--mu);line-height:2.1}
.hdr-meta b{color:var(--tx)}
.risk-panel{margin-top:20px;background:rgba(255,255,255,.025);border:1px solid var(--bdr);
  border-radius:var(--r2);padding:18px 22px;display:flex;align-items:center;gap:22px;flex-wrap:wrap}
.rgauge{position:relative;width:86px;height:86px;flex-shrink:0}
.rlbl{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.rnum{font-size:22px;font-weight:900;line-height:1}
.rsub{font-size:8px;color:var(--mu);letter-spacing:1px;text-transform:uppercase}
.rtext h2{font-size:18px;font-weight:700;margin-bottom:3px}
.rtext p{font-size:12px;color:var(--mu)}
.qs-row{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap}
.qs{text-align:center;padding:10px 15px;background:rgba(255,255,255,.03);
  border:1px solid var(--bdr);border-radius:10px;min-width:68px}
.qs b{display:block;font-size:19px;font-weight:800}
.qs span{font-size:10px;color:var(--mu);text-transform:uppercase;letter-spacing:.4px}

/* Cards */
.card{background:var(--sur);border:1px solid var(--bdr);border-radius:var(--r2);overflow:hidden;margin-bottom:16px}
.card-hdr{padding:12px 18px;border-bottom:1px solid var(--bdr);display:flex;justify-content:space-between;align-items:center}
.card-hdr h3{font-size:13px;font-weight:600}
.card-body{padding:16px 18px}
section{margin:24px 0}
.st{font-size:15px;font-weight:700;margin-bottom:12px;display:flex;align-items:center;gap:9px}
.st::after{content:'';flex:1;height:1px;background:var(--bdr)}

/* Progress */
.prow{display:flex;align-items:center;gap:10px;padding:5px 0}
.plbl{width:185px;font-size:12px;color:var(--mu);flex-shrink:0}
.ptrk{flex:1;height:7px;background:var(--s3);border-radius:4px;overflow:hidden}
.pfil{height:100%;border-radius:4px;width:0;transition:width 1s ease}
.pcnt{width:32px;text-align:right;font-size:12px;font-weight:700}
.pstat{width:72px;text-align:right;font-size:10px;flex-shrink:0}

/* Module toggles */
.tgl-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:9px}
.tc{background:var(--sur);border:1px solid var(--bdr);border-radius:10px;
  padding:12px 14px;display:flex;align-items:center;justify-content:space-between;gap:10px;cursor:pointer;transition:all .18s}
.tc:hover{background:var(--s2);border-color:var(--bdr2)}
.tc.enabled{border-color:rgba(79,142,247,.35);background:rgba(79,142,247,.05)}
.tc.has-fi{border-color:rgba(239,68,68,.3);background:rgba(239,68,68,.04)}
.tc-n{font-size:13px;font-weight:600}
.tc-s{font-size:11px;color:var(--mu);margin-top:2px}
.tc-s.red{color:#f87171}
.sw{position:relative;width:38px;height:20px;flex-shrink:0}
.sw input{opacity:0;width:0;height:0;position:absolute}
.sw-t{position:absolute;inset:0;background:var(--s3);border-radius:10px;border:1px solid var(--bdr2);transition:all .22s;cursor:pointer}
.sw input:checked + .sw-t{background:var(--ac);border-color:var(--ac)}
.sw-k{position:absolute;top:2px;left:2px;width:14px;height:14px;background:white;border-radius:50%;transition:transform .22s;pointer-events:none;box-shadow:0 1px 3px rgba(0,0,0,.4)}
.sw input:checked ~ .sw-k{transform:translateX(18px)}

/* Severity cards */
.sev-cards{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:16px}
@media(max-width:640px){.sev-cards{grid-template-columns:repeat(3,1fr)}}
.sc{background:var(--sur);border:1px solid var(--bdr);border-radius:10px;padding:13px;
  text-align:center;cursor:pointer;transition:all .18s}
.sc:hover{background:var(--s2);transform:translateY(-2px)}
.sc-n{font-size:27px;font-weight:900;line-height:1;margin:3px 0 1px}
.sc-l{font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:var(--mu)}
.sc-b{margin-top:8px;height:3px;background:var(--s3);border-radius:2px;overflow:hidden}
.sc-f{height:100%;border-radius:2px;width:0;transition:width 1.2s ease}

/* Bar charts */
.bc{display:flex;flex-direction:column;gap:8px}
.bcr{display:flex;align-items:center;gap:9px;font-size:12px}
.bcl{width:86px;color:var(--mu);text-align:right;flex-shrink:0}
.bct{flex:1;height:18px;background:var(--s3);border-radius:4px;overflow:hidden}
.bcf{height:100%;border-radius:4px;display:flex;align-items:center;padding:0 6px;
  font-size:11px;font-weight:700;color:white;width:0;transition:width 1.2s cubic-bezier(.4,0,.2,1)}
.bcv{width:26px;text-align:right;font-weight:700}

/* OWASP */
.owlist{display:flex;flex-direction:column}
.owrow{display:flex;align-items:center;gap:9px;padding:6px 0;border-bottom:1px solid var(--bdr);font-size:12px}
.owrow:last-child{border-bottom:none}
.owdot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.owid{font-family:var(--mono);font-size:10px;color:var(--mu);width:80px;flex-shrink:0}
.own{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.owbw{width:70px;height:5px;background:var(--s3);border-radius:2px;overflow:hidden;flex-shrink:0}
.owbf{height:100%;border-radius:2px}
.owcnt{width:22px;text-align:right;font-weight:700;flex-shrink:0}

/* MITRE */
.mtlist{display:flex;flex-direction:column;gap:5px}
.mtrow{display:flex;align-items:center;gap:9px;padding:6px 10px;border-radius:7px;border:1px solid transparent;font-size:12px}
.mtrow:hover{background:var(--s2)}
.mtrow.hit{border-color:rgba(239,68,68,.25);background:rgba(239,68,68,.04)}
.mtid{font-family:var(--mono);font-size:10px;color:var(--mu);width:70px;flex-shrink:0}
.mtn{flex:1}
.mbdg{font-size:10px;font-weight:600;padding:2px 8px;border-radius:100px;flex-shrink:0}
.mbdg.d{background:rgba(239,68,68,.12);color:#f87171;border:1px solid rgba(239,68,68,.25)}
.mbdg.c{background:rgba(34,197,94,.08);color:#4ade80;border:1px solid rgba(34,197,94,.18)}

/* Stats */
.vs-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:11px}
@media(max-width:640px){.vs-grid{grid-template-columns:1fr 1fr}}
.vs{background:var(--s2);border:1px solid var(--bdr);border-radius:10px;padding:14px}
.vs-t{font-size:11px;color:var(--mu);margin-bottom:3px}
.vs-v{font-size:23px;font-weight:900}
.vs-s{font-size:10px;color:var(--mu);margin-top:2px}

/* Timeline */
.tl{position:relative;padding-left:18px}
.tl::before{content:'';position:absolute;left:5px;top:8px;bottom:8px;width:1px;background:var(--bdr)}
.tli{position:relative;margin-bottom:12px;padding-left:17px}
.tldot{position:absolute;left:-13px;top:5px;width:9px;height:9px;border-radius:50%;border:2px solid;background:var(--sur)}
.tlts{font-size:10px;color:var(--mu);font-family:var(--mono);margin-bottom:1px}
.tltx{font-size:12px}

/* Config */
.cfg{width:100%;border-collapse:collapse;font-size:12px}
.cfg tr{border-bottom:1px solid var(--bdr)}
.cfg tr:last-child{border-bottom:none}
.cfg td{padding:7px 0}
.cfg td:first-child{color:var(--mu);width:145px;padding-right:10px}
.cfg code{font-family:var(--mono);font-size:11px;background:var(--s2);padding:2px 6px;border-radius:4px;word-break:break-all}

/* Filter bar */
.fbar{display:flex;gap:7px;margin-bottom:12px;flex-wrap:wrap;align-items:center}
.fb{padding:5px 12px;border-radius:100px;border:1px solid var(--bdr);background:transparent;
  color:var(--mu);cursor:pointer;font-size:12px;transition:all .14s;font-family:var(--ff)}
.fb:hover,.fb.on{background:var(--ac);color:white;border-color:var(--ac)}
.srch{margin-left:auto;position:relative}
.srch input{background:var(--s2);border:1px solid var(--bdr);color:var(--tx);
  padding:5px 11px 5px 28px;border-radius:7px;font-size:12px;width:195px;font-family:var(--ff);outline:none;transition:border .18s}
.srch input:focus{border-color:var(--ac)}
.srch::before{content:'⌕';position:absolute;left:8px;top:50%;transform:translateY(-50%);font-size:14px;color:var(--mu);pointer-events:none}

/* Findings */
.fi{background:var(--sur);border:1px solid var(--bdr);border-radius:11px;margin-bottom:9px;overflow:hidden;transition:box-shadow .18s}
.fi:hover{box-shadow:0 2px 18px rgba(0,0,0,.28)}
.fi-hdr{padding:13px 17px;cursor:pointer;display:flex;align-items:flex-start;gap:11px}
.fi-hdr:hover{background:rgba(255,255,255,.012)}
.pill{padding:3px 10px;border-radius:100px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;white-space:nowrap;flex-shrink:0;margin-top:1px}
.fi-main{flex:1;min-width:0}
.fi-title{font-size:14px;font-weight:600;margin-bottom:3px;line-height:1.3}
.fi-meta{font-size:11px;color:var(--mu);display:flex;gap:12px;flex-wrap:wrap}
.fi-tags{display:flex;flex-direction:column;align-items:flex-end;gap:3px;flex-shrink:0}
.tag{font-size:10px;padding:2px 7px;border-radius:4px;background:var(--s2);border:1px solid var(--bdr);font-family:var(--mono);white-space:nowrap}
.expbtn{color:var(--mu);font-size:10px;margin-left:7px;flex-shrink:0;margin-top:4px;transition:transform .18s;display:inline-block}
.expbtn.open{transform:rotate(180deg)}
.fi-body{display:none;padding:0 17px 17px;border-top:1px solid var(--bdr)}
.fi-body.show{display:block}
.fbg{display:grid;grid-template-columns:1fr 1fr;gap:15px;margin-top:13px}
@media(max-width:600px){.fbg{grid-template-columns:1fr}}
.fb-s h4{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--mu);margin-bottom:5px}
.fb-s p{font-size:12px;line-height:1.6}
.codebox{background:#04080e;border:1px solid var(--bdr);border-radius:6px;padding:9px 12px;
  font-family:var(--mono);font-size:11px;color:#7dd3fc;white-space:pre-wrap;word-break:break-all;max-height:130px;overflow-y:auto}
.remed{background:rgba(52,211,153,.05);border:1px solid rgba(52,211,153,.18);border-radius:8px;
  padding:11px 13px;margin-top:11px;font-size:12px;color:#6ee7b7;line-height:1.7}
.remed strong{color:#34d399;display:block;margin-bottom:3px}
.rl{display:inline-block;font-size:11px;color:var(--ac);margin:3px 4px 0 0;text-decoration:none;
  padding:2px 7px;border-radius:4px;border:1px solid rgba(79,142,247,.22);background:rgba(79,142,247,.05)}
.rl:hover{background:rgba(79,142,247,.14)}
.ctags{display:flex;flex-wrap:wrap;gap:4px}
.exbar{background:var(--s3);border-radius:4px;height:7px;overflow:hidden;margin-top:5px}
.exfil{height:100%;border-radius:4px}
.empty{text-align:center;padding:44px;color:var(--mu)}
.empty h3{color:var(--tx);margin:10px 0 6px}

/* Footer */
footer{margin-top:54px;border-top:1px solid var(--bdr);padding:22px 0;background:var(--sur)}
.ft{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}
.ftb{display:flex;align-items:center;gap:10px}
.fticon{width:28px;height:28px;background:linear-gradient(135deg,#4f8ef7,#a78bfa);
  border-radius:7px;display:flex;align-items:center;justify-content:center;font-size:14px}
.ftn{font-size:13px;font-weight:700}
.ftc{font-size:11px;color:var(--mu)}
.ftwarn{font-size:11px;color:var(--mu);background:rgba(234,179,8,.05);border:1px solid rgba(234,179,8,.18);border-radius:6px;padding:6px 12px}
@media print{.fi-body{display:block!important}.fi{break-inside:avoid}}
</style>"""

    # ── JavaScript ────────────────────────────────────────────────────────────
    def _js(self, fi_js: str, mods_js: str) -> str:
        return f"""<script>
var activeSev='all', activeSearch='', activeMods=new Set({mods_js});

function applyFilters(){{
  document.querySelectorAll('.fi').forEach(function(el){{
    var show = true;
    if(activeSev!=='all' && el.dataset.sev!==activeSev) show=false;
    if(!activeMods.has(el.dataset.mod)) show=false;
    if(activeSearch && !el.dataset.search.includes(activeSearch)) show=false;
    el.style.display = show ? '' : 'none';
  }});
}}
function filterSev(sev,btn){{
  activeSev=sev;
  document.querySelectorAll('.fb').forEach(function(b){{b.classList.remove('on');}});
  btn.classList.add('on');
  applyFilters();
}}
function doSearch(q){{activeSearch=q.toLowerCase();applyFilters();}}
function toggleMod(mod,on){{
  if(on) activeMods.add(mod); else activeMods.delete(mod);
  document.querySelectorAll('.tc').forEach(function(c){{
    if(c.dataset.mod===mod) c.classList.toggle('enabled',on);
  }});
  applyFilters();
}}
function tog(hdr){{
  var body=hdr.nextElementSibling;
  var btn=hdr.querySelector('.expbtn');
  var open=body.classList.toggle('show');
  btn.classList.toggle('open',open);
}}
function animN(el,t){{
  var n=0,step=Math.max(1,Math.ceil(t/22));
  var iv=setInterval(function(){{n=Math.min(n+step,t);el.textContent=n;if(n>=t)clearInterval(iv);}},38);
}}
window.addEventListener('DOMContentLoaded',function(){{
  document.querySelectorAll('.sc-n[data-n]').forEach(function(el){{animN(el,parseInt(el.dataset.n)||0);}});
  setTimeout(function(){{
    document.querySelectorAll('[data-w]').forEach(function(el){{el.style.width=el.dataset.w;}});
  }},80);
  var first=document.querySelector('.fi[data-sev="critical"] .fi-hdr')||
            document.querySelector('.fi[data-sev="high"] .fi-hdr');
  if(first) tog(first);
}});
</script>"""
