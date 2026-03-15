"""Scan report generation — HTML and plain text output.

Generates professional reports from iocx scan results,
including direct links to each OSINT source.
"""

import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# OSINT source URL builders
# ---------------------------------------------------------------------------

def _vt_ip_url(ip: str) -> str:
    return f"https://www.virustotal.com/gui/ip-address/{ip}"

def _vt_domain_url(domain: str) -> str:
    return f"https://www.virustotal.com/gui/domain/{domain}"

def _vt_hash_url(h: str) -> str:
    return f"https://www.virustotal.com/gui/file/{h}"

def _abuseipdb_url(ip: str) -> str:
    return f"https://www.abuseipdb.com/check/{ip}"

def _shodan_url(ip: str) -> str:
    return f"https://www.shodan.io/host/{ip}"

def _urlhaus_domain_url(domain: str) -> str:
    return f"https://urlhaus.abuse.ch/browse.php?search={domain}"

def _urlhaus_url_url(url: str) -> str:
    return f"https://urlhaus.abuse.ch/browse.php?search={url}"

def _mbazaar_hash_url(h: str) -> str:
    return f"https://bazaar.abuse.ch/sample/{h}/"

def _ipapi_url(ip: str) -> str:
    return f"https://ip-api.com/#/{ip}"


# ---------------------------------------------------------------------------
# Risk helpers
# ---------------------------------------------------------------------------

def _risk_from_results(ioc_type: str, results: list[dict]) -> tuple[str, str]:
    """Return (risk_label, risk_class) based on source results."""
    abuse = next((r for r in results if r.get("source") == "AbuseIPDB" and "error" not in r), {})
    vt = next((r for r in results if r.get("source") == "VirusTotal" and "error" not in r), {})
    uh = next((r for r in results if r.get("source") == "URLhaus" and "error" not in r), {})
    mb = next((r for r in results if r.get("source") == "MalwareBazaar" and "error" not in r), {})

    score = abuse.get("score", 0)
    vt_mal = vt.get("malicious", 0)
    vt_total = vt.get("total", 1)

    if score >= 75 or vt_mal >= 10 or mb.get("found") or (uh.get("found") and vt_mal > 0):
        return "HIGH", "risk-high"
    if score >= 25 or vt_mal >= 3 or uh.get("found"):
        return "MEDIUM", "risk-medium"
    if score > 0 or vt_mal > 0:
        return "LOW", "risk-low"
    return "CLEAN", "risk-clean"


# ---------------------------------------------------------------------------
# Per-IOC row data builder
# ---------------------------------------------------------------------------

def build_row(ioc: str, ioc_type: str, results: list[dict]) -> dict:
    """Build a data dict for one IOC row in the report."""
    risk_label, risk_class = _risk_from_results(ioc_type, results)

    abuse = next((r for r in results if r.get("source") == "AbuseIPDB" and "error" not in r), None)
    vt    = next((r for r in results if r.get("source") == "VirusTotal" and "error" not in r), None)
    shodan= next((r for r in results if r.get("source") == "Shodan" and "error" not in r), None)
    uh    = next((r for r in results if r.get("source") == "URLhaus" and "error" not in r), None)
    mb    = next((r for r in results if r.get("source") == "MalwareBazaar" and "error" not in r), None)
    dns   = next((r for r in results if r.get("source") == "DNS" and "error" not in r), None)
    geo   = next((r for r in results if r.get("source") == "ip-api" and "error" not in r), None)

    sources = []

    if ioc_type == "ip":
        if abuse:
            sources.append({
                "name": "AbuseIPDB",
                "value": f"{abuse.get('score', 0)}/100 · {abuse.get('reports', 0):,} reports"
                         + (" · TOR" if abuse.get("is_tor") else ""),
                "url": _abuseipdb_url(ioc),
            })
        if vt:
            sources.append({
                "name": "VirusTotal",
                "value": f"{vt.get('malicious', 0)}/{vt.get('total', 0)} engines",
                "url": _vt_ip_url(ioc),
            })
        if shodan:
            ports = ", ".join(str(p) for p in shodan.get("ports", [])[:8])
            sources.append({
                "name": "Shodan",
                "value": ports or "no open ports",
                "url": _shodan_url(ioc),
            })
        if geo:
            sources.append({
                "name": "GeoIP",
                "value": f"{geo.get('country', '?')} · {geo.get('asn', '?')}",
                "url": _ipapi_url(ioc),
            })

    elif ioc_type == "domain":
        if vt:
            sources.append({
                "name": "VirusTotal",
                "value": f"{vt.get('malicious', 0)}/{vt.get('total', 0)} engines",
                "url": _vt_domain_url(ioc),
            })
        if uh:
            found = uh.get("found", False)
            sources.append({
                "name": "URLhaus",
                "value": f"Found · {uh.get('url_count', 0)} URLs" if found else "Not found",
                "url": _urlhaus_domain_url(ioc),
            })
        if dns:
            sources.append({
                "name": "DNS",
                "value": "  ".join(dns.get("ips", [])[:4]),
                "url": f"https://mxtoolbox.com/SuperTool.aspx?action=dns%3a{ioc}",
            })

    elif ioc_type in ("md5", "sha1", "sha256"):
        if mb:
            found = mb.get("found", False)
            sources.append({
                "name": "MalwareBazaar",
                "value": f"Found · {mb.get('signature', mb.get('file_type', ''))} · {mb.get('first_seen', '')[:10]}"
                         if found else "Not found",
                "url": _mbazaar_hash_url(ioc),
            })
        if vt:
            sources.append({
                "name": "VirusTotal",
                "value": f"{vt.get('malicious', 0)}/{vt.get('total', 0)} engines",
                "url": _vt_hash_url(ioc),
            })

    return {
        "ioc": ioc,
        "type": ioc_type,
        "risk_label": risk_label,
        "risk_class": risk_class,
        "sources": sources,
    }


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>iocx Scan Report — {date}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: #f8fafc;
    color: #1e293b;
    margin: 0;
    padding: 2rem;
    font-size: 14px;
  }}
  .container {{ max-width: 1100px; margin: 0 auto; }}

  /* Header */
  .header {{
    background: #0f172a;
    color: #e2e8f0;
    border-radius: 8px;
    padding: 1.5rem 2rem;
    margin-bottom: 1.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .header-title {{
    font-size: 1.4rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    color: #f1f5f9;
  }}
  .header-title span {{ color: #818cf8; }}
  .header-meta {{
    font-size: 0.8rem;
    color: #94a3b8;
    text-align: right;
    line-height: 1.6;
  }}

  /* Summary bar */
  .summary {{
    display: flex;
    gap: 1rem;
    margin-bottom: 1.5rem;
    flex-wrap: wrap;
  }}
  .summary-card {{
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 0.75rem 1.25rem;
    flex: 1;
    min-width: 110px;
    text-align: center;
  }}
  .summary-card .count {{
    font-size: 1.8rem;
    font-weight: 700;
    line-height: 1;
  }}
  .summary-card .label {{
    font-size: 0.72rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-top: 0.3rem;
  }}
  .count-total  {{ color: #1e293b; }}
  .count-high   {{ color: #dc2626; }}
  .count-medium {{ color: #d97706; }}
  .count-low    {{ color: #2563eb; }}
  .count-clean  {{ color: #16a34a; }}

  /* Table */
  .table-wrap {{
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    overflow: hidden;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
  }}
  thead th {{
    background: #f1f5f9;
    padding: 0.65rem 1rem;
    text-align: left;
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #64748b;
    border-bottom: 1px solid #e2e8f0;
  }}
  tbody tr {{
    border-bottom: 1px solid #f1f5f9;
    transition: background 0.1s;
  }}
  tbody tr:last-child {{ border-bottom: none; }}
  tbody tr:hover {{ background: #f8fafc; }}
  td {{
    padding: 0.75rem 1rem;
    vertical-align: top;
  }}

  /* IOC cell */
  .ioc-value {{
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    font-size: 0.85rem;
    font-weight: 500;
    color: #1e293b;
    word-break: break-all;
  }}
  .ioc-type {{
    display: inline-block;
    font-size: 0.65rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 0.15rem 0.4rem;
    border-radius: 3px;
    margin-top: 0.25rem;
    background: #e2e8f0;
    color: #475569;
  }}

  /* Risk badge */
  .risk-badge {{
    display: inline-block;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    padding: 0.25rem 0.6rem;
    border-radius: 4px;
    white-space: nowrap;
  }}
  .risk-high   {{ background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }}
  .risk-medium {{ background: #fffbeb; color: #d97706; border: 1px solid #fde68a; }}
  .risk-low    {{ background: #eff6ff; color: #2563eb; border: 1px solid #bfdbfe; }}
  .risk-clean  {{ background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }}

  /* Sources */
  .sources {{ display: flex; flex-direction: column; gap: 0.35rem; }}
  .source-row {{ display: flex; align-items: baseline; gap: 0.5rem; }}
  .source-name {{
    font-size: 0.7rem;
    font-weight: 600;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    min-width: 90px;
  }}
  .source-value {{ font-size: 0.82rem; color: #334155; }}
  .source-link {{
    font-size: 0.72rem;
    color: #6366f1;
    text-decoration: none;
    padding: 0.1rem 0.35rem;
    background: #eef2ff;
    border-radius: 3px;
    white-space: nowrap;
  }}
  .source-link:hover {{ background: #e0e7ff; color: #4f46e5; }}

  /* Footer */
  .footer {{
    margin-top: 1.5rem;
    text-align: center;
    font-size: 0.75rem;
    color: #94a3b8;
  }}
  .footer a {{ color: #818cf8; text-decoration: none; }}
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <div>
      <div class="header-title"><span>iocx</span> Scan Report</div>
      <div style="font-size:0.75rem;color:#64748b;margin-top:0.3rem;">
        IOC triage at terminal speed
      </div>
    </div>
    <div class="header-meta">
      {date}<br>
      {total} targets scanned<br>
      iocx v0.1.0
    </div>
  </div>

  <div class="summary">
    <div class="summary-card">
      <div class="count count-total">{total}</div>
      <div class="label">Total</div>
    </div>
    <div class="summary-card">
      <div class="count count-high">{high}</div>
      <div class="label">High</div>
    </div>
    <div class="summary-card">
      <div class="count count-medium">{medium}</div>
      <div class="label">Medium</div>
    </div>
    <div class="summary-card">
      <div class="count count-low">{low}</div>
      <div class="label">Low</div>
    </div>
    <div class="summary-card">
      <div class="count count-clean">{clean}</div>
      <div class="label">Clean</div>
    </div>
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>IOC</th>
          <th>Risk</th>
          <th>Sources &amp; Links</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
  </div>

  <div class="footer">
    Generated by <a href="https://github.com/Nervi0z/iocx">iocx</a> —
    Always verify findings manually before taking action.
  </div>

</div>
</body>
</html>"""


def _html_row(row: dict) -> str:
    sources_html = ""
    for s in row["sources"]:
        sources_html += f"""
        <div class="source-row">
          <span class="source-name">{s['name']}</span>
          <span class="source-value">{s['value']}</span>
          <a class="source-link" href="{s['url']}" target="_blank" rel="noopener">↗ open</a>
        </div>"""

    if not sources_html:
        sources_html = '<span style="color:#94a3b8;font-size:0.8rem;">no data</span>'

    return f"""
        <tr>
          <td>
            <div class="ioc-value">{row['ioc']}</div>
            <div class="ioc-type">{row['type']}</div>
          </td>
          <td>
            <span class="risk-badge {row['risk_class']}">{row['risk_label']}</span>
          </td>
          <td>
            <div class="sources">{sources_html}</div>
          </td>
        </tr>"""


def generate_html(rows: list[dict]) -> str:
    """Generate a complete HTML report from a list of row dicts."""
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}
    for r in rows:
        counts[r["risk_label"]] = counts.get(r["risk_label"], 0) + 1

    rows_html = "".join(_html_row(r) for r in rows)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return _HTML_TEMPLATE.format(
        date=now,
        total=len(rows),
        high=counts["HIGH"],
        medium=counts["MEDIUM"],
        low=counts["LOW"],
        clean=counts["CLEAN"],
        rows=rows_html,
    )


# ---------------------------------------------------------------------------
# TXT report
# ---------------------------------------------------------------------------

def generate_txt(rows: list[dict]) -> str:
    """Generate a plain text report."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}
    for r in rows:
        counts[r["risk_label"]] = counts.get(r["risk_label"], 0) + 1

    lines = [
        f"iocx scan report — {now}",
        f"iocx v0.1.0 · https://github.com/Nervi0z/iocx",
        "=" * 72,
        "",
    ]

    for r in rows:
        label = f"[{r['risk_label']:<6}]"
        lines.append(f"{label}  {r['ioc']}  ({r['type']})")
        for s in r["sources"]:
            lines.append(f"           {s['name']:<14} {s['value']}")
            lines.append(f"           > {s['url']}")
        if not r["sources"]:
            lines.append("           no data returned")
        lines.append("")

    lines += [
        "-" * 72,
        f"SUMMARY: {len(rows)} targets · "
        f"{counts['HIGH']} HIGH · {counts['MEDIUM']} MEDIUM · "
        f"{counts['LOW']} LOW · {counts['CLEAN']} CLEAN",
        "",
        "Always verify findings manually before taking action.",
    ]

    return "\n".join(lines)
