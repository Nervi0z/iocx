"""Output rendering — rich panels and JSON mode."""

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text
from rich.columns import Columns

console = Console()
err = Console(stderr=True)


# ---------------------------------------------------------------------------
# Risk coloring
# ---------------------------------------------------------------------------

def risk_color(score: int) -> str:
    if score >= 75:
        return "bold red"
    if score >= 40:
        return "bold yellow"
    if score > 0:
        return "yellow"
    return "green"


def risk_label(score: int) -> str:
    if score >= 75:
        return "HIGH RISK"
    if score >= 40:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "CLEAN"


def risk_bar(score: int, width: int = 20) -> str:
    filled = int(score / 100 * width)
    return "█" * filled + "░" * (width - filled)


def vt_color(malicious: int, total: int) -> str:
    if total == 0:
        return "dim"
    ratio = malicious / total
    if ratio >= 0.3:
        return "bold red"
    if ratio >= 0.1:
        return "yellow"
    if malicious > 0:
        return "yellow"
    return "green"


# ---------------------------------------------------------------------------
# IP panel
# ---------------------------------------------------------------------------

def render_ip(ip: str, results: list[dict], json_mode: bool = False) -> None:
    if json_mode:
        print(json.dumps({"ioc": ip, "type": "ip", "results": results}, indent=2))
        return

    abuse = next((r for r in results if r["source"] == "AbuseIPDB"), {})
    geo = next((r for r in results if r["source"] == "ip-api"), {})
    vt = next((r for r in results if r["source"] == "VirusTotal"), {})
    shodan = next((r for r in results if r["source"] == "Shodan"), {})

    score = abuse.get("score", 0) if "error" not in abuse else 0
    color = risk_color(score)
    label = risk_label(score)

    title = Text()
    title.append(f"  {ip}  ", style="bold white")
    title.append(f" {label} ", style=f"bold {color} on #1a0a0a" if "HIGH" in label else f"bold {color}")

    lines: list[Text] = []

    # Geo
    if "error" not in geo:
        t = Text()
        t.append("  Country   ", style="dim")
        t.append(geo.get("country", "?"), style="white")
        if geo.get("hosting"):
            t.append("  [hosting]", style="dim cyan")
        if geo.get("proxy"):
            t.append("  [proxy]", style="yellow")
        lines.append(t)

        t = Text()
        t.append("  ASN       ", style="dim")
        t.append(geo.get("asn", "?"), style="white")
        lines.append(t)

    # AbuseIPDB
    if "error" not in abuse and "score" in abuse:
        t = Text()
        t.append("  AbuseIPDB ", style="dim")
        t.append(f"{score}/100  ", style=color)
        t.append(risk_bar(score), style=color)
        t.append(f"  {abuse.get('reports', 0):,} reports", style="dim")
        lines.append(t)

        if abuse.get("is_tor"):
            t = Text()
            t.append("             ", style="dim")
            t.append("TOR EXIT NODE", style="bold red")
            lines.append(t)

        if abuse.get("last_reported") and abuse.get("last_reported") != "never":
            t = Text()
            t.append("  Last seen  ", style="dim")
            t.append(str(abuse.get("last_reported", ""))[:19], style="white")
            lines.append(t)
    elif "error" in abuse:
        t = Text()
        t.append("  AbuseIPDB ", style="dim")
        t.append(abuse["error"], style="dim yellow")
        lines.append(t)

    # VirusTotal
    if "error" not in vt and "malicious" in vt:
        malicious = vt.get("malicious", 0)
        total = vt.get("total", 0)
        t = Text()
        t.append("  VT        ", style="dim")
        t.append(f"{malicious}/{total} engines flagged", style=vt_color(malicious, total))
        lines.append(t)
    elif "error" in vt:
        t = Text()
        t.append("  VT        ", style="dim")
        t.append(vt["error"], style="dim yellow")
        lines.append(t)

    # Shodan
    if "error" not in shodan and "ports" in shodan:
        t = Text()
        t.append("  Shodan    ", style="dim")
        ports_str = ", ".join(str(p) for p in shodan.get("ports", [])[:12])
        t.append(ports_str or "no open ports", style="cyan")
        lines.append(t)

        tags = shodan.get("tags", [])
        vulns = shodan.get("vulns", [])
        if tags or vulns:
            t = Text()
            t.append("  Tags      ", style="dim")
            for tag in tags:
                t.append(f" {tag.upper()} ", style="bold red on #1a0000")
                t.append(" ")
            for v in vulns[:5]:
                t.append(f" {v} ", style="yellow")
                t.append(" ")
            lines.append(t)
    elif "error" in shodan:
        t = Text()
        t.append("  Shodan    ", style="dim")
        t.append(shodan["error"], style="dim yellow")
        lines.append(t)

    content = Text("\n").join(lines)
    panel = Panel(
        content,
        title=title,
        border_style=color,
        padding=(1, 2),
        box=box.HEAVY,
    )
    console.print()
    console.print(panel)
    console.print()


# ---------------------------------------------------------------------------
# Hash panel
# ---------------------------------------------------------------------------

def render_hash(hash_val: str, results: list[dict], json_mode: bool = False) -> None:
    if json_mode:
        print(json.dumps({"ioc": hash_val, "type": "hash", "results": results}, indent=2))
        return

    mb = next((r for r in results if r["source"] == "MalwareBazaar"), {})
    vt = next((r for r in results if r["source"] == "VirusTotal"), {})

    found_anywhere = mb.get("found") or vt.get("found")
    malicious = vt.get("malicious", 0) if "error" not in vt else 0
    total = vt.get("total", 1) if "error" not in vt else 1
    color = vt_color(malicious, total) if found_anywhere else "green"

    lines: list[Text] = []

    short = hash_val[:16] + "..." + hash_val[-8:] if len(hash_val) > 32 else hash_val
    title = Text()
    title.append(f"  {short}  ", style="bold white")
    if found_anywhere:
        title.append(" MALICIOUS ", style="bold red")
    else:
        title.append(" NOT FOUND ", style="bold green")

    if "error" not in mb:
        if mb.get("found"):
            t = Text()
            t.append("  MalwareBazaar  ", style="dim")
            t.append("FOUND", style="bold red")
            t.append(f"  {mb.get('file_name', '')}  {mb.get('file_type', '')}", style="white")
            lines.append(t)

            if mb.get("signature"):
                t = Text()
                t.append("  Signature      ", style="dim")
                t.append(mb["signature"], style="bold yellow")
                lines.append(t)

            if mb.get("tags"):
                t = Text()
                t.append("  Tags           ", style="dim")
                t.append("  ".join(mb["tags"]), style="red")
                lines.append(t)

            t = Text()
            t.append("  First seen     ", style="dim")
            t.append(str(mb.get("first_seen", ""))[:19], style="white")
            lines.append(t)
        else:
            t = Text()
            t.append("  MalwareBazaar  ", style="dim")
            t.append("not found", style="green")
            lines.append(t)

    if "error" not in vt and "malicious" in vt:
        t = Text()
        t.append("  VirusTotal     ", style="dim")
        t.append(f"{malicious}/{total} engines", style=vt_color(malicious, total))
        if vt.get("name"):
            t.append(f"  {vt['name']}", style="white")
        lines.append(t)
    elif "error" in vt:
        t = Text()
        t.append("  VirusTotal     ", style="dim")
        t.append(vt["error"], style="dim yellow")
        lines.append(t)

    content = Text("\n").join(lines) if lines else Text("No data returned.", style="dim")
    panel = Panel(content, title=title, border_style=color, padding=(1, 2), box=box.HEAVY)
    console.print()
    console.print(panel)
    console.print()


# ---------------------------------------------------------------------------
# Domain panel
# ---------------------------------------------------------------------------

def render_domain(domain: str, results: list[dict], json_mode: bool = False) -> None:
    if json_mode:
        print(json.dumps({"ioc": domain, "type": "domain", "results": results}, indent=2))
        return

    vt = next((r for r in results if r["source"] == "VirusTotal"), {})
    dns = next((r for r in results if r["source"] == "DNS"), {})
    uh = next((r for r in results if r["source"] == "URLhaus"), {})

    malicious = vt.get("malicious", 0) if "error" not in vt else 0
    total = vt.get("total", 1) if "error" not in vt else 1
    color = vt_color(malicious, total)

    lines: list[Text] = []

    if "error" not in dns and "ips" in dns:
        t = Text()
        t.append("  DNS        ", style="dim")
        t.append("  ".join(dns["ips"][:6]), style="cyan")
        lines.append(t)

    if "error" not in vt and "malicious" in vt:
        t = Text()
        t.append("  VT         ", style="dim")
        t.append(f"{malicious}/{total} engines", style=color)
        if vt.get("registrar"):
            t.append(f"  Registrar: {vt['registrar']}", style="dim")
        lines.append(t)

        if vt.get("categories"):
            t = Text()
            t.append("  Categories ", style="dim")
            t.append("  ".join(vt["categories"]), style="white")
            lines.append(t)
    elif "error" in vt:
        t = Text()
        t.append("  VT         ", style="dim")
        t.append(vt["error"], style="dim yellow")
        lines.append(t)

    if "error" not in uh:
        if uh.get("found"):
            t = Text()
            t.append("  URLhaus    ", style="dim")
            t.append(f"FOUND  {uh.get('url_count', 0)} URLs", style="bold red")
            if uh.get("tags"):
                t.append(f"  tags: {', '.join(uh['tags'][:5])}", style="yellow")
            lines.append(t)
        else:
            t = Text()
            t.append("  URLhaus    ", style="dim")
            t.append("not found", style="green")
            lines.append(t)

    title = Text()
    title.append(f"  {domain}  ", style="bold white")
    if malicious >= 5:
        title.append(" MALICIOUS ", style="bold red")
    elif malicious > 0:
        title.append(" SUSPICIOUS ", style="bold yellow")

    content = Text("\n").join(lines) if lines else Text("No data returned.", style="dim")
    panel = Panel(content, title=title, border_style=color, padding=(1, 2), box=box.HEAVY)
    console.print()
    console.print(panel)
    console.print()


# ---------------------------------------------------------------------------
# Decode panel
# ---------------------------------------------------------------------------

def render_decode(value: str, results: dict, json_mode: bool = False) -> None:
    if json_mode:
        print(json.dumps({"raw": value, "decoded": results}, indent=2, ensure_ascii=False))
        return

    lines: list[Text] = []
    for key, val in results.items():
        if key == "raw":
            continue
        t = Text()
        t.append(f"  {key:<20}", style="cyan")
        if isinstance(val, dict):
            t.append(json.dumps(val, indent=2), style="white")
        else:
            t.append(str(val)[:400], style="white")
        lines.append(t)

    if not lines:
        lines.append(Text("  No known encoding detected.", style="dim"))

    title = Text()
    title.append("  decode  ", style="bold cyan")
    title.append(f"{value[:40]}{'...' if len(value) > 40 else ''}  ", style="dim")

    content = Text("\n").join(lines)
    panel = Panel(content, title=title, border_style="cyan", padding=(1, 2), box=box.HEAVY)
    console.print()
    console.print(panel)
    console.print()


# ---------------------------------------------------------------------------
# IOC scan summary
# ---------------------------------------------------------------------------

def render_scan_summary(ioc_result, json_mode: bool = False) -> None:
    if json_mode:
        d = {
            "ips": ioc_result.ips,
            "domains": ioc_result.domains,
            "urls": ioc_result.urls,
            "md5s": ioc_result.md5s,
            "sha1s": ioc_result.sha1s,
            "sha256s": ioc_result.sha256s,
            "emails": ioc_result.emails,
            "cves": ioc_result.cves,
        }
        print(json.dumps(d, indent=2))
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    table.add_column("Type", style="dim", width=10)
    table.add_column("Count", width=7)
    table.add_column("Values", style="white")

    rows = [
        ("IP", ioc_result.ips),
        ("Domain", ioc_result.domains),
        ("URL", ioc_result.urls),
        ("SHA256", ioc_result.sha256s),
        ("SHA1", ioc_result.sha1s),
        ("MD5", ioc_result.md5s),
        ("Email", ioc_result.emails),
        ("CVE", ioc_result.cves),
    ]

    for label, items in rows:
        if items:
            preview = "  ".join(str(i)[:60] for i in items[:4])
            if len(items) > 4:
                preview += f"  (+{len(items) - 4} more)"
            table.add_row(label, str(len(items)), preview)

    if ioc_result.total() == 0:
        console.print("[dim]No IOCs found in input.[/dim]")
        return

    console.print()
    console.print(Panel(table, title="  IOC Extraction Results  ", border_style="cyan", box=box.HEAVY))
    console.print()


def error(msg: str) -> None:
    err.print(f"[bold red]error:[/bold red] {msg}")


def info(msg: str) -> None:
    console.print(f"[dim]{msg}[/dim]")
