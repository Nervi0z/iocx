"""Visual CLI components for iocx.

Banner, live progress scanner, and summary table.
All rendering uses rich — no external dependencies beyond what's already installed.
"""

import time
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.live import Live
from rich.columns import Columns
from rich.rule import Rule
from rich import box

console = Console()


# ---------------------------------------------------------------------------
# ASCII banner — shown at startup of scan command
# ---------------------------------------------------------------------------

_BANNER_LINES = [
    " ██╗ ██████╗  ██████╗██╗  ██╗",
    " ██║██╔═══██╗██╔════╝╚██╗██╔╝",
    " ██║██║   ██║██║      ╚███╔╝ ",
    " ██║██║   ██║██║      ██╔██╗ ",
    " ██║╚██████╔╝╚██████╗██╔╝ ██╗",
    " ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝",
]

def print_banner(target_count: int, source_file: str) -> None:
    """Print the iocx startup banner with scan metadata."""
    console.print()

    # Gradient colors for each banner line
    colors = ["#7C3AED", "#8B45F0", "#9650F2", "#7C3AED", "#5B8AF0", "#06B6D4"]

    for i, line in enumerate(_BANNER_LINES):
        console.print(f"  [bold {colors[i]}]{line}[/bold {colors[i]}]")

    console.print()
    console.print(
        f"  [dim]IOC triage at terminal speed[/dim]"
        f"  [dim]·[/dim]"
        f"  [dim cyan]v0.1.0[/dim cyan]"
    )
    console.print(
        f"  [dim]github.com/Nervi0z/iocx[/dim]"
    )
    console.print()
    console.print(Rule(style="dim #7C3AED"))
    console.print()
    console.print(
        f"  [bold white]{target_count}[/bold white] [dim]targets loaded from[/dim] "
        f"[cyan]{source_file}[/cyan]"
    )
    console.print(f"  [dim]querying across 6 OSINT sources...[/dim]")
    console.print()


# ---------------------------------------------------------------------------
# Live progress line — printed as each IOC completes
# ---------------------------------------------------------------------------

def _risk_style(risk: str) -> str:
    return {
        "HIGH":   "bold red",
        "MEDIUM": "bold yellow",
        "LOW":    "bold blue",
        "CLEAN":  "bold green",
    }.get(risk, "white")


def _risk_icon(risk: str) -> str:
    return {
        "HIGH":   "[bold red]  ●  HIGH  [/bold red]",
        "MEDIUM": "[bold yellow]  ◑  MED   [/bold yellow]",
        "LOW":    "[bold blue]  ○  LOW   [/bold blue]",
        "CLEAN":  "[bold green]  ✓  CLEAN [/bold green]",
    }.get(risk, "  ?  ???  ")


def print_progress_line(index: int, total: int, ioc: str, ioc_type: str,
                        risk: str, top_finding: str, elapsed: float) -> None:
    """Print one progress line after an IOC has been queried."""
    idx_str = f"[dim][{index:>2}/{total}][/dim]"
    icon    = _risk_icon(risk)
    ioc_str = f"[bold white]{ioc:<28}[/bold white]"
    type_str= f"[dim]{ioc_type:<7}[/dim]"
    find_str= f"[dim]{top_finding}[/dim]"
    time_str= f"[dim]{elapsed:.1f}s[/dim]"

    console.print(f"  {idx_str} {icon} {ioc_str} {type_str} {find_str}  {time_str}")


# ---------------------------------------------------------------------------
# Summary table — shown after all IOCs are processed
# ---------------------------------------------------------------------------

def print_summary_table(rows: list[dict], total_time: float,
                        output_file: Optional[str] = None) -> None:
    """Print the final summary table with all results."""
    console.print()
    console.print(Rule(style="dim #7C3AED"))
    console.print()

    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold dim",
        show_lines=False,
        padding=(0, 1),
        expand=False,
    )

    table.add_column("IOC",          style="bold white",  min_width=28, no_wrap=True)
    table.add_column("TYPE",         style="dim",         width=8)
    table.add_column("RISK",         width=10)
    table.add_column("ABUSEIPDB",    style="dim",         width=10)
    table.add_column("VIRUSTOTAL",   style="dim",         width=12)
    table.add_column("SHODAN",       style="dim",         width=16)
    table.add_column("URLHAUS",      style="dim",         width=10)

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}

    for row in rows:
        risk  = row["risk_label"]
        counts[risk] = counts.get(risk, 0) + 1

        # Extract values from sources
        sources_data = {s["name"]: s["value"] for s in row.get("sources", [])}
        abuse  = sources_data.get("AbuseIPDB", "—")
        vt     = sources_data.get("VirusTotal", "—")
        shodan = sources_data.get("Shodan", "—")
        uh     = sources_data.get("URLhaus", "—")

        # Trim long values
        shodan = shodan[:14] + "…" if len(shodan) > 15 else shodan

        risk_text = Text()
        if risk == "HIGH":
            risk_text.append("● HIGH",   style="bold red")
        elif risk == "MEDIUM":
            risk_text.append("◑ MEDIUM", style="bold yellow")
        elif risk == "LOW":
            risk_text.append("○ LOW",    style="bold blue")
        else:
            risk_text.append("✓ CLEAN",  style="bold green")

        table.add_row(
            row["ioc"],
            row["type"],
            risk_text,
            abuse,
            vt,
            shodan,
            uh,
        )

    console.print(table)
    console.print()

    # Stats line
    h = counts["HIGH"]
    m = counts["MEDIUM"]
    l = counts["LOW"]
    c = counts["CLEAN"]
    total = len(rows)

    stats = Text("  ")
    stats.append(f"{total} targets", style="bold white")
    stats.append("  ·  ", style="dim")
    stats.append(f"{h} HIGH",   style="bold red"    if h else "dim")
    stats.append("  ·  ", style="dim")
    stats.append(f"{m} MEDIUM", style="bold yellow" if m else "dim")
    stats.append("  ·  ", style="dim")
    stats.append(f"{l} LOW",    style="bold blue"   if l else "dim")
    stats.append("  ·  ", style="dim")
    stats.append(f"{c} CLEAN",  style="bold green"  if c else "dim")
    stats.append("  ·  ", style="dim")
    stats.append(f"{total_time:.1f}s", style="dim cyan")

    console.print(stats)
    console.print()

    if output_file:
        console.print(
            f"  [dim]report →[/dim] [bold cyan]{output_file}[/bold cyan]"
        )
        console.print()


# ---------------------------------------------------------------------------
# Top finding extractor — one-line summary per IOC for progress line
# ---------------------------------------------------------------------------

def top_finding(ioc_type: str, results: list[dict]) -> str:
    """Extract the most relevant finding as a short string."""
    abuse = next((r for r in results if r.get("source") == "AbuseIPDB"
                  and "error" not in r), {})
    vt    = next((r for r in results if r.get("source") == "VirusTotal"
                  and "error" not in r), {})
    uh    = next((r for r in results if r.get("source") == "URLhaus"
                  and "error" not in r), {})
    mb    = next((r for r in results if r.get("source") == "MalwareBazaar"
                  and "error" not in r), {})
    geo   = next((r for r in results if r.get("source") == "ip-api"
                  and "error" not in r), {})

    parts = []

    if abuse.get("score", 0) > 0:
        parts.append(f"AbuseIPDB:{abuse['score']}/100")
    if abuse.get("is_tor"):
        parts.append("TOR")
    if vt.get("malicious", 0) > 0:
        parts.append(f"VT:{vt['malicious']}/{vt.get('total', 0)}")
    if uh.get("found"):
        parts.append(f"URLhaus:found")
    if mb.get("found"):
        sig = mb.get("signature") or mb.get("file_type", "")
        parts.append(f"Bazaar:{sig}" if sig else "Bazaar:found")
    if geo.get("country"):
        parts.append(geo["country"].split(" ")[0])

    if not parts:
        return "no detections"
    return "  ".join(parts[:4])
