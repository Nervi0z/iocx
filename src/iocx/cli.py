"""iocx — IOC triage at terminal speed.

Usage:
  iocx ip <IP>
  iocx hash <HASH>
  iocx domain <DOMAIN>
  iocx url <URL>
  iocx scan <FILE>
  iocx decode <STRING>
  iocx config set <SERVICE> <KEY>
  iocx config list
  iocx config delete <SERVICE>
"""

import sys
import concurrent.futures
from typing import Optional

import click
from rich.console import Console

from . import config, decode, extract, output, sources

console = Console()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parallel(*fns) -> list[dict]:
    """Run lookup functions concurrently and return results list."""
    with concurrent.futures.ThreadPoolExecutor() as pool:
        futures = [pool.submit(fn) for fn in fns]
        return [f.result() for f in futures]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(package_name="iocx")
def cli():
    """iocx — IOC triage at terminal speed.

    Query IPs, hashes, domains and URLs across multiple threat intel
    sources with a single command. Works without API keys using open
    sources; add keys for VirusTotal, AbuseIPDB and Shodan for deeper results.

    \b
    Quick start:
      iocx ip 185.220.101.45
      iocx hash d41d8cd98f00b204e9800998ecf8427e
      iocx domain evil-c2.ru
      iocx scan report.txt
      iocx decode SGVsbG8gV29ybGQ=
      iocx config set virustotal YOUR_KEY
    """
    pass


# ---------------------------------------------------------------------------
# iocx ip
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("ip")
@click.option("--json", "json_mode", is_flag=True, help="Output JSON.")
def ip(ip: str, json_mode: bool):
    """Query reputation for an IP address.

    \b
    Sources (open):  ip-api.com
    Sources (key):   AbuseIPDB · VirusTotal · Shodan

    \b
    Examples:
      iocx ip 185.220.101.45
      iocx ip 8.8.8.8 --json
    """
    if not json_mode:
        console.print(f"[dim]querying {ip}...[/dim]")

    results = _parallel(
        lambda: sources.ip_api(ip),
        lambda: sources.abuseipdb(ip),
        lambda: sources.virustotal_ip(ip),
        lambda: sources.shodan_ip(ip),
    )

    output.render_ip(ip, results, json_mode=json_mode)


# ---------------------------------------------------------------------------
# iocx hash
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("hash_val", metavar="HASH")
@click.option("--json", "json_mode", is_flag=True, help="Output JSON.")
def hash(hash_val: str, json_mode: bool):
    """Query reputation for an MD5, SHA1 or SHA256 hash.

    \b
    Sources (open):  MalwareBazaar
    Sources (key):   VirusTotal

    \b
    Examples:
      iocx hash d41d8cd98f00b204e9800998ecf8427e
      iocx hash 44d88612fea8a8f36de82e1278abb02f --json
    """
    h = hash_val.strip().lower()
    if len(h) not in (32, 40, 64):
        output.error(f"'{hash_val}' does not look like an MD5 (32), SHA1 (40) or SHA256 (64) hash.")
        sys.exit(1)

    if not json_mode:
        console.print(f"[dim]querying {h[:16]}...[/dim]")

    results = _parallel(
        lambda: sources.malwarebazaar_hash(h),
        lambda: sources.virustotal_hash(h),
    )

    output.render_hash(h, results, json_mode=json_mode)


# ---------------------------------------------------------------------------
# iocx domain
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("domain")
@click.option("--json", "json_mode", is_flag=True, help="Output JSON.")
def domain(domain: str, json_mode: bool):
    """Query reputation for a domain.

    \b
    Sources (open):  DNS · URLhaus
    Sources (key):   VirusTotal

    \b
    Examples:
      iocx domain evil-c2.ru
      iocx domain suspicious.xyz --json
    """
    d = domain.strip().lower().rstrip(".")

    if not json_mode:
        console.print(f"[dim]querying {d}...[/dim]")

    results = _parallel(
        lambda: sources.dns_resolve(d),
        lambda: sources.urlhaus_domain(d),
        lambda: sources.virustotal_domain(d),
    )

    output.render_domain(d, results, json_mode=json_mode)


# ---------------------------------------------------------------------------
# iocx url
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("url")
@click.option("--json", "json_mode", is_flag=True, help="Output JSON.")
def url(url: str, json_mode: bool):
    """Query reputation for a URL.

    Accepts defanged URLs: hxxps://evil[.]com/payload

    \b
    Sources (open):  URLhaus
    Sources (key):   VirusTotal (domain extracted)

    \b
    Examples:
      iocx url "hxxps://malware[.]ru/payload.exe"
      iocx url "https://suspicious.xyz/gate.php"
    """
    import re as _re
    clean = url.strip().replace("hxxp", "http").replace("[.]", ".").replace("[:]", ":")

    if not json_mode:
        console.print(f"[dim]querying url...[/dim]")

    uh = sources.urlhaus_url(clean)

    # Also query the domain
    domain_match = _re.search(r"https?://([^/:?#\s]+)", clean)
    domain_results = []
    if domain_match:
        dom = domain_match.group(1)
        domain_results = _parallel(
            lambda: sources.dns_resolve(dom),
            lambda: sources.virustotal_domain(dom),
        )

    results = [uh] + domain_results

    if json_mode:
        import json as _json
        print(_json.dumps({"ioc": url, "type": "url", "results": results}, indent=2))
    else:
        output.render_domain(clean, results, json_mode=False)


# ---------------------------------------------------------------------------
# iocx scan
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--json", "json_mode", is_flag=True, help="Output JSON.")
@click.option("--query", is_flag=True, help="Automatically query all extracted IOCs.")
@click.option("--private", is_flag=True, help="Include private/RFC1918 IPs.")
def scan(file: str, json_mode: bool, query: bool, private: bool):
    """Extract IOCs from a file and optionally query them.

    \b
    Examples:
      iocx scan report.txt
      iocx scan incident.log --query
      iocx scan advisory.pdf --json
    """
    from pathlib import Path
    text = Path(file).read_text(encoding="utf-8", errors="replace")
    result = extract.extract(text, include_private=private)
    output.render_scan_summary(result, json_mode=json_mode)

    if query and not json_mode:
        for ip_val in result.ips[:10]:
            console.print(f"[dim]querying {ip_val}...[/dim]")
            r = _parallel(
                lambda v=ip_val: sources.ip_api(v),
                lambda v=ip_val: sources.abuseipdb(v),
                lambda v=ip_val: sources.virustotal_ip(v),
                lambda v=ip_val: sources.shodan_ip(v),
            )
            output.render_ip(ip_val, r)

        for h in result.sha256s[:5] + result.sha1s[:5] + result.md5s[:5]:
            console.print(f"[dim]querying {h[:16]}...[/dim]")
            r = _parallel(
                lambda v=h: sources.malwarebazaar_hash(v),
                lambda v=h: sources.virustotal_hash(v),
            )
            output.render_hash(h, r)

        for dom in result.domains[:10]:
            console.print(f"[dim]querying {dom}...[/dim]")
            r = _parallel(
                lambda v=dom: sources.dns_resolve(v),
                lambda v=dom: sources.urlhaus_domain(v),
                lambda v=dom: sources.virustotal_domain(v),
            )
            output.render_domain(dom, r)


# ---------------------------------------------------------------------------
# iocx decode
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("value")
@click.option("--json", "json_mode", is_flag=True, help="Output JSON.")
def decode_cmd(value: str, json_mode: bool):
    """Auto-detect and decode an encoded string.

    Tries: base64 · base64url · hex · URL encoding · JWT · ROT13

    \b
    Examples:
      iocx decode SGVsbG8gV29ybGQ=
      iocx decode 48656c6c6f
      iocx decode "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc"
    """
    results = decode.decode_all(value)
    output.render_decode(value, results, json_mode=json_mode)


# Give the command the right name
decode_cmd.name = "decode"
cli.add_command(decode_cmd)


# ---------------------------------------------------------------------------
# iocx config
# ---------------------------------------------------------------------------

@cli.group()
def config_cmd():
    """Manage API keys for optional threat intel sources.

    Keys are stored in ~/.iocx/config.json (chmod 600).
    Environment variables take priority: VT_API_KEY, ABUSEIPDB_API_KEY, SHODAN_API_KEY.

    \b
    Services: virustotal · abuseipdb · shodan
    """
    pass


config_cmd.name = "config"
cli.add_command(config_cmd)


@config_cmd.command("set")
@click.argument("service")
@click.argument("key")
def config_set(service: str, key: str):
    """Store an API key for a service.

    \b
    Example:
      iocx config set virustotal abc123...
      iocx config set abuseipdb xyz789...
      iocx config set shodan abc000...
    """
    service = service.lower()
    if service not in config.KNOWN_KEYS:
        output.error(f"Unknown service '{service}'. Known: {', '.join(config.KNOWN_KEYS)}")
        sys.exit(1)
    config.set_key(service, key)
    console.print(f"[green]Key for '{service}' saved to ~/.iocx/config.json[/green]")


@config_cmd.command("list")
def config_list():
    """Show configured API keys (values are hidden)."""
    keys = config.list_keys()
    for service, status in keys.items():
        style = "green" if status == "configured" else "dim"
        console.print(f"  {service:<15} [{style}]{status}[/{style}]")


@config_cmd.command("delete")
@click.argument("service")
def config_delete(service: str):
    """Remove a stored API key."""
    if config.delete_key(service.lower()):
        console.print(f"[green]Key for '{service}' removed.[/green]")
    else:
        output.error(f"No stored key found for '{service}'.")
        sys.exit(1)


def main():
    cli()
