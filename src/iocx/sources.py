"""Data source lookups — all external calls live here.

Each function returns a dict with a 'source' key and the relevant fields.
On failure, returns {'source': '...', 'error': 'message'} — never raises.
"""

import ipaddress
import re
import socket
from typing import Optional

import requests

from . import config

TIMEOUT = 10


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(url: str, headers: Optional[dict] = None, params: Optional[dict] = None) -> Optional[requests.Response]:
    try:
        return requests.get(url, headers=headers or {}, params=params or {}, timeout=TIMEOUT)
    except Exception:
        return None


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# IP sources
# ---------------------------------------------------------------------------

def ip_api(ip: str) -> dict:
    """Free geolocation and ASN — no key required."""
    r = _get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,hosting,proxy,mobile,query")
    if not r or r.status_code != 200:
        return {"source": "ip-api", "error": "unreachable"}
    d = r.json()
    if d.get("status") != "success":
        return {"source": "ip-api", "error": d.get("message", "unknown")}
    return {
        "source": "ip-api",
        "country": f"{d.get('country', '?')} ({d.get('countryCode', '?')})",
        "region": d.get("regionName", ""),
        "city": d.get("city", ""),
        "org": d.get("org", ""),
        "asn": d.get("as", ""),
        "hosting": d.get("hosting", False),
        "proxy": d.get("proxy", False),
        "mobile": d.get("mobile", False),
    }


def abuseipdb(ip: str) -> dict:
    """AbuseIPDB reputation — requires API key."""
    key = config.get("abuseipdb")
    if not key:
        return {"source": "AbuseIPDB", "error": "no API key (iocx config set abuseipdb YOUR_KEY)"}
    r = _get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
    )
    if not r or r.status_code != 200:
        return {"source": "AbuseIPDB", "error": f"HTTP {r.status_code if r else 'timeout'}"}
    d = r.json().get("data", {})
    return {
        "source": "AbuseIPDB",
        "score": d.get("abuseConfidenceScore", 0),
        "reports": d.get("totalReports", 0),
        "last_reported": d.get("lastReportedAt", "never"),
        "domain": d.get("domain", ""),
        "usage": d.get("usageType", ""),
        "is_tor": d.get("isTor", False),
    }


def virustotal_ip(ip: str) -> dict:
    """VirusTotal IP reputation — requires API key."""
    key = config.get("virustotal")
    if not key:
        return {"source": "VirusTotal", "error": "no API key (iocx config set virustotal YOUR_KEY)"}
    r = _get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": key},
    )
    if not r or r.status_code != 200:
        return {"source": "VirusTotal", "error": f"HTTP {r.status_code if r else 'timeout'}"}
    stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {
        "source": "VirusTotal",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "total": sum(stats.values()),
    }


def shodan_ip(ip: str) -> dict:
    """Shodan host lookup — requires API key."""
    key = config.get("shodan")
    if not key:
        return {"source": "Shodan", "error": "no API key (iocx config set shodan YOUR_KEY)"}
    r = _get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": key})
    if not r:
        return {"source": "Shodan", "error": "timeout"}
    if r.status_code == 404:
        return {"source": "Shodan", "error": "not in index"}
    if r.status_code != 200:
        return {"source": "Shodan", "error": f"HTTP {r.status_code}"}
    d = r.json()
    ports = sorted({item.get("port") for item in d.get("data", []) if item.get("port")})
    tags = d.get("tags", [])
    vulns = list(d.get("vulns", {}).keys())
    return {
        "source": "Shodan",
        "ports": ports[:20],
        "tags": tags,
        "vulns": vulns[:10],
        "hostnames": d.get("hostnames", [])[:5],
        "last_update": d.get("last_update", ""),
    }


# ---------------------------------------------------------------------------
# Hash sources
# ---------------------------------------------------------------------------

def malwarebazaar_hash(hash_val: str) -> dict:
    """MalwareBazaar hash lookup — no key required."""
    r = None
    try:
        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": hash_val},
            timeout=TIMEOUT,
        )
    except Exception:
        return {"source": "MalwareBazaar", "error": "unreachable"}
    if not r or r.status_code != 200:
        return {"source": "MalwareBazaar", "error": "HTTP error"}
    d = r.json()
    if d.get("query_status") == "hash_not_found":
        return {"source": "MalwareBazaar", "found": False}
    data = d.get("data", [{}])[0]
    return {
        "source": "MalwareBazaar",
        "found": True,
        "file_name": data.get("file_name", ""),
        "file_type": data.get("file_type", ""),
        "file_size": data.get("file_size", 0),
        "tags": data.get("tags", []),
        "signature": data.get("signature", ""),
        "first_seen": data.get("first_seen", ""),
        "last_seen": data.get("last_seen", ""),
        "delivery_method": data.get("delivery_method", ""),
    }


def virustotal_hash(hash_val: str) -> dict:
    """VirusTotal file reputation — requires API key."""
    key = config.get("virustotal")
    if not key:
        return {"source": "VirusTotal", "error": "no API key (iocx config set virustotal YOUR_KEY)"}
    r = _get(
        f"https://www.virustotal.com/api/v3/files/{hash_val}",
        headers={"x-apikey": key},
    )
    if not r:
        return {"source": "VirusTotal", "error": "timeout"}
    if r.status_code == 404:
        return {"source": "VirusTotal", "found": False}
    if r.status_code != 200:
        return {"source": "VirusTotal", "error": f"HTTP {r.status_code}"}
    attrs = r.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "source": "VirusTotal",
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "total": sum(stats.values()),
        "name": attrs.get("meaningful_name", ""),
        "type": attrs.get("type_description", ""),
        "size": attrs.get("size", 0),
        "tags": attrs.get("tags", []),
    }


# ---------------------------------------------------------------------------
# Domain sources
# ---------------------------------------------------------------------------

def dns_resolve(domain: str) -> dict:
    """Basic DNS resolution — no key required."""
    try:
        result = socket.getaddrinfo(domain, None)
        ips = list({r[4][0] for r in result})
        return {"source": "DNS", "ips": ips[:10]}
    except socket.gaierror as e:
        return {"source": "DNS", "error": str(e)}


def urlhaus_domain(domain: str) -> dict:
    """URLhaus domain lookup — no key required."""
    r = None
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            timeout=TIMEOUT,
        )
    except Exception:
        return {"source": "URLhaus", "error": "unreachable"}
    if not r or r.status_code != 200:
        return {"source": "URLhaus", "error": "HTTP error"}
    d = r.json()
    if d.get("query_status") == "no_results":
        return {"source": "URLhaus", "found": False}
    urls = d.get("urls", [])
    return {
        "source": "URLhaus",
        "found": True,
        "url_count": len(urls),
        "tags": list({tag for u in urls for tag in (u.get("tags") or [])}),
        "payloads": list({u.get("url_status") for u in urls[:5]}),
    }


def virustotal_domain(domain: str) -> dict:
    """VirusTotal domain reputation — requires API key."""
    key = config.get("virustotal")
    if not key:
        return {"source": "VirusTotal", "error": "no API key (iocx config set virustotal YOUR_KEY)"}
    r = _get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": key},
    )
    if not r or r.status_code != 200:
        return {"source": "VirusTotal", "error": f"HTTP {r.status_code if r else 'timeout'}"}
    attrs = r.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    cats = attrs.get("categories", {})
    return {
        "source": "VirusTotal",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "total": sum(stats.values()),
        "categories": list(set(cats.values()))[:5],
        "reputation": attrs.get("reputation", 0),
        "registrar": attrs.get("registrar", ""),
        "creation_date": attrs.get("creation_date", ""),
    }


def urlhaus_url(url: str) -> dict:
    """URLhaus URL lookup — no key required."""
    r = None
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=TIMEOUT,
        )
    except Exception:
        return {"source": "URLhaus", "error": "unreachable"}
    if not r or r.status_code != 200:
        return {"source": "URLhaus", "error": "HTTP error"}
    d = r.json()
    if d.get("query_status") == "no_results":
        return {"source": "URLhaus", "found": False}
    return {
        "source": "URLhaus",
        "found": True,
        "url_status": d.get("url_status", ""),
        "threat": d.get("threat", ""),
        "tags": d.get("tags", []),
        "blacklists": d.get("blacklists", {}),
        "date_added": d.get("date_added", ""),
    }
