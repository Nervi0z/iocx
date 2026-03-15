"""Extract IOCs from free-form text.

Handles defanged formats: hxxp, [.], (.), x.x.x.x style obfuscation.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class IOCResult:
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    md5s: list[str] = field(default_factory=list)
    sha1s: list[str] = field(default_factory=list)
    sha256s: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)

    def total(self) -> int:
        return sum(len(getattr(self, f)) for f in self.__dataclass_fields__)


def _refang(text: str) -> str:
    """Convert defanged IOCs to standard form."""
    text = re.sub(r'hxxps?', lambda m: m.group().replace('xx', 'tt'), text, flags=re.IGNORECASE)
    text = text.replace("[.]", ".").replace("(.", ".").replace("[dot]", ".")
    text = text.replace("[:]", ":").replace("[@]", "@")
    return text


_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,}"
    r"(?:com|net|org|io|ru|cn|de|fr|uk|nl|info|biz|xyz|top|online|site|club|tk|ml|ga|cf|gq|pw|cc|co|me|tv|us|ca|au|jp)\b",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s\"'<>\]]+", re.IGNORECASE)
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
_SHA1_RE   = re.compile(r"[0-9a-fA-F]{40}")
_MD5_RE    = re.compile(r"[0-9a-fA-F]{32}")
_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

# Private/loopback ranges to exclude from IP results
_PRIVATE = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.255\.255\.255)"
)

# Common false-positive domains
_FP_DOMAINS = {
    "example.com", "github.com", "microsoft.com", "google.com",
    "windows.com", "apple.com", "cloudflare.com",
}


def extract(text: str, include_private: bool = False) -> IOCResult:
    """Extract all IOC types from text.

    Args:
        text: Raw text, including defanged IOCs.
        include_private: Include RFC1918 IPs in results.

    Returns:
        IOCResult with deduplicated lists per IOC type.
    """
    clean = _refang(text)
    result = IOCResult()

    # URLs first — extract them before domain regex picks up fragments
    urls = _URL.findall(clean)
    result.urls = list(dict.fromkeys(urls))

    # IPs
    ips = _IPV4_RE.findall(clean)
    if not include_private:
        ips = [ip for ip in ips if not _PRIVATE.match(ip)]
    result.ips = list(dict.fromkeys(ips))

    # SHA256 before SHA1 before MD5 (length order prevents partial matches)
    sha256s = _SHA256_RE.findall(clean)
    remaining = _SHA256_RE.sub("", clean)
    sha1s = _SHA1_RE.findall(remaining)
    remaining = _SHA1_RE.sub("", remaining)
    md5s = _MD5_RE.findall(remaining)

    result.sha256s = list(dict.fromkeys(sha256s))
    result.sha1s = list(dict.fromkeys(sha1s))
    result.md5s = list(dict.fromkeys(md5s))

    # Domains — exclude anything already in URLs and false positives
    url_hostnames = {u.split("/")[2].split(":")[0] for u in result.urls}
    domains = [
        d for d in _DOMAIN_RE.findall(clean)
        if d.lower() not in _FP_DOMAINS and d not in url_hostnames
    ]
    result.domains = list(dict.fromkeys(domains))

    # Emails
    result.emails = list(dict.fromkeys(_EMAIL.findall(clean)))

    # CVEs
    result.cves = list(dict.fromkeys(m.upper() for m in _CVE.findall(clean)))

    return result
