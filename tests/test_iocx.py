"""Tests for iocx — no network calls."""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from iocx.extract import extract, _refang
from iocx.decode import decode_all


# ---------------------------------------------------------------------------
# refang
# ---------------------------------------------------------------------------

def test_refang_hxxp():
    assert _refang("hxxps://evil.com") == "https://evil.com"

def test_refang_dot():
    assert _refang("evil[.]com") == "evil.com"

def test_refang_dot_paren():
    assert _refang("evil(.com") == "evil.com"


# ---------------------------------------------------------------------------
# extract — IPs
# ---------------------------------------------------------------------------

def test_extract_ipv4():
    r = extract("Connection from 185.220.101.45 accepted")
    assert "185.220.101.45" in r.ips

def test_extract_multiple_ips():
    r = extract("src=1.2.3.4 dst=5.6.7.8")
    assert len(r.ips) == 2

def test_extract_excludes_private_by_default():
    r = extract("Login from 192.168.1.5")
    assert "192.168.1.5" not in r.ips

def test_extract_includes_private_when_flagged():
    r = extract("Login from 192.168.1.5", include_private=True)
    assert "192.168.1.5" in r.ips


# ---------------------------------------------------------------------------
# extract — hashes
# ---------------------------------------------------------------------------

def test_extract_md5():
    r = extract("hash: d41d8cd98f00b204e9800998ecf8427e")
    assert "d41d8cd98f00b204e9800998ecf8427e" in r.md5s

def test_extract_sha256():
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    r = extract(f"sha256: {h}")
    assert h in r.sha256s

def test_sha256_not_in_md5():
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    r = extract(f"sha256: {h}")
    assert h not in r.md5s


# ---------------------------------------------------------------------------
# extract — domains
# ---------------------------------------------------------------------------

def test_extract_domain():
    r = extract("C2 at evil-c2.ru communicating")
    assert "evil-c2.ru" in r.domains

def test_extract_excludes_fp_domains():
    r = extract("downloaded from github.com")
    assert "github.com" not in r.domains


# ---------------------------------------------------------------------------
# extract — CVEs
# ---------------------------------------------------------------------------

def test_extract_cve():
    r = extract("Exploited via CVE-2021-44228 (Log4Shell)")
    assert "CVE-2021-44228" in r.cves

def test_extract_cve_lowercase():
    r = extract("via cve-2024-1234")
    assert "CVE-2024-1234" in r.cves


# ---------------------------------------------------------------------------
# extract — defanged
# ---------------------------------------------------------------------------

def test_extract_defanged_ip():
    r = extract("attacker: 185[.]220[.]101[.]45")
    assert "185.220.101.45" in r.ips

def test_extract_defanged_url():
    r = extract("payload at hxxps://evil[.]ru/drop.exe")
    assert any("evil.ru" in u or "https://evil.ru" in u for u in r.urls + r.domains)


# ---------------------------------------------------------------------------
# decode
# ---------------------------------------------------------------------------

def test_decode_base64():
    r = decode_all("SGVsbG8gV29ybGQ=")
    assert r.get("base64") == "Hello World"

def test_decode_hex():
    r = decode_all("48656c6c6f")
    assert r.get("hex") == "Hello"

def test_decode_url():
    r = decode_all("Hello%20World")
    assert r.get("url_decoded") == "Hello World"

def test_decode_jwt():
    # header.payload.sig — base64url encoded
    import base64, json
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b'=').decode()
    payload = base64.urlsafe_b64encode(b'{"sub":"test"}').rstrip(b'=').decode()
    token = f"{header}.{payload}.fakesig"
    r = decode_all(token)
    assert "jwt" in r
    assert r["jwt"]["header"]["alg"] == "HS256"

def test_decode_rot13():
    r = decode_all("Uryyb")
    assert r.get("rot13") == "Hello"

def test_decode_unrecognized():
    r = decode_all("justplaintext123!")
    assert "raw" in r
