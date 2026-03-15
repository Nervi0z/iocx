"""Auto-detect and decode encoded strings.

Tries multiple encodings in order and returns all successful results.
"""

import base64
import binascii
import json
import re
import urllib.parse
from typing import Optional


def _try_base64(value: str) -> Optional[str]:
    """Attempt standard and URL-safe base64 decoding."""
    for variant in (value, value + "=" * (-len(value) % 4)):
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decoder(variant)
                return decoded.decode("utf-8", errors="replace")
            except Exception:
                continue
    return None


def _try_hex(value: str) -> Optional[str]:
    """Attempt hex decoding."""
    clean = re.sub(r"[\s:\\]", "", value)
    if not re.fullmatch(r"[0-9a-fA-F]+", clean):
        return None
    if len(clean) % 2 != 0:
        return None
    try:
        decoded = bytes.fromhex(clean)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def _try_url(value: str) -> Optional[str]:
    """Attempt URL percent-decoding."""
    decoded = urllib.parse.unquote(value)
    if decoded == value:
        return None
    return decoded


def _try_jwt(value: str) -> Optional[dict]:
    """Attempt JWT parsing (no signature verification)."""
    parts = value.split(".")
    if len(parts) != 3:
        return None
    results = {}
    for label, part in [("header", parts[0]), ("payload", parts[1])]:
        decoded = _try_base64(part)
        if decoded:
            try:
                results[label] = json.loads(decoded)
            except Exception:
                results[label] = decoded
    if results:
        results["signature"] = parts[2] + " (not verified)"
        return results
    return None


def _try_rot13(value: str) -> Optional[str]:
    """ROT13 decode."""
    result = value.translate(
        str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
        )
    )
    if result == value:
        return None
    return result


def decode_all(value: str) -> dict:
    """Try all decoders and return a dict of successful results.

    Args:
        value: Encoded string.

    Returns:
        Dict mapping decoder name to decoded output.
        Always includes 'raw' key with the original value.
    """
    results: dict = {"raw": value}

    jwt = _try_jwt(value)
    if jwt:
        results["jwt"] = jwt
        return results  # JWT is definitive — stop here

    url_decoded = _try_url(value)
    if url_decoded:
        results["url_decoded"] = url_decoded
        # Also try base64 on the URL-decoded result
        b64_of_url = _try_base64(url_decoded)
        if b64_of_url:
            results["url_then_base64"] = b64_of_url

    b64 = _try_base64(value)
    if b64:
        results["base64"] = b64
        # Recursive: if the base64 result looks encoded, try again
        nested = _try_base64(b64.strip())
        if nested and nested != b64:
            results["base64_double"] = nested

    hex_decoded = _try_hex(value)
    if hex_decoded:
        results["hex"] = hex_decoded

    rot13 = _try_rot13(value)
    if rot13 and rot13 != value:
        results["rot13"] = rot13

    return results
