"""API key management stored in ~/.iocx/config.json."""

import json
import os
from pathlib import Path
from typing import Optional

CONFIG_DIR = Path.home() / ".iocx"
CONFIG_FILE = CONFIG_DIR / "config.json"

KNOWN_KEYS = ("virustotal", "abuseipdb", "shodan")


def _load() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text())
    except Exception:
        return {}


def _save(data: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(data, indent=2))
    CONFIG_FILE.chmod(0o600)


def get(key: str) -> Optional[str]:
    """Return API key — env var takes priority over config file."""
    env_map = {
        "virustotal": "VT_API_KEY",
        "abuseipdb":  "ABUSEIPDB_API_KEY",
        "shodan":     "SHODAN_API_KEY",
    }
    env_val = os.environ.get(env_map.get(key, ""))
    if env_val:
        return env_val
    return _load().get(key)


def set_key(key: str, value: str) -> None:
    data = _load()
    data[key] = value
    _save(data)


def list_keys() -> dict:
    stored = _load()
    result = {}
    for k in KNOWN_KEYS:
        val = get(k)
        result[k] = "configured" if val else "not set"
    return result


def delete_key(key: str) -> bool:
    data = _load()
    if key in data:
        del data[key]
        _save(data)
        return True
    return False
