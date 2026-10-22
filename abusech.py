"""Rate-limited, cached client for abuse.ch exports (auth via .env, never logged)."""
import io
import os
import time
import zipfile
from pathlib import Path

import requests

CACHE_DIR = Path(".cache")
MIN_INTERVAL = 5          # seconds between any two requests
CACHE_TTL = 60 * 60       # never refetch the same export within an hour
MAX_RETRIES = 2           # polite backoff only on 429/5xx

_last_request = 0.0


def load_auth_key(env_path=".env"):
    key = os.environ.get("ABUSECH_AUTH_KEY")
    if key:
        return key.strip()
    p = Path(env_path)
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, sep, value = line.replace("=", ":", 1).partition(":")
            if sep and name.strip().lower().replace("_", "-") in ("auth-key", "abusech-auth-key"):
                return value.strip().strip('"\'')
    raise RuntimeError("Auth-Key not found in .env or ABUSECH_AUTH_KEY")


EXPORT_BASE = "https://threatfox-api.abuse.ch/v2/files/exports"


def threatfox_full_csv():
    """Return the ThreatFox full CSV dump (text). Key goes in the URL path, so it is scrubbed from errors."""
    global _last_request
    CACHE_DIR.mkdir(exist_ok=True)
    cache = CACHE_DIR / "threatfox_full.csv"
    if cache.exists() and time.time() - cache.stat().st_mtime < CACHE_TTL:
        print("using cached ThreatFox export (<1h old, no request made)")
        return cache.read_text(encoding="utf-8")

    key = load_auth_key()
    url = f"{EXPORT_BASE}/{key}/full.csv.zip"
    for attempt in range(MAX_RETRIES + 1):
        wait = MIN_INTERVAL - (time.time() - _last_request)
        if wait > 0:
            time.sleep(wait)
        _last_request = time.time()
        try:
            r = requests.get(url, headers={"User-Agent": "Intel-WatchTower/1.0"}, timeout=120)
            if (r.status_code == 429 or r.status_code >= 500) and attempt < MAX_RETRIES:
                time.sleep(int(r.headers.get("Retry-After", 30 * (attempt + 1))))
                continue
            r.raise_for_status()
        except requests.RequestException as e:
            raise RuntimeError(str(e).replace(key, "<AUTH-KEY>")) from None
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            text = z.read(z.namelist()[0]).decode("utf-8")
        cache.write_text(text, encoding="utf-8")
        return text
