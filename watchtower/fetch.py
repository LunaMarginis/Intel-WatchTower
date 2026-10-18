"""Polite, bounded downloads: a timeout on every request, retries with back-off, a size cap and an honest User-Agent."""
from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass

USER_AGENT = "Intel-WatchTower/2.0 (+https://github.com/LunaMarginis/Intel-WatchTower)"
RETRY_STATUS = {429, 500, 502, 503, 504}


class FetchError(RuntimeError):
    """The download failed for good (after the retries)."""


@dataclass
class Fetched:
    url: str
    text: str
    status: int
    size: int          # bytes received
    seconds: float     # time of the successful attempt
    attempts: int


def get(url: str, *, timeout: float = 60.0, retries: int = 3, backoff: float = 4.0,
        max_bytes: int = 60_000_000, sleep=time.sleep) -> Fetched:
    """GET `url` as text. Retries 429/5xx and network errors with growing pauses (honouring Retry-After)."""
    last = "no attempt made"
    for attempt in range(1, retries + 1):
        started = time.monotonic()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/csv,text/plain,*/*"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(max_bytes + 1)
                if len(body) > max_bytes:
                    raise FetchError(f"{url} is larger than the {max_bytes // 1_000_000} MB limit")
                return Fetched(url, body.decode("utf-8", errors="replace"), resp.status, len(body),
                               time.monotonic() - started, attempt)
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            if e.code not in RETRY_STATUS:
                raise FetchError(f"{url}: {last}") from e
            wait = _retry_after(e) or backoff * attempt
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = f"{type(e).__name__}: {getattr(e, 'reason', e)}"
            wait = backoff * attempt
        if attempt < retries:
            sleep(min(wait, 120.0))
    raise FetchError(f"{url}: {last} (after {retries} attempts)")


def _retry_after(err: urllib.error.HTTPError) -> float:
    value = err.headers.get("Retry-After") if err.headers else None
    return float(value) if value and value.strip().isdigit() else 0.0
