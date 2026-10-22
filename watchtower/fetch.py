"""Polite, bounded downloads: a timeout on every request, retries with back-off, a size cap and an honest User-Agent."""
from __future__ import annotations

import io
import time
import urllib.error
import urllib.request
import zipfile
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
        max_bytes: int = 60_000_000, sleep=time.sleep, unzip: bool = False, redact: str = "") -> Fetched:
    """GET `url` as text. Retries 429/5xx and network errors with growing pauses (honouring Retry-After).

    unzip: the body is a zip holding one text file. redact: a secret inside the URL, removed from every message and from `Fetched.url`."""
    hide = (lambda t: t.replace(redact, "<AUTH-KEY>")) if redact else (lambda t: t)
    shown = hide(url)
    last = "no attempt made"
    for attempt in range(1, retries + 1):
        started = time.monotonic()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/csv,text/plain,*/*"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(max_bytes + 1)
                if len(body) > max_bytes:
                    raise FetchError(f"{shown} is larger than the {max_bytes // 1_000_000} MB limit")
                size = len(body)
                if unzip:
                    body = _unzip(body, max_bytes, shown)
                return Fetched(shown, body.decode("utf-8", errors="replace"), resp.status, size,
                               time.monotonic() - started, attempt)
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            if e.code not in RETRY_STATUS:
                raise FetchError(f"{shown}: {last}") from None
            wait = _retry_after(e) or backoff * attempt
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = hide(f"{type(e).__name__}: {getattr(e, 'reason', e)}")
            wait = backoff * attempt
        if attempt < retries:
            sleep(min(wait, 120.0))
    raise FetchError(f"{shown}: {last} (after {retries} attempts)")


def _retry_after(err: urllib.error.HTTPError) -> float:
    value = err.headers.get("Retry-After") if err.headers else None
    return float(value) if value and value.strip().isdigit() else 0.0


def _unzip(body: bytes, max_bytes: int, shown: str) -> bytes:
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as z:
            names = z.namelist()
            if len(names) != 1:
                raise FetchError(f"{shown}: expected one file in the zip, found {len(names)}")
            data = z.open(names[0]).read(max_bytes + 1)
    except zipfile.BadZipFile:
        raise FetchError(f"{shown}: the answer is not a zip file") from None
    if len(data) > max_bytes:
        raise FetchError(f"{shown}: unzipped file is larger than the {max_bytes // 1_000_000} MB limit")
    return data
