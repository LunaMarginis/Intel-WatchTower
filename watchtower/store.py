"""Files on disk: the published CSVs, and the run history. Writes are atomic (temp file, then rename) and deterministic
(stable ordering, no timestamps inside data files), so an unchanged day produces an unchanged file and git stores almost nothing."""
from __future__ import annotations

import csv
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .parse import Hash, Url, defang_url

MHASH_FIELDS = ["ioc_value", "fk_malware", "malware_alias", "malware_printable", "count", "first_seen_utc", "confidence_level", "threat_type", "tags", "reporter"]
URL_FIELDS = ["tags", "url", "url_status", "dateadded", "id"]
HISTORY_KEEP = 800   # run records


def write_text(path: Path, text: str) -> bool:
    """Write atomically. Returns True when the content changed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(encoding="utf-8") == text:
        return False
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.replace(tmp, path)
    return True


def csv_text(fields: list[str], rows: list[dict]) -> str:
    import io
    buf = io.StringIO(newline="")
    w = csv.DictWriter(buf, fieldnames=fields, lineterminator="\n", extrasaction="ignore")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


# ---------------------------------------------------------------- hashes

def mhash_text(current: list[Hash], occurrences: dict[str, int]) -> str:
    """The latest export, one clean row per hash. Same first five columns as before (now without the stray quotes), richer columns after them."""
    rows = []
    for h in sorted(current, key=lambda h: (h.first_seen, h.ioc_value), reverse=True):
        rows.append({"ioc_value": h.ioc_value, "fk_malware": h.malware, "malware_alias": h.alias, "malware_printable": h.printable, "count": occurrences.get(h.ioc_value, 1),
                     "first_seen_utc": h.first_seen.strftime("%Y-%m-%d %H:%M:%S"), "confidence_level": h.confidence, "threat_type": h.threat_type, "tags": ",".join(h.tags), "reporter": h.reporter})
    return csv_text(MHASH_FIELDS, rows)


# ---------------------------------------------------------------- urls

def urls_text(urls: list[Url]) -> str:
    """Same first three columns as before (defanged), then the date added and the URLhaus id."""
    def key(u: Url):
        return (-int(u.id) if u.id.isdigit() else 0, u.url)
    rows = [{"tags": ",".join(u.tags), "url": defang_url(u.url), "url_status": u.status, "dateadded": u.added.strftime("%Y-%m-%d %H:%M:%S"), "id": u.id} for u in sorted(urls, key=key)]
    return csv_text(URL_FIELDS, rows)


def previous_url_status(path: Path) -> dict[str, str]:
    """id -> status of every URL in the previous export (empty on the first run)."""
    return {r["id"]: r.get("url_status", "") for r in read_csv(path) if r.get("id")}


# ---------------------------------------------------------------- history

def read_history(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def history_text(records: list[dict]) -> str:
    return "".join(json.dumps(r, separators=(",", ":"), sort_keys=True) + "\n" for r in records[-HISTORY_KEEP:])


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
