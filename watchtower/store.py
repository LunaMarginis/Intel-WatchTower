"""Files on disk: the published CSVs, the accumulating hash archive and the run history. Writes are atomic (temp file, then rename) and deterministic
(stable ordering, no timestamps inside data files), so an unchanged day produces an unchanged file and git stores almost nothing."""
from __future__ import annotations

import csv
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .parse import Hash, Url, defang_url, to_dt

ARCHIVE_FIELDS = ["ioc_value", "first_seen_utc", "ioc_id", "fk_malware", "malware_alias", "malware_printable", "threat_type", "confidence_level", "tags", "reporter", "reference"]
MHASH_FIELDS = ["ioc_value", "fk_malware", "malware_alias", "malware_printable", "count", "first_seen_utc", "confidence_level", "threat_type", "tags", "reporter"]
URL_FIELDS = ["tags", "url", "url_status", "dateadded", "id"]
ARCHIVE_DAYS = 400   # hashes older than this leave the archive (it stays a few MB)
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

def hash_row(h: Hash) -> dict:
    return {"ioc_value": h.ioc_value, "first_seen_utc": h.first_seen.strftime("%Y-%m-%d %H:%M:%S"), "ioc_id": h.ioc_id, "fk_malware": h.malware, "malware_alias": h.alias,
            "malware_printable": h.printable, "threat_type": h.threat_type, "confidence_level": h.confidence, "tags": ",".join(h.tags), "reporter": h.reporter, "reference": h.reference}


def hash_from_row(r: dict) -> Hash | None:
    seen = to_dt(r.get("first_seen_utc", ""))
    if not seen or not r.get("ioc_value"):
        return None
    try:
        conf = int(r.get("confidence_level") or 0)
    except ValueError:
        conf = 0
    return Hash(r["ioc_value"], seen, r.get("ioc_id", ""), r.get("threat_type", ""), r.get("fk_malware", ""), r.get("malware_alias", ""), r.get("malware_printable", ""), conf,
                [t for t in r.get("tags", "").split(",") if t], r.get("reference", ""), r.get("reporter", ""))


def load_archive(path: Path) -> dict[str, Hash]:
    return {h.ioc_value: h for h in (hash_from_row(r) for r in read_csv(path)) if h}


def merge_archive(archive: dict[str, Hash], current: list[Hash], now: datetime) -> tuple[dict[str, Hash], int]:
    """Add what is new, keep the earliest sighting, drop what is older than ARCHIVE_DAYS. Returns (archive, number added)."""
    added = 0
    for h in current:
        if h.ioc_value not in archive:
            archive[h.ioc_value] = h
            added += 1
        elif h.first_seen < archive[h.ioc_value].first_seen:
            archive[h.ioc_value] = h
    cut = now - timedelta(days=ARCHIVE_DAYS)
    return {k: v for k, v in archive.items() if v.first_seen >= cut}, added


def archive_text(archive: dict[str, Hash]) -> str:
    rows = [hash_row(h) for h in sorted(archive.values(), key=lambda h: (h.first_seen, h.ioc_value), reverse=True)]
    return csv_text(ARCHIVE_FIELDS, rows)


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


def previous_url_ids(path: Path) -> set[str]:
    return {r.get("id") or r.get("url", "") for r in read_csv(path)}


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
