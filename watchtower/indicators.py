"""The enriched indicator dataset: JSON Lines, one folder per kind, one file per UTC day of collection.

    indicators/hashes/2026-10-18.jsonl   MD5 hashes first seen by this collector that day
    indicators/urls/2026-10-18.jsonl     malware URLs that appeared, or changed status, that day

Why per day and not per run: git already keeps every run as a snapshot, so per-run files would only duplicate it. A day file is partitioned by the day WE collected
the record, so once the day has passed it never changes again (stable for downstream consumers, and git stores nothing new for old days). The records carry both
times: when the source first saw the indicator and when we collected it. One record per line loads straight into pandas, DuckDB, Elastic or Splunk.

The dataset is the accumulating store: the hash archive is simply all hash files read together."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .parse import Hash, Url, defang_host, defang_url

SCHEMA = 1
HASH_DIR = "indicators/hashes"
URL_DIR = "indicators/urls"
HASH_KEEP_DAYS = 400
URL_KEEP_DAYS = 120       # URL records are many and small; urls.csv always holds the full latest export
URL_BACKLOG_HOURS = 48    # on a first run, only URLs this recent become records (the older backlog lives in urls.csv)
TS = "%Y-%m-%dT%H:%M:%SZ"


def stamp(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(TS)


def unstamp(text: str) -> datetime | None:
    try:
        return datetime.strptime(text, TS).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


# ---------------------------------------------------------------- files

def day_path(root: Path, folder: str, now: datetime) -> Path:
    return root / folder / f"{now.astimezone(timezone.utc).date().isoformat()}.jsonl"


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def jsonl_text(records: list[dict]) -> str:
    return "".join(json.dumps(r, separators=(",", ":"), sort_keys=True, ensure_ascii=False) + "\n" for r in records)


def prune(root: Path, folder: str, now: datetime, keep_days: int) -> int:
    base = root / folder
    if not base.exists():
        return 0
    cut = (now - timedelta(days=keep_days)).date().isoformat()
    old = [f for f in base.glob("*.jsonl") if f.stem < cut]
    for f in old:
        f.unlink()
    return len(old)


# ---------------------------------------------------------------- hashes

def hash_record(h: Hash, collected: datetime) -> dict:
    return {
        "schema": SCHEMA, "kind": "hash", "algo": "md5", "value": h.ioc_value, "source": "threatfox",
        "first_seen": stamp(h.first_seen), "collected_at": stamp(collected), "age_at_collection_h": round(max(0.0, (collected - h.first_seen).total_seconds() / 3600), 1),
        "ioc_id": h.ioc_id, "family": h.family, "malware_key": h.malware, "aliases": [a.strip() for a in h.alias.split(",") if a.strip()],
        "threat_type": h.threat_type, "confidence": h.confidence, "tags": list(h.tags), "reporter": h.reporter, "reference": defang_url(h.reference) if h.reference else "",
    }


def hash_from_record(r: dict) -> Hash | None:
    seen = unstamp(r.get("first_seen", ""))
    if not seen or not r.get("value"):
        return None
    return Hash(r["value"], seen, r.get("ioc_id", ""), r.get("threat_type", ""), r.get("malware_key", ""), ",".join(r.get("aliases", [])),
                "" if r.get("family") == r.get("malware_key") else r.get("family", ""), int(r.get("confidence") or 0), list(r.get("tags", [])), r.get("reference", ""), r.get("reporter", ""))


def load_hashes(root: Path, now: datetime) -> dict[str, Hash]:
    """Every collected hash still inside the retention window, keyed by value."""
    cut = now - timedelta(days=HASH_KEEP_DAYS)
    out: dict[str, Hash] = {}
    base = root / HASH_DIR
    for f in sorted(base.glob("*.jsonl")) if base.exists() else []:
        for r in read_jsonl(f):
            h = hash_from_record(r)
            if h and h.first_seen >= cut and h.ioc_value not in out:
                out[h.ioc_value] = h
    return out


def add_hashes(root: Path, known: dict[str, Hash], current: list[Hash], now: datetime) -> tuple[dict[Path, str], list[Hash]]:
    """New hashes become records in today's file. Returns ({file: text}, the hashes that were new)."""
    new = sorted((h for h in {h.ioc_value: h for h in current}.values() if h.ioc_value not in known), key=lambda h: (h.first_seen, h.ioc_value))
    if not new:
        return {}, []
    path = day_path(root, HASH_DIR, now)
    records = read_jsonl(path) + [hash_record(h, now) for h in new]
    records.sort(key=lambda r: (r["first_seen"], r["value"]))
    return {path: jsonl_text(records)}, new


# ---------------------------------------------------------------- urls

def family_names(hashes: list[Hash]) -> dict[str, str]:
    """normalised name -> family, so a URLhaus tag such as 'Stealc' can be linked to the ThreatFox family 'Stealc'."""
    names: dict[str, str] = {}
    for h in hashes:
        for n in (h.printable, h.malware.split(".")[-1] if h.malware else ""):
            if len(norm(n)) >= 4:
                names.setdefault(norm(n), h.family)
    return names


def url_record(u: Url, change: str, previous: str, collected: datetime, families: dict[str, str]) -> dict:
    related = sorted({families[norm(t)] for t in u.tags if norm(t) in families})
    return {
        "schema": SCHEMA, "kind": "url", "source": "urlhaus", "id": u.id, "url": defang_url(u.url), "host": defang_host(u.host), "host_type": "ip" if u.host_is_ip else "domain",
        "ext": u.ext, "status": u.status, "previous_status": previous, "change": change, "threat": u.threat, "tags": list(u.tags), "added": stamp(u.added),
        "collected_at": stamp(collected), "reporter": u.reporter,
        "related_families": related,  # INFERRED from matching names, not stated by the source
    }


def add_urls(root: Path, previous: dict[str, str], urls: list[Url], families: dict[str, str], now: datetime) -> tuple[dict[Path, str], int, int]:
    """Records for URLs that are new (and recent) or whose status changed since the previous export. Returns ({file: text}, new, changed)."""
    fresh_after = now - timedelta(hours=URL_BACKLOG_HOURS)
    out: list[dict] = []
    new = changed = 0
    for u in sorted(urls, key=lambda u: (u.added, u.id)):
        if u.id not in previous:
            if u.added >= fresh_after:
                out.append(url_record(u, "new", "", now, families))
                new += 1
        elif previous[u.id] != u.status:
            out.append(url_record(u, "status_changed", previous[u.id], now, families))
            changed += 1
    if not out:
        return {}, 0, 0
    path = day_path(root, URL_DIR, now)
    have = read_jsonl(path)
    seen = {(r["id"], r["change"], r["status"]) for r in have}
    out = [r for r in out if (r["id"], r["change"], r["status"]) not in seen]
    if not out:
        return {}, 0, 0
    return {path: jsonl_text(sorted(have + out, key=lambda r: (r["added"], r["id"], r["change"])))}, new, changed
