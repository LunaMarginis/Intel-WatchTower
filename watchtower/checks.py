"""Data-quality and health checks. Every run produces a list of checks; the report shows all of them, Slack summarises them, and a `fail` stops the
bad data from replacing good data (and turns the workflow red, so GitHub emails the owner)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from .fetch import Fetched
from .parse import Export

PASS, WARN, FAIL = "pass", "warn", "fail"
ICON = {PASS: "✅", WARN: "⚠️", FAIL: "❌"}


@dataclass
class Check:
    name: str
    status: str
    detail: str


def overall(checks: list[Check]) -> str:
    return FAIL if any(c.status == FAIL for c in checks) else WARN if any(c.status == WARN for c in checks) else PASS


def download(label: str, f: Fetched | None, error: str = "") -> Check:
    if f is None:
        return Check(f"{label}: download", FAIL, error or "no response")
    note = f"{f.size / 1024:.0f} KB in {f.seconds:.1f} s" + (f", after {f.attempts} attempts" if f.attempts > 1 else "")
    return Check(f"{label}: download", PASS if f.status == 200 and f.size > 0 else FAIL, note)


def columns(label: str, export: Export, required: list[str]) -> Check:
    if not export.header:
        return Check(f"{label}: columns", FAIL, "no column header found in the file (upstream format changed?)")
    missing = [c for c in required if c not in export.header]
    extra = [c for c in export.header if c not in required]
    if missing:
        return Check(f"{label}: columns", FAIL, "missing: " + ", ".join(missing))
    return Check(f"{label}: columns", PASS, f"all {len(required)} needed columns present" + (f" ({len(extra)} others ignored)" if extra else ""))


def lines_read(label: str, export: Export) -> Check:
    n = len(export.skipped)
    if n == 0:
        return Check(f"{label}: lines read", PASS, f"all {export.data_lines:,} data lines parsed")
    share = n / max(1, export.data_lines)
    return Check(f"{label}: lines read", FAIL if share > 0.01 else WARN, f"{n} of {export.data_lines:,} lines skipped ({share:.1%}); e.g. line {export.skipped[0][0]}: {export.skipped[0][1]}")


def rejected(label: str, items: list[str]) -> Check:
    if not items:
        return Check(f"{label}: values valid", PASS, "every row passed validation")
    return Check(f"{label}: values valid", WARN, f"{len(items)} rows rejected, e.g. {items[0]}")


def volume(label: str, count: int, minimum: int, previous: int | None) -> Check:
    if count < minimum:
        return Check(f"{label}: volume", FAIL, f"{count:,} rows, expected at least {minimum:,}")
    if previous and count < 0.3 * previous:
        return Check(f"{label}: volume", WARN, f"{count:,} rows, down from {previous:,} last time")
    return Check(f"{label}: volume", PASS, f"{count:,} rows" + (f" (last time {previous:,})" if previous else ""))


def freshness(label: str, newest: datetime | None, now: datetime, warn_hours: float, fail_hours: float, what: str = "newest record") -> Check:
    if newest is None:
        # the export's own "Last updated" stamp is a bonus signal: losing it is worth a warning, losing the newest record is not survivable
        return Check(f"{label}: freshness", WARN if what == "export file" else FAIL, f"no {what} found")
    age = (now - newest).total_seconds() / 3600
    status = PASS if age <= warn_hours else WARN if age <= fail_hours else FAIL
    return Check(f"{label}: freshness", status, f"{what} is {age:.1f} h old")


def new_volume(label: str, new_count: int, recent: list[int]) -> Check:
    """Is the number of new items in line with the recent runs? Needs at least 4 earlier runs to judge."""
    if len(recent) < 4:
        return Check(f"{label}: new items", PASS, f"{new_count} new (collecting a baseline: {len(recent)} earlier runs)")
    avg = sum(recent) / len(recent)
    if avg >= 10 and new_count < 0.25 * avg:
        return Check(f"{label}: new items", WARN, f"{new_count} new, far below the recent average of {avg:.0f}")
    if avg >= 10 and new_count > 4 * avg:
        return Check(f"{label}: new items", WARN, f"{new_count} new, far above the recent average of {avg:.0f}")
    return Check(f"{label}: new items", PASS, f"{new_count} new (recent average {avg:.0f})")


LIVE_URL = re.compile(r"https?://", re.IGNORECASE)
ALLOWED_LINKS = ("https://github.com/LunaMarginis/", "https://threatfox.abuse.ch", "https://urlhaus.abuse.ch", "https://abuse.ch", "https://docs.github.com",
                 "https://img.shields.io", "https://stix2.readthedocs.io", "https://oasis-open.github.io", "https://creativecommons.org")


def defanged(name: str, text: str) -> Check:
    """Nothing published may contain a clickable malicious URL: every http(s):// must be one of our own documentation links."""
    bad = [m.start() for m in LIVE_URL.finditer(text) if not text[m.start():].startswith(ALLOWED_LINKS)]
    if bad:
        return Check(f"output safety: {name}", FAIL, f"{len(bad)} live URL(s), first at offset {bad[0]}")
    return Check(f"output safety: {name}", PASS, "no live URLs")
