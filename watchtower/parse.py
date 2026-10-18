"""Reading the abuse.ch exports correctly.

What the first version got wrong, and this module fixes:
  * ThreatFox separates fields with `", "` (a comma AND a space). A quote that follows a space is not seen as a quote by pandas, so a value with a comma
    inside, such as the alias "NetWeird,NetWire,Recam", was split in the middle, the row had too many fields and `on_bad_lines="skip"` silently threw
    it away (13 of 71 hashes on the day this was checked). It also left stray quotes and a leading space on every value. `skipinitialspace=True` fixes both.
  * `comment="#"` cuts a line at the first `#`, which truncates URLs that contain one. Here only lines that START with `#` are comments.
  * Columns are read by NAME from the header line in the file, not by position, so a new column upstream cannot shift everything.
  * Nothing is dropped silently: every skipped line is counted with a reason and shows up in the report.
"""
from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

NONE_VALUES = {"", "none", "null", "n/a", "na", "-"}
MD5 = re.compile(r"^[a-f0-9]{32}$")
UPDATED = re.compile(r"Last updated:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
MAX_RECORD_LINES = 6  # a single record spanning more physical lines than this is a damaged quote, not data


@dataclass
class Export:
    header: list[str]
    rows: list[dict[str, str]]
    data_lines: int                      # physical lines that are not comments
    skipped: list[tuple[int, str]]       # (line number, reason)
    last_updated: datetime | None        # from the "Last updated" comment of the file itself


def clean(value: str) -> str:
    """Strip whitespace and turn abuse.ch's placeholder 'None' into an empty string."""
    v = (value or "").strip()
    return "" if v.lower() in NONE_VALUES else v


def parse_export(text: str) -> Export:
    lines = text.splitlines()
    comments = [ln for ln in lines if ln.startswith("#")]
    data = [ln for ln in lines if ln.strip() and not ln.startswith("#")]
    header: list[str] = []
    for ln in reversed(comments):  # the column names are the last comment line that looks like a header
        fields = next(csv.reader([ln.lstrip("# ").strip()], skipinitialspace=True), [])
        if len(fields) >= 5 and all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", f.strip()) for f in fields):
            header = [f.strip() for f in fields]
            break
    updated = None
    for ln in comments:
        m = UPDATED.search(ln)
        if m:
            updated = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            break
    rows: list[dict[str, str]] = []
    skipped: list[tuple[int, str]] = []
    if header:
        reader = csv.reader(io.StringIO("\n".join(data)), skipinitialspace=True)
        prev_line = 0
        for rec in reader:
            span = reader.line_num - prev_line
            prev_line = reader.line_num
            if span > MAX_RECORD_LINES:
                skipped.append((reader.line_num, f"record spans {span} lines (damaged quote)"))
            elif len(rec) != len(header):
                skipped.append((reader.line_num, f"{len(rec)} fields, expected {len(header)}"))
            else:
                rows.append({h: clean(v) for h, v in zip(header, rec)})
    return Export(header, rows, len(data), skipped, updated)


# ---------------------------------------------------------------- typed records

def to_dt(value: str) -> datetime | None:
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


@dataclass
class Hash:
    ioc_value: str
    first_seen: datetime
    ioc_id: str
    threat_type: str
    malware: str          # fk_malware, e.g. "win.valley_rat"
    alias: str            # may hold several names separated by commas
    printable: str        # human name, e.g. "ValleyRAT"
    confidence: int
    tags: list[str] = field(default_factory=list)
    reference: str = ""
    reporter: str = ""

    @property
    def family(self) -> str:
        """The name to show people: the printable name, else the malware key."""
        return self.printable or self.malware or "unknown"


THREATFOX_REQUIRED = ["first_seen_utc", "ioc_id", "ioc_value", "ioc_type", "threat_type", "fk_malware", "malware_alias", "malware_printable", "confidence_level", "reporter"]
URLHAUS_REQUIRED = ["id", "dateadded", "url", "url_status", "threat", "tags", "reporter"]


def threatfox_records(export: Export) -> tuple[list[Hash], list[str]]:
    """(valid hashes, reasons for the ones rejected). Duplicate hashes keep their earliest sighting."""
    out: dict[str, Hash] = {}
    rejected: list[str] = []
    for r in export.rows:
        value = r.get("ioc_value", "").lower()
        seen = to_dt(r.get("first_seen_utc", ""))
        if not MD5.match(value):
            rejected.append(f"not an MD5: {value[:40]!r}")
            continue
        if r.get("ioc_type") and r["ioc_type"] != "md5_hash":
            rejected.append(f"{value}: type {r['ioc_type']}")
            continue
        if seen is None:
            rejected.append(f"{value}: unreadable first_seen_utc")
            continue
        try:
            conf = int(r.get("confidence_level") or 0)
        except ValueError:
            conf = 0
        h = Hash(value, seen, r.get("ioc_id", ""), r.get("threat_type", ""), r.get("fk_malware", ""), r.get("malware_alias", ""), r.get("malware_printable", ""),
                 conf, [t.strip() for t in r.get("tags", "").split(",") if t.strip()], r.get("reference", ""), r.get("reporter", ""))
        if value not in out or h.first_seen < out[value].first_seen:
            out[value] = h
    return list(out.values()), rejected


@dataclass
class Url:
    id: str
    added: datetime
    url: str
    status: str           # online | offline | unknown
    threat: str
    tags: list[str]
    reporter: str
    host: str
    host_is_ip: bool
    ext: str

    @property
    def defanged(self) -> str:
        return defang_url(self.url)


IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def urlhaus_records(export: Export) -> tuple[list[Url], list[str]]:
    out: dict[str, Url] = {}
    rejected: list[str] = []
    for r in export.rows:
        url = r.get("url", "")
        added = to_dt(r.get("dateadded", ""))
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("http", "https", "ftp") or not parsed.hostname:
            rejected.append(f"not a URL: {url[:60]!r}")
            continue
        if added is None:
            rejected.append(f"{r.get('id', '?')}: unreadable dateadded")
            continue
        host = (parsed.hostname or "").lower()
        last = parsed.path.rsplit("/", 1)[-1]
        ext = last.rsplit(".", 1)[-1].lower()[:8] if "." in last else ""
        u = Url(r.get("id", ""), added, url, (r.get("url_status") or "unknown").lower(), r.get("threat", ""),
                [t.strip() for t in r.get("tags", "").split(",") if t.strip()], r.get("reporter", ""), host, bool(IPV4.match(host)), ext)
        out.setdefault(u.id or url, u)
    return list(out.values()), rejected


def defang_url(url: str) -> str:
    """Same style as the first version (so existing consumers keep working): every '.' becomes [.] and every ':' becomes [:]."""
    return url.replace(".", "[.]").replace(":", "[:]")


def defang_host(host: str) -> str:
    return host.replace(".", "[.]").replace(":", "[:]")


# ---------------------------------------------------------------- ThreatFox infrastructure (domains and ip:port)

DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$")
IPPORT = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}):(\d{1,5})$")


@dataclass
class Infra:
    """A domain, or an IP address with the ports ThreatFox reported on it (ip:port rows of one IP are merged)."""
    kind: str             # domain | ip
    value: str
    first_seen: datetime
    ioc_id: str
    threat_type: str      # botnet_cc | payload_delivery | ...
    malware: str
    alias: str
    printable: str
    confidence: int
    tags: list[str] = field(default_factory=list)
    reporter: str = ""
    ports: list[int] = field(default_factory=list)

    @property
    def family(self) -> str:
        return self.printable or self.malware or "unknown"

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.value}"


def refang(value: str) -> str:
    return value.replace("[.]", ".").replace("[:]", ":")


def infra_records(export: Export, kind: str) -> tuple[list[Infra], list[str]]:
    """(valid entries, reasons for the rejected ones). kind is 'domain' or 'ip'. Several ip:port rows of one IP become one entry with its ports."""
    want = "domain" if kind == "domain" else "ip:port"
    out: dict[str, Infra] = {}
    rejected: list[str] = []
    for r in export.rows:
        raw = r.get("ioc_value", "").strip().lower().rstrip(".")
        seen = to_dt(r.get("first_seen_utc", ""))
        if r.get("ioc_type") and r["ioc_type"] != want:
            rejected.append(f"{raw[:50]}: type {r['ioc_type']}")
            continue
        port = 0
        if kind == "domain":
            if not DOMAIN.match(raw):
                rejected.append(f"not a domain: {raw[:50]!r}")
                continue
            value = raw
        else:
            m = IPPORT.match(raw)
            if not m or any(int(g) > 255 for g in m.groups()[:4]) or not 0 < int(m.group(5)) < 65536:
                rejected.append(f"not an ip:port: {raw[:50]!r}")
                continue
            value, port = ".".join(m.groups()[:4]), int(m.group(5))
        if seen is None:
            rejected.append(f"{raw}: unreadable first_seen_utc")
            continue
        try:
            conf = int(r.get("confidence_level") or 0)
        except ValueError:
            conf = 0
        i = Infra(kind, value, seen, r.get("ioc_id", ""), r.get("threat_type", ""), r.get("fk_malware", ""), r.get("malware_alias", ""), r.get("malware_printable", ""),
                  conf, [t.strip() for t in r.get("tags", "").split(",") if t.strip()], r.get("reporter", ""), [port] if port else [])
        have = out.get(value)
        if have is None:
            out[value] = i
        else:
            have.ports = sorted(set(have.ports) | set(i.ports))
            if i.first_seen < have.first_seen:
                i.ports = have.ports
                out[value] = i
    return list(out.values()), rejected
