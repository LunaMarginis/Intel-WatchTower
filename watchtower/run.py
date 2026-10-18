"""One run: download, parse, check, archive, analyse, write, report, notify.

The rule that matters: a failed check never overwrites good data. If a download or its format is broken, the previous files stay, the report says exactly what
went wrong, Slack is told, and the workflow turns red (GitHub then emails the owner)."""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__, analyze, checks as C, export, fetch, indicators, parse, render, store

THREATFOX_URL = "https://threatfox.abuse.ch/export/csv/md5/recent/"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
URL_REFRESH_HOURS = 20          # the big URL export is refreshed about once a day
BLOCKING = ("download", "columns", "lines read", "volume")   # a failure of these keeps the previous data


def _blocked(label: str, cs: list[C.Check]) -> bool:
    return any(c.status == C.FAIL and c.name.startswith(label + ":") and any(b in c.name for b in BLOCKING) for c in cs)


def run(root: Path, *, offline: Path | None = None, now: datetime | None = None, force_urls: bool = False, slack_url: str = "", summary_path: str = "", log=print) -> int:
    now = now or store.utcnow()
    root.mkdir(parents=True, exist_ok=True)
    prev_path = root / "feeds" / "iocs.json"
    prev = json.loads(prev_path.read_text(encoding="utf-8")) if prev_path.exists() else {}
    history = store.read_history(root / "history" / "runs.jsonl")
    cs: list[C.Check] = []
    writes: dict[Path, str] = {}

    # ------------------------------------------------------------ ThreatFox (hashes): every run
    tf_text, tf_fetch = None, None
    if offline:
        tf_text = (offline / "tf.csv").read_text(encoding="utf-8")
        tf_fetch = fetch.Fetched("offline", tf_text, 200, len(tf_text.encode()), 0.0, 1)
        cs.append(C.download("threatfox", tf_fetch))
    else:
        try:
            tf_fetch = fetch.get(THREATFOX_URL)
            tf_text = tf_fetch.text
            cs.append(C.download("threatfox", tf_fetch))
        except fetch.FetchError as e:
            cs.append(C.download("threatfox", None, str(e)))
    archive = indicators.load_hashes(root, now)
    known = set(archive)
    hashes: list[parse.Hash] = []
    occurrences: dict[str, int] = {}
    if tf_text is not None:
        ex = parse.parse_export(tf_text)
        hashes, rej = parse.threatfox_records(ex)
        occurrences = Counter(r.get("ioc_value", "").lower() for r in ex.rows)
        prev_count = (prev.get("hashes") or {}).get("in_export")
        cs += [C.columns("threatfox", ex, parse.THREATFOX_REQUIRED), C.lines_read("threatfox", ex), C.rejected("threatfox", rej), C.volume("threatfox", len(hashes), 5, prev_count),
               C.freshness("threatfox", max((h.first_seen for h in hashes), default=None), now, 24, 72, "newest hash"),
               C.freshness("threatfox", ex.last_updated, now, 12, 48, "export file")]
    tf_ok = tf_text is not None and not _blocked("threatfox", cs)
    if tf_ok:
        new_files, _ = indicators.add_hashes(root, archive, hashes, now)
        writes.update(new_files)
        for h in hashes:
            archive.setdefault(h.ioc_value, h)
        writes[root / "mhash.csv"] = store.mhash_text(hashes, occurrences)
        recent = [r["hashes"]["new_this_run"] for r in history[-12:] if r.get("hashes")]
    h_summary = analyze.hash_summary(hashes if tf_ok else [], list(archive.values()), known if tf_ok else set(archive), now)
    if tf_ok:
        cs.append(C.new_volume("threatfox", h_summary["new_this_run"], recent))
        al = list(archive.values())
        writes[root / "feeds" / "md5_7d.txt"] = export.md5_feed(al, now, 7)
        writes[root / "feeds" / "md5_30d.txt"] = export.md5_feed(al, now, 30)
        writes[root / "feeds" / "stix_md5_7d.json"] = export.stix_text(export.stix_bundle(al, now, 7))

    # ------------------------------------------------------------ URLhaus (URLs): about once a day
    u_summary, u_at = prev.get("urls"), prev.get("urls_at", "")
    last_refresh = datetime.fromisoformat(u_at) if u_at else None
    # A summary saved by an older version lacks fields the reports now use: refresh at once instead of rendering from it.
    outdated = bool(u_summary) and not set(analyze.url_summary([], set(), now)) <= set(u_summary)
    due = force_urls or not u_summary or outdated or last_refresh is None or (now - last_refresh) >= timedelta(hours=URL_REFRESH_HOURS)
    if due:
        uh_text = None
        if offline:
            uh_text = (offline / "uh.csv").read_text(encoding="utf-8")
            uh_fetch = fetch.Fetched("offline", uh_text, 200, len(uh_text.encode()), 0.0, 1)
            cs.append(C.download("urlhaus", uh_fetch))
        else:
            try:
                uh_fetch = fetch.get(URLHAUS_URL, timeout=120)
                uh_text = uh_fetch.text
                cs.append(C.download("urlhaus", uh_fetch))
            except fetch.FetchError as e:
                cs.append(C.download("urlhaus", None, str(e)))
        if uh_text is not None:
            ux = parse.parse_export(uh_text)
            urls, urej = parse.urlhaus_records(ux)
            cs += [C.columns("urlhaus", ux, parse.URLHAUS_REQUIRED), C.lines_read("urlhaus", ux), C.rejected("urlhaus", urej),
                   C.volume("urlhaus", len(urls), 1000, (u_summary or {}).get("total")),
                   C.freshness("urlhaus", ux.last_updated, now, 12, 48, "export file"),
                   C.freshness("urlhaus", max((u.added for u in urls), default=None), now, 24, 72, "newest URL")]
            if not _blocked("urlhaus", cs):
                prev_status = store.previous_url_status(root / "urls.csv")
                u_summary, u_at = analyze.url_summary(urls, set(prev_status), now), now.isoformat()
                url_files, n_new, n_changed = indicators.add_urls(root, prev_status, urls, indicators.family_names(list(archive.values())), now)
                writes.update(url_files)
                cs.append(C.Check("urlhaus: indicators", C.PASS, f"{n_new} new URLs and {n_changed} status changes recorded"))
                writes[root / "urls.csv"] = store.urls_text(urls)
                writes[root / "feeds" / "hosts_online.txt"] = export.hosts_feed(urls)
    else:
        cs.append(C.Check("urlhaus: refresh", C.PASS, f"not due: refreshed {render.when(u_at)} (once a day)"))

    # ------------------------------------------------------------ safety of everything about to be published, then the reports
    state = {"at": now.isoformat(timespec="seconds"), "version": __version__, "hashes": h_summary, "urls": u_summary, "urls_at": u_at, "checks": []}
    def stamp() -> None:
        state["checks"] = [{"name": c.name, "status": c.status, "detail": c.detail} for c in cs]
        state["status"] = C.overall(cs)
    stamp()
    files = _files(root, writes)
    for _ in range(2):  # second pass: the report shows the safety checks too
        report_path = f"reports/{now.date().isoformat()}.md"
        rendered = {root / "README.md": render.readme(state, files), root / report_path: render.report(state, files)}
        safety = [C.defanged(p.name, t) for p, t in {**writes, **rendered}.items() if p.suffix in (".md", ".txt", ".csv", ".jsonl")]
        cs[:] = [c for c in cs if not c.name.startswith("output safety")]
        bad = [c for c in safety if c.status == C.FAIL]
        if bad:
            cs.append(C.Check("output safety", C.FAIL, f"{bad[0].detail}: nothing new was published"))
            stamp()
            writes.clear()   # unsafe content: keep everything as it was
            rendered = {}
            break
        cs[:] = [c for c in cs if not c.name.startswith("output safety")] + [C.Check("output safety", C.PASS, f"{len(safety)} published files contain no live URL")]
        stamp()
    writes.update(rendered)
    writes[prev_path] = export.iocs_json(state)
    rec = {"at": state["at"], "status": state["status"], "hashes": {k: h_summary[k] for k in ("in_export", "new_this_run", "last7", "last24h", "archive_total")},
           "urls": ({k: u_summary[k] for k in ("total", "online", "added_24h")} if u_summary and u_at == now.isoformat() else None),
           "checks": {s: sum(1 for c in cs if c.status == s) for s in (C.PASS, C.WARN, C.FAIL)}}
    writes[root / "history" / "runs.jsonl"] = store.history_text(history + [rec])

    # ------------------------------------------------------------ write, prune, notify
    changed = [str(p.relative_to(root)) for p, t in writes.items() if store.write_text(p, t)]
    _prune_reports(root / "reports", now)
    indicators.prune(root, indicators.HASH_DIR, now, indicators.HASH_KEEP_DAYS)
    indicators.prune(root, indicators.URL_DIR, now, indicators.URL_KEEP_DAYS)
    log(f"status: {state['status']} · hashes in export {len(hashes)} (new {h_summary['new_this_run']}) · urls {(u_summary or {}).get('total', 'n/a')} · changed files: {len(changed)}")
    for c in cs:
        log(f"  {C.ICON[c.status]} {c.name}: {c.detail}")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write(render.step_summary(state) + "\n")
    if slack_url:
        _notify(slack_url, render.slack(state, report_path), log)
    return 1 if state["status"] == C.FAIL else 0


def _files(root: Path, writes: dict[Path, str]) -> list[dict]:
    spec = [("README.md", "This page", None), ("mhash.csv", "Latest ThreatFox MD5 export, clean (first_seen, confidence, reporter…)", None), ("urls.csv", "Latest URLhaus export, defanged", None),
            ("indicators/hashes/", "Enriched hash records, one file per day, one JSON object per line (kept 400 days)", None),
            ("indicators/urls/", "Enriched URL records: new URLs and status changes, one file per day (kept 120 days)", None), ("feeds/md5_7d.txt", "Plain list: hashes of the last 7 days", None),
            ("feeds/md5_30d.txt", "Plain list: hashes of the last 30 days", None), ("feeds/hosts_online.txt", "Hosts serving malware now, defanged", None),
            ("feeds/stix_md5_7d.json", "STIX 2.1 bundle of the last 7 days of hashes", None), ("feeds/iocs.json", "The numbers behind this page, as JSON", None),
            ("history/runs.jsonl", "One line per run: counts and check results", None), ("reports/", "A report per day", None)]
    out = []
    for rel, what, _ in spec:
        p = root / rel
        if rel.endswith("/"):
            pattern = "*.md" if rel == "reports/" else "*.jsonl"
            found = {f for f in p.glob(pattern)} if p.exists() else set()
            found |= {w for w in writes if w.parent == p and w.match(pattern)}   # written by this run, not on disk yet
            texts = [writes[f] if f in writes else f.read_text(encoding="utf-8") for f in found]
            rows = sum(t.count("\n") for t in texts) if pattern == "*.jsonl" else len(texts)
            out.append({"path": rel, "what": what, "rows": rows, "size": sum(len(t.encode("utf-8")) for t in texts)})
            continue
        text = writes.get(p)
        size = len(text.encode("utf-8")) if text is not None else (p.stat().st_size if p.exists() else 0)
        rows = None
        if text is not None and rel.endswith((".csv", ".txt")):
            rows = max(0, len([ln for ln in text.splitlines() if ln and not ln.startswith("#")]) - (1 if rel.endswith(".csv") else 0))
        elif text is None and p.exists() and rel.endswith((".csv", ".txt")):
            rows = max(0, len([ln for ln in p.read_text(encoding="utf-8").splitlines() if ln and not ln.startswith("#")]) - (1 if rel.endswith(".csv") else 0))
        out.append({"path": rel, "what": what, "rows": rows, "size": size})
    return out


def _prune_reports(folder: Path, now: datetime, keep_days: int = 120) -> None:
    if not folder.exists():
        return
    cut = (now - timedelta(days=keep_days)).date().isoformat()
    for f in folder.glob("*.md"):
        if f.stem < cut:
            f.unlink()


def _notify(url: str, payload: dict, log) -> None:
    if not url.startswith("https://hooks.slack.com/"):
        log("  (Slack skipped: SLACK_WEBHOOK_URL is not a hooks.slack.com address)")
        return
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json", "User-Agent": fetch.USER_AGENT})
        with urllib.request.urlopen(req, timeout=20) as r:
            log(f"  Slack: HTTP {r.status}")
    except Exception as e:  # a Slack problem must never fail the collection
        log(f"  Slack failed ({type(e).__name__}): {e}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="watchtower", description=__doc__.splitlines()[0])
    p.add_argument("--root", default=".", help="repository folder (default: current folder)")
    p.add_argument("--offline", help="folder with tf.csv and uh.csv to use instead of downloading (tests, local trials)")
    p.add_argument("--force-urls", action="store_true", help="refresh the URL export even if it is not due")
    p.add_argument("--now", help="pretend it is this UTC time (ISO), for tests")
    p.add_argument("--no-slack", action="store_true")
    a = p.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):  # Windows consoles default to cp1252; the log uses icons
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    now = datetime.fromisoformat(a.now).astimezone(timezone.utc) if a.now else None
    return run(Path(a.root).resolve(), offline=Path(a.offline) if a.offline else None, now=now, force_urls=a.force_urls,
               slack_url="" if a.no_slack else os.environ.get("SLACK_WEBHOOK_URL", ""), summary_path=os.environ.get("GITHUB_STEP_SUMMARY", ""))


if __name__ == "__main__":
    sys.exit(main())
