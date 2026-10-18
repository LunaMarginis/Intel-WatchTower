"""The reports: README dashboard, daily report file, Slack message and the GitHub Actions run summary.

Text that comes from outside (family names, tags, reporters, hosts) always goes through `safe_text`: a hostile tag such as `![x](https://tracker)` or `<img onerror=…>`
cannot turn into a link, an image or HTML on the project page or in Slack."""
from __future__ import annotations

from .analyze import arrow
from .checks import ICON, PASS, WARN, FAIL
from .export import SIGNATURE, safe_text
from .parse import defang_host

REPO = "https://github.com/LunaMarginis/Intel-WatchTower"
HEAD_ICON = {PASS: "✅", WARN: "⚠️", FAIL: "❌"}


def n(v) -> str:
    return f"{int(v):,}"


def when(iso: str) -> str:
    return iso[:16].replace("T", " ") + " UTC" if iso else "n/a"


def age(hours) -> str:
    if hours is None:
        return "n/a"
    return f"{hours:.0f} min ago" if hours < 1 and hours * 60 >= 1 else "just now" if hours < 1 else f"{hours:.1f} h ago" if hours < 48 else f"{hours / 24:.1f} days ago"


def cell(v, limit: int = 60) -> str:
    return safe_text(v, limit).replace("|", "/")


def table(head: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "_Nothing to show yet._\n"
    return "\n".join(["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"] + ["| " + " | ".join(r) + " |" for r in rows]) + "\n"


def health_line(state: dict) -> str:
    cs = state["checks"]
    bad = [c for c in cs if c["status"] == FAIL]
    warn = [c for c in cs if c["status"] == WARN]
    if bad:
        return f"❌ **{len(bad)} check(s) failed**" + (f", {len(warn)} warning(s)" if warn else "") + ": the affected data was kept from the previous good run."
    if warn:
        return f"⚠️ {len(cs) - len(warn)} checks passed, **{len(warn)} warning(s)**: see Data health."
    return f"✅ all {len(cs)} checks passed"


# ---------------------------------------------------------------- sections

def glance(h: dict, u: dict | None, u_at: str) -> str:
    rows = [
        ["In the latest export", n(h["in_export"]), n(u["total"]) if u else "–"],
        ["New since the previous run", n(h["new_this_run"]), (n(u["new_since_last"]) if u and u["new_since_last"] is not None else "–")],
        ["Added in the last 24 hours", n(h["last24h"]), n(u["added_24h"]) if u else "–"],
        ["Added in the last 7 days", n(h["last7"]), n(u["added_7d"]) if u else "–"],
        ["Online right now", "–", f"{n(u['online'])} ({u['online_share']}%)" if u else "–"],
        ["Period the export covers", f"{h['window_hours']} h", f"{u['window_days']} days" if u else "–"],
        ["Newest entry", age(h["newest_age_hours"]), age(u["newest_age_hours"]) if u else "–"],
    ]
    return table(["", "🧬 ThreatFox · MD5 hashes", "🔗 URLhaus · malware URLs"], rows) + (f"\n_URL data refreshed {when(u_at)}._\n" if u else "")


def families(h: dict, limit: int, with_samples: bool) -> str:
    fams = h["families"][:limit]
    if not fams:
        return "_No hashes in the last 7 days._\n"
    rows = [[str(i + 1), f"**{cell(f['family'])}**", n(f["count"]), arrow(f["count"], f["previous"]), f"`{_spark(f['daily'])}`",
             f["first_seen"].strftime("%m-%d %H:%M") if hasattr(f["first_seen"], "strftime") else str(f["first_seen"])[5:16], f"{f['confidence']}%",
             ", ".join(cell(a, 24) for a in f["aliases"][:3]) or "–"] for i, f in enumerate(fams)]
    out = table(["#", "Family", "Hashes (7 d)", "vs previous 7 d", "Per day", "First seen (UTC)", "Confidence", "Also known as"], rows)
    if with_samples:
        out += "\n"
        for f in fams:
            out += f"<details><summary>{cell(f['family'])}: {n(f['count'])} hashes (latest {len(f['sample'])} shown)</summary>\n\n```\n" + "\n".join(f["sample"]) + "\n```\n</details>\n\n"
    return out


def _spark(values: list[int]) -> str:
    from .analyze import sparkline
    return sparkline(values)


def hash_extras(h: dict) -> str:
    out = f"**New hashes per day, last 14 days:** `{h['spark']}` (today {h['daily'][-1][1]}, busiest day {max(c for _, c in h['daily'])}).\n\n"
    out += "**Threat types:** " + (", ".join(f"{cell(k)} {n(v)}" for k, v in h["threat_types"]) or "n/a") + "  \n"
    c = h["confidence"]
    out += f"**Reporter confidence in the latest export:** {c['min']}–{c['max']}% (average {c['avg']}%)  \n" if c else ""
    out += "**Top reporters (7 d):** " + (", ".join(f"{cell(k)} {n(v)}" for k, v in h["reporters"]) or "n/a") + "  \n"
    if h["tags"]:
        out += "**Tags (7 d):** " + ", ".join(f"{cell(k)} {n(v)}" for k, v in h["tags"]) + "  \n"
    return out + f"\n_Archive: {n(h['archive_total'])} hashes collected so far (kept up to 400 days)._\n"


def url_section(u: dict, long: bool) -> str:
    rows = []
    for tag, count in u["tags"][: 10 if long else 8]:
        on = dict(u["tags_online"]).get(tag)
        rows.append([f"`{cell(tag, 32)}`", n(count), n(on) if on is not None else "–"])
    out = f"**Added per day, last 14 days:** `{u['spark']}` (last 24 h: {n(u['added_24h'])}, last 7 d: {n(u['added_7d'])}).\n\n"
    out += "#### Top tags (each tag counted on its own)\n\n" + table(["Tag", "URLs", "Online"], rows)
    out += f"\n_{n(u['untagged'])} URLs ({round(100 * u['untagged'] / max(1, u['total']))}%) carry no tag and are not counted above._\n"
    if u["risers"]:
        out += "\n**Fastest growing this week:** " + ", ".join(f"`{cell(t, 30)}` {n(a)} ({arrow(a, b)})" for t, a, b in u["risers"]) + "\n"
    combos = ", ".join(f"`{cell(t.replace(',', ' + '), 60)}` {n(c)}" for t, c in u["tag_combos"][:5])
    out += f"\n**Most common tag combinations:** {combos or 'n/a'}\n"
    out += f"\n**Where it is hosted:** {u['bare_ip_share']}% of URLs sit on a bare IP address; {n(u['unique_hosts'])} different hosts, {n(u['unique_online_hosts'])} serving malware right now.  \n"
    out += "**Busiest hosts:** " + ", ".join(f"`{defang_host(cell(h, 50))}` {n(c)}" for h, c in u["hosts"][:6]) + "  \n"
    out += "**Online right now, busiest hosts:** " + (", ".join(f"`{defang_host(cell(h, 50))}` {n(c)}" for h, c in u["hosts_online"][:6]) or "n/a") + "  \n"
    out += "**File types:** " + ", ".join(f"{cell(e, 10)} {n(c)}" for e, c in u["extensions"][:8]) + "  \n"
    out += "**Top reporters:** " + ", ".join(f"{cell(k)} {n(v)}" for k, v in u["reporters"][:5]) + "\n"
    out += "\n_Hosting platforms such as GitHub, GitLab or Dropbox appear because attackers abuse them: do not block those platforms because of this list._\n"
    return out


def checks_table(checks: list[dict]) -> str:
    return table(["", "Check", "Result"], [[ICON[c["status"]], f"`{c['name']}`", cell(c["detail"], 160)] for c in checks])


def files_table(files: list[dict]) -> str:
    return table(["File", "What it holds", "Rows", "Size"], [[f"[`{f['path']}`]({REPO}/blob/main/{f['path']})", f["what"], n(f["rows"]) if f["rows"] is not None else "–", f"{n(round(f['size'] / 1024))} KB" if f["size"] else "–"] for f in files])


METHOD = f"""
- **Runs** every 6 hours on GitHub Actions. GitHub may start a scheduled run a few hours late; the times above are when it really ran.
- **Hashes** come from the ThreatFox "recent MD5" export, which covers only a short window (see "Period the export covers"). Every run adds the new hashes to
  the daily files in `indicators/hashes/`, so nothing that appeared between two runs is lost and the 7-day figures are real 7-day figures.
- **URLs** come from the URLhaus "recent" export (about 30 days). It is large, so it is refreshed once a day.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped, no live URLs in anything published). If a check fails, the affected
  data is **not** replaced, the report says so, and the workflow turns red.
- **Safety:** URLs and hosts are defanged (`[.]`, `[:]`); text from outside is reduced to plain characters before it is written here.
- **Not verified:** these are community reports to abuse.ch. Treat every entry as a lead, not a verdict. False positives happen, especially for shared hosting.
"""

TERMS = ("Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/faq/#tos) and [URLhaus](https://urlhaus.abuse.ch/api/). Please read their terms of use before reusing it. "
         "This project only collects and summarises it.")


def head(state: dict) -> str:
    return (f"# 🛰️ Intel WatchTower\n\nDaily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.\n\n"
            f"![collect]({REPO}/actions/workflows/collect.yml/badge.svg)\n\n**Last run:** {when(state['at'])} · **Health:** {health_line(state)}\n")


def readme(state: dict, files: list[dict]) -> str:
    h, u = state["hashes"], state.get("urls")
    s = head(state) + "\n## At a glance\n\n" + glance(h, u, state.get("urls_at", ""))
    s += "\n## 🧬 Malware hashes\n\n### Top malware families · last 7 days\n\nUnique MD5 hashes first reported in the last 7 days, against the 7 days before.\n\n" + families(h, 10, True)
    s += hash_extras(h)
    if u:
        s += "\n## 🔗 Malware URLs\n\n" + url_section(u, False)
    s += "\n## Data health\n\n" + checks_table(state["checks"])
    s += "\n## Files\n\n" + files_table(files)
    s += "\n## How this works\n" + METHOD + "\n" + TERMS + f"\n\n_{SIGNATURE}._\n"
    return s


def report(state: dict, files: list[dict]) -> str:
    """The daily report file (reports/YYYY-MM-DD.md): the dashboard with longer tables."""
    h, u = state["hashes"], state.get("urls")
    s = f"# Intel WatchTower report · {state['at'][:10]}\n\n**Run:** {when(state['at'])} · **Health:** {health_line(state)}\n\n## At a glance\n\n" + glance(h, u, state.get("urls_at", ""))
    s += "\n## Malware families · last 7 days (top 25)\n\n" + families(h, 25, False) + "\n" + hash_extras(h)
    if u:
        s += "\n## Malware URLs\n\n" + url_section(u, True)
    s += "\n## Data health\n\n" + checks_table(state["checks"])
    return s + f"\n{TERMS}\n\n_{SIGNATURE}._\n"


# ---------------------------------------------------------------- Slack and the Actions summary

def slack(state: dict, report_path: str) -> dict:
    h, u = state["hashes"], state.get("urls")
    bad = [c for c in state["checks"] if c["status"] != PASS]
    fields = [{"type": "mrkdwn", "text": f"*Hashes in the export*\n{n(h['in_export'])} ({n(h['new_this_run'])} new)"},
              {"type": "mrkdwn", "text": f"*Hashes, last 7 days*\n{n(h['last7'])}"}]
    if u:
        fields += [{"type": "mrkdwn", "text": f"*Malware URLs*\n{n(u['total'])} ({u['online_share']}% online)"}, {"type": "mrkdwn", "text": f"*URLs added, 24 h*\n{n(u['added_24h'])}"}]
    fam = "\n".join(f"• {cell(f['family'], 40)}: {n(f['count'])} ({arrow(f['count'], f['previous'])})" for f in h["families"][:5]) or "_none_"
    blocks = [{"type": "header", "text": {"type": "plain_text", "text": f"{HEAD_ICON[state['status']]} Intel WatchTower · {state['at'][:10]}"}},
              {"type": "section", "fields": fields},
              {"type": "section", "text": {"type": "mrkdwn", "text": f"*Top malware families, 7 days*\n{fam}"}}]
    if u and u["tags"]:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*Top URL tags*\n" + "\n".join(f"• {cell(t, 30)}: {n(c)}" for t, c in u["tags"][:3])}})
    health = f"{len(state['checks']) - len(bad)} of {len(state['checks'])} checks passed" + "".join(f"\n{ICON[c['status']]} {cell(c['name'], 50)}: {cell(c['detail'], 100)}" for c in bad[:6])
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": health}]})
    blocks.append({"type": "actions", "elements": [{"type": "button", "text": {"type": "plain_text", "text": "Open the report"}, "url": f"{REPO}/blob/main/{report_path}"}]})
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": SIGNATURE}]})
    return {"text": f"Intel WatchTower {state['at'][:10]}: {n(h['in_export'])} hashes, {n(h['last7'])} in 7 days. {len(bad)} warning(s)/failure(s).", "blocks": blocks}


def step_summary(state: dict) -> str:
    h, u = state["hashes"], state.get("urls")
    s = f"## Intel WatchTower · {when(state['at'])}\n\n{health_line(state)}\n\n"
    s += f"- Hashes in export: **{n(h['in_export'])}** ({n(h['new_this_run'])} new), last 7 days **{n(h['last7'])}**, archive **{n(h['archive_total'])}**\n"
    if u:
        s += f"- URLs: **{n(u['total'])}** ({u['online_share']}% online), added in 24 h **{n(u['added_24h'])}**\n"
    return s + "\n" + checks_table(state["checks"])
