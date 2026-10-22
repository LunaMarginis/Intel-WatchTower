"""The reports: README dashboard, daily report file, Slack message and the GitHub Actions run summary.

Text that comes from outside (family names, tags, reporters, hosts) always goes through `safe_text`: a hostile tag such as `![x](https://tracker)` or `<img onerror=…>`
cannot turn into a link, an image or HTML on the project page or in Slack."""
from __future__ import annotations

from .analyze import arrow
from .checks import ICON, PASS, WARN, FAIL
from .export import SIGNATURE, safe_text
from .parse import defang_host

REPO = "https://github.com/LunaMarginis/Intel-WatchTower"
DATA_REPO = REPO + "-data"   # private: the indicators, feeds and full reports live there
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

def infra_section(i: dict, long: bool, public: bool = False) -> str:
    """ThreatFox command-and-control and delivery infrastructure (domains and IP addresses), and what also serves malware in URLhaus."""
    d, p = i.get("domains"), i.get("ips")
    if not d and not p:
        return ""
    cols = lambda k: [x.get(k, 0) if x else None for x in (d, p)]
    show = lambda vals: [n(v) if v is not None else "–" for v in vals]
    rows = [["In the latest export"] + show(cols("in_export")), ["New since the previous run"] + show(cols("new_this_run")), ["First reported, last 24 h"] + show(cols("last24h")),
            ["First reported, last 7 days"] + show(cols("last7")), ["…of them command-and-control"] + show(cols("c2_7d")), ["…delivery and other"] + show(cols("other_7d"))]
    out = table(["", "🌐 Domains", "🖥️ IP addresses"], rows) + "\n"
    for title, part in (("Domains", d), ("IP addresses", p)):
        if not part:
            continue
        out += f"\n**{title}, top families (7 days):** " + (", ".join(f"{cell(f, 30)} {n(c)}" for f, c in part["families"][: 8 if long else 5]) or "none") + "  \n"
        if part["families_c2"]:
            out += f"**{title}, top command-and-control families:** " + ", ".join(f"{cell(f, 30)} {n(c)}" for f, c in part["families_c2"][:5]) + "  \n"
    if p and p["ports"]:
        out += "**Most reported ports:** " + ", ".join(f"{pt} ({n(c)})" for pt, c in p["ports"][:8]) + "  \n"
    recent = [(("domain", x) if part is d else ("ip", x)) for part in (d, p) if part for x in part["recent"][: 6 if long else 4]]
    if recent and not public:
        out += "\n#### Newest entries\n\n" + table(["Kind", "Entry (defanged)", "Family", "Type", "First reported"],
                                                    [[k, f"`{defang_host(cell(x['value'], 60))}`" + (f" ports {','.join(str(q) for q in x['ports'])}" if x.get("ports") else ""), cell(x["family"], 30), cell(x["type"], 20), when(x["seen"])] for k, x in recent])
    ov = i.get("overlap") or []
    if public:
        return out + f"\n**Also serving malware in URLhaus:** {n(i.get('overlap_total', len(ov)))} entries (the list itself is not published).\n"
    out += f"\n#### Also serving malware in URLhaus ({n(i.get('overlap_total', len(ov)))})\n\n"
    if ov:
        out += "Infrastructure that ThreatFox reports **and** that URLhaus sees hosting malware URLs: the strongest leads.\n\n" + table(
            ["Entry (defanged)", "ThreatFox family", "Type", "URLhaus URLs", "Online"], [[f"`{defang_host(cell(x['value'], 60))}`", cell(x["family"], 30), cell(x["type"], 20), n(x["urls"]), n(x["online"])] for x in ov[: 10 if long else 6]])
    else:
        out += "None right now.\n"
    return out + "\n_Community reports, not verified. Servers move and addresses are reused: check hosting and age before blocking._\n"


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


def hash_extras(h: dict, public: bool = False) -> str:
    out = f"**New hashes per day, last 14 days:** `{h['spark']}` (today {h['daily'][-1][1]}, busiest day {max(c for _, c in h['daily'])}).\n\n"
    out += "**Threat types:** " + (", ".join(f"{cell(k)} {n(v)}" for k, v in h["threat_types"]) or "n/a") + "  \n"
    c = h["confidence"]
    out += f"**Reporter confidence in the latest export:** {c['min']}–{c['max']}% (average {c['avg']}%)  \n" if c else ""
    if not public:
        out += "**Top reporters (7 d):** " + (", ".join(f"{cell(k)} {n(v)}" for k, v in h["reporters"]) or "n/a") + "  \n"
    if h["tags"]:
        out += "**Tags (7 d):** " + ", ".join(f"{cell(k)} {n(v)}" for k, v in h["tags"]) + "  \n"
    return out + f"\n_Archive: {n(h['archive_total'])} hashes collected so far (kept up to 400 days)._\n"


def url_section(u: dict, long: bool, public: bool = False) -> str:
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
    out += f"**Abused platforms:** {u.get('platform_share', 0)}% of URLs sit on shared platforms: " + (", ".join(f"{cell(p, 30)} {n(c)}" for p, c in u.get("platforms", [])[:6]) or "none") + "  \n"
    if not public:
        top = lambda pairs: ", ".join(f"`{defang_host(cell(h, 50))}` {n(c)}" for h, c in pairs[:6]) or "n/a"
        out += f"**Busiest domains** (platforms left out; {n(u.get('unique_domains', 0))} different): " + top(u.get("domains", [])) + "  \n"
        out += f"**Busiest IP addresses** ({n(u.get('unique_ips', 0))} different): " + top(u.get("ips", [])) + "  \n"
        out += "**Online right now, busiest domains:** " + top(u.get("domains_online", [])) + "  \n"
        out += "**Online right now, busiest IP addresses:** " + top(u.get("ips_online", [])) + "  \n"
    out += "**File types:** " + ", ".join(f"{cell(e, 10)} {n(c)}" for e, c in u["extensions"][:8]) + "  \n"
    if not public:
        out += "**Top reporters:** " + ", ".join(f"{cell(k)} {n(v)}" for k, v in u["reporters"][:5]) + "\n"
    out += "\n_Platforms such as GitHub, Discord or Dropbox are counted apart: attackers abuse them, so a URL there says nothing about where the attacker is, and they must not be blocked because of this list._\n"
    return out


def checks_table(checks: list[dict]) -> str:
    return table(["", "Check", "Result"], [[ICON[c["status"]], f"`{c['name']}`", cell(c["detail"], 160)] for c in checks])


def files_table(files: list[dict], base: str = DATA_REPO) -> str:
    return table(["File", "What it holds", "Rows", "Size"], [[f"[`{f['path']}`]({base}/blob/main/{f['path']})", f["what"], n(f["rows"]) if f["rows"] is not None else "–", f"{n(round(f['size'] / 1024))} KB" if f["size"] else "–"] for f in files])


METHOD = f"""
- **Runs** every 12 hours on GitHub Actions. GitHub may start a scheduled run a few hours late; the times above are when it really ran.
- **Hashes** come from the authenticated ThreatFox export (one download per run, filtered to the last 7 days). Every run adds the new hashes to
  the daily files in `indicators/hashes/`, so nothing that appeared between two runs is lost and the 7-day figures are real 7-day figures.
- **URLs** come from the URLhaus "recent" export (about 30 days). It is large, so it is refreshed once a day.
- **Infrastructure** (command-and-control and delivery domains, and IP addresses with their ports) comes from the same ThreatFox export on every run. Entries that URLhaus also sees serving malware are listed apart: they are the strongest leads.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped, no live URLs in anything published). If a check fails, the affected
  data is **not** replaced, the report says so, and the workflow turns red.
- **Safety:** URLs and hosts are defanged (`[.]`, `[:]`); text from outside is reduced to plain characters before it is written here.
- **Not verified:** these are community reports to abuse.ch. Treat every entry as a lead, not a verdict. False positives happen, especially for shared hosting.
"""

TERMS = ("Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). "
         "This project only collects and summarises it.")

PUBLIC_METHOD = """
- **Runs** every 12 hours on GitHub Actions, authenticated with a free abuse.ch Auth-Key and within its query limits (one ThreatFox download per run, one URLhaus download a day).
- **What is published here:** counts, trends and rankings only. The indicators themselves (hashes, hosts, URLs, feeds) are kept in a private repository: abuse.ch's terms
  do not grant a right to republish them. Get them from the source: [ThreatFox](https://threatfox.abuse.ch/export/) and [URLhaus](https://urlhaus.abuse.ch/api/).
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.
"""

PUBLIC_FOOTER = ("**Purpose:** a non-commercial, not-for-profit research and learning project. It is provided as is, without warranty, and may contain false positives: "
                 "validate before acting on anything. Commercial use of the underlying data needs your own abuse.ch subscription, and the data must not be used to train AI models "
                 "(abuse.ch terms, section 7.3).")


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
    if state.get("infra"):
        s += "\n## 🛰️ Command-and-control infrastructure\n\nDomains and IP addresses reported to ThreatFox, with the malware family behind them.\n\n" + infra_section(state["infra"], False)
    s += "\n## Data health\n\n" + checks_table(state["checks"])
    s += "\n## Files\n\n" + files_table(files)
    s += "\n## How this works\n" + METHOD + "\n" + TERMS + f"\n\n_{SIGNATURE}._\n"
    return s


def public_readme(state: dict) -> str:
    """The README of the public repository: aggregates only. No hash, host, URL, feed link, file list or reporter name can appear in it."""
    h, u = state["hashes"], state.get("urls")
    s = head(state) + "\n## At a glance\n\n" + glance(h, u, state.get("urls_at", ""))
    s += "\n## 🧬 Malware hashes\n\n### Top malware families · last 7 days\n\nUnique MD5 hashes first reported in the last 7 days, against the 7 days before.\n\n" + families(h, 10, False)
    s += hash_extras(h, True)
    if u:
        s += "\n## 🔗 Malware URLs\n\n" + url_section(u, False, True)
    if state.get("infra"):
        s += "\n## 🛰️ Command-and-control infrastructure\n\nDomains and IP addresses reported to ThreatFox, with the malware family behind them (counts only).\n\n" + infra_section(state["infra"], False, True)
    s += "\n## Data health\n\n" + checks_table(state["checks"])
    s += "\n## How this works\n" + PUBLIC_METHOD + "\n" + TERMS + "\n\n" + PUBLIC_FOOTER + f"\n\n_{SIGNATURE}._\n"
    return s


def report(state: dict, files: list[dict]) -> str:
    """The daily report file (reports/YYYY-MM-DD.md): the dashboard with longer tables."""
    h, u = state["hashes"], state.get("urls")
    s = f"# Intel WatchTower report · {state['at'][:10]}\n\n**Run:** {when(state['at'])} · **Health:** {health_line(state)}\n\n## At a glance\n\n" + glance(h, u, state.get("urls_at", ""))
    s += "\n## Malware families · last 7 days (top 25)\n\n" + families(h, 25, False) + "\n" + hash_extras(h)
    if u:
        s += "\n## Malware URLs\n\n" + url_section(u, True)
    if state.get("infra"):
        s += "\n## Command-and-control infrastructure\n\n" + infra_section(state["infra"], True)
    s += "\n## Data health\n\n" + checks_table(state["checks"])
    return s + f"\n{TERMS}\n\n_{SIGNATURE}._\n"


# ---------------------------------------------------------------- Slack and the Actions summary

def slack(state: dict, report_path: str, report_base: str = DATA_REPO) -> dict:
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
    inf = state.get("infra") or {}
    if inf.get("domains") or inf.get("ips"):
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*C2 infrastructure, 7 days*\n• {n((inf.get('domains') or {}).get('last7', 0))} domains, {n((inf.get('ips') or {}).get('last7', 0))} IP addresses\n• {n(inf.get('overlap_total', 0))} also serve malware in URLhaus"}})
    if u and u["tags"]:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*Top URL tags*\n" + "\n".join(f"• {cell(t, 30)}: {n(c)}" for t, c in u["tags"][:3])}})
    health = f"{len(state['checks']) - len(bad)} of {len(state['checks'])} checks passed" + "".join(f"\n{ICON[c['status']]} {cell(c['name'], 50)}: {cell(c['detail'], 100)}" for c in bad[:6])
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": health}]})
    blocks.append({"type": "actions", "elements": [{"type": "button", "text": {"type": "plain_text", "text": "Open the report"}, "url": f"{report_base}/blob/main/{report_path}"}]})
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": SIGNATURE}]})
    return {"text": f"Intel WatchTower {state['at'][:10]}: {n(h['in_export'])} hashes, {n(h['last7'])} in 7 days. {len(bad)} warning(s)/failure(s).", "blocks": blocks}


def step_summary(state: dict) -> str:
    h, u = state["hashes"], state.get("urls")
    s = f"## Intel WatchTower · {when(state['at'])}\n\n{health_line(state)}\n\n"
    s += f"- Hashes in export: **{n(h['in_export'])}** ({n(h['new_this_run'])} new), last 7 days **{n(h['last7'])}**, archive **{n(h['archive_total'])}**\n"
    if u:
        s += f"- URLs: **{n(u['total'])}** ({u['online_share']}% online), added in 24 h **{n(u['added_24h'])}**\n"
    i = state.get("infra") or {}
    if i.get("domains") or i.get("ips"):
        s += f"- Command-and-control infrastructure, last 7 days: **{n((i.get('domains') or {}).get('last7', 0))}** domains, **{n((i.get('ips') or {}).get('last7', 0))}** IP addresses, **{n(i.get('overlap_total', 0))}** also serving malware in URLhaus\n"
    return s + "\n" + checks_table(state["checks"])
