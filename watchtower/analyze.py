"""Numbers for the reports: families, trends, deltas, tag and host statistics. Pure functions of the records, so they are easy to test."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from statistics import mean

from .parse import Hash, Infra, Url
from .platforms import platform_of

BLOCKS = "▁▂▃▄▅▆▇█"


def sparkline(values: list[int]) -> str:
    """A one-line chart. All zero gives flat low bars; one value gives one bar."""
    if not values:
        return ""
    top = max(values)
    if top <= 0:
        return BLOCKS[0] * len(values)
    return "".join(BLOCKS[min(len(BLOCKS) - 1, round(v / top * (len(BLOCKS) - 1)))] for v in values)


def arrow(now: int, before: int) -> str:
    """▲ +12 / ▼ -3 / ▬ 0, and 'new' when it was absent before."""
    if before == 0 and now > 0:
        return "🆕 new"
    d = now - before
    return f"▲ +{d}" if d > 0 else f"▼ {d}" if d < 0 else "▬ 0"


def per_day(times: list[datetime], now: datetime, days: int = 14) -> list[tuple[str, int]]:
    """Counts per UTC day for the last `days` days (oldest first, today last)."""
    start = (now - timedelta(days=days - 1)).date()
    counts = Counter(t.date() for t in times)
    return [((start + timedelta(days=i)).isoformat(), counts.get(start + timedelta(days=i), 0)) for i in range(days)]


def hours_between(a: datetime, b: datetime) -> float:
    return abs((a - b).total_seconds()) / 3600.0


# ---------------------------------------------------------------- hashes

def family_stats(archive: list[Hash], now: datetime, days: int = 7) -> list[dict]:
    """Per malware family: unique hashes first seen in the last `days` days, against the `days` before that."""
    cut, prev_cut = now - timedelta(days=days), now - timedelta(days=2 * days)
    cur: dict[str, list[Hash]] = defaultdict(list)
    prev: Counter = Counter()
    for h in archive:
        key = h.malware or h.family
        if h.first_seen >= cut:
            cur[key].append(h)
        elif h.first_seen >= prev_cut:
            prev[key] += 1
    out = []
    for key, hs in cur.items():
        hs.sort(key=lambda h: (h.first_seen, h.ioc_value), reverse=True)
        names = sorted({n.strip() for h in hs for n in h.alias.split(",") if n.strip()})[:6]
        out.append({
            "key": key, "family": hs[0].family, "aliases": names, "count": len(hs), "previous": prev.get(key, 0),
            "first_seen": min(h.first_seen for h in hs), "last_seen": max(h.first_seen for h in hs),
            "confidence": round(mean(h.confidence for h in hs)), "reporters": sorted({h.reporter for h in hs if h.reporter})[:3],
            "sample": [h.ioc_value for h in hs[:10]],
            "daily": [c for _, c in per_day([h.first_seen for h in hs], now, 7)],
        })
    out.sort(key=lambda f: (-f["count"], f["family"].lower()))
    return out


def hash_summary(current: list[Hash], archive: list[Hash], previously_known: set[str], now: datetime) -> dict:
    new = [h for h in current if h.ioc_value not in previously_known]
    newest = max((h.first_seen for h in current), default=None)
    oldest = min((h.first_seen for h in current), default=None)
    last7 = [h for h in archive if h.first_seen >= now - timedelta(days=7)]
    conf = [h.confidence for h in current]
    daily = per_day([h.first_seen for h in archive], now, 14)
    return {
        "in_export": len(current), "new_this_run": len(new), "archive_total": len(archive), "last7": len(last7),
        "last24h": sum(1 for h in archive if h.first_seen >= now - timedelta(hours=24)),
        "families_in_export": len({h.malware or h.family for h in current}),
        "window_hours": round(hours_between(newest, oldest), 1) if newest and oldest else 0.0,
        "newest": newest.isoformat() if newest else "", "newest_age_hours": round(hours_between(now, newest), 1) if newest else None,
        "confidence": {"min": min(conf), "avg": round(mean(conf)), "max": max(conf)} if conf else {},
        "threat_types": Counter(h.threat_type or "unknown" for h in last7).most_common(6),
        "reporters": Counter(h.reporter or "unknown" for h in last7).most_common(5),
        "tags": Counter(t for h in last7 for t in h.tags).most_common(8),
        "families": family_stats(archive, now),
        "daily": daily, "spark": sparkline([c for _, c in daily]),
    }


# ---------------------------------------------------------------- urls

def url_summary(urls: list[Url], previous_ids: set[str], now: datetime) -> dict:
    total = len(urls)
    online = [u for u in urls if u.status == "online"]
    new = [u for u in urls if (u.id or u.url) not in previous_ids] if previous_ids else []
    tag_all = Counter(t for u in urls for t in u.tags)
    tag_online = Counter(t for u in online for t in u.tags)
    combos = Counter(",".join(u.tags) for u in urls if u.tags)
    cut, prev_cut = now - timedelta(days=7), now - timedelta(days=14)
    tag_7, tag_prev = Counter(), Counter()
    for u in urls:
        for t in u.tags:
            if u.added >= cut:
                tag_7[t] += 1
            elif u.added >= prev_cut:
                tag_prev[t] += 1
    risers = sorted(((t, n, tag_prev.get(t, 0)) for t, n in tag_7.items() if n >= 20), key=lambda x: (-(x[1] - x[2]), x[0]))[:6]
    # Dedicated infrastructure (own domains, bare IPs) is listed host by host; shared platforms attackers abuse (GitHub, Discord, Dropbox ...) are counted apart.
    own = [u for u in urls if not platform_of(u.host)]
    hosts = Counter(u.host for u in own)
    hosts_online = Counter(u.host for u in own if u.status == "online")
    domains = Counter(u.host for u in own if not u.host_is_ip)
    domains_online = Counter(u.host for u in own if not u.host_is_ip and u.status == "online")
    ips = Counter(u.host for u in own if u.host_is_ip)
    ips_online = Counter(u.host for u in own if u.host_is_ip and u.status == "online")
    plat = Counter(platform_of(u.host) for u in urls if platform_of(u.host))
    plat_online = Counter(platform_of(u.host) for u in online if platform_of(u.host))
    exts = Counter(u.ext or "(none)" for u in urls)
    daily = per_day([u.added for u in urls], now, 14)
    newest = max((u.added for u in urls), default=None)
    return {
        "total": total, "online": len(online), "offline": total - len(online),
        "online_share": round(100 * len(online) / total) if total else 0,
        "added_24h": sum(1 for u in urls if u.added >= now - timedelta(hours=24)),
        "added_7d": sum(1 for u in urls if u.added >= cut), "new_since_last": len(new) if previous_ids else None,
        "untagged": sum(1 for u in urls if not u.tags),
        "tags": tag_all.most_common(10), "tags_online": tag_online.most_common(10), "tag_combos": combos.most_common(8), "risers": risers,
        "hosts": hosts.most_common(8), "hosts_online": hosts_online.most_common(8),
        "domains": domains.most_common(8), "domains_online": domains_online.most_common(8), "ips": ips.most_common(8), "ips_online": ips_online.most_common(8),
        "unique_domains": len(domains), "unique_ips": len(ips), "unique_hosts": len(hosts), "unique_online_hosts": len(hosts_online),
        "platforms": plat.most_common(8), "platforms_online": plat_online.most_common(8), "platform_urls": sum(plat.values()), "platform_share": round(100 * sum(plat.values()) / total) if total else 0,
        "bare_ip_share": round(100 * sum(1 for u in urls if u.host_is_ip) / total) if total else 0,
        "bare_ip_online": sum(1 for u in online if u.host_is_ip),
        "extensions": exts.most_common(8), "reporters": Counter(u.reporter or "unknown" for u in urls).most_common(5),
        "threats": Counter(u.threat or "unknown" for u in urls).most_common(4),
        "newest": newest.isoformat() if newest else "", "newest_age_hours": round(hours_between(now, newest), 1) if newest else None,
        "window_days": round((newest - min(u.added for u in urls)).total_seconds() / 86400, 1) if urls else 0.0,
        "daily": daily, "spark": sparkline([c for _, c in daily]),
    }


def infra_part(current: list[Infra], archive: list[Infra], known: set[str], now: datetime) -> dict:
    """One kind (domains or IP addresses) of ThreatFox infrastructure. `current` is the latest export, `archive` everything collected (for the 7-day figures)."""
    week = [i for i in archive if i.first_seen >= now - timedelta(days=7)]
    c2 = [i for i in week if i.threat_type == "botnet_cc"]
    newest = max((i.first_seen for i in archive), default=None)
    daily = per_day([i.first_seen for i in archive], now, 14)
    return {
        "in_export": len(current), "new_this_run": sum(1 for i in current if i.key not in known),
        "last24h": sum(1 for i in archive if i.first_seen >= now - timedelta(hours=24)), "last7": len(week), "c2_7d": len(c2), "other_7d": len(week) - len(c2),
        "families": Counter(i.family for i in week).most_common(8), "families_c2": Counter(i.family for i in c2).most_common(8),
        "types": Counter(i.threat_type or "unknown" for i in week).most_common(4), "reporters": Counter(i.reporter or "unknown" for i in week).most_common(4),
        "ports": Counter(p for i in week for p in i.ports).most_common(8),
        "recent": [{"value": i.value, "family": i.family, "type": i.threat_type, "seen": i.first_seen.isoformat(), "ports": i.ports[:4], "confidence": i.confidence}
                   for i in sorted(archive, key=lambda i: (i.first_seen, i.value), reverse=True)[:8]],
        "newest": newest.isoformat() if newest else "", "newest_age_hours": round(hours_between(now, newest), 1) if newest else None,
        "daily": daily, "spark": sparkline([c for _, c in daily]),
    }


def infra_overlap(items: list[Infra], url_hosts: dict[str, list[int]]) -> list[dict]:
    """Infrastructure that ThreatFox reports AND that URLhaus sees serving malware: the strongest leads. Most online URLs first."""
    out = []
    for i in items:
        c = url_hosts.get(i.value)
        if c:
            out.append({"value": i.value, "kind": i.kind, "family": i.family, "type": i.threat_type, "urls": c[0], "online": c[1], "seen": i.first_seen.isoformat()})
    return sorted(out, key=lambda x: (-x["online"], -x["urls"], x["value"]))



def url_host_counts(urls: list[Url]) -> dict[str, list[int]]:
    """host -> [URLs, URLs online], the same shape store.url_hosts reads back from urls.csv."""
    out: dict[str, list[int]] = {}
    for u in urls:
        c = out.setdefault(u.host.lower(), [0, 0])
        c[0] += 1
        c[1] += u.status == "online"
    return out
