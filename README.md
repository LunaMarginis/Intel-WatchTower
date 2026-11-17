# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-11-17 08:04 UTC · **Health:** ❌ **1 check(s) failed**, 1 warning(s): the affected data was kept from the previous good run.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 503 | 33,970 |
| New since the previous run | 0 | 472 |
| Added in the last 24 hours | 70 | 472 |
| Added in the last 7 days | 503 | 3,388 |
| Online right now | – | 16,550 (49%) |
| Period the export covers | 145.5 h | 30.5 days |
| Newest entry | 15.6 h ago | 0 min ago |

_URL data refreshed 2026-10-21 11:43 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **SalatStealer** | 82 | ▲ +22 | `█▂▁▂▁▃▁` | 11-10 14:58 | 95% | – |
| 2 | **Raven Stealer** | 64 | ▲ +5 | `▃▂▂▇▁█▁` | 11-10 14:58 | 95% | – |
| 3 | **ZStealer** | 44 | ▼ -7 | `▁▁▃▃▁█▁` | 11-13 15:28 | 95% | ZStealer |
| 4 | **NjRAT** | 38 | ▲ +30 | `▁█▂▅▁▂▁` | 11-10 14:59 | 95% | Bladabindi, Lime-Worm |
| 5 | **RN Stealer** | 30 | ▼ -5 | `▃▁█▅▁▂▁` | 11-11 07:28 | 95% | – |
| 6 | **KAgent** | 19 | 🆕 new | `▁█▁▁▁▁▁` | 11-12 22:30 | 95% | – |
| 7 | **stealler** | 17 | ▲ +9 | `▁▁█▃▁▅▁` | 11-10 14:58 | 95% | – |
| 8 | **Formbook** | 13 | ▼ -10 | `▁█▇▁▁▇▁` | 11-12 22:31 | 95% | win.xloader |
| 9 | **Vidar** | 13 | ▬ 0 | `▁▁▅▃▁█▁` | 11-13 15:28 | 95% | – |
| 10 | **ValleyRAT** | 12 | ▼ -11 | `▁▁▂▄▁█▁` | 11-10 15:00 | 95% | Winos |
**New hashes per day, last 14 days:** `▅▄▆▅▅▃▄▅▅▄▅▁█▁` (today 0, busiest day 140).

**Threat types:** payload 503  
**Reporter confidence in the latest export:** 75–95% (average 95%)  
**Tags (7 d):** EvilAI 7, upStage 7  

_Archive: 2,196 hashes collected so far (kept up to 400 days)._

## 🔗 Malware URLs

**Added per day, last 14 days:** `█▃▃▂▅▃▃▂▂▂▃▂▃▂` (last 24 h: 472, last 7 d: 3,388).

#### Top tags (each tag counted on its own)

| Tag | URLs | Online |
|---|---|---|
| `zip` | 15,138 | 14,290 |
| `github` | 14,954 | 14,540 |
| `SmartLoader` | 14,455 | 14,048 |
| `LuaJIT-loader` | 13,762 | 13,374 |
| `mirai` | 5,780 | – |
| `Mozi` | 5,765 | – |
| `elf` | 4,922 | 691 |
| `ua-wget` | 2,600 | – |

_3,261 URLs (10%) carry no tag and are not counted above._

**Fastest growing this week:** `zapret` 322 (🆕 new), `SalatStealer` 224 (🆕 new), `rar` 152 (🆕 new), `cowrie` 188 (▲ +82), `31-56-209-86` 81 (▲ +75), `honeypot` 173 (▲ +62)

**Most common tag combinations:** `github + LuaJIT-loader + SmartLoader + zip` 13,746, `Mozi` 3,533, `mirai` 3,053, `32-bit + elf + mips + Mozi` 1,202, `32-bit + arm + elf + mirai + Mozi` 771

**Where it is hosted:** 46% of URLs sit on a bare IP address; 7,104 different hosts, 534 serving malware right now.  
**Abused platforms:** 50% of URLs sit on shared platforms: GitHub 15,761, GitLab 697, Discord 150, Dropbox 89, Google Drive 79, Cloudflare Workers 55  
**File types:** zip 15,397, (none) 8,871, sh 4,658, exe 1,459, jar 357, ps1 184, rar 183, mips 145  

_Platforms such as GitHub, Discord or Dropbox are counted apart: attackers abuse them, so a URL there says nothing about where the attacker is, and they must not be blocked because of this list._

## 🛰️ Command-and-control infrastructure

Domains and IP addresses reported to ThreatFox, with the malware family behind them (counts only).

|  | 🌐 Domains | 🖥️ IP addresses |
|---|---|---|
| In the latest export | 4,303 | 1,077 |
| New since the previous run | 254 | 74 |
| First reported, last 24 h | 604 | 358 |
| First reported, last 7 days | 4,302 | 995 |
| …of them command-and-control | 667 | 983 |
| …delivery and other | 3,635 | 12 |


**Domains, top families (7 days):** Unknown Loader 1,661, ClearFake 802, IClickFix 798, Vidar 298, Unknown malware 214  
**Domains, top command-and-control families:** Vidar 298, Unknown malware 104, WARDENStealer 75, ACR Stealer 42, Unknown Stealer 20  

**IP addresses, top families (7 days):** Unknown malware 472, Cobalt Strike 52, Sliver 52, PureRAT 45, VShell 41  
**IP addresses, top command-and-control families:** Unknown malware 469, Cobalt Strike 52, Sliver 52, PureRAT 45, VShell 41  
**Most reported ports:** 443 (209), 80 (138), 3333 (72), 8080 (58), 8787 (57), 8443 (48), 31337 (44), 8888 (37)  

**Also serving malware in URLhaus:** 1 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 4962 KB in 1.7 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 503 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 503 rows (last time 503) |
| ✅ | `threatfox: freshness` | newest hash is 15.6 h old |
| ✅ | `threatfox: freshness` | export file is 0.5 h old |
| ⚠️ | `threatfox: new items` | 0 new far below the recent average of 36 |
| ❌ | `urlhaus: download` | https://urlhaus.abuse.ch/downloads/csv_recent/: HTTP 410 |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 4305 data lines parsed |
| ✅ | `threatfox domains: values valid` | every row passed validation |
| ✅ | `threatfox domains: volume` | 4303 rows (last time 4147) |
| ✅ | `threatfox domains: freshness` | newest entry is 0.8 h old |
| ✅ | `threatfox domains: freshness` | export file is 0.5 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 1370 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 1077 rows (last time 1060) |
| ✅ | `threatfox ips: freshness` | newest entry is 0.5 h old |
| ✅ | `threatfox ips: freshness` | export file is 0.5 h old |
| ✅ | `output safety` | 11 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
