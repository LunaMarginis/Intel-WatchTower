# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-11-12 20:03 UTC · **Health:** ❌ **1 check(s) failed**, 2 warning(s): the affected data was kept from the previous good run.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 456 | 33,970 |
| New since the previous run | 0 | 472 |
| Added in the last 24 hours | 0 | 472 |
| Added in the last 7 days | 456 | 3,388 |
| Online right now | – | 16,550 (49%) |
| Period the export covers | 113.8 h | 30.5 days |
| Newest entry | 36.6 h ago | 0 min ago |

_URL data refreshed 2026-10-21 11:43 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **SalatStealer** | 68 | ▼ -29 | `▁▂▁▂▁█▁` | 11-07 16:41 | 95% | – |
| 2 | **Raven Stealer** | 51 | ▲ +22 | `▂▅█▃▁▃▁` | 11-06 14:33 | 95% | – |
| 3 | **ZStealer** | 51 | 🆕 new | `█▁▁▁▁▁▁` | 11-06 14:33 | 95% | ZStealer |
| 4 | **VShell** | 47 | ▲ +9 | `▆█▅▂▁▁▁` | 11-06 14:33 | 95% | – |
| 5 | **RN Stealer** | 32 | ▲ +21 | `▁█▄▄▁▃▁` | 11-07 16:41 | 95% | – |
| 6 | **Prometei** | 16 | ▲ +14 | `▁▁▁█▂▁▁` | 11-09 07:28 | 95% | – |
| 7 | **ValleyRAT** | 15 | ▼ -2 | `█▃▆▁▂▁▁` | 11-06 14:33 | 95% | Winos |
| 8 | **Creal Stealer** | 10 | ▼ -8 | `▅▁█▁▂▂▁` | 11-06 14:33 | 95% | – |
| 9 | **AsyncRAT** | 9 | ▬ 0 | `▅▁▅█▃▁▁` | 11-06 14:33 | 95% | – |
| 10 | **stealler** | 9 | ▼ -14 | `▁▁▅▁█▁▁` | 11-08 17:43 | 95% | – |
**New hashes per day, last 14 days:** `▂▇▇▆▇▇▆█▇▇▄▆▆▁` (today 0, busiest day 97).

**Threat types:** payload 456  
**Reporter confidence in the latest export:** 50–95% (average 95%)  

_Archive: 1,834 hashes collected so far (kept up to 400 days)._

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
| In the latest export | 2,225 | 908 |
| New since the previous run | 170 | 25 |
| First reported, last 24 h | 307 | 82 |
| First reported, last 7 days | 2,223 | 833 |
| …of them command-and-control | 585 | 826 |
| …delivery and other | 1,638 | 7 |


**Domains, top families (7 days):** ClearFake 592, IClickFix 424, Vidar 314, php.shin_webshell 197, Unknown Loader 197  
**Domains, top command-and-control families:** Vidar 314, ACR Stealer 82, XWorm 21, Unknown RAT 20, Unknown malware 18  

**IP addresses, top families (7 days):** Unknown malware 167, Sliver 92, ValleyRAT 72, Cobalt Strike 68, VShell 55  
**IP addresses, top command-and-control families:** Unknown malware 166, Sliver 92, ValleyRAT 72, Cobalt Strike 68, VShell 55  
**Most reported ports:** 443 (184), 31337 (78), 8080 (51), 80 (50), 3333 (47), 8888 (46), 8443 (29), 2404 (21)  

**Also serving malware in URLhaus:** 3 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 4803 KB in 2.0 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 456 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 456 rows (last time 524) |
| ⚠️ | `threatfox: freshness` | newest hash is 36.6 h old |
| ✅ | `threatfox: freshness` | export file is 0.4 h old |
| ⚠️ | `threatfox: new items` | 0 new far below the recent average of 38 |
| ❌ | `urlhaus: download` | https://urlhaus.abuse.ch/downloads/csv_recent/: HTTP 410 |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 2226 data lines parsed |
| ✅ | `threatfox domains: values valid` | every row passed validation |
| ✅ | `threatfox domains: volume` | 2225 rows (last time 2232) |
| ✅ | `threatfox domains: freshness` | newest entry is 0.4 h old |
| ✅ | `threatfox domains: freshness` | export file is 0.4 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 1277 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 908 rows (last time 953) |
| ✅ | `threatfox ips: freshness` | newest entry is 0.5 h old |
| ✅ | `threatfox ips: freshness` | export file is 0.4 h old |
| ✅ | `output safety` | 11 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
