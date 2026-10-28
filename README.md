# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-10-28 18:26 UTC · **Health:** ❌ **1 check(s) failed**, 2 warning(s): the affected data was kept from the previous good run.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 409 | 33,970 |
| New since the previous run | 0 | 472 |
| Added in the last 24 hours | 89 | 472 |
| Added in the last 7 days | 409 | 3,388 |
| Online right now | – | 16,550 (49%) |
| Period the export covers | 126.7 h | 30.5 days |
| Newest entry | 22.9 h ago | 0 min ago |

_URL data refreshed 2026-10-21 11:43 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **SalatStealer** | 119 | ▲ +100 | `▁▁▃▄▁█▁` | 10-23 13:39 | 95% | – |
| 2 | **Coinminer** | 42 | ▲ +1 | `█▁▁▁▁▂▁` | 10-22 12:50 | 95% | – |
| 3 | **Raven Stealer** | 36 | ▲ +5 | `▁▅█▄▁▆▁` | 10-23 13:39 | 95% | – |
| 4 | **Vidar** | 23 | ▲ +5 | `▁▆▅▅▁█▁` | 10-23 13:39 | 95% | – |
| 5 | **Formbook** | 14 | ▼ -2 | `▆▆▁▁▁█▁` | 10-22 12:50 | 95% | win.xloader |
| 6 | **NetWire RC** | 12 | ▲ +3 | `▁▂▁▁▁█▁` | 10-23 13:39 | 95% | NetWeird, NetWire, Recam |
| 7 | **ValleyRAT** | 12 | ▼ -5 | `▁▂▄▂▁█▁` | 10-23 13:39 | 95% | Winos |
| 8 | **stealler** | 11 | ▲ +3 | `▁██▆▁▁▁` | 10-23 13:39 | 95% | – |
| 9 | **Venus Stealer** | 11 | ▼ -6 | `▁█▅▁▁▃▁` | 10-23 13:39 | 95% | – |
| 10 | **WannaCryptor** | 9 | ▲ +1 | `▃▃▆█▁▆▁` | 10-22 12:50 | 95% | Wana Decrypt0r, WannaCry, WannaCrypt |
**New hashes per day, last 14 days:** `▃▃▃▂▃▃▃▃▃▄▄▁█▁` (today 0, busiest day 169).

**Threat types:** payload 409  
**Reporter confidence in the latest export:** 50–100% (average 95%)  
**Tags (7 d):** clickfix 1, ghostpulse 1, hijackloader 1, msi 1, sideload 1  

_Archive: 744 hashes collected so far (kept up to 400 days)._

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
| In the latest export | 3,570 | 2,543 |
| New since the previous run | 84 | 119 |
| First reported, last 24 h | 169 | 138 |
| First reported, last 7 days | 3,567 | 2,433 |
| …of them command-and-control | 410 | 2,411 |
| …delivery and other | 3,157 | 22 |


**Domains, top families (7 days):** IClickFix 1,002, ClearFake 952, StrelaStealer 620, Unknown Loader 470, php.shin_webshell 211  
**Domains, top command-and-control families:** IClickFix 154, Vidar 78, Unknown malware 40, Remcos 20, Unknown RAT 17  

**IP addresses, top families (7 days):** Unknown malware 1,249, VShell 258, Cobalt Strike 203, Sliver 135, Mirai 86  
**IP addresses, top command-and-control families:** Unknown malware 1,242, VShell 258, Cobalt Strike 203, Sliver 135, Mirai 80  
**Most reported ports:** 3333 (404), 443 (289), 3000 (266), 8877 (163), 80 (139), 8080 (107), 31337 (91), 8888 (89)  

**Also serving malware in URLhaus:** 22 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 4295 KB in 2.2 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 409 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 409 rows (last time 462) |
| ✅ | `threatfox: freshness` | newest hash is 22.9 h old |
| ✅ | `threatfox: freshness` | export file is 0.8 h old |
| ⚠️ | `threatfox: new items` | 0 new far below the recent average of 34 |
| ❌ | `urlhaus: download` | https://urlhaus.abuse.ch/downloads/csv_recent/: HTTP 410 |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 3578 data lines parsed |
| ⚠️ | `threatfox domains: values valid` | 1 rows rejected |
| ✅ | `threatfox domains: volume` | 3570 rows (last time 4338) |
| ✅ | `threatfox domains: freshness` | newest entry is 1.3 h old |
| ✅ | `threatfox domains: freshness` | export file is 0.8 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 3288 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 2543 rows (last time 2550) |
| ✅ | `threatfox ips: freshness` | newest entry is 0.8 h old |
| ✅ | `threatfox ips: freshness` | export file is 0.8 h old |
| ✅ | `output safety` | 11 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
