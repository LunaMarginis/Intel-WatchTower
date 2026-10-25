# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-10-25 16:32 UTC · **Health:** ❌ **1 check(s) failed**, 2 warning(s): the affected data was kept from the previous good run.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 337 | 33,970 |
| New since the previous run | 0 | 472 |
| Added in the last 24 hours | 76 | 472 |
| Added in the last 7 days | 337 | 3,388 |
| Online right now | – | 16,550 (49%) |
| Period the export covers | 129.2 h | 30.5 days |
| Newest entry | 23.1 h ago | 0 min ago |

_URL data refreshed 2026-10-21 11:43 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **Coinminer** | 73 | ▲ +69 | `▂▂▇█▁▁▁` | 10-19 08:12 | 95% | – |
| 2 | **SalatStealer** | 34 | ▲ +26 | `▂▃▂▁▁█▁` | 10-19 08:12 | 95% | – |
| 3 | **Raven Stealer** | 29 | ▲ +6 | `▁▄▃▁▅█▁` | 10-20 07:54 | 95% | – |
| 4 | **Formbook** | 20 | ▲ +16 | `██▁▆▆▁▁` | 10-19 08:12 | 95% | win.xloader |
| 5 | **Vidar** | 17 | ▲ +5 | `▁▅▅▁█▇▁` | 10-20 07:54 | 95% | – |
| 6 | **Venus Stealer** | 16 | ▲ +6 | `▅▆▁▁█▅▁` | 10-19 08:13 | 95% | – |
| 7 | **stealler** | 10 | ▲ +4 | `▁▁▅▁██▁` | 10-21 13:40 | 95% | – |
| 8 | **RN Stealer** | 9 | ▲ +6 | `█▁▂▁▁▂▁` | 10-19 08:12 | 95% | – |
| 9 | **Prometei** | 8 | ▲ +6 | `▃█▁▁▁▁▁` | 10-19 08:12 | 95% | – |
| 10 | **ValleyRAT** | 8 | ▼ -5 | `▆▃▃▁▃█▁` | 10-19 08:13 | 95% | Winos |
**New hashes per day, last 14 days:** `▁▁▁▆▅▆▃▆▆▆▅▆█▁` (today 0, busiest day 78).

**Threat types:** payload 337  
**Reporter confidence in the latest export:** 50–100% (average 95%)  
**Tags (7 d):** acr 1, ACRStealer 1, fake game 1, ROM 1, setup.exe 1, setup.py 1, clickfix 1, ghostpulse 1  

_Archive: 508 hashes collected so far (kept up to 400 days)._

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
| In the latest export | 3,762 | 2,483 |
| New since the previous run | 525 | 1,508 |
| First reported, last 24 h | 1,086 | 1,534 |
| First reported, last 7 days | 3,761 | 2,378 |
| …of them command-and-control | 453 | 2,352 |
| …delivery and other | 3,308 | 26 |


**Domains, top families (7 days):** IClickFix 1,164, ClearFake 811, Unknown Loader 699, StrelaStealer 500, php.shin_webshell 235  
**Domains, top command-and-control families:** IClickFix 159, Vidar 77, Unknown malware 64, MacSync 23, Unknown RAT 18  

**IP addresses, top families (7 days):** Unknown malware 1,212, VShell 344, Cobalt Strike 148, Sliver 133, Remcos 67  
**IP addresses, top command-and-control families:** Unknown malware 1,206, VShell 344, Cobalt Strike 148, Sliver 133, Remcos 67  
**Most reported ports:** 3333 (396), 3000 (268), 8877 (258), 443 (214), 80 (114), 8080 (103), 31337 (89), 8888 (79)  

**Also serving malware in URLhaus:** 56 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 4049 KB in 2.1 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 337 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 337 rows (last time 355) |
| ✅ | `threatfox: freshness` | newest hash is 23.1 h old |
| ✅ | `threatfox: freshness` | export file is 0.8 h old |
| ⚠️ | `threatfox: new items` | 0 new far below the recent average of 27 |
| ❌ | `urlhaus: download` | https://urlhaus.abuse.ch/downloads/csv_recent/: HTTP 410 |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 3777 data lines parsed |
| ⚠️ | `threatfox domains: values valid` | 1 rows rejected |
| ✅ | `threatfox domains: volume` | 3762 rows (last time 3677) |
| ✅ | `threatfox domains: freshness` | newest entry is 1.4 h old |
| ✅ | `threatfox domains: freshness` | export file is 0.8 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 3210 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 2483 rows (last time 1121) |
| ✅ | `threatfox ips: freshness` | newest entry is 2.0 h old |
| ✅ | `threatfox ips: freshness` | export file is 0.8 h old |
| ✅ | `output safety` | 11 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
