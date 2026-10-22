# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-10-22 06:53 UTC · **Health:** ⚠️ 21 checks passed, **1 warning(s)**: see Data health.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 335 | 33,970 |
| New since the previous run | 0 | 472 |
| Added in the last 24 hours | 53 | 472 |
| Added in the last 7 days | 335 | 3,388 |
| Online right now | – | 16,550 (49%) |
| Period the export covers | 139.1 h | 30.5 days |
| Newest entry | 17.2 h ago | 0 min ago |

_URL data refreshed 2026-10-21 11:43 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **Coinminer** | 41 | 🆕 new | `▁▁▁▂▂█▁` | 10-16 06:36 | 95% | – |
| 2 | **Raven Stealer** | 31 | 🆕 new | `▃█▁▁▄▃▁` | 10-15 18:36 | 95% | – |
| 3 | **SalatStealer** | 19 | 🆕 new | `▅█▁▇█▄▁` | 10-16 06:36 | 95% | – |
| 4 | **Vidar** | 18 | 🆕 new | `▃█▁▁▅▅▁` | 10-15 18:35 | 95% | – |
| 5 | **ValleyRAT** | 17 | 🆕 new | `▆█▅▅▃▃▁` | 10-15 18:35 | 95% | Winos |
| 6 | **Venus Stealer** | 17 | 🆕 new | `▆▅▆▆█▁▁` | 10-15 18:35 | 95% | – |
| 7 | **Formbook** | 16 | 🆕 new | `▁▁▁██▁▁` | 10-15 18:35 | 95% | win.xloader |
| 8 | **RN Stealer** | 11 | 🆕 new | `▂▁▃█▁▂▁` | 10-16 06:36 | 95% | – |
| 9 | **AsyncRAT** | 10 | 🆕 new | `█▅▁▁█▁▁` | 10-15 18:35 | 95% | – |
| 10 | **NjRAT** | 10 | 🆕 new | `█▅▁██▁▁` | 10-15 18:35 | 95% | Bladabindi, Lime-Worm |
**New hashes per day, last 14 days:** `▁▁▁▁▁▁█▆▇▃██▇▁` (today 0, busiest day 59).

**Threat types:** payload 335  
**Reporter confidence in the latest export:** 95–100% (average 95%)  
**Tags (7 d):** acr 1, ACRStealer 1, fake game 1, ROM 1, setup.exe 1, setup.py 1  

_Archive: 335 hashes collected so far (kept up to 400 days)._

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
| In the latest export | 3,129 | 1,086 |
| New since the previous run | 94 | 6 |
| First reported, last 24 h | 1,228 | 203 |
| First reported, last 7 days | 3,129 | 1,027 |
| …of them command-and-control | 549 | 1,007 |
| …delivery and other | 2,580 | 20 |


**Domains, top families (7 days):** IClickFix 1,273, Unknown Loader 675, php.shin_webshell 263, ClearFake 253, StrelaStealer 163  
**Domains, top command-and-control families:** IClickFix 155, Vidar 78, Unknown malware 77, Remus 49, DeerStealer 44  

**IP addresses, top families (7 days):** VShell 272, Unknown malware 110, Sliver 95, Remcos 92, Mirai 77  
**IP addresses, top command-and-control families:** VShell 272, Unknown malware 104, Sliver 95, Remcos 92, Mirai 70  
**Most reported ports:** 8877 (149), 443 (129), 80 (78), 31337 (74), 8080 (37), 8443 (30), 2404 (28), 56003 (26)  

**Also serving malware in URLhaus:** 73 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 3872 KB in 1.5 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 335 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 335 rows (last time 335) |
| ✅ | `threatfox: freshness` | newest hash is 17.2 h old |
| ✅ | `threatfox: freshness` | export file is 0.2 h old |
| ⚠️ | `threatfox: new items` | 0 new far below the recent average of 18 |
| ✅ | `urlhaus: refresh` | not due: refreshed 2026-10-21 11:43 UTC (once a day) |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 3139 data lines parsed |
| ✅ | `threatfox domains: values valid` | every row passed validation |
| ✅ | `threatfox domains: volume` | 3129 rows (last time 3037) |
| ✅ | `threatfox domains: freshness` | newest entry is 0.5 h old |
| ✅ | `threatfox domains: freshness` | export file is 0.2 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 1502 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 1086 rows (last time 1080) |
| ✅ | `threatfox ips: freshness` | newest entry is 0.6 h old |
| ✅ | `threatfox ips: freshness` | export file is 0.2 h old |
| ✅ | `output safety` | 11 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
