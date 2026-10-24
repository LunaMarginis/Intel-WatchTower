# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-10-24 04:46 UTC · **Health:** ❌ **1 check(s) failed**, 2 warning(s): the affected data was kept from the previous good run.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 330 | 33,970 |
| New since the previous run | 0 | 472 |
| Added in the last 24 hours | 52 | 472 |
| Added in the last 7 days | 330 | 3,388 |
| Online right now | – | 16,550 (49%) |
| Period the export covers | 142.1 h | 30.5 days |
| Newest entry | 15.1 h ago | 0 min ago |

_URL data refreshed 2026-10-21 11:43 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **Coinminer** | 75 | ▲ +74 | `▁▂▂▇█▁▁` | 10-17 15:33 | 95% | – |
| 2 | **Raven Stealer** | 29 | ▲ +19 | `▁▁▅▄▁█▁` | 10-17 15:32 | 95% | – |
| 3 | **Formbook** | 20 | ▲ +16 | `▁██▁▆▆▁` | 10-19 08:12 | 95% | win.xloader |
| 4 | **Venus Stealer** | 18 | ▲ +13 | `▅▅▆▁▁█▁` | 10-17 15:32 | 95% | – |
| 5 | **Vidar** | 18 | ▲ +12 | `▁▁▅▅▁█▁` | 10-17 15:32 | 95% | – |
| 6 | **SalatStealer** | 17 | ▲ +14 | `▁▇█▄▁▂▁` | 10-17 15:32 | 95% | – |
| 7 | **ValleyRAT** | 11 | ▲ +4 | `██▅▅▁▅▁` | 10-17 15:32 | 95% | Winos |
| 8 | **RN Stealer** | 10 | ▲ +9 | `▃█▁▂▁▁▁` | 10-18 06:28 | 95% | – |
| 9 | **stealler** | 10 | ▲ +8 | `▆▁▁▅▁█▁` | 10-17 15:32 | 95% | – |
| 10 | **CrossRAT** | 8 | ▲ +7 | `▁██▃▁▁▁` | 10-17 15:32 | 95% | Trupto |
**New hashes per day, last 14 days:** `▁▁▁▁█▆▇▃██▇▆▇▁` (today 0, busiest day 59).

**Threat types:** payload 330  
**Reporter confidence in the latest export:** 50–100% (average 95%)  
**Tags (7 d):** acr 1, ACRStealer 1, fake game 1, ROM 1, setup.exe 1, setup.py 1  

_Archive: 430 hashes collected so far (kept up to 400 days)._

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
| In the latest export | 3,389 | 1,072 |
| New since the previous run | 77 | 23 |
| First reported, last 24 h | 373 | 112 |
| First reported, last 7 days | 3,389 | 1,004 |
| …of them command-and-control | 518 | 982 |
| …delivery and other | 2,871 | 22 |


**Domains, top families (7 days):** IClickFix 1,342, Unknown Loader 629, ClearFake 398, StrelaStealer 363, php.shin_webshell 238  
**Domains, top command-and-control families:** IClickFix 159, Vidar 83, Unknown malware 75, DeerStealer 44, MacSync 23  

**IP addresses, top families (7 days):** VShell 309, Unknown malware 109, Sliver 82, Remcos 76, Mirai 68  
**IP addresses, top command-and-control families:** VShell 309, Unknown malware 105, Sliver 82, Remcos 76, PureRAT 64  
**Most reported ports:** 8877 (251), 443 (112), 80 (68), 31337 (64), 8080 (40), 2404 (27), 8093 (24), 8443 (23)  

**Also serving malware in URLhaus:** 68 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 3941 KB in 2.1 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 330 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 330 rows (last time 330) |
| ✅ | `threatfox: freshness` | newest hash is 15.1 h old |
| ✅ | `threatfox: freshness` | export file is 1.1 h old |
| ⚠️ | `threatfox: new items` | 0 new far below the recent average of 21 |
| ❌ | `urlhaus: download` | https://urlhaus.abuse.ch/downloads/csv_recent/: HTTP 410 |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 3404 data lines parsed |
| ⚠️ | `threatfox domains: values valid` | 1 rows rejected |
| ✅ | `threatfox domains: volume` | 3389 rows (last time 3380) |
| ✅ | `threatfox domains: freshness` | newest entry is 1.1 h old |
| ✅ | `threatfox domains: freshness` | export file is 1.1 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 1487 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 1072 rows (last time 1074) |
| ✅ | `threatfox ips: freshness` | newest entry is 2.1 h old |
| ✅ | `threatfox ips: freshness` | export file is 1.1 h old |
| ✅ | `output safety` | 11 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
