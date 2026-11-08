# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-11-08 06:15 UTC · **Health:** ❌ **1 check(s) failed**, 1 warning(s): the affected data was kept from the previous good run.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 563 | 33,970 |
| New since the previous run | 45 | 472 |
| Added in the last 24 hours | 87 | 472 |
| Added in the last 7 days | 563 | 3,388 |
| Online right now | – | 16,550 (49%) |
| Period the export covers | 144.2 h | 30.5 days |
| Newest entry | 13.5 h ago | 0 min ago |

_URL data refreshed 2026-10-21 11:43 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **VShell** | 71 | ▲ +70 | `▅▄▄▄▆█▁` | 11-02 21:28 | 95% | – |
| 2 | **SalatStealer** | 68 | ▼ -179 | `▅▃█▆▁▂▁` | 11-01 16:31 | 95% | – |
| 3 | **ZStealer** | 51 | 🆕 new | `▁▁▁▁█▁▁` | 11-06 14:33 | 95% | ZStealer |
| 4 | **Raven Stealer** | 42 | ▲ +25 | `▄▅▃▃▂█▁` | 11-01 16:32 | 95% | – |
| 5 | **Formbook** | 28 | ▲ +19 | `▆▇█▅▃▅▁` | 11-02 21:28 | 95% | win.xloader |
| 6 | **RN Stealer** | 26 | ▲ +18 | `▂▂▁▃▁█▁` | 11-01 16:32 | 95% | – |
| 7 | **Agent Tesla** | 22 | ▲ +17 | `▆█▅▄▂▃▁` | 11-02 21:28 | 95% | AgenTesla, AgentTesla, Negasteal |
| 8 | **Creal Stealer** | 21 | ▲ +15 | `█▆▆▆█▁▁` | 11-01 16:31 | 95% | – |
| 9 | **ValleyRAT** | 20 | ▲ +5 | `▃█▂▁▇▃▁` | 11-02 21:28 | 95% | Winos |
| 10 | **Venus Stealer** | 15 | ▲ +12 | `▁▁▁█▄▅▁` | 11-01 16:32 | 95% | – |
**New hashes per day, last 14 days:** `▁█▄▅▁▄▄▄▄▄▄▅▅▁` (today 0, busiest day 169).

**Threat types:** payload 563  
**Reporter confidence in the latest export:** 25–95% (average 95%)  

_Archive: 1,562 hashes collected so far (kept up to 400 days)._

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
| In the latest export | 2,969 | 1,773 |
| New since the previous run | 291 | 68 |
| First reported, last 24 h | 350 | 104 |
| First reported, last 7 days | 2,966 | 1,701 |
| …of them command-and-control | 530 | 1,687 |
| …delivery and other | 2,436 | 14 |


**Domains, top families (7 days):** ClearFake 809, IClickFix 572, Unknown Loader 567, Vidar 270, StrelaStealer 255  
**Domains, top command-and-control families:** Vidar 270, Astaroth 66, ACR Stealer 34, IClickFix 29, Remcos 27  

**IP addresses, top families (7 days):** Unknown malware 941, VShell 87, ValleyRAT 80, Cobalt Strike 67, Sliver 57  
**IP addresses, top command-and-control families:** Unknown malware 937, VShell 87, ValleyRAT 80, Cobalt Strike 67, Sliver 57  
**Most reported ports:** 443 (273), 5001 (228), 5000 (218), 702 (198), 701 (182), 8443 (111), 14101 (103), 21001 (71)  

**Also serving malware in URLhaus:** 3 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 4691 KB in 5.7 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 563 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 563 rows (last time 595) |
| ✅ | `threatfox: freshness` | newest hash is 13.5 h old |
| ✅ | `threatfox: freshness` | export file is 0.6 h old |
| ✅ | `threatfox: new items` | 45 new (recent average 36) |
| ❌ | `urlhaus: download` | https://urlhaus.abuse.ch/downloads/csv_recent/: HTTP 410 |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 2976 data lines parsed |
| ⚠️ | `threatfox domains: values valid` | 4 rows rejected |
| ✅ | `threatfox domains: volume` | 2969 rows (last time 3170) |
| ✅ | `threatfox domains: freshness` | newest entry is 0.6 h old |
| ✅ | `threatfox domains: freshness` | export file is 0.6 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 2561 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 1773 rows (last time 1831) |
| ✅ | `threatfox ips: freshness` | newest entry is 1.0 h old |
| ✅ | `threatfox ips: freshness` | export file is 0.6 h old |
| ✅ | `output safety` | 12 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
