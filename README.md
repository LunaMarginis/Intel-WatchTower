# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-11-09 22:28 UTC · **Health:** ❌ **1 check(s) failed**, 1 warning(s): the affected data was kept from the previous good run.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 544 | 33,970 |
| New since the previous run | 46 | 472 |
| Added in the last 24 hours | 46 | 472 |
| Added in the last 7 days | 544 | 3,388 |
| Online right now | – | 16,550 (49%) |
| Period the export covers | 134.8 h | 30.5 days |
| Newest entry | 15.0 h ago | 0 min ago |

_URL data refreshed 2026-10-21 11:43 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **VShell** | 73 | ▲ +60 | `▄▄▄▆█▅▂` | 11-03 16:41 | 95% | – |
| 2 | **SalatStealer** | 60 | ▼ -172 | `▃█▆▁▂▁▃` | 11-03 16:42 | 95% | – |
| 3 | **Raven Stealer** | 59 | ▲ +36 | `▄▂▂▂▅█▃` | 11-03 16:41 | 95% | – |
| 4 | **ZStealer** | 51 | 🆕 new | `▁▁▁█▁▁▁` | 11-06 14:33 | 95% | ZStealer |
| 5 | **RN Stealer** | 35 | ▲ +24 | `▂▁▃▁█▄▄` | 11-03 16:41 | 95% | – |
| 6 | **Formbook** | 23 | ▲ +9 | `▇█▅▃▅▁▁` | 11-03 16:41 | 95% | win.xloader |
| 7 | **ValleyRAT** | 23 | ▲ +7 | `█▂▁▇▃▅▁` | 11-03 16:41 | 95% | Winos |
| 8 | **Agent Tesla** | 17 | ▲ +7 | `█▅▄▂▃▁▁` | 11-03 16:41 | 95% | AgenTesla, AgentTesla, Negasteal |
| 9 | **Creal Stealer** | 14 | ▼ -4 | `▄▄▄▅▁█▁` | 11-03 16:41 | 95% | – |
| 10 | **Prometei** | 14 | ▲ +11 | `▁▁▁▁▁▁█` | 11-09 07:28 | 95% | – |
**New hashes per day, last 14 days:** `█▄▅▁▄▄▄▄▄▄▅▅▅▃` (today 46, busiest day 169).

**Threat types:** payload 544  
**Reporter confidence in the latest export:** 25–95% (average 95%)  

_Archive: 1,693 hashes collected so far (kept up to 400 days)._

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
| In the latest export | 2,004 | 966 |
| New since the previous run | 136 | 67 |
| First reported, last 24 h | 191 | 76 |
| First reported, last 7 days | 2,000 | 894 |
| …of them command-and-control | 676 | 881 |
| …delivery and other | 1,324 | 13 |


**Domains, top families (7 days):** ClearFake 497, Vidar 332, IClickFix 244, Unknown Loader 203, php.shin_webshell 194  
**Domains, top command-and-control families:** Vidar 332, ACR Stealer 70, Astaroth 66, IClickFix 37, Unknown malware 32  

**IP addresses, top families (7 days):** Unknown malware 181, ValleyRAT 78, VShell 64, Sliver 63, Cobalt Strike 62  
**IP addresses, top command-and-control families:** Unknown malware 178, ValleyRAT 78, VShell 64, Sliver 63, Cobalt Strike 62  
**Most reported ports:** 443 (238), 31337 (57), 80 (52), 8080 (52), 8888 (50), 8443 (30), 2404 (21), 22 (20)  

**Also serving malware in URLhaus:** 2 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 4719 KB in 2.0 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 544 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 544 rows (last time 565) |
| ✅ | `threatfox: freshness` | newest hash is 15.0 h old |
| ✅ | `threatfox: freshness` | export file is 1.0 h old |
| ✅ | `threatfox: new items` | 46 new (recent average 42) |
| ❌ | `urlhaus: download` | https://urlhaus.abuse.ch/downloads/csv_recent/: HTTP 410 |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 2011 data lines parsed |
| ⚠️ | `threatfox domains: values valid` | 4 rows rejected |
| ✅ | `threatfox domains: volume` | 2004 rows (last time 2249) |
| ✅ | `threatfox domains: freshness` | newest entry is 1.0 h old |
| ✅ | `threatfox domains: freshness` | export file is 1.0 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 1342 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 966 rows (last time 1723) |
| ✅ | `threatfox ips: freshness` | newest entry is 2.4 h old |
| ✅ | `threatfox ips: freshness` | export file is 1.0 h old |
| ✅ | `output safety` | 12 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
