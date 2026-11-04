# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-11-04 06:38 UTC · **Health:** ❌ **1 check(s) failed**, 2 warning(s): the affected data was kept from the previous good run.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 484 | 33,970 |
| New since the previous run | 0 | 472 |
| Added in the last 24 hours | 79 | 472 |
| Added in the last 7 days | 484 | 3,388 |
| Online right now | – | 16,550 (49%) |
| Period the export covers | 137.1 h | 30.5 days |
| Newest entry | 13.9 h ago | 0 min ago |

_URL data refreshed 2026-10-21 11:43 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **SalatStealer** | 173 | ▲ +52 | `█▁▄▁▂▂▁` | 10-28 23:36 | 95% | – |
| 2 | **Raven Stealer** | 22 | ▼ -17 | `▁▁▃▆▆█▁` | 10-31 19:29 | 95% | – |
| 3 | **stealler** | 22 | ▲ +9 | `▂▁█▂▁▂▁` | 10-29 18:55 | 95% | – |
| 4 | **VShell** | 22 | 🆕 new | `▁▁▁▁█▆▁` | 10-28 23:36 | 95% | – |
| 5 | **ValleyRAT** | 17 | ▲ +4 | `▂▁▆▁▃█▁` | 10-29 18:55 | 95% | Winos |
| 6 | **Creal Stealer** | 16 | ▲ +10 | `▃▁▁█▃▃▁` | 10-29 18:55 | 95% | – |
| 7 | **Agent Tesla** | 14 | ▲ +8 | `▁▁▁▁▆█▁` | 10-28 23:36 | 95% | AgenTesla, AgentTesla, Negasteal |
| 8 | **Formbook** | 14 | ▬ 0 | `▂▁▁▁▇█▁` | 10-28 23:36 | 95% | win.xloader |
| 9 | **win.icexloader** | 14 | 🆕 new | `▁▁▁█▁▁▁` | 11-01 16:31 | 95% | – |
| 10 | **Manuscrypt** | 11 | 🆕 new | `▁█▁▁▁▁▁` | 10-30 13:05 | 50% | – |
**New hashes per day, last 14 days:** `▃▃▄▄▁█▄▅▁▄▄▄▄▁` (today 0, busiest day 169).

**Threat types:** payload 484  
**Reporter confidence in the latest export:** 50–95% (average 94%)  

_Archive: 1,228 hashes collected so far (kept up to 400 days)._

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
| In the latest export | 5,628 | 2,014 |
| New since the previous run | 55 | 36 |
| First reported, last 24 h | 255 | 81 |
| First reported, last 7 days | 5,628 | 1,910 |
| …of them command-and-control | 265 | 1,893 |
| …delivery and other | 5,363 | 17 |


**Domains, top families (7 days):** IClickFix 2,436, ClearFake 1,822, Unknown Loader 492, StrelaStealer 322, php.shin_webshell 206  
**Domains, top command-and-control families:** Vidar 120, Remcos 29, WARDENStealer 22, Unknown malware 21, ACR Stealer 12  

**IP addresses, top families (7 days):** Unknown malware 984, VShell 312, Cobalt Strike 87, Sliver 76, PureRAT 68  
**IP addresses, top command-and-control families:** Unknown malware 979, VShell 312, Cobalt Strike 87, Sliver 76, PureRAT 68  
**Most reported ports:** 9097 (232), 5001 (229), 443 (225), 5000 (216), 702 (198), 701 (182), 8443 (113), 14101 (103)  

**Also serving malware in URLhaus:** 4 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 4548 KB in 1.6 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 484 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 484 rows (last time 484) |
| ✅ | `threatfox: freshness` | newest hash is 13.9 h old |
| ✅ | `threatfox: freshness` | export file is 0.9 h old |
| ⚠️ | `threatfox: new items` | 0 new far below the recent average of 40 |
| ❌ | `urlhaus: download` | https://urlhaus.abuse.ch/downloads/csv_recent/: HTTP 410 |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 5634 data lines parsed |
| ⚠️ | `threatfox domains: values valid` | 4 rows rejected |
| ✅ | `threatfox domains: volume` | 5628 rows (last time 5654) |
| ✅ | `threatfox domains: freshness` | newest entry is 1.5 h old |
| ✅ | `threatfox domains: freshness` | export file is 0.9 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 2772 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 2014 rows (last time 2002) |
| ✅ | `threatfox ips: freshness` | newest entry is 1.5 h old |
| ✅ | `threatfox ips: freshness` | export file is 0.9 h old |
| ✅ | `output safety` | 11 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
