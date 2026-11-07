# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-11-07 17:46 UTC · **Health:** ❌ **1 check(s) failed**, 1 warning(s): the affected data was kept from the previous good run.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 595 | 33,970 |
| New since the previous run | 42 | 472 |
| Added in the last 24 hours | 42 | 472 |
| Added in the last 7 days | 595 | 3,388 |
| Online right now | – | 16,550 (49%) |
| Period the export covers | 165.2 h | 30.5 days |
| Newest entry | 1.1 h ago | 0 min ago |

_URL data refreshed 2026-10-21 11:43 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **SalatStealer** | 101 | ▼ -113 | `▂▅▃█▆▁▂` | 10-31 19:29 | 95% | – |
| 2 | **VShell** | 61 | ▲ +60 | `▁▇▆▆▅█▆` | 11-02 21:28 | 95% | – |
| 3 | **ZStealer** | 51 | 🆕 new | `▁▁▁▁▁█▁` | 11-06 14:33 | 95% | ZStealer |
| 4 | **Raven Stealer** | 37 | ▲ +22 | `▆▆█▅▄▃▆` | 10-31 19:29 | 95% | – |
| 5 | **ValleyRAT** | 26 | ▲ +17 | `▁▃█▂▁▇▃` | 10-31 19:29 | 95% | Winos |
| 6 | **Formbook** | 25 | ▲ +16 | `▁▆▇█▅▃▂` | 11-02 21:28 | 95% | win.xloader |
| 7 | **stealler** | 23 | ▲ +18 | `█▁▆▃▆▁▁` | 10-31 19:29 | 95% | – |
| 8 | **Agent Tesla** | 21 | ▲ +16 | `▁▆█▅▄▂▂` | 11-02 21:28 | 95% | AgenTesla, AgentTesla, Negasteal |
| 9 | **Creal Stealer** | 21 | ▲ +15 | `█▃▃▃▃▃▁` | 11-01 16:31 | 95% | – |
| 10 | **RN Stealer** | 16 | ▲ +8 | `▄▄▄▂▇▁█` | 11-01 16:32 | 95% | – |
**New hashes per day, last 14 days:** `▄▁█▄▅▁▄▄▄▄▄▄▅▃` (today 42, busiest day 169).

**Threat types:** payload 595  
**Reporter confidence in the latest export:** 25–95% (average 95%)  

_Archive: 1,517 hashes collected so far (kept up to 400 days)._

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
| In the latest export | 3,170 | 1,831 |
| New since the previous run | 64 | 36 |
| First reported, last 24 h | 118 | 115 |
| First reported, last 7 days | 3,167 | 1,750 |
| …of them command-and-control | 517 | 1,736 |
| …delivery and other | 2,650 | 14 |


**Domains, top families (7 days):** ClearFake 946, IClickFix 693, Unknown Loader 516, StrelaStealer 259, Vidar 248  
**Domains, top command-and-control families:** Vidar 248, Astaroth 66, ACR Stealer 34, IClickFix 29, Remcos 27  

**IP addresses, top families (7 days):** Unknown malware 949, VShell 113, ValleyRAT 80, Cobalt Strike 69, Sliver 65  
**IP addresses, top command-and-control families:** Unknown malware 945, VShell 113, ValleyRAT 80, Cobalt Strike 69, Sliver 65  
**Most reported ports:** 443 (268), 5001 (228), 5000 (218), 702 (198), 701 (182), 8443 (110), 14101 (103), 21001 (71)  

**Also serving malware in URLhaus:** 3 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 4669 KB in 5.6 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 595 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 595 rows (last time 553) |
| ✅ | `threatfox: freshness` | newest hash is 1.1 h old |
| ✅ | `threatfox: freshness` | export file is 1.1 h old |
| ✅ | `threatfox: new items` | 42 new (recent average 40) |
| ❌ | `urlhaus: download` | https://urlhaus.abuse.ch/downloads/csv_recent/: HTTP 410 |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 3177 data lines parsed |
| ⚠️ | `threatfox domains: values valid` | 4 rows rejected |
| ✅ | `threatfox domains: volume` | 3170 rows (last time 3213) |
| ✅ | `threatfox domains: freshness` | newest entry is 1.3 h old |
| ✅ | `threatfox domains: freshness` | export file is 1.1 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 2627 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 1831 rows (last time 1973) |
| ✅ | `threatfox ips: freshness` | newest entry is 2.7 h old |
| ✅ | `threatfox ips: freshness` | export file is 1.1 h old |
| ✅ | `output safety` | 12 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
