# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-11-09 06:48 UTC · **Health:** ❌ **1 check(s) failed**, 1 warning(s): the affected data was kept from the previous good run.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 565 | 33,970 |
| New since the previous run | 85 | 472 |
| Added in the last 24 hours | 85 | 472 |
| Added in the last 7 days | 565 | 3,388 |
| Online right now | – | 16,550 (49%) |
| Period the export covers | 140.3 h | 30.5 days |
| Newest entry | 13.1 h ago | 0 min ago |

_URL data refreshed 2026-10-21 11:43 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **VShell** | 83 | ▲ +82 | `▄▄▄▆█▅▁` | 11-02 21:28 | 95% | – |
| 2 | **SalatStealer** | 65 | ▼ -155 | `▃█▆▁▂▁▁` | 11-02 21:29 | 95% | – |
| 3 | **Raven Stealer** | 58 | ▲ +41 | `▄▂▂▂▅█▁` | 11-02 21:29 | 95% | – |
| 4 | **ZStealer** | 51 | 🆕 new | `▁▁▁█▁▁▁` | 11-06 14:33 | 95% | ZStealer |
| 5 | **RN Stealer** | 30 | ▲ +21 | `▂▁▃▁█▄▁` | 11-02 21:28 | 95% | – |
| 6 | **Formbook** | 28 | ▲ +19 | `▇█▅▃▅▁▁` | 11-02 21:28 | 95% | win.xloader |
| 7 | **ValleyRAT** | 25 | ▲ +11 | `█▂▁▇▃▅▁` | 11-02 21:28 | 95% | Winos |
| 8 | **Agent Tesla** | 22 | ▲ +17 | `█▅▄▂▃▁▁` | 11-02 21:28 | 95% | AgenTesla, AgentTesla, Negasteal |
| 9 | **Creal Stealer** | 17 | ▲ +2 | `▄▄▄▅▁█▁` | 11-02 21:28 | 95% | – |
| 10 | **Vidar** | 13 | ▲ +1 | `▅▄▁▁█▅▁` | 11-03 16:42 | 95% | – |
**New hashes per day, last 14 days:** `█▄▅▁▄▄▄▄▄▄▅▅▅▁` (today 0, busiest day 169).

**Threat types:** payload 565  
**Reporter confidence in the latest export:** 25–95% (average 95%)  

_Archive: 1,647 hashes collected so far (kept up to 400 days)._

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
| In the latest export | 2,249 | 1,723 |
| New since the previous run | 91 | 25 |
| First reported, last 24 h | 288 | 54 |
| First reported, last 7 days | 2,245 | 1,649 |
| …of them command-and-control | 638 | 1,637 |
| …delivery and other | 1,607 | 12 |


**Domains, top families (7 days):** ClearFake 632, Unknown Loader 340, Vidar 309, IClickFix 234, StrelaStealer 197  
**Domains, top command-and-control families:** Vidar 309, ACR Stealer 66, Astaroth 66, Unknown malware 32, IClickFix 29  

**IP addresses, top families (7 days):** Unknown malware 919, ValleyRAT 80, Cobalt Strike 64, VShell 62, Sliver 61  
**IP addresses, top command-and-control families:** Unknown malware 916, ValleyRAT 80, Cobalt Strike 64, VShell 62, Sliver 61  
**Most reported ports:** 443 (274), 5001 (228), 5000 (218), 702 (198), 701 (182), 8443 (108), 14101 (103), 21001 (71)  

**Also serving malware in URLhaus:** 1 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 4695 KB in 8.1 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 565 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 565 rows (last time 480) |
| ✅ | `threatfox: freshness` | newest hash is 13.1 h old |
| ✅ | `threatfox: freshness` | export file is 0.3 h old |
| ✅ | `threatfox: new items` | 85 new (recent average 40) |
| ❌ | `urlhaus: download` | https://urlhaus.abuse.ch/downloads/csv_recent/: HTTP 410 |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 2255 data lines parsed |
| ⚠️ | `threatfox domains: values valid` | 4 rows rejected |
| ✅ | `threatfox domains: volume` | 2249 rows (last time 2685) |
| ✅ | `threatfox domains: freshness` | newest entry is 0.3 h old |
| ✅ | `threatfox domains: freshness` | export file is 0.3 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 2462 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 1723 rows (last time 1740) |
| ✅ | `threatfox ips: freshness` | newest entry is 0.7 h old |
| ✅ | `threatfox ips: freshness` | export file is 0.3 h old |
| ✅ | `output safety` | 12 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
