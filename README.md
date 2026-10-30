# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-10-30 18:04 UTC · **Health:** ❌ **1 check(s) failed**: the affected data was kept from the previous good run.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 492 | 33,970 |
| New since the previous run | 11 | 472 |
| Added in the last 24 hours | 99 | 472 |
| Added in the last 7 days | 492 | 3,388 |
| Online right now | – | 16,550 (49%) |
| Period the export covers | 150.9 h | 30.5 days |
| Newest entry | 5.0 h ago | 0 min ago |

_URL data refreshed 2026-10-21 11:43 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **SalatStealer** | 236 | ▲ +219 | `▃▄▁█▆█▁` | 10-24 17:23 | 95% | – |
| 2 | **Raven Stealer** | 28 | ▼ -1 | `█▄▁▆▁▁▁` | 10-24 17:23 | 95% | – |
| 3 | **Vidar** | 17 | ▼ -1 | `▅▅▁█▁▁▁` | 10-24 17:23 | 95% | – |
| 4 | **ValleyRAT** | 12 | ▲ +1 | `▄▂▁█▁▂▁` | 10-24 17:23 | 95% | Winos |
| 5 | **Manuscrypt** | 11 | 🆕 new | `▁▁▁▁▁▁█` | 10-30 13:05 | 50% | – |
| 6 | **NetWire RC** | 11 | ▲ +3 | `▁▁▁█▁▂▁` | 10-27 19:32 | 95% | NetWeird, NetWire, Recam |
| 7 | **WannaCryptor** | 11 | ▲ +3 | `▆█▁▆▃█▁` | 10-24 17:23 | 95% | Wana Decrypt0r, WannaCry, WannaCrypt |
| 8 | **Coinminer** | 9 | ▼ -66 | `▂▂▁█▄▁▁` | 10-24 17:23 | 95% | – |
| 9 | **Formbook** | 9 | ▼ -11 | `▁▁▁█▃▂▁` | 10-27 00:40 | 95% | win.xloader |
| 10 | **RN Stealer** | 9 | ▼ -1 | `▃▃▁█▆▁▁` | 10-24 17:23 | 95% | – |
**New hashes per day, last 14 days:** `▃▂▃▃▃▃▃▄▄▁█▄▅▁` (today 11, busiest day 169).

**Threat types:** payload 492  
**Reporter confidence in the latest export:** 50–100% (average 94%)  
**Tags (7 d):** clickfix 1, ghostpulse 1, hijackloader 1, msi 1, sideload 1  

_Archive: 922 hashes collected so far (kept up to 400 days)._

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
| In the latest export | 4,970 | 2,550 |
| New since the previous run | 89 | 82 |
| First reported, last 24 h | 1,922 | 158 |
| First reported, last 7 days | 4,969 | 2,422 |
| …of them command-and-control | 265 | 2,402 |
| …delivery and other | 4,704 | 20 |


**Domains, top families (7 days):** IClickFix 2,204, ClearFake 1,549, StrelaStealer 370, Unknown Loader 315, php.shin_webshell 205  
**Domains, top command-and-control families:** Vidar 88, Unknown malware 48, Remcos 30, Unknown RAT 15, Remus 13  

**IP addresses, top families (7 days):** Unknown malware 1,288, VShell 204, Cobalt Strike 203, Sliver 150, Mirai 94  
**IP addresses, top command-and-control families:** Unknown malware 1,278, VShell 204, Cobalt Strike 203, Sliver 150, Mirai 89  
**Most reported ports:** 3333 (415), 443 (310), 3000 (269), 80 (147), 8080 (112), 31337 (101), 9097 (95), 8888 (90)  

**Also serving malware in URLhaus:** 20 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 4381 KB in 2.1 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 492 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 492 rows (last time 533) |
| ✅ | `threatfox: freshness` | newest hash is 5.0 h old |
| ✅ | `threatfox: freshness` | export file is 0.4 h old |
| ✅ | `threatfox: new items` | 11 new (recent average 40) |
| ❌ | `urlhaus: download` | https://urlhaus.abuse.ch/downloads/csv_recent/: HTTP 410 |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 4971 data lines parsed |
| ✅ | `threatfox domains: values valid` | every row passed validation |
| ✅ | `threatfox domains: volume` | 4970 rows (last time 5022) |
| ✅ | `threatfox domains: freshness` | newest entry is 0.6 h old |
| ✅ | `threatfox domains: freshness` | export file is 0.4 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 3337 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 2550 rows (last time 2543) |
| ✅ | `threatfox ips: freshness` | newest entry is 1.0 h old |
| ✅ | `threatfox ips: freshness` | export file is 0.4 h old |
| ✅ | `output safety` | 12 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
