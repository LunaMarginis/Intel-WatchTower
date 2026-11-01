# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-11-01 06:20 UTC · **Health:** ❌ **1 check(s) failed**: the affected data was kept from the previous good run.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 491 | 33,970 |
| New since the previous run | 77 | 472 |
| Added in the last 24 hours | 77 | 472 |
| Added in the last 7 days | 491 | 3,388 |
| Online right now | – | 16,550 (49%) |
| Period the export covers | 145.8 h | 30.5 days |
| Newest entry | 10.8 h ago | 0 min ago |

_URL data refreshed 2026-10-21 11:43 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **SalatStealer** | 247 | ▲ +213 | `▁█▆█▁▄▁` | 10-25 17:41 | 95% | – |
| 2 | **stealler** | 20 | ▲ +7 | `▁▁▁▂▁█▁` | 10-25 17:41 | 95% | – |
| 3 | **Raven Stealer** | 17 | ▼ -12 | `▁█▁▁▁▃▁` | 10-25 17:42 | 95% | – |
| 4 | **ValleyRAT** | 15 | ▲ +5 | `▁█▁▂▁▇▁` | 10-25 17:41 | 95% | Winos |
| 5 | **NetWire RC** | 12 | ▲ +10 | `▁█▁▂▁▂▁` | 10-27 19:32 | 95% | NetWeird, NetWire, Recam |
| 6 | **Vidar** | 12 | ▼ -5 | `▁█▁▁▁▁▁` | 10-25 17:41 | 95% | – |
| 7 | **Coinminer** | 11 | ▼ -63 | `▁█▄▁▁▅▁` | 10-25 17:42 | 95% | – |
| 8 | **Manuscrypt** | 11 | 🆕 new | `▁▁▁▁█▁▁` | 10-30 13:05 | 50% | – |
| 9 | **WannaCryptor** | 11 | ▲ +1 | `▁▆▃█▁▆▁` | 10-25 17:42 | 95% | Wana Decrypt0r, WannaCry, WannaCrypt |
| 10 | **Formbook** | 9 | ▼ -11 | `▁█▃▂▁▁▁` | 10-27 00:40 | 95% | win.xloader |
**New hashes per day, last 14 days:** `▃▃▃▃▃▄▄▁█▄▅▁▄▁` (today 0, busiest day 169).

**Threat types:** payload 491  
**Reporter confidence in the latest export:** 50–100% (average 94%)  

_Archive: 999 hashes collected so far (kept up to 400 days)._

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
| In the latest export | 5,227 | 2,789 |
| New since the previous run | 496 | 118 |
| First reported, last 24 h | 586 | 290 |
| First reported, last 7 days | 5,226 | 2,645 |
| …of them command-and-control | 260 | 2,626 |
| …delivery and other | 4,966 | 19 |


**Domains, top families (7 days):** IClickFix 2,681, ClearFake 1,501, StrelaStealer 267, Unknown Loader 260, php.shin_webshell 201  
**Domains, top command-and-control families:** Vidar 83, Unknown malware 48, Remcos 29, Unknown RAT 14, ACR Stealer 10  

**IP addresses, top families (7 days):** Unknown malware 1,348, VShell 312, Cobalt Strike 198, Sliver 184, Mirai 108  
**IP addresses, top command-and-control families:** Unknown malware 1,340, VShell 312, Cobalt Strike 198, Sliver 184, Mirai 103  
**Most reported ports:** 3333 (450), 443 (310), 3000 (271), 9097 (217), 80 (135), 31337 (129), 8080 (107), 8888 (95)  

**Also serving malware in URLhaus:** 17 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 4431 KB in 2.1 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 491 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 491 rows (last time 490) |
| ✅ | `threatfox: freshness` | newest hash is 10.8 h old |
| ✅ | `threatfox: freshness` | export file is 0.7 h old |
| ✅ | `threatfox: new items` | 77 new (recent average 34) |
| ❌ | `urlhaus: download` | https://urlhaus.abuse.ch/downloads/csv_recent/: HTTP 410 |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 5228 data lines parsed |
| ✅ | `threatfox domains: values valid` | every row passed validation |
| ✅ | `threatfox domains: volume` | 5227 rows (last time 5321) |
| ✅ | `threatfox domains: freshness` | newest entry is 0.9 h old |
| ✅ | `threatfox domains: freshness` | export file is 0.7 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 3403 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 2789 rows (last time 2682) |
| ✅ | `threatfox ips: freshness` | newest entry is 1.0 h old |
| ✅ | `threatfox ips: freshness` | export file is 0.7 h old |
| ✅ | `output safety` | 12 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
