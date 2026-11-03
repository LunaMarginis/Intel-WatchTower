# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-11-03 06:57 UTC · **Health:** ❌ **1 check(s) failed**: the affected data was kept from the previous good run.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 495 | 33,970 |
| New since the previous run | 67 | 472 |
| Added in the last 24 hours | 67 | 472 |
| Added in the last 7 days | 495 | 3,388 |
| Online right now | – | 16,550 (49%) |
| Period the export covers | 158.2 h | 30.5 days |
| Newest entry | 9.5 h ago | 0 min ago |

_URL data refreshed 2026-10-21 11:43 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **SalatStealer** | 203 | ▲ +113 | `▆█▁▄▁▂▁` | 10-27 19:31 | 95% | – |
| 2 | **stealler** | 20 | ▲ +7 | `▁▂▁█▂▁▁` | 10-29 18:55 | 95% | – |
| 3 | **Raven Stealer** | 18 | ▼ -22 | `▁▁▁▃██▁` | 10-27 19:33 | 95% | – |
| 4 | **Creal Stealer** | 15 | ▲ +10 | `▁▃▁▁█▃▁` | 10-27 19:32 | 95% | – |
| 5 | **NetWire RC** | 15 | ▲ +13 | `▁▅▁▅▅█▁` | 10-27 19:32 | 95% | NetWeird, NetWire, Recam |
| 6 | **ValleyRAT** | 14 | ▲ +5 | `▁▂▁█▁▃▁` | 10-27 19:32 | 95% | Winos |
| 7 | **win.icexloader** | 14 | 🆕 new | `▁▁▁▁█▁▁` | 11-01 16:31 | 95% | – |
| 8 | **VShell** | 13 | ▲ +11 | `▂▁▁▁▁█▁` | 10-28 23:36 | 95% | – |
| 9 | **Coinminer** | 11 | ▼ -60 | `▆▁▁█▆▁▁` | 10-27 19:32 | 95% | – |
| 10 | **Manuscrypt** | 11 | 🆕 new | `▁▁█▁▁▁▁` | 10-30 13:05 | 50% | – |
**New hashes per day, last 14 days:** `▃▃▃▄▄▁█▄▅▁▄▄▄▁` (today 0, busiest day 169).

**Threat types:** payload 495  
**Reporter confidence in the latest export:** 50–100% (average 94%)  

_Archive: 1,149 hashes collected so far (kept up to 400 days)._

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
| In the latest export | 5,537 | 2,001 |
| New since the previous run | 499 | 81 |
| First reported, last 24 h | 659 | 902 |
| First reported, last 7 days | 5,537 | 1,901 |
| …of them command-and-control | 256 | 1,885 |
| …delivery and other | 5,281 | 16 |


**Domains, top families (7 days):** IClickFix 2,413, ClearFake 1,816, Unknown Loader 491, StrelaStealer 269, php.shin_webshell 205  
**Domains, top command-and-control families:** Vidar 118, Remcos 24, Unknown malware 22, Unknown RAT 14, ACR Stealer 12  

**IP addresses, top families (7 days):** Unknown malware 981, VShell 315, Cobalt Strike 86, Sliver 78, PureRAT 64  
**IP addresses, top command-and-control families:** Unknown malware 976, VShell 315, Cobalt Strike 86, Sliver 78, PureRAT 64  
**Most reported ports:** 9097 (232), 5001 (229), 443 (215), 5000 (215), 702 (198), 701 (182), 8443 (113), 14101 (103)  

**Also serving malware in URLhaus:** 5 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 4517 KB in 2.1 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 495 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 495 rows (last time 507) |
| ✅ | `threatfox: freshness` | newest hash is 9.5 h old |
| ✅ | `threatfox: freshness` | export file is 0.3 h old |
| ✅ | `threatfox: new items` | 67 new (recent average 36) |
| ❌ | `urlhaus: download` | https://urlhaus.abuse.ch/downloads/csv_recent/: HTTP 410 |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 5537 data lines parsed |
| ✅ | `threatfox domains: values valid` | every row passed validation |
| ✅ | `threatfox domains: volume` | 5537 rows (last time 5121) |
| ✅ | `threatfox domains: freshness` | newest entry is 0.5 h old |
| ✅ | `threatfox domains: freshness` | export file is 0.3 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 2758 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 2001 rows (last time 1975) |
| ✅ | `threatfox ips: freshness` | newest entry is 0.4 h old |
| ✅ | `threatfox ips: freshness` | export file is 0.3 h old |
| ✅ | `output safety` | 12 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
