# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-11-02 21:46 UTC · **Health:** ❌ **1 check(s) failed**, 2 warning(s): the affected data was kept from the previous good run.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 507 | 33,970 |
| New since the previous run | 0 | 472 |
| Added in the last 24 hours | 0 | 472 |
| Added in the last 7 days | 507 | 3,388 |
| Online right now | – | 16,550 (49%) |
| Period the export covers | 135.9 h | 30.5 days |
| Newest entry | 29.2 h ago | 0 min ago |

_URL data refreshed 2026-10-21 11:43 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **SalatStealer** | 220 | ▲ +159 | `█▆█▁▄▁▁` | 10-27 00:39 | 95% | – |
| 2 | **stealler** | 20 | ▲ +7 | `▁▁▂▁█▂▁` | 10-29 18:55 | 95% | – |
| 3 | **Raven Stealer** | 17 | ▼ -18 | `█▁▁▁▃▆▁` | 10-27 00:40 | 95% | – |
| 4 | **Creal Stealer** | 15 | ▲ +13 | `▄▁▃▁▁█▁` | 10-27 00:40 | 95% | – |
| 5 | **ValleyRAT** | 14 | ▲ +7 | `█▁▂▁▇▁▁` | 10-27 00:40 | 95% | Winos |
| 6 | **win.icexloader** | 14 | 🆕 new | `▁▁▁▁▁█▁` | 11-01 16:31 | 95% | – |
| 7 | **NetWire RC** | 13 | ▲ +11 | `█▁▂▁▂▂▁` | 10-27 19:32 | 95% | NetWeird, NetWire, Recam |
| 8 | **Coinminer** | 12 | ▼ -58 | `█▄▁▁▅▄▁` | 10-27 00:41 | 95% | – |
| 9 | **Vidar** | 12 | ▼ -9 | `█▁▁▁▁▅▁` | 10-27 00:40 | 95% | – |
| 10 | **Manuscrypt** | 11 | 🆕 new | `▁▁▁█▁▁▁` | 10-30 13:05 | 50% | – |
**New hashes per day, last 14 days:** `▃▃▃▃▄▄▁█▄▅▁▄▄▁` (today 0, busiest day 169).

**Threat types:** payload 507  
**Reporter confidence in the latest export:** 50–100% (average 94%)  

_Archive: 1,082 hashes collected so far (kept up to 400 days)._

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
| In the latest export | 5,121 | 1,975 |
| New since the previous run | 418 | 843 |
| First reported, last 24 h | 667 | 853 |
| First reported, last 7 days | 5,121 | 1,870 |
| …of them command-and-control | 222 | 1,854 |
| …delivery and other | 4,899 | 16 |


**Domains, top families (7 days):** IClickFix 2,305, ClearFake 1,692, Unknown Loader 331, StrelaStealer 283, php.shin_webshell 203  
**Domains, top command-and-control families:** Vidar 73, Remcos 25, Unknown malware 23, Unknown RAT 14, ACR Stealer 12  

**IP addresses, top families (7 days):** Unknown malware 990, VShell 312, Cobalt Strike 77, Sliver 75, PureRAT 60  
**IP addresses, top command-and-control families:** Unknown malware 984, VShell 312, Cobalt Strike 77, Sliver 75, PureRAT 60  
**Most reported ports:** 9097 (232), 5001 (229), 5000 (215), 702 (198), 443 (195), 701 (182), 8443 (115), 14101 (103)  

**Also serving malware in URLhaus:** 5 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 4501 KB in 1.8 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 507 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 507 rows (last time 507) |
| ⚠️ | `threatfox: freshness` | newest hash is 29.2 h old |
| ✅ | `threatfox: freshness` | export file is 1.1 h old |
| ⚠️ | `threatfox: new items` | 0 new far below the recent average of 36 |
| ❌ | `urlhaus: download` | https://urlhaus.abuse.ch/downloads/csv_recent/: HTTP 410 |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 5121 data lines parsed |
| ✅ | `threatfox domains: values valid` | every row passed validation |
| ✅ | `threatfox domains: volume` | 5121 rows (last time 4879) |
| ✅ | `threatfox domains: freshness` | newest entry is 1.1 h old |
| ✅ | `threatfox domains: freshness` | export file is 1.1 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 2718 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 1975 rows (last time 1209) |
| ✅ | `threatfox ips: freshness` | newest entry is 2.0 h old |
| ✅ | `threatfox ips: freshness` | export file is 1.1 h old |
| ✅ | `output safety` | 11 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
