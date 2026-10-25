# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-10-25 04:52 UTC · **Health:** ❌ **1 check(s) failed**, 1 warning(s): the affected data was kept from the previous good run.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 355 | 33,970 |
| New since the previous run | 77 | 472 |
| Added in the last 24 hours | 78 | 472 |
| Added in the last 7 days | 355 | 3,388 |
| Online right now | – | 16,550 (49%) |
| Period the export covers | 154.9 h | 30.5 days |
| Newest entry | 11.5 h ago | 0 min ago |

_URL data refreshed 2026-10-21 11:43 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **Coinminer** | 74 | ▲ +71 | `▂▂▇█▁▁▁` | 10-18 06:28 | 95% | – |
| 2 | **SalatStealer** | 34 | ▲ +26 | `▂▃▂▁▁█▁` | 10-19 08:12 | 95% | – |
| 3 | **Raven Stealer** | 29 | ▲ +6 | `▁▄▃▁▅█▁` | 10-20 07:54 | 95% | – |
| 4 | **Formbook** | 20 | ▲ +16 | `██▁▆▆▁▁` | 10-19 08:12 | 95% | win.xloader |
| 5 | **Venus Stealer** | 19 | ▲ +12 | `▅▆▁▁█▅▁` | 10-18 06:28 | 95% | – |
| 6 | **Vidar** | 17 | ▲ +5 | `▁▅▅▁█▇▁` | 10-20 07:54 | 95% | – |
| 7 | **stealler** | 13 | ▲ +10 | `▁▁▅▁██▁` | 10-18 06:28 | 95% | – |
| 8 | **RN Stealer** | 11 | ▲ +10 | `█▁▂▁▁▂▁` | 10-18 06:28 | 95% | – |
| 9 | **ValleyRAT** | 10 | ▼ -1 | `▆▃▃▁▃█▁` | 10-18 06:28 | 95% | Winos |
| 10 | **WannaCryptor** | 10 | ▲ +8 | `▅█▅▅▅█▁` | 10-18 06:28 | 95% | Wana Decrypt0r, WannaCry, WannaCrypt |
**New hashes per day, last 14 days:** `▁▁▁▆▅▆▃▆▆▆▅▆█▁` (today 0, busiest day 78).

**Threat types:** payload 355  
**Reporter confidence in the latest export:** 50–100% (average 95%)  
**Tags (7 d):** acr 1, ACRStealer 1, fake game 1, ROM 1, setup.exe 1, setup.py 1, clickfix 1, ghostpulse 1  

_Archive: 508 hashes collected so far (kept up to 400 days)._

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
| In the latest export | 3,677 | 1,121 |
| New since the previous run | 579 | 36 |
| First reported, last 24 h | 686 | 123 |
| First reported, last 7 days | 3,676 | 1,047 |
| …of them command-and-control | 468 | 1,022 |
| …delivery and other | 3,208 | 25 |


**Domains, top families (7 days):** IClickFix 1,068, ClearFake 776, Unknown Loader 747, StrelaStealer 481, php.shin_webshell 232  
**Domains, top command-and-control families:** IClickFix 159, Vidar 75, Unknown malware 69, MacSync 23, Unknown RAT 20  

**IP addresses, top families (7 days):** VShell 324, Unknown malware 120, Sliver 80, Remcos 71, Mirai 70  
**IP addresses, top command-and-control families:** VShell 324, Unknown malware 114, Sliver 80, Remcos 71, Mirai 64  
**Most reported ports:** 8877 (258), 443 (131), 80 (82), 31337 (61), 8080 (40), 8443 (28), 2404 (27), 7443 (23)  

**Also serving malware in URLhaus:** 63 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 3974 KB in 2.3 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 355 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 355 rows (last time 278) |
| ✅ | `threatfox: freshness` | newest hash is 11.5 h old |
| ✅ | `threatfox: freshness` | export file is 0.2 h old |
| ✅ | `threatfox: new items` | 77 new (recent average 21) |
| ❌ | `urlhaus: download` | https://urlhaus.abuse.ch/downloads/csv_recent/: HTTP 410 |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 3691 data lines parsed |
| ⚠️ | `threatfox domains: values valid` | 1 rows rejected |
| ✅ | `threatfox domains: volume` | 3677 rows (last time 3253) |
| ✅ | `threatfox domains: freshness` | newest entry is 0.2 h old |
| ✅ | `threatfox domains: freshness` | export file is 0.2 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 1669 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 1121 rows (last time 1099) |
| ✅ | `threatfox ips: freshness` | newest entry is 1.8 h old |
| ✅ | `threatfox ips: freshness` | export file is 0.2 h old |
| ✅ | `output safety` | 12 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
