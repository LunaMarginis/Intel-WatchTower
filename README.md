# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-10-27 05:14 UTC · **Health:** ❌ **1 check(s) failed**, 1 warning(s): the affected data was kept from the previous good run.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 428 | 33,970 |
| New since the previous run | 79 | 472 |
| Added in the last 24 hours | 79 | 472 |
| Added in the last 7 days | 428 | 3,388 |
| Online right now | – | 16,550 (49%) |
| Period the export covers | 160.8 h | 30.5 days |
| Newest entry | 4.5 h ago | 0 min ago |

_URL data refreshed 2026-10-21 11:43 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **SalatStealer** | 90 | ▲ +78 | `▁▁▁▆█▁█` | 10-20 07:54 | 95% | – |
| 2 | **Coinminer** | 71 | ▲ +63 | `▇█▁▁▁▁▁` | 10-20 07:54 | 95% | – |
| 3 | **Raven Stealer** | 40 | ▲ +17 | `▃▁▅█▄▁▄` | 10-20 07:54 | 95% | – |
| 4 | **Vidar** | 29 | ▲ +17 | `▄▁▆▅▅▁█` | 10-20 07:54 | 95% | – |
| 5 | **Formbook** | 20 | ▲ +10 | `▁▆▆▁▁▁█` | 10-20 07:54 | 95% | win.xloader |
| 6 | **Venus Stealer** | 14 | ▲ +1 | `▁▁█▅▁▁▂` | 10-20 07:54 | 95% | – |
| 7 | **stealler** | 13 | ▲ +7 | `▅▁██▆▁▁` | 10-21 13:40 | 95% | – |
| 8 | **WannaCryptor** | 11 | ▲ +6 | `▃▃▃▆█▁▃` | 10-20 07:54 | 95% | Wana Decrypt0r, WannaCry, WannaCrypt |
| 9 | **ValleyRAT** | 9 | ▼ -6 | `▃▁▃█▃▁▆` | 10-20 07:55 | 95% | Winos |
| 10 | **AsyncRAT** | 8 | ▬ 0 | `▁▁█▆▃▁▁` | 10-20 07:54 | 95% | – |
**New hashes per day, last 14 days:** `▁▆▅▆▃▆▆▆▅▆█▇▁█` (today 79, busiest day 79).

**Threat types:** payload 428  
**Reporter confidence in the latest export:** 50–100% (average 95%)  
**Tags (7 d):** clickfix 1, ghostpulse 1, hijackloader 1, msi 1, sideload 1  

_Archive: 654 hashes collected so far (kept up to 400 days)._

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
| In the latest export | 4,393 | 2,541 |
| New since the previous run | 97 | 38 |
| First reported, last 24 h | 230 | 119 |
| First reported, last 7 days | 4,388 | 2,435 |
| …of them command-and-control | 436 | 2,410 |
| …delivery and other | 3,952 | 25 |


**Domains, top families (7 days):** IClickFix 1,622, ClearFake 943, Unknown Loader 697, StrelaStealer 567, php.shin_webshell 225  
**Domains, top command-and-control families:** IClickFix 159, Vidar 82, Unknown malware 51, MacSync 23, Unknown RAT 17  

**IP addresses, top families (7 days):** Unknown malware 1,220, VShell 339, Cobalt Strike 175, Sliver 134, Mirai 88  
**IP addresses, top command-and-control families:** Unknown malware 1,213, VShell 339, Cobalt Strike 175, Sliver 134, Mirai 81  
**Most reported ports:** 3333 (397), 443 (275), 3000 (267), 8877 (258), 80 (110), 8080 (103), 31337 (90), 8888 (84)  

**Also serving malware in URLhaus:** 38 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 4201 KB in 1.5 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 428 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 428 rows (last time 349) |
| ✅ | `threatfox: freshness` | newest hash is 4.5 h old |
| ✅ | `threatfox: freshness` | export file is 0.5 h old |
| ✅ | `threatfox: new items` | 79 new (recent average 33) |
| ❌ | `urlhaus: download` | https://urlhaus.abuse.ch/downloads/csv_recent/: HTTP 410 |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 4405 data lines parsed |
| ⚠️ | `threatfox domains: values valid` | 1 rows rejected |
| ✅ | `threatfox domains: volume` | 4393 rows (last time 4368) |
| ✅ | `threatfox domains: freshness` | newest entry is 0.7 h old |
| ✅ | `threatfox domains: freshness` | export file is 0.5 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 3277 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 2541 rows (last time 2540) |
| ✅ | `threatfox ips: freshness` | newest entry is 1.8 h old |
| ✅ | `threatfox ips: freshness` | export file is 0.5 h old |
| ✅ | `output safety` | 12 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
