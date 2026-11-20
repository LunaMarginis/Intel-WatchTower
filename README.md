# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-11-20 07:27 UTC · **Health:** ✅ all 29 checks passed

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 475 | 116,590 |
| New since the previous run | 49 | 116,281 |
| Added in the last 24 hours | 49 | 955 |
| Added in the last 7 days | 475 | 6,123 |
| Online right now | – | 91,302 (78%) |
| Period the export covers | 143.1 h | 30.3 days |
| Newest entry | 16.9 h ago | 0 min ago |

_URL data refreshed 2026-11-20 07:27 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **ZStealer** | 76 | ▲ +25 | `▃▁▇▁▁█▁` | 11-13 15:28 | 95% | ZStealer |
| 2 | **Raven Stealer** | 75 | ▲ +20 | `▇▁█▃▅▁▁` | 11-13 15:28 | 95% | – |
| 3 | **NjRAT** | 28 | ▲ +3 | `█▁▂▂▄▃▁` | 11-13 15:28 | 95% | Bladabindi, Lime-Worm |
| 4 | **RN Stealer** | 26 | ▼ -7 | `█▁▃▁▂▁▁` | 11-13 15:27 | 95% | – |
| 5 | **Formbook** | 22 | ▲ +11 | `▁▁▅██▁▁` | 11-13 15:27 | 95% | win.xloader |
| 6 | **SalatStealer** | 21 | ▼ -55 | `▅▁█▂▂▁▁` | 11-14 18:11 | 95% | – |
| 7 | **stealler** | 20 | ▲ +11 | `▃▁▃█▁▁▁` | 11-13 15:27 | 95% | – |
| 8 | **Agent Tesla** | 17 | ▲ +11 | `▁▁▂█▄▂▁` | 11-13 15:27 | 95% | AgenTesla, AgentTesla, Negasteal |
| 9 | **ValleyRAT** | 16 | ▲ +1 | `▄▁█▁▆▁▁` | 11-13 15:27 | 95% | Winos |
| 10 | **Vidar** | 15 | ▲ +7 | `▃▁█▃▁▁▁` | 11-13 15:28 | 95% | – |
**New hashes per day, last 14 days:** `▅▅▃▄▅▅▄▅▁█▅▅▃▁` (today 0, busiest day 140).

**Threat types:** payload 475  
**Reporter confidence in the latest export:** 95–95% (average 95%)  

_Archive: 2,387 hashes collected so far (kept up to 400 days)._

## 🔗 Malware URLs

**Added per day, last 14 days:** `▆█▅▄▆▄▄▄▅▃▄▇▆▁` (last 24 h: 955, last 7 d: 6,123).

#### Top tags (each tag counted on its own)

| Tag | URLs | Online |
|---|---|---|
| `github` | 98,568 | 88,860 |
| `zip` | 52,729 | 48,104 |
| `zapret` | 48,152 | 44,024 |
| `SmartLoader` | 39,165 | 36,395 |
| `SalatStealer` | 33,476 | 28,240 |
| `exe` | 5,385 | 3,946 |
| `elf` | 4,806 | – |
| `Mozi` | 4,071 | – |

_6,808 URLs (6%) carry no tag and are not counted above._

**Fastest growing this week:** `js` 1,121 (▲ +1118), `VSCode` 988 (🆕 new), `TxDataHiding` 740 (🆕 new), `DEVPOPPER` 603 (🆕 new), `DEVBOX` 368 (🆕 new), `github` 1,984 (▲ +185)

**Most common tag combinations:** `github + SmartLoader + zip` 37,095, `github + zapret` 20,987, `github + SalatStealer + zapret` 13,722, `github + SalatStealer + zapret + zip` 10,542, `exe + github + SalatStealer` 5,084

**Where it is hosted:** 13% of URLs sit on a bare IP address; 6,383 different hosts, 580 serving malware right now.  
**Abused platforms:** 85% of URLs sit on shared platforms: GitHub 98,699, Discord 246, GitLab 169, Google Drive 155, Cloudflare Workers 96, Dropbox 76  
**File types:** zip 63,155, rar 16,768, (none) 9,726, exe 9,446, bat 9,042, sh 4,315, woff2 771, jar 212  

_Platforms such as GitHub, Discord or Dropbox are counted apart: attackers abuse them, so a URL there says nothing about where the attacker is, and they must not be blocked because of this list._

## 🛰️ Command-and-control infrastructure

Domains and IP addresses reported to ThreatFox, with the malware family behind them (counts only).

|  | 🌐 Domains | 🖥️ IP addresses |
|---|---|---|
| In the latest export | 3,695 | 1,516 |
| New since the previous run | 156 | 282 |
| First reported, last 24 h | 137 | 265 |
| First reported, last 7 days | 3,693 | 1,424 |
| …of them command-and-control | 640 | 1,399 |
| …delivery and other | 3,053 | 25 |


**Domains, top families (7 days):** Unknown Loader 1,500, IClickFix 649, ClearFake 638, Vidar 307, Unknown malware 140  
**Domains, top command-and-control families:** Vidar 307, Unknown malware 95, WARDENStealer 72, Unknown Stealer 27, RevStealer 22  

**IP addresses, top families (7 days):** Unknown malware 794, Sliver 63, Cobalt Strike 53, VShell 43, Jackskid 42  
**IP addresses, top command-and-control families:** Unknown malware 787, Sliver 63, Cobalt Strike 53, VShell 43, Jackskid 42  
**Most reported ports:** 443 (303), 80 (209), 8080 (133), 8787 (109), 3333 (68), 31337 (58), 8443 (49), 8001 (37)  

**Also serving malware in URLhaus:** 54 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 5023 KB in 2.1 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 475 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 475 rows |
| ✅ | `threatfox: freshness` | newest hash is 16.9 h old |
| ✅ | `threatfox: freshness` | export file is 0.9 h old |
| ✅ | `threatfox: new items` | 49 new (recent average 30) |
| ✅ | `urlhaus: download` | 29694 KB in 3.4 s |
| ✅ | `urlhaus: columns` | all 7 needed columns present (2 others ignored) |
| ✅ | `urlhaus: lines read` | all 116590 data lines parsed |
| ✅ | `urlhaus: values valid` | every row passed validation |
| ✅ | `urlhaus: volume` | 116590 rows (last time 116328) |
| ✅ | `urlhaus: freshness` | export file is 0.4 h old |
| ✅ | `urlhaus: freshness` | newest URL is 0.4 h old |
| ✅ | `urlhaus: indicators` | 2120 new URLs and 138 status changes recorded |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 3698 data lines parsed |
| ✅ | `threatfox domains: values valid` | every row passed validation |
| ✅ | `threatfox domains: volume` | 3695 rows (last time 4060) |
| ✅ | `threatfox domains: freshness` | newest entry is 1.0 h old |
| ✅ | `threatfox domains: freshness` | export file is 0.9 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 1852 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 1516 rows (last time 1305) |
| ✅ | `threatfox ips: freshness` | newest entry is 2.0 h old |
| ✅ | `threatfox ips: freshness` | export file is 0.9 h old |
| ✅ | `output safety` | 15 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
