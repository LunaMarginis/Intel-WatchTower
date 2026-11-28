# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-11-28 07:59 UTC · **Health:** ⚠️ 21 checks passed, **1 warning(s)**: see Data health.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 508 | 41,045 |
| New since the previous run | 0 | 1,110 |
| Added in the last 24 hours | 53 | 1,110 |
| Added in the last 7 days | 508 | 6,000 |
| Online right now | – | 20,517 (50%) |
| Period the export covers | 142.0 h | 30.9 days |
| Newest entry | 17.5 h ago | 0 min ago |

_URL data refreshed 2026-11-27 21:26 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **ZStealer** | 200 | ▲ +80 | `▁▁█▆▁▅▁` | 11-24 17:36 | 95% | ZStealer |
| 2 | **Raven Stealer** | 79 | ▼ -16 | `▁█▂▂▃▁▁` | 11-21 16:32 | 95% | – |
| 3 | **Vidar** | 36 | ▲ +25 | `▁█▁▄▂▂▁` | 11-23 00:45 | 95% | – |
| 4 | **NjRAT** | 25 | ▼ -1 | `▁█▁▁▄▂▁` | 11-23 00:45 | 95% | Bladabindi, Lime-Worm |
| 5 | **Agent Tesla** | 22 | ▲ +7 | `▁▆▁▁█▁▁` | 11-23 00:45 | 95% | AgenTesla, AgentTesla, Negasteal |
| 6 | **Formbook** | 22 | ▲ +4 | `▁▄▂▂█▂▁` | 11-23 15:29 | 95% | win.xloader |
| 7 | **ValleyRAT** | 14 | ▼ -5 | `▁█▁▁▆▁▁` | 11-21 16:33 | 95% | Winos |
| 8 | **MASS Logger** | 8 | ▬ 0 | `▁█▁▁█▁▁` | 11-23 15:29 | 95% | – |
| 9 | **VShell** | 8 | ▼ -1 | `▁█▁▁▁▁▁` | 11-23 00:46 | 95% | – |
| 10 | **WannaCryptor** | 8 | ▼ -4 | `▁▂▁▂█▁▁` | 11-21 16:32 | 95% | Wana Decrypt0r, WannaCry, WannaCrypt |
**New hashes per day, last 14 days:** `▁▇▄▄▃▁█▁█▆▅▅▃▁` (today 0, busiest day 155).

**Threat types:** payload 508  
**Reporter confidence in the latest export:** 95–95% (average 95%)  

_Archive: 3,030 hashes collected so far (kept up to 400 days)._

## 🔗 Malware URLs

**Added per day, last 14 days:** `▄▆▄▄█▇▆█▅▄▄▄▄▆` (last 24 h: 1,110, last 7 d: 6,000).

#### Top tags (each tag counted on its own)

| Tag | URLs | Online |
|---|---|---|
| `github` | 23,554 | 17,851 |
| `SalatStealer` | 14,199 | 10,013 |
| `zapret` | 12,558 | 9,649 |
| `Mozi` | 5,746 | – |
| `mirai` | 4,608 | – |
| `elf` | 4,184 | – |
| `zip` | 3,955 | 2,739 |
| `exe` | 3,014 | 1,849 |

_2,999 URLs (7%) carry no tag and are not counted above._

**Fastest growing this week:** `luajit` 379 (🆕 new), `SmartLoader` 537 (▲ +367), `zip` 629 (▲ +345), `mirai` 1,095 (▲ +229), `github-pages` 133 (🆕 new), `fake-repo` 117 (🆕 new)

**Most common tag combinations:** `github + SalatStealer + zapret` 8,784, `Mozi` 3,394, `exe + github + SalatStealer` 2,824, `mirai` 2,686, `github + zapret` 2,483

**Where it is hosted:** 36% of URLs sit on a bare IP address; 6,417 different hosts, 584 serving malware right now.  
**Abused platforms:** 59% of URLs sit on shared platforms: GitHub 23,500, Discord 247, Google Drive 141, GitLab 104, Dropbox 89, Cloudflare Workers 71  
**File types:** zip 10,128, (none) 9,865, bat 5,976, sh 4,229, exe 4,155, woff2 1,799, rar 1,538, ps1 191  

_Platforms such as GitHub, Discord or Dropbox are counted apart: attackers abuse them, so a URL there says nothing about where the attacker is, and they must not be blocked because of this list._

## 🛰️ Command-and-control infrastructure

Domains and IP addresses reported to ThreatFox, with the malware family behind them (counts only).

|  | 🌐 Domains | 🖥️ IP addresses |
|---|---|---|
| In the latest export | 3,296 | 8,336 |
| New since the previous run | 100 | 314 |
| First reported, last 24 h | 196 | 835 |
| First reported, last 7 days | 3,295 | 7,965 |
| …of them command-and-control | 600 | 7,908 |
| …delivery and other | 2,695 | 57 |


**Domains, top families (7 days):** Unknown Webinject 878, ClearFake 686, IClickFix 510, Unknown Loader 428, Vidar 242  
**Domains, top command-and-control families:** Vidar 242, Unknown malware 120, XWorm 53, Unknown Stealer 39, WARDENStealer 25  

**IP addresses, top families (7 days):** Unknown malware 7,356, Cobalt Strike 72, Sliver 62, VShell 60, PureRAT 42  
**IP addresses, top command-and-control families:** Unknown malware 7,337, Cobalt Strike 72, Sliver 62, VShell 60, PureRAT 41  
**Most reported ports:** 8787 (3,265), 443 (1,698), 8080 (684), 80 (435), 8443 (338), 3000 (306), 8444 (257), 8666 (237)  

**Also serving malware in URLhaus:** 86 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 5408 KB in 2.1 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 508 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 508 rows (last time 643) |
| ✅ | `threatfox: freshness` | newest hash is 17.5 h old |
| ✅ | `threatfox: freshness` | export file is 0.6 h old |
| ⚠️ | `threatfox: new items` | 0 new far below the recent average of 58 |
| ✅ | `urlhaus: refresh` | not due: refreshed 2026-11-27 21:26 UTC (once a day) |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 3298 data lines parsed |
| ✅ | `threatfox domains: values valid` | every row passed validation |
| ✅ | `threatfox domains: volume` | 3296 rows (last time 3608) |
| ✅ | `threatfox domains: freshness` | newest entry is 0.6 h old |
| ✅ | `threatfox domains: freshness` | export file is 0.6 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 9904 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 8336 rows (last time 8132) |
| ✅ | `threatfox ips: freshness` | newest entry is 0.6 h old |
| ✅ | `threatfox ips: freshness` | export file is 0.6 h old |
| ✅ | `output safety` | 11 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
