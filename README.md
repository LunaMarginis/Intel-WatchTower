# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-11-24 00:00 UTC · **Health:** ✅ all 22 checks passed

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 497 | 103,631 |
| New since the previous run | 70 | 1,795 |
| Added in the last 24 hours | 155 | 694 |
| Added in the last 7 days | 497 | 7,252 |
| Online right now | – | 79,603 (77%) |
| Period the export covers | 144.0 h | 30.3 days |
| Newest entry | 8.5 h ago | 0 min ago |

_URL data refreshed 2026-11-23 07:50 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **Raven Stealer** | 97 | ▲ +33 | `▃▁▁▅▁█▁` | 11-17 15:32 | 95% | – |
| 2 | **ZStealer** | 84 | ▲ +40 | `▁▅▁█▁▁▁` | 11-19 14:32 | 95% | ZStealer |
| 3 | **Merdoor** | 40 | 🆕 new | `▁▁▁█▁▁▁` | 11-21 02:43 | 95% | – |
| 4 | **NjRAT** | 28 | ▼ -10 | `▃▃▁▁▁█▁` | 11-17 15:32 | 95% | Bladabindi, Lime-Worm |
| 5 | **Agent Tesla** | 23 | ▲ +17 | `▄▂▁▁▁█▁` | 11-17 15:32 | 95% | AgenTesla, AgentTesla, Negasteal |
| 6 | **Vidar** | 23 | ▲ +10 | `▁▁▁▁▁█▁` | 11-17 15:33 | 95% | – |
| 7 | **Formbook** | 19 | ▲ +6 | `█▁▁▁▁▆▁` | 11-17 15:32 | 95% | win.xloader |
| 8 | **ValleyRAT** | 18 | ▲ +6 | `▆▁▁▇▁█▁` | 11-18 14:33 | 95% | Winos |
| 9 | **VShell** | 17 | 🆕 new | `▁▁▁▁▁█▁` | 11-17 15:33 | 95% | – |
| 10 | **SalatStealer** | 15 | ▼ -67 | `▃▁▁█▁▅▁` | 11-17 15:33 | 95% | – |
**New hashes per day, last 14 days:** `▄▅▄▅▁▇▄▄▃▁█▁█▁` (today 0, busiest day 155).

**Threat types:** payload 497  
**Reporter confidence in the latest export:** 95–95% (average 95%)  

_Archive: 2,693 hashes collected so far (kept up to 400 days)._

## 🔗 Malware URLs

**Added per day, last 14 days:** `▄▆▅▄▄▆▄▄█▇▆█▅▂` (last 24 h: 694, last 7 d: 7,252).

#### Top tags (each tag counted on its own)

| Tag | URLs | Online |
|---|---|---|
| `github` | 85,559 | 76,958 |
| `zapret` | 47,244 | 43,180 |
| `zip` | 38,040 | 34,499 |
| `SalatStealer` | 32,786 | 27,615 |
| `SmartLoader` | 25,520 | 23,790 |
| `Mozi` | 5,971 | – |
| `exe` | 5,669 | 4,264 |
| `mirai` | 4,790 | – |

_3,108 URLs (3%) carry no tag and are not counted above._

**Fastest growing this week:** `js` 2,406 (▲ +2402), `github` 3,440 (▲ +2184), `VSCode` 2,182 (🆕 new), `TxDataHiding` 1,789 (🆕 new), `DEVPOPPER` 1,557 (🆕 new), `DEVBOX` 604 (🆕 new)

**Most common tag combinations:** `github + SmartLoader + zip` 24,135, `github + zapret` 21,077, `github + SalatStealer + zapret` 13,770, `github + SalatStealer + zapret + zip` 9,506, `exe + github + SalatStealer` 5,401

**Where it is hosted:** 15% of URLs sit on a bare IP address; 6,370 different hosts, 537 serving malware right now.  
**Abused platforms:** 84% of URLs sit on shared platforms: GitHub 85,659, Discord 273, GitLab 172, Google Drive 144, Dropbox 87, Cloudflare Workers 82  
**File types:** zip 48,998, rar 16,337, (none) 9,970, exe 9,715, bat 9,035, sh 4,301, woff2 1,741, jar 191  

_Platforms such as GitHub, Discord or Dropbox are counted apart: attackers abuse them, so a URL there says nothing about where the attacker is, and they must not be blocked because of this list._

## 🛰️ Command-and-control infrastructure

Domains and IP addresses reported to ThreatFox, with the malware family behind them (counts only).

|  | 🌐 Domains | 🖥️ IP addresses |
|---|---|---|
| In the latest export | 3,221 | 6,156 |
| New since the previous run | 202 | 4,108 |
| First reported, last 24 h | 276 | 4,152 |
| First reported, last 7 days | 3,221 | 5,959 |
| …of them command-and-control | 616 | 5,933 |
| …delivery and other | 2,605 | 26 |


**Domains, top families (7 days):** Unknown Webinject 878, ClearFake 411, Unknown Loader 342, Skimer 333, IClickFix 328  
**Domains, top command-and-control families:** Vidar 244, Unknown malware 120, XWorm 54, Unknown Stealer 42, ACR Stealer 27  

**IP addresses, top families (7 days):** Unknown malware 5,293, Sliver 74, Cobalt Strike 65, VShell 52, PureRAT 49  
**IP addresses, top command-and-control families:** Unknown malware 5,282, Sliver 74, Cobalt Strike 65, VShell 52, PureRAT 49  
**Most reported ports:** 8787 (2,517), 443 (1,032), 8080 (621), 8443 (404), 80 (278), 8444 (254), 8666 (237), 31337 (69)  

**Also serving malware in URLhaus:** 61 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 5234 KB in 7.6 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 497 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 497 rows (last time 497) |
| ✅ | `threatfox: freshness` | newest hash is 8.5 h old |
| ✅ | `threatfox: freshness` | export file is 0.3 h old |
| ✅ | `threatfox: new items` | 70 new (recent average 36) |
| ✅ | `urlhaus: refresh` | not due: refreshed 2026-11-23 07:50 UTC (once a day) |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 3224 data lines parsed |
| ✅ | `threatfox domains: values valid` | every row passed validation |
| ✅ | `threatfox domains: volume` | 3221 rows (last time 3495) |
| ✅ | `threatfox domains: freshness` | newest entry is 0.3 h old |
| ✅ | `threatfox domains: freshness` | export file is 0.3 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 7299 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 6156 rows (last time 2232) |
| ✅ | `threatfox ips: freshness` | newest entry is 0.5 h old |
| ✅ | `threatfox ips: freshness` | export file is 0.3 h old |
| ✅ | `output safety` | 12 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
