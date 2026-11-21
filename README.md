# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-11-21 19:25 UTC · **Health:** ✅ all 22 checks passed

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 482 | 116,063 |
| New since the previous run | 16 | 1,690 |
| Added in the last 24 hours | 151 | 1,690 |
| Added in the last 7 days | 482 | 7,242 |
| Online right now | – | 91,121 (79%) |
| Period the export covers | 134.9 h | 30.3 days |
| Newest entry | 2.9 h ago | 0 min ago |

_URL data refreshed 2026-11-21 07:21 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **ZStealer** | 113 | ▲ +98 | `▁▅▁▁▅▁█` | 11-16 16:28 | 95% | ZStealer |
| 2 | **Raven Stealer** | 76 | ▲ +9 | `▁▇▃▅▁▁█` | 11-16 01:41 | 95% | – |
| 3 | **Merdoor** | 40 | 🆕 new | `▁▁▁▁▁▁█` | 11-21 02:43 | 95% | – |
| 4 | **SalatStealer** | 23 | ▼ -55 | `▁█▂▂▁▁▆` | 11-16 01:40 | 95% | – |
| 5 | **Formbook** | 18 | ▲ +9 | `▁▅██▁▁▁` | 11-16 16:28 | 95% | win.xloader |
| 6 | **ValleyRAT** | 18 | ▲ +8 | `▁█▁▆▁▁▇` | 11-16 01:41 | 95% | Winos |
| 7 | **stealler** | 16 | ▼ -1 | `▁▃█▁▁▁▄` | 11-16 01:41 | 95% | – |
| 8 | **Agent Tesla** | 15 | ▲ +10 | `▁▂█▄▂▁▁` | 11-16 16:29 | 95% | AgenTesla, AgentTesla, Negasteal |
| 9 | **NjRAT** | 14 | ▼ -23 | `▁▄▄█▇▁▂` | 11-16 01:41 | 95% | Bladabindi, Lime-Worm |
| 10 | **XWorm** | 12 | ▲ +8 | `▁▃▄█▁▁▁` | 11-16 16:29 | 95% | – |
**New hashes per day, last 14 days:** `▅▃▄▄▅▄▅▁▇▄▄▃▁█` (today 151, busiest day 151).

**Threat types:** payload 482  
**Reporter confidence in the latest export:** 95–95% (average 95%)  

_Archive: 2,538 hashes collected so far (kept up to 400 days)._

## 🔗 Malware URLs

**Added per day, last 14 days:** `█▅▄▆▄▄▄▅▃▄▇▆▆▄` (last 24 h: 1,690, last 7 d: 7,242).

#### Top tags (each tag counted on its own)

| Tag | URLs | Online |
|---|---|---|
| `github` | 97,903 | 88,409 |
| `zip` | 51,213 | 46,791 |
| `zapret` | 48,201 | 44,074 |
| `SmartLoader` | 37,666 | 35,101 |
| `SalatStealer` | 33,574 | 28,345 |
| `exe` | 5,493 | 4,066 |
| `elf` | 4,582 | – |
| `Mozi` | 3,976 | – |

_7,295 URLs (6%) carry no tag and are not counted above._

**Fastest growing this week:** `js` 1,820 (▲ +1816), `VSCode` 1,597 (🆕 new), `TxDataHiding` 1,204 (🆕 new), `github` 2,820 (▲ +1092), `DEVPOPPER` 1,005 (🆕 new), `DEVBOX` 604 (🆕 new)

**Most common tag combinations:** `github + SmartLoader + zip` 35,796, `github + zapret` 21,041, `github + SalatStealer + zapret` 13,722, `github + SalatStealer + zapret + zip` 10,539, `exe + github + SalatStealer` 5,201

**Where it is hosted:** 13% of URLs sit on a bare IP address; 6,424 different hosts, 589 serving malware right now.  
**Abused platforms:** 85% of URLs sit on shared platforms: GitHub 98,034, Discord 259, GitLab 170, Google Drive 159, Cloudflare Workers 91, Dropbox 78  
**File types:** zip 61,680, rar 16,787, (none) 9,977, exe 9,545, bat 9,034, sh 4,345, woff2 1,370, jar 205  

_Platforms such as GitHub, Discord or Dropbox are counted apart: attackers abuse them, so a URL there says nothing about where the attacker is, and they must not be blocked because of this list._

## 🛰️ Command-and-control infrastructure

Domains and IP addresses reported to ThreatFox, with the malware family behind them (counts only).

|  | 🌐 Domains | 🖥️ IP addresses |
|---|---|---|
| In the latest export | 3,463 | 1,934 |
| New since the previous run | 177 | 271 |
| First reported, last 24 h | 556 | 359 |
| First reported, last 7 days | 3,462 | 1,841 |
| …of them command-and-control | 599 | 1,810 |
| …delivery and other | 2,863 | 31 |


**Domains, top families (7 days):** Unknown Loader 931, ClearFake 670, IClickFix 665, Skimer 333, Vidar 280  
**Domains, top command-and-control families:** Vidar 280, Unknown malware 83, Unknown Stealer 47, RevStealer 21, XWorm 19  

**IP addresses, top families (7 days):** Unknown malware 1,150, Sliver 77, Cobalt Strike 58, VShell 52, Mirai 40  
**IP addresses, top command-and-control families:** Unknown malware 1,141, Sliver 77, Cobalt Strike 58, VShell 52, PureRAT 39  
**Most reported ports:** 8080 (324), 443 (317), 80 (222), 8443 (174), 8787 (140), 31337 (68), 3333 (54), 8001 (34)  

**Also serving malware in URLhaus:** 69 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 5081 KB in 2.0 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 482 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 482 rows (last time 547) |
| ✅ | `threatfox: freshness` | newest hash is 2.9 h old |
| ✅ | `threatfox: freshness` | export file is 1.0 h old |
| ✅ | `threatfox: new items` | 16 new (recent average 39) |
| ✅ | `urlhaus: refresh` | not due: refreshed 2026-11-21 07:21 UTC (once a day) |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 3467 data lines parsed |
| ✅ | `threatfox domains: values valid` | every row passed validation |
| ✅ | `threatfox domains: volume` | 3463 rows (last time 3395) |
| ✅ | `threatfox domains: freshness` | newest entry is 1.0 h old |
| ✅ | `threatfox domains: freshness` | export file is 1.0 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 2305 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 1934 rows (last time 1695) |
| ✅ | `threatfox ips: freshness` | newest entry is 2.8 h old |
| ✅ | `threatfox ips: freshness` | export file is 1.0 h old |
| ✅ | `output safety` | 12 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
