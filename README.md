# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-11-27 08:45 UTC · **Health:** ⚠️ 21 checks passed, **1 warning(s)**: see Data health.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 590 | 41,739 |
| New since the previous run | 0 | 1,010 |
| Added in the last 24 hours | 85 | 749 |
| Added in the last 7 days | 590 | 5,985 |
| Online right now | – | 20,535 (49%) |
| Period the export covers | 136.0 h | 30.9 days |
| Newest entry | 14.1 h ago | 0 min ago |

_URL data refreshed 2026-11-26 21:41 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **ZStealer** | 207 | ▲ +131 | `▅▁▁█▆▁▁` | 11-21 02:44 | 95% | ZStealer |
| 2 | **Raven Stealer** | 101 | ▲ +26 | `▅▁█▂▂▃▁` | 11-21 02:42 | 95% | – |
| 3 | **Merdoor** | 40 | 🆕 new | `█▁▁▁▁▁▁` | 11-21 02:43 | 95% | – |
| 4 | **Vidar** | 34 | ▲ +19 | `▁▁█▁▄▂▁` | 11-23 00:45 | 95% | – |
| 5 | **NjRAT** | 24 | ▼ -4 | `▁▁█▁▁▄▁` | 11-21 02:43 | 95% | Bladabindi, Lime-Worm |
| 6 | **Agent Tesla** | 22 | ▲ +5 | `▁▁▆▁▁█▁` | 11-23 00:45 | 95% | AgenTesla, AgentTesla, Negasteal |
| 7 | **Formbook** | 21 | ▼ -1 | `▁▁▄▂▂█▁` | 11-23 15:29 | 95% | win.xloader |
| 8 | **ValleyRAT** | 18 | ▲ +2 | `▇▁█▁▁▆▁` | 11-21 02:42 | 95% | Winos |
| 9 | **SalatStealer** | 12 | ▼ -9 | `█▁▅▁▁▁▁` | 11-21 02:42 | 95% | – |
| 10 | **WannaCryptor** | 9 | ▼ -4 | `▄▁▂▁▂█▁` | 11-21 02:42 | 95% | Wana Decrypt0r, WannaCry, WannaCrypt |
**New hashes per day, last 14 days:** `▅▁▇▄▄▃▁█▁█▆▅▅▁` (today 0, busiest day 155).

**Threat types:** payload 590  
**Reporter confidence in the latest export:** 95–95% (average 95%)  

_Archive: 2,977 hashes collected so far (kept up to 400 days)._

## 🔗 Malware URLs

**Added per day, last 14 days:** `▄▄▆▄▄█▇▆█▅▄▄▄▃` (last 24 h: 749, last 7 d: 5,985).

#### Top tags (each tag counted on its own)

| Tag | URLs | Online |
|---|---|---|
| `github` | 23,648 | 18,008 |
| `SalatStealer` | 14,651 | 10,456 |
| `zapret` | 12,600 | 9,655 |
| `Mozi` | 5,838 | – |
| `mirai` | 4,816 | – |
| `elf` | 4,587 | – |
| `zip` | 3,674 | 2,458 |
| `exe` | 3,055 | 1,850 |

_3,044 URLs (7%) carry no tag and are not counted above._

**Fastest growing this week:** `github` 2,523 (▲ +531), `exe` 679 (▲ +405), `DEVPOPPER` 991 (▲ +388), `TxDataHiding` 1,086 (▲ +346), `VSCode` 1,254 (▲ +266), `SalatStealer` 727 (▲ +254)

**Most common tag combinations:** `github + SalatStealer + zapret` 8,784, `Mozi` 3,417, `exe + github + SalatStealer` 2,824, `mirai` 2,677, `github + SalatStealer` 2,593

**Where it is hosted:** 37% of URLs sit on a bare IP address; 6,461 different hosts, 570 serving malware right now.  
**Abused platforms:** 59% of URLs sit on shared platforms: GitHub 23,711, Discord 258, Google Drive 143, GitLab 114, Dropbox 86, Cloudflare Workers 76  
**File types:** (none) 10,028, zip 9,865, bat 5,983, exe 4,495, sh 4,299, woff2 1,796, rar 1,729, ps1 205  

_Platforms such as GitHub, Discord or Dropbox are counted apart: attackers abuse them, so a URL there says nothing about where the attacker is, and they must not be blocked because of this list._

## 🛰️ Command-and-control infrastructure

Domains and IP addresses reported to ThreatFox, with the malware family behind them (counts only).

|  | 🌐 Domains | 🖥️ IP addresses |
|---|---|---|
| In the latest export | 3,617 | 7,770 |
| New since the previous run | 90 | 459 |
| First reported, last 24 h | 386 | 782 |
| First reported, last 7 days | 3,616 | 7,435 |
| …of them command-and-control | 604 | 7,383 |
| …delivery and other | 3,012 | 52 |


**Domains, top families (7 days):** Unknown Webinject 876, ClearFake 676, IClickFix 503, Unknown Loader 403, Skimer 333  
**Domains, top command-and-control families:** Vidar 242, Unknown malware 122, Unknown Stealer 62, XWorm 60, ACR Stealer 19  

**IP addresses, top families (7 days):** Unknown malware 6,791, Cobalt Strike 77, Sliver 72, VShell 59, Mirai 43  
**IP addresses, top command-and-control families:** Unknown malware 6,769, Cobalt Strike 77, Sliver 72, VShell 59, PureRAT 38  
**Most reported ports:** 8787 (3,047), 443 (1,510), 8080 (657), 8443 (439), 80 (374), 3000 (279), 8444 (256), 8666 (237)  

**Also serving malware in URLhaus:** 76 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 5368 KB in 2.0 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 590 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 590 rows (last time 590) |
| ✅ | `threatfox: freshness` | newest hash is 14.1 h old |
| ✅ | `threatfox: freshness` | export file is 1.2 h old |
| ⚠️ | `threatfox: new items` | 0 new far below the recent average of 53 |
| ✅ | `urlhaus: refresh` | not due: refreshed 2026-11-26 21:41 UTC (once a day) |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 3620 data lines parsed |
| ✅ | `threatfox domains: values valid` | every row passed validation |
| ✅ | `threatfox domains: volume` | 3617 rows (last time 3599) |
| ✅ | `threatfox domains: freshness` | newest entry is 1.2 h old |
| ✅ | `threatfox domains: freshness` | export file is 1.2 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 9190 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 7770 rows (last time 7462) |
| ✅ | `threatfox ips: freshness` | newest entry is 1.7 h old |
| ✅ | `threatfox ips: freshness` | export file is 1.2 h old |
| ✅ | `output safety` | 11 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
