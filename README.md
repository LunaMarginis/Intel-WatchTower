# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-11-26 21:41 UTC · **Health:** ⚠️ 28 checks passed, **1 warning(s)**: see Data health.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 590 | 41,739 |
| New since the previous run | 184 | 1,010 |
| Added in the last 24 hours | 85 | 749 |
| Added in the last 7 days | 590 | 5,985 |
| Online right now | – | 20,535 (49%) |
| Period the export covers | 136.0 h | 30.9 days |
| Newest entry | 3.0 h ago | 0 min ago |

_URL data refreshed 2026-11-26 21:41 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **ZStealer** | 207 | ▲ +131 | `▁▅▁▁█▆▁` | 11-21 02:44 | 95% | ZStealer |
| 2 | **Raven Stealer** | 101 | ▲ +22 | `▁▅▁█▂▂▃` | 11-21 02:42 | 95% | – |
| 3 | **Merdoor** | 40 | 🆕 new | `▁█▁▁▁▁▁` | 11-21 02:43 | 95% | – |
| 4 | **Vidar** | 34 | ▲ +19 | `▁▁▁█▁▄▂` | 11-23 00:45 | 95% | – |
| 5 | **NjRAT** | 24 | ▼ -23 | `▁▁▁█▁▁▄` | 11-21 02:43 | 95% | Bladabindi, Lime-Worm |
| 6 | **Agent Tesla** | 22 | ▲ +3 | `▁▁▁▆▁▁█` | 11-23 00:45 | 95% | AgenTesla, AgentTesla, Negasteal |
| 7 | **Formbook** | 21 | ▼ -6 | `▁▁▁▄▂▂█` | 11-23 15:29 | 95% | win.xloader |
| 8 | **ValleyRAT** | 18 | ▲ +2 | `▁▇▁█▁▁▆` | 11-21 02:42 | 95% | Winos |
| 9 | **SalatStealer** | 12 | ▼ -17 | `▁█▁▅▁▁▁` | 11-21 02:42 | 95% | – |
| 10 | **WannaCryptor** | 9 | ▼ -5 | `▁▄▁▂▁▂█` | 11-21 02:42 | 95% | Wana Decrypt0r, WannaCry, WannaCrypt |
**New hashes per day, last 14 days:** `▄▅▁▇▄▄▃▁█▁█▆▅▅` (today 85, busiest day 155).

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
| In the latest export | 3,599 | 7,462 |
| New since the previous run | 1,126 | 948 |
| First reported, last 24 h | 803 | 606 |
| First reported, last 7 days | 3,598 | 7,136 |
| …of them command-and-control | 602 | 7,101 |
| …delivery and other | 2,996 | 35 |


**Domains, top families (7 days):** Unknown Webinject 876, ClearFake 664, IClickFix 503, Unknown Loader 402, Skimer 333  
**Domains, top command-and-control families:** Vidar 243, Unknown malware 111, Unknown Stealer 62, XWorm 59, ACR Stealer 19  

**IP addresses, top families (7 days):** Unknown malware 6,477, Sliver 87, Cobalt Strike 80, VShell 54, Mirai 44  
**IP addresses, top command-and-control families:** Unknown malware 6,464, Sliver 87, Cobalt Strike 80, VShell 54, PureRAT 42  
**Most reported ports:** 8787 (2,947), 443 (1,384), 8080 (655), 8443 (439), 80 (337), 3000 (278), 8444 (256), 8666 (237)  

**Also serving malware in URLhaus:** 69 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 5352 KB in 1.6 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 590 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 590 rows (last time 526) |
| ✅ | `threatfox: freshness` | newest hash is 3.0 h old |
| ✅ | `threatfox: freshness` | export file is 1.5 h old |
| ⚠️ | `threatfox: new items` | 184 new far above the recent average of 38 |
| ✅ | `urlhaus: download` | 9482 KB in 1.8 s |
| ✅ | `urlhaus: columns` | all 7 needed columns present (2 others ignored) |
| ✅ | `urlhaus: lines read` | all 41739 data lines parsed |
| ✅ | `urlhaus: values valid` | every row passed validation |
| ✅ | `urlhaus: volume` | 41739 rows (last time 60558) |
| ✅ | `urlhaus: freshness` | export file is 0.4 h old |
| ✅ | `urlhaus: freshness` | newest URL is 0.4 h old |
| ✅ | `urlhaus: indicators` | 1010 new URLs and 618 status changes recorded |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 3602 data lines parsed |
| ✅ | `threatfox domains: values valid` | every row passed validation |
| ✅ | `threatfox domains: volume` | 3599 rows (last time 2781) |
| ✅ | `threatfox domains: freshness` | newest entry is 1.5 h old |
| ✅ | `threatfox domains: freshness` | export file is 1.5 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 8697 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 7462 rows (last time 6745) |
| ✅ | `threatfox ips: freshness` | newest entry is 1.9 h old |
| ✅ | `threatfox ips: freshness` | export file is 1.5 h old |
| ✅ | `output safety` | 15 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
