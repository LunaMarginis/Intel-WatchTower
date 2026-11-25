# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-11-25 08:47 UTC · **Health:** ✅ all 29 checks passed

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 526 | 60,558 |
| New since the previous run | 100 | 616 |
| Added in the last 24 hours | 100 | 629 |
| Added in the last 7 days | 526 | 6,850 |
| Online right now | – | 38,838 (64%) |
| Period the export covers | 147.1 h | 30.4 days |
| Newest entry | 15.1 h ago | 0 min ago |

_URL data refreshed 2026-11-25 08:47 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **ZStealer** | 171 | ▲ +127 | `▄▁▅▁▁█▁` | 11-19 14:32 | 95% | ZStealer |
| 2 | **Raven Stealer** | 96 | ▲ +33 | `▁▁▅▁█▂▁` | 11-18 14:33 | 95% | – |
| 3 | **Merdoor** | 40 | 🆕 new | `▁▁█▁▁▁▁` | 11-21 02:43 | 95% | – |
| 4 | **NjRAT** | 26 | ▼ -12 | `▃▁▁▁█▁▁` | 11-18 14:33 | 95% | Bladabindi, Lime-Worm |
| 5 | **Vidar** | 21 | ▲ +6 | `▁▁▁▁█▁▁` | 11-23 00:45 | 95% | – |
| 6 | **ValleyRAT** | 18 | ▲ +7 | `▁▁▇▁█▁▁` | 11-18 14:33 | 95% | Winos |
| 7 | **Agent Tesla** | 14 | ▬ 0 | `▂▁▁▁█▁▁` | 11-18 14:33 | 95% | AgenTesla, AgentTesla, Negasteal |
| 8 | **Formbook** | 14 | ▼ -6 | `▁▁▁▁█▄▁` | 11-18 14:33 | 95% | win.xloader |
| 9 | **SalatStealer** | 14 | ▼ -13 | `▁▁█▁▅▁▁` | 11-18 14:33 | 95% | – |
| 10 | **XWorm** | 10 | ▲ +3 | `▁▁▁▁█▅▁` | 11-18 14:32 | 95% | – |
**New hashes per day, last 14 days:** `▅▄▅▁▇▄▄▃▁█▁█▆▁` (today 0, busiest day 155).

**Threat types:** payload 526  
**Reporter confidence in the latest export:** 95–95% (average 95%)  

_Archive: 2,793 hashes collected so far (kept up to 400 days)._

## 🔗 Malware URLs

**Added per day, last 14 days:** `▅▄▄▆▄▄█▇▆█▅▄▄▂` (last 24 h: 629, last 7 d: 6,850).

#### Top tags (each tag counted on its own)

| Tag | URLs | Online |
|---|---|---|
| `github` | 42,668 | 36,338 |
| `zapret` | 22,666 | 19,464 |
| `SalatStealer` | 21,979 | 17,720 |
| `zip` | 9,595 | 7,997 |
| `SmartLoader` | 8,043 | 7,557 |
| `Mozi` | 5,817 | – |
| `exe` | 4,776 | 3,536 |
| `mirai` | 4,741 | – |

_3,004 URLs (5%) carry no tag and are not counted above._

**Fastest growing this week:** `github` 3,271 (▲ +2102), `js` 2,091 (▲ +1725), `VSCode` 1,929 (▲ +1631), `TxDataHiding` 1,635 (▲ +1453), `DEVPOPPER` 1,403 (▲ +1221), `exe` 799 (▲ +727)

**Most common tag combinations:** `github + SalatStealer + zapret` 13,363, `github + zapret` 7,900, `github + SmartLoader + zip` 7,260, `exe + github + SalatStealer` 4,509, `github + SalatStealer` 3,574

**Where it is hosted:** 25% of URLs sit on a bare IP address; 6,343 different hosts, 536 serving malware right now.  
**Abused platforms:** 72% of URLs sit on shared platforms: GitHub 42,737, Discord 262, Google Drive 159, GitLab 127, Dropbox 79, Cloudflare Workers 79  
**File types:** zip 18,694, (none) 9,942, bat 9,037, exe 8,796, rar 4,561, sh 4,232, woff2 1,783, ps1 197  

_Platforms such as GitHub, Discord or Dropbox are counted apart: attackers abuse them, so a URL there says nothing about where the attacker is, and they must not be blocked because of this list._

## 🛰️ Command-and-control infrastructure

Domains and IP addresses reported to ThreatFox, with the malware family behind them (counts only).

|  | 🌐 Domains | 🖥️ IP addresses |
|---|---|---|
| In the latest export | 2,781 | 6,745 |
| New since the previous run | 186 | 596 |
| First reported, last 24 h | 191 | 699 |
| First reported, last 7 days | 2,781 | 6,476 |
| …of them command-and-control | 633 | 6,449 |
| …delivery and other | 2,148 | 27 |


**Domains, top families (7 days):** Unknown Webinject 878, Skimer 333, ClearFake 318, Vidar 246, Unknown Loader 212  
**Domains, top command-and-control families:** Vidar 246, Unknown malware 135, Unknown Stealer 61, XWorm 55, Agent Tesla 16  

**IP addresses, top families (7 days):** Unknown malware 5,796, Sliver 88, Cobalt Strike 70, VShell 59, PureRAT 51  
**IP addresses, top command-and-control families:** Unknown malware 5,787, Sliver 88, Cobalt Strike 70, VShell 59, PureRAT 51  
**Most reported ports:** 8787 (2,752), 443 (1,176), 8080 (586), 8443 (433), 80 (266), 8444 (256), 8666 (237), 3000 (175)  

**Also serving malware in URLhaus:** 64 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ✅ | `threatfox: download` | 5262 KB in 1.7 s |
| ✅ | `threatfox: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox: lines read` | all 526 data lines parsed |
| ✅ | `threatfox: values valid` | every row passed validation |
| ✅ | `threatfox: volume` | 526 rows |
| ✅ | `threatfox: freshness` | newest hash is 15.1 h old |
| ✅ | `threatfox: freshness` | export file is 0.4 h old |
| ✅ | `threatfox: new items` | 100 new (recent average 36) |
| ✅ | `urlhaus: download` | 14454 KB in 2.4 s |
| ✅ | `urlhaus: columns` | all 7 needed columns present (2 others ignored) |
| ✅ | `urlhaus: lines read` | all 60558 data lines parsed |
| ✅ | `urlhaus: values valid` | every row passed validation |
| ✅ | `urlhaus: volume` | 60558 rows (last time 83405) |
| ✅ | `urlhaus: freshness` | export file is 0.3 h old |
| ✅ | `urlhaus: freshness` | newest URL is 0.3 h old |
| ✅ | `urlhaus: indicators` | 616 new URLs and 433 status changes recorded |
| ✅ | `threatfox domains: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox domains: lines read` | all 2785 data lines parsed |
| ✅ | `threatfox domains: values valid` | every row passed validation |
| ✅ | `threatfox domains: volume` | 2781 rows (last time 3082) |
| ✅ | `threatfox domains: freshness` | newest entry is 0.5 h old |
| ✅ | `threatfox domains: freshness` | export file is 0.4 h old |
| ✅ | `threatfox ips: columns` | all 10 needed columns present (5 others ignored) |
| ✅ | `threatfox ips: lines read` | all 7902 data lines parsed |
| ✅ | `threatfox ips: values valid` | every row passed validation |
| ✅ | `threatfox ips: volume` | 6745 rows (last time 6398) |
| ✅ | `threatfox ips: freshness` | newest entry is 0.4 h old |
| ✅ | `threatfox ips: freshness` | export file is 0.4 h old |
| ✅ | `output safety` | 15 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
