# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-11-24 22:33 UTC · **Health:** ❌ **3 check(s) failed**: the affected data was kept from the previous good run.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 0 | 83,405 |
| New since the previous run | 0 | 739 |
| Added in the last 24 hours | 0 | 682 |
| Added in the last 7 days | 426 | 7,361 |
| Online right now | – | 60,799 (73%) |
| Period the export covers | 0.0 h | 30.4 days |
| Newest entry | n/a | 0 min ago |

_URL data refreshed 2026-11-24 10:02 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **Raven Stealer** | 91 | ▲ +22 | `▃▁▁▅▁█▁` | 11-18 14:33 | 95% | – |
| 2 | **ZStealer** | 84 | ▲ +40 | `▁▅▁█▁▁▁` | 11-19 14:32 | 95% | ZStealer |
| 3 | **Merdoor** | 40 | 🆕 new | `▁▁▁█▁▁▁` | 11-21 02:43 | 95% | – |
| 4 | **NjRAT** | 26 | ▼ -12 | `▃▃▁▁▁█▁` | 11-18 14:33 | 95% | Bladabindi, Lime-Worm |
| 5 | **Vidar** | 21 | ▲ +6 | `▁▁▁▁▁█▁` | 11-23 00:45 | 95% | – |
| 6 | **ValleyRAT** | 18 | ▲ +7 | `▆▁▁▇▁█▁` | 11-18 14:33 | 95% | Winos |
| 7 | **Agent Tesla** | 14 | ▼ -1 | `▄▂▁▁▁█▁` | 11-18 14:33 | 95% | AgenTesla, AgentTesla, Negasteal |
| 8 | **SalatStealer** | 14 | ▼ -68 | `▃▁▁█▁▅▁` | 11-18 14:33 | 95% | – |
| 9 | **Formbook** | 12 | ▼ -8 | `█▁▁▁▁▆▁` | 11-18 14:33 | 95% | win.xloader |
| 10 | **XWorm** | 9 | ▲ +1 | `█▁▁▁▁▃▁` | 11-18 14:32 | 95% | – |
**New hashes per day, last 14 days:** `▄▅▄▅▁▇▄▄▃▁█▁█▁` (today 0, busiest day 155).

**Threat types:** payload 426  

_Archive: 2,693 hashes collected so far (kept up to 400 days)._

## 🔗 Malware URLs

**Added per day, last 14 days:** `▆▅▄▄▆▄▄█▇▆█▅▄▂` (last 24 h: 682, last 7 d: 7,361).

#### Top tags (each tag counted on its own)

| Tag | URLs | Online |
|---|---|---|
| `github` | 65,282 | 58,175 |
| `zapret` | 39,675 | 36,079 |
| `SalatStealer` | 25,282 | 20,579 |
| `zip` | 17,598 | 15,504 |
| `SmartLoader` | 12,674 | 11,971 |
| `Mozi` | 5,909 | – |
| `exe` | 5,786 | 4,382 |
| `mirai` | 4,861 | – |

_3,045 URLs (4%) carry no tag and are not counted above._

**Fastest growing this week:** `github` 3,523 (▲ +2574), `js` 2,391 (▲ +2360), `VSCode` 2,172 (▲ +2153), `TxDataHiding` 1,783 (▲ +1773), `DEVPOPPER` 1,551 (▲ +1541), `exe` 732 (▲ +708)

**Most common tag combinations:** `github + zapret` 21,130, `github + SalatStealer + zapret` 13,770, `github + SmartLoader + zip` 11,592, `exe + github + SalatStealer` 5,519, `github + SalatStealer` 3,575

**Where it is hosted:** 18% of URLs sit on a bare IP address; 6,368 different hosts, 550 serving malware right now.  
**Abused platforms:** 79% of URLs sit on shared platforms: GitHub 65,359, Discord 260, GitLab 174, Google Drive 143, Dropbox 79, Cloudflare Workers 79  
**File types:** zip 32,372, rar 12,554, (none) 9,988, exe 9,836, bat 9,036, sh 4,264, woff2 1,747, jar 186  

_Platforms such as GitHub, Discord or Dropbox are counted apart: attackers abuse them, so a URL there says nothing about where the attacker is, and they must not be blocked because of this list._

## 🛰️ Command-and-control infrastructure

Domains and IP addresses reported to ThreatFox, with the malware family behind them (counts only).

|  | 🌐 Domains | 🖥️ IP addresses |
|---|---|---|
| In the latest export | 3,082 | 6,398 |
| New since the previous run | 70 | 333 |
| First reported, last 24 h | 233 | 4,417 |
| First reported, last 7 days | 3,081 | 6,186 |
| …of them command-and-control | 615 | 6,160 |
| …delivery and other | 2,466 | 26 |


**Domains, top families (7 days):** Unknown Webinject 878, ClearFake 380, Skimer 333, IClickFix 313, Unknown Loader 277  
**Domains, top command-and-control families:** Vidar 245, Unknown malware 120, XWorm 54, Unknown Stealer 42, ACR Stealer 25  

**IP addresses, top families (7 days):** Unknown malware 5,506, Sliver 79, Cobalt Strike 66, VShell 53, PureRAT 47  
**IP addresses, top command-and-control families:** Unknown malware 5,495, Sliver 79, Cobalt Strike 66, VShell 53, PureRAT 47  
**Most reported ports:** 8787 (2,612), 443 (1,083), 8080 (634), 8443 (409), 80 (272), 8444 (254), 8666 (237), 3000 (108)  

**Also serving malware in URLhaus:** 65 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ❌ | `threatfox: download` | https://threatfox-api.abuse.ch/v2/files/exports/AUTH-KEY/full.csv.zip: HTTP 429 the server asks to wait 1.4 h (quota) not retrying |
| ✅ | `urlhaus: refresh` | not due: refreshed 2026-11-24 10:02 UTC (once a day) |
| ❌ | `threatfox domains: download` | the ThreatFox export could not be downloaded |
| ❌ | `threatfox ips: download` | the ThreatFox export could not be downloaded |
| ✅ | `output safety` | 5 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
