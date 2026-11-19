# 🛰️ Intel WatchTower

Daily malware intelligence from abuse.ch: what is new, who is behind it, and whether this collection itself can be trusted today.

![collect](https://github.com/LunaMarginis/Intel-WatchTower/actions/workflows/collect.yml/badge.svg)

**Last run:** 2026-11-19 20:45 UTC · **Health:** ❌ **3 check(s) failed**: the affected data was kept from the previous good run.

## At a glance

|  | 🧬 ThreatFox · MD5 hashes | 🔗 URLhaus · malware URLs |
|---|---|---|
| In the latest export | 0 | 116,328 |
| New since the previous run | 0 | 115,359 |
| Added in the last 24 hours | 0 | 1,093 |
| Added in the last 7 days | 497 | 5,766 |
| Online right now | – | 91,282 (78%) |
| Period the export covers | 0.0 h | 30.3 days |
| Newest entry | n/a | 0 min ago |

_URL data refreshed 2026-11-19 08:47 UTC._

## 🧬 Malware hashes

### Top malware families · last 7 days

Unique MD5 hashes first reported in the last 7 days, against the 7 days before.

| # | Family | Hashes (7 d) | vs previous 7 d | Per day | First seen (UTC) | Confidence | Also known as |
|---|---|---|---|---|---|---|---|
| 1 | **Raven Stealer** | 78 | ▲ +27 | `▂▇▁█▃▅▁` | 11-12 22:30 | 95% | – |
| 2 | **ZStealer** | 44 | ▼ -7 | `▃▃▁█▁▁▁` | 11-13 15:28 | 95% | ZStealer |
| 3 | **NjRAT** | 43 | ▲ +37 | `▃█▁▂▂▄▁` | 11-12 22:30 | 95% | Bladabindi, Lime-Worm |
| 4 | **SalatStealer** | 29 | ▼ -39 | `▁▅▁█▂▂▁` | 11-12 22:30 | 95% | – |
| 5 | **Formbook** | 27 | ▲ +21 | `▅▁▁▅██▁` | 11-12 22:31 | 95% | win.xloader |
| 6 | **RN Stealer** | 27 | ▼ -5 | `█▅▁▂▁▁▁` | 11-12 22:31 | 95% | – |
| 7 | **stealler** | 20 | ▲ +11 | `▆▃▁▃█▁▁` | 11-13 15:27 | 95% | – |
| 8 | **KAgent** | 19 | 🆕 new | `▁▁▁▁▁▁▁` | 11-12 22:30 | 95% | – |
| 9 | **Agent Tesla** | 18 | ▲ +14 | `▃▁▁▂█▄▁` | 11-12 22:31 | 95% | AgenTesla, AgentTesla, Negasteal |
| 10 | **ValleyRAT** | 16 | ▲ +1 | `▂▄▁█▁▆▁` | 11-13 15:27 | 95% | Winos |
**New hashes per day, last 14 days:** `▆▅▅▃▄▅▅▄▅▁█▅▅▁` (today 0, busiest day 140).

**Threat types:** payload 497  

_Archive: 2,338 hashes collected so far (kept up to 400 days)._

## 🔗 Malware URLs

**Added per day, last 14 days:** `▄▆█▅▄▆▄▄▄▅▃▄▇▃` (last 24 h: 1,093, last 7 d: 5,766).

#### Top tags (each tag counted on its own)

| Tag | URLs | Online |
|---|---|---|
| `github` | 98,463 | 88,736 |
| `zip` | 52,871 | 48,248 |
| `zapret` | 48,433 | 44,292 |
| `SmartLoader` | 39,165 | 36,393 |
| `SalatStealer` | 33,587 | 28,341 |
| `exe` | 5,286 | 3,849 |
| `elf` | 4,909 | – |
| `Mozi` | 4,140 | – |

_6,630 URLs (6%) carry no tag and are not counted above._

**Fastest growing this week:** `js` 820 (▲ +817), `VSCode` 702 (🆕 new), `TxDataHiding` 509 (🆕 new), `DEVPOPPER` 422 (🆕 new), `DEVBOX` 299 (🆕 new), `ssh` 104 (▲ +58)

**Most common tag combinations:** `github + SmartLoader + zip` 37,075, `github + zapret` 20,951, `github + SalatStealer + zapret` 13,722, `github + SalatStealer + zapret + zip` 10,661, `exe + github + SalatStealer` 4,994

**Where it is hosted:** 13% of URLs sit on a bare IP address; 6,334 different hosts, 586 serving malware right now.  
**Abused platforms:** 86% of URLs sit on shared platforms: GitHub 98,595, Discord 240, GitLab 172, Google Drive 150, Cloudflare Workers 97, Dropbox 74  
**File types:** zip 63,306, rar 16,893, (none) 9,705, exe 9,342, bat 9,042, sh 4,287, woff2 541, jar 223  

_Platforms such as GitHub, Discord or Dropbox are counted apart: attackers abuse them, so a URL there says nothing about where the attacker is, and they must not be blocked because of this list._

## 🛰️ Command-and-control infrastructure

Domains and IP addresses reported to ThreatFox, with the malware family behind them (counts only).

|  | 🌐 Domains | 🖥️ IP addresses |
|---|---|---|
| In the latest export | 4,060 | 1,305 |
| New since the previous run | 72 | 47 |
| First reported, last 24 h | 199 | 142 |
| First reported, last 7 days | 4,059 | 1,219 |
| …of them command-and-control | 654 | 1,202 |
| …delivery and other | 3,405 | 17 |


**Domains, top families (7 days):** Unknown Loader 1,648, ClearFake 761, IClickFix 698, Vidar 297, Unknown malware 195  
**Domains, top command-and-control families:** Vidar 297, Unknown malware 134, WARDENStealer 70, ACR Stealer 28, RevStealer 20  

**IP addresses, top families (7 days):** Unknown malware 691, Cobalt Strike 45, Jackskid 45, Aisuru 37, VShell 36  
**IP addresses, top command-and-control families:** Unknown malware 686, Cobalt Strike 45, Jackskid 45, Aisuru 37, VShell 36  
**Most reported ports:** 443 (272), 80 (186), 8080 (130), 8787 (90), 8443 (49), 3333 (42), 8001 (37), 8888 (34)  

**Also serving malware in URLhaus:** 1 entries (the list itself is not published).

## Data health

|  | Check | Result |
|---|---|---|
| ❌ | `threatfox: download` | https://threatfox-api.abuse.ch/v2/files/exports/AUTH-KEY/full.csv.zip: HTTP 429 the server asks to wait 3.2 h (quota) not retrying |
| ✅ | `urlhaus: refresh` | not due: refreshed 2026-11-19 08:47 UTC (once a day) |
| ❌ | `threatfox domains: download` | the ThreatFox export could not be downloaded |
| ❌ | `threatfox ips: download` | the ThreatFox export could not be downloaded |
| ✅ | `output safety` | 5 published files contain no live URL |

## How this works

- **Runs** every 12 hours on GitHub Actions.
- **Checks** run on every download (format, row counts, freshness, valid values, nothing dropped). If a check fails, the affected data is **not** replaced and the workflow turns red.
- **Not verified:** these are community reports to abuse.ch. Treat every figure as a lead, not a verdict. False positives happen, especially for shared hosting.

Data: [abuse.ch ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/), used under the abuse.ch [terms of use](https://abuse.ch/terms-of-use/). This project only collects and summarises it.

_Generated by Intel WatchTower._
