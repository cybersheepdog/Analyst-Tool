# Analyst Tool — Lookups & Features Guide (for Analysts)

A practical, day-to-day guide to everything the tool can look up and how to read
what it gives back. For installing/connecting see `QUICKSTART.md` and (for the
shared database) `ANALYST_REMOTE_DB_GUIDE.md`.

---

## How you use it

You don't type commands or paste into a prompt. The tool watches your clipboard:

1. Start it (terminal: `python analyst_tool.py`; Jupyter: run `analyst()`).
2. **Copy** an indicator — an IP, hash, domain, URL, MITRE ID, port number, etc.
3. The report appears automatically. Copy the next indicator for the next report.

It only reacts when the clipboard **changes**, so if nothing happens, copy the
value again. Everything is **passive** — the tool only *reads* from each service's
API; it never submits an indicator for active scanning.

You can copy **defanged** indicators straight out of a report or email —
`hxxps://evil[.]com`, `8[.]8[.]8[.]8`, `bad(dot)com`, `user[at]evil[.]com` — and
the tool re-fangs them automatically before looking them up.

### Reading the output

- **Colors flag severity.** Red = high / notable-bad, orange = medium, green =
  noteworthy (e.g. a Tor exit node or a detected beacon). Headings are underlined
  or bold.
- **Indicators are "defanged"** so you can't fatfinger a click: URLs show as
  `hxxp://` / `hxxps://` and dotted values as `example[.]com`.
- **A cached result** shows a dim `(cached result — N days old, M lookups)` marker
  and costs no API call.
- **A multi-user notice** (`*** MULTI-USER NOTICE: …`) appears at the top of a
  report when more than one analyst has recently checked the same indicator.
- **A one-line verdict** opens every IP/hash/domain/URL report, e.g.
  `VERDICT: Likely malicious — VirusTotal 12 malicious; AbuseIPDB 97%; VPN egress`.
  It's a quick-triage summary of the detail below — red = likely malicious,
  orange = suspicious.
- **A `*** TEAM NOTES ***` block** appears at the very top when the indicator has
  shared notes — durable context a teammate (or you) left, with author, date, and
  colour-coded tags. See "Leaving notes for the team" below.

---

## What you can copy — and what you get back

The tool figures out the indicator type automatically. Below is each type, what
triggers it, and how to interpret the result.

### 1. IP address (public IPv4) — the full report

Copy any public IPv4 (e.g. `45.145.66.165`) and the tool queries every enabled
service at once and prints one combined report.

**VirusTotal Detections** — how many engines flagged the IP, by category
(Malicious, Malware, Suspicious, Phishing, Spam, plus Clean / Undetected / Time
Out). Counts turn **orange at ≥5** and **red at ≥10** engines — a handful of
malicious hits is worth noting; double digits is a strong signal.

**Shodan** — what's exposed on the host: Last Seen, Open Ports, Domains, and
Hostnames. It also runs **Cobalt Strike beacon detection**: "No", "Yes, but no
config info", or "Yes" with the recovered beacon config (port, beacon type,
spawn-to, sleep time, HTTP GET URI, watermark, and a VirusTotal link for the
process-inject stub hash). A "Yes" here is a high-value finding.

**IP Information (WhoIs)** — Organization, CIDR, IP Range, Country, and any abuse
contact emails. Good for attribution and for spotting bulletproof/abuse-prone
hosting.

**TOR Exit Node** — `Yes` (green) means traffic from this IP may be anonymized Tor
egress; treat sourcing/attribution accordingly.

**VPN Provider** — `Yes` (highlighted in orange) means the IP falls within a known
commercial VPN provider's network (matched against the daily-updated X4BNet list,
no API key). It's a heuristic, IPv4 signal: a match tells you the "real" source is
hidden behind a VPN, so weigh geolocation and attribution accordingly. Pair it with
the WhoIs Organization/ASN, which often names the provider. A `No` doesn't fully
rule out a VPN (residential/obscure ones may not be listed).

**Datacenter/Hosting** — `Yes` (yellow) means the IP is in datacenter/hosting space
rather than a residential/consumer ISP. Most VPNs, proxies, scanners, and C2 run
from hosting, so this is a useful "non-residential source" signal even when the VPN
list doesn't have a specific match.

**Abuse IP DB** — community abuse reporting. The **Abuse Confidence Score** is the
headline: **orange at ≥40%, red at ≥70%**. Also shows Total Reports, Last Reported,
Distinct Reporters, Usage Type, and Domain. Many recent reports from many distinct
reporters is a strong abuse signal. (You may also see a quota warning as you near
your daily AbuseIPDB limit.)

**AlienVault OTX** — threat-intel context: Related Pulses (how many community
reports reference this IP), Reputation, and Passive DNS (domains that have resolved
to it; if five or fewer, each is listed with first/last-seen dates). If your team
configured trusted "intel providers", pulses from those authors are highlighted
with extra detail.

**OpenCTI** — your organization's own intel platform, if connected: whether the
indicator is Active, a Malicious score (**orange ≥50, red ≥75**), Confidence
(Low / Medium / High), Source, Tags, and TLP marking, plus a dashboard link.

**C2 Live** — whether the IP appears in your team's tracked command-and-control
data, and which frameworks, with first/last-seen dates. "IP not found in tracked
C2's" is the normal/clean result.

> A **private (RFC1918) IP** — `10.x`, `172.16–31.x`, `192.168.x` — just returns a
> note that it's internal; no external lookups are done.

### 2. IPv6 address

Returns WhoIs information (Organization, CIDR, Range, Country, abuse emails). The
external reputation services above are IPv4-focused.

### 3. File hash (MD5, SHA-1, or SHA-256)

Copy a 32-, 40-, or 64-character hex hash. You get, in parallel:

**VirusTotal** —
- *File Reputation*: Malicious / Suspicious counts (orange ≥5, red ≥10), plus
  Harmless and Undetected.
- *File Threat Classification* and *File Threat Name*: the malware family/category
  labels VT's engines agree on (e.g. trojan, ransomware) with vote counts.
- *File Info*: signature status and signer(s), file type, product, copyright,
  creation and last-modification dates. An invalid/absent signature on something
  claiming to be a known product is a red flag.
- *Submission Info*: first/last submission, last analysis, and times submitted.

**OpenCTI** — Active status, Malicious score, Confidence, Source, Tags, TLP, and a
"Rule" field (a YARA rule if one exists, otherwise a note that there isn't one).

**AlienVault OTX** — Related Pulses and any Contacted Domains/IPs observed from
sandbox analysis (with whitelisted flags). Helpful for pivoting to network IOCs.

### 4. Domain

Copy a domain (e.g. `example.com`). In parallel:

**VirusTotal** — Last Analysis Stats (the same Malicious/Malware/Suspicious/
Phishing/Spam categories, orange ≥5 / red ≥10), Domain Info (creation, last-update,
last-modification dates — a very recently created domain is a classic phishing
tell), and Certificate Info (issuer, validity dates).

**OpenCTI** — Active / Malicious / Confidence / Source / Tags / TLP (the domain is
shown defanged as `example[.]com`).

**AlienVault OTX** — Related Pulses count and a link for deeper context.

**DNS & Certificate Transparency** — the domain's resolved A/AAAA addresses (each
with a reverse PTR), MX/NS records (when the optional `dnspython` package is
installed), and subdomains observed in Certificate Transparency logs via crt.sh.
Great for pivoting — the resolved IPs and sibling subdomains often expand an
investigation quickly.

> Domain detection can fire on dotted strings that aren't real domains (e.g.
> `first.last`). If you get a domain report you didn't expect, that's why — just
> ignore it.

### 5. URL

Copy a full URL. The URL is shown defanged (`hxxps://…`). You get:

**VirusTotal** — detection counts, Tags, Threat Names, and submission dates
(last analysis, first/last submission, times submitted) with a link.

**OpenCTI** — matched to the exact URL; if found, Active / Malicious / Confidence /
Source / Tags / TLP; otherwise "URL not found in OpenCTI".

**AlienVault OTX** — Related Pulses and a link.

### 6. MITRE ATT&CK ID

Copy a tactic (`TA0001`), technique (`T1059`), or sub-technique (`T1059.001`):

- **Tactic** → its name, the ATT&CK URL, and the description.
- **Technique** → name, description, and **Detection** guidance (what to look for).
- **Sub-technique** → its parent tactic and technique, the sub-technique name and
  URL, description, and detection guidance.

In a Jupyter notebook the descriptions render as formatted Markdown; in a terminal
they print as plain text.

### 7. LOLBAS — living-off-the-land binary

Copy a binary name (e.g. `certutil.exe`). If it's a known LOLBin you get its Name,
Description, Full Path(s), example **Commands** (each with its description, use
case, required privileges, and MITRE technique ID), known **IOCs**, and the LOLBAS
project URL. Use this to understand how a legitimate Windows binary can be abused.

### 8. LOLDriver — vulnerable/malicious driver

Copy a driver filename. For a known entry you get its Name, Description, MITRE ID,
the command/operating-system/privileges/use-case details, reference Resources, and
the LOLDrivers URL. Useful for BYOVD (bring-your-own-vulnerable-driver) triage.

### 9. Port number or Windows Event ID

Copy a 1–5 digit number. Because the same number could be either, the tool gives
you **both**: a SpeedGuide reference link for that **port**, and an Ultimate Windows
Security reference link for that **Windows Event ID**. Click whichever you meant.

### 10. Epoch timestamp

Copy a 10–16 digit Unix timestamp (optionally with a decimal) and it's converted to
a human-readable date/time — handy when a log gives you raw epoch values.

### 11. OTX Pulse ID

Copy a 24-character hex AlienVault OTX pulse ID to pull the full pulse: author
(highlighted if they're one of your trusted providers), name, TLP, created/modified
dates, tags, malware families, description, and references.

### 12. CVE id

Copy a CVE id (e.g. `CVE-2021-44228`) to get:

**CISA KEV status (shown first)** — whether the CVE is on CISA's Known Exploited
Vulnerabilities catalog. A `YES` (red) is a strong "patch now" signal: it means the
vulnerability is known to be exploited in the wild. When listed, you also see the
date added, the required action, the due date, and whether it's used in known
ransomware campaigns.

**NVD details** — the CVSS base score and severity (red for High/Critical, orange
for Medium), the attack vector, publish date, description, and reference links.

---

## Services at a glance

| Service | Applies to | Tells you |
|---------|-----------|-----------|
| VirusTotal | IP, hash, domain, URL | Multi-engine detections, file/domain metadata |
| AbuseIPDB | IP | Community abuse score & reports |
| Shodan | IP | Exposed ports/services + Cobalt Strike beacons |
| AlienVault OTX | IP, hash, domain, URL, pulse | Threat-intel pulses, passive DNS |
| OpenCTI | IP, hash, domain, URL | Your org's intel (score, confidence, TLP) |
| C2 Live | IP | Your tracked C2 infrastructure |
| WhoIs | IP (v4/v6) | Ownership, range, country, abuse contact |
| Tor check | IP | Known Tor exit node? |
| VPN check | IP (IPv4) | In a known commercial VPN range? (X4BNet, no key) |
| Datacenter check | IP (IPv4) | In datacenter/hosting space? (X4BNet, no key) |
| DNS + crt.sh | Domain | Resolved IPs/PTR, MX/NS, subdomains from CT logs |
| CVE / CISA KEV | CVE id | NVD details + known-exploited status |
| MITRE ATT&CK | tactic/technique IDs | Definitions + detection guidance |
| LOLBAS / LOLDrivers | filenames | How a binary/driver gets abused |

A service that your team hasn't configured simply shows "not configured" in its
section rather than failing — the rest of the report still runs.

---

## Saving API calls & seeing teammates' activity

If your team uses the shared cache, repeat lookups within the freshness window
(default 7 days) are served from the database instead of spending an API call:

![Cached result example](graphics/screenshot_cached_hit.svg)

And when more than one analyst has checked the same indicator recently, you'll see a
heads-up so you know a colleague may already be on it:

![Multi-user notice example](graphics/screenshot_multiuser_notice.svg)

Need a guaranteed-fresh result? Copy the indicator with a `!` in front (e.g.
`!8.8.8.8`) to bypass the cache for that one lookup. Full details are in
`ANALYST_REMOTE_DB_GUIDE.md`.

---

## Leaving notes for the team

You can attach a note or tags to an indicator so your teammates (and future you)
see it automatically on the next lookup. Looking things up is unchanged — only
clipboard lines starting with `>>` are treated as commands.

The easiest way: copy the short trigger `>>note 45.145.66.165`, and the tool
prompts you to type the note:

![Adding a note](graphics/screenshot_add_note.svg)

And the note then appears at the top of everyone's next lookup of that indicator:

![Team notes on a lookup](graphics/screenshot_team_notes.svg)

You can also paste the whole thing at once (`>>note 45.145.66.165 confirmed
phishing #c2`), annotate your **last** lookup with a bare `>>note`, add tags only
with `>>tag 45.145.66.165 phishing c2`, or remove your own notes with
`>>note-rm 45.145.66.165`. Inline `#tags` colour-code the indicator for everyone
(malicious-type tags red, `fp`/`benign` green). There's also an `annotate.py` CLI.
Full reference: `NOTE_COMMANDS.md`.

## Quick tips

- The tool reacts only when the clipboard **changes** — re-copy if nothing appears.
- Everything is **passive**: looking an indicator up never submits it for scanning.
- **Color is your friend** — scan for red/orange first.
- Treat **defanged** output (`hxxp`, `[.]`) as the safe form; re-fang carefully if
  you need to use it elsewhere.
- A surprise **domain report on something like `first.last`** is a known false
  positive — ignore it.
- In **Jupyter**, MITRE write-ups render as rich Markdown; in a **terminal** they're
  plain text. Both contain the same information.
