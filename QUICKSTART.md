# Analyst Tool — Quick Start

A clipboard-driven threat-intel assistant. **Copy** an indicator (IP, hash, domain, MITRE
ID, etc.) and the tool detects it, queries every configured service in parallel, and prints
a report. It's passive — it only looks indicators up, never submits them for scanning.

For the full reference, see `USER_GUIDE.md`.

---

## 1. Install

```bash
pip install -r requirements.txt
```

**Linux only:** also install a clipboard backend and run inside a graphical session, e.g.
`sudo apt-get install xclip`. (Windows and macOS work out of the box.)

## 2. Configure

Open `config.ini` and add the API keys for the services you want. **Every service is
optional** — anything left blank is simply skipped. No keys are needed for WhoIs, Tor
checks, MITRE ATT&CK, LOLBAS, or LOLDrivers.

Common keys: `[VIRUS_TOTAL] x-apikey`, `[ABUSE_IP_DB] key`, `[ALIEN_VAULT_OTX] otx_api_key`,
`[SHODAN] shodan_api_key`, `[OPEN_CTI] opencti_api_token`.

Leave `[GENERAL] ssl_verify = true` unless you're behind a TLS-intercepting proxy.

## 3. Run

**Jupyter Notebook** — open `Analyst Tool.ipynb` and run:

```python
from analyst import *
analyst()
```

**Terminal:**

```bash
python analyst_tool.py
```

Wait for `Analyst Tool Initialized.`, then **copy an indicator** to your clipboard — the
report appears automatically. Copy the next one for the next report.

**Stop it:** interrupt the Jupyter kernel, or press `Ctrl+C` in the terminal.

---

## What you can copy (capabilities at a glance)

| Copy this | You get |
|-----------|---------|
| **Public IPv4** | VirusTotal, Shodan (+ Cobalt Strike beacon), WhoIs, Tor check, AbuseIPDB, OTX, OpenCTI, C2Live — all at once |
| **Private IPv4** | A note that it's an RFC1918 address |
| **IPv6** | WhoIs (org, CIDR, range, country, emails) |
| **File hash** (MD5/SHA1/SHA256) | VirusTotal + OpenCTI + OTX hash reports |
| **Domain** | VirusTotal + OpenCTI + OTX domain reports |
| **URL** | VirusTotal + OpenCTI + OTX URL reports (defanged display) |
| **MITRE ID** (`TA0001`, `T1059`, `T1059.001`) | Name, ATT&CK link, description, detection guidance |
| **Port / Windows Event ID** (1–5 digits) | SpeedGuide port link + Ultimate Windows Security event link |
| **LOLBAS binary** (e.g. `cmd.exe`) | Description, paths, commands, IOCs, link |
| **LOLDriver** filename | Description, MITRE ID, command/OS/privileges, link |
| **OTX Pulse ID** (24 hex chars) | Full pulse: author, TLP, tags, malware families, references |
| **Epoch timestamp** (10–16 digits) | Human-readable date/time |

---

## Tips

- The tool reacts only when the clipboard **changes** — re-copy if nothing happens.
- `analyst()` defaults to notebook mode; `analyst(terminal=1)` (used by `analyst_tool.py`)
  prints MITRE output as plain text for terminals.
- Reports for multi-service indicators run concurrently, so print order may vary.
