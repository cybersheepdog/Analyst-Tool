# Analyst-Tool
[![Build Status](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue.svg)](https://shields.io/)
![Maintenance](https://img.shields.io/maintenance/yes/2026.svg?style=flat-square)
[![GitHub last commit](https://img.shields.io/github/last-commit/cybersheepdog/Analyst-Tool.svg?style=flat-square)](https://github.com/cybersheepdog/Analyst-Tool/commit/master)
![GitHub](https://img.shields.io/github/license/cybersheepdog/Analyst-Tool)

A python script which can be run in the terminal or a Jupyter Notebook to automate as much as possible (simply copy one of the following to your clipboard) an analyst's investigation and intelligence gathering for:
- Domains
- URLs
- Hashes (MD5 / SHA-1 / SHA-256)
- IP addresses (IPv4 and IPv6)
- Mitre ATT&CK Tactics, Techniques & Sub-Techniques
- LOLBAS (living-off-the-land binaries) & LOLDrivers
- CVEs (NVD details + CISA Known Exploited Vulnerabilities status)
- Ports
- Windows Event IDs
- Epoch timestamp conversion to human readable
- OTX Pulse ID Lookup

Defanged indicators copied from reports (e.g. `hxxps://evil[.]com`, `8[.]8[.]8[.]8`) are automatically re-fanged before lookup, and every multi-service report opens with a one-line **verdict** summarizing the key signals.

**NOTE: This is passive only in that it only searches via API and does not submit anything to the services that would cause it to be actively scanned.**  For example.  If an IP has not been seen by Virus Total before, using this tool to check its status will not submit it and cause it to be scanned for the 1st time.

Once configured simply copy one of the above items and program will do the rest based on the configured modules and present the information to the screen.

It integrates VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, OpenCTI, C2 Live, WhoIs, a Tor exit-node check, VPN-provider and datacenter/hosting checks (X4BNet lists, no API key), DNS resolution + Certificate Transparency (crt.sh), CVE enrichment (NVD + CISA KEV), MITRE ATT&CK, and the LOLBAS/LOLDrivers projects. All of an indicator's lookups run **concurrently**, so a report comes back as fast as the slowest single service.

## What's new

- **Result caching (save API calls).** Lookups for VirusTotal, AbuseIPDB, Shodan and OTX are cached so a repeat lookup within a freshness window (default 7 days) is served from a database instead of spending an API call. Use a zero-setup local **SQLite** file, or a shared **PostgreSQL** database so a whole team saves calls together. On by default (local).
- **Multi-user check tracking.** The database also logs who looked up each indicator. When more than one analyst (or the same analyst in sessions more than 60 minutes apart) has checked an indicator recently, the report shows a heads-up such as `*** MULTI-USER NOTICE: 3 users have checked this IP in the last 7 days`.
- **Shared annotations & tags.** Analysts can attach durable notes and tags to an indicator (`>>note 8.8.8.8 confirmed phishing #c2`); they appear automatically at the top of everyone's next lookup. See [NOTE_COMMANDS.md](NOTE_COMMANDS.md).
- **Optional SSL-verify fallback.** A `config.ini` flag lets outbound API calls retry with certificate verification disabled when needed (e.g. behind a TLS-intercepting proxy). Off by default.
- **Automated remote-DB server setup.** `server_setup/setup_remote_db.sh` stands up the shared PostgreSQL database (install, role, schema, network config) in one idempotent command on Debian/Ubuntu.
- **More enrichment.** Refang of defanged IOCs, CVE / CISA KEV lookups, DNS + crt.sh subdomain pivoting, a datacenter/hosting flag, and a one-line verdict atop each report.
- **Enriched port / Event ID lookups.** A copied number now returns the port's service (cached IANA registry) and malware/C2 associations, plus the Windows Event ID's name, log, category and an analyst note — not just reference links.
- **Domain exclusions.** A configurable `[EXCLUSIONS]` list skips domain/URL lookups for chosen domains (pre-filled with the tool's own reference-link domains), so copying a link it printed doesn't trigger a lookup.
- **Tests & CI.** A `pytest` suite (`tests/`) and a GitHub Actions workflow run the tests and a syntax check on every push/PR.

## Documentation

| Guide | For |
|-------|-----|
| [QUICKSTART.md](QUICKSTART.md) | Get running in three steps |
| [USER_GUIDE.md](USER_GUIDE.md) | Full reference: install, every config key, run modes, caching, SSL |
| [ANALYST_USER_GUIDE.md](ANALYST_USER_GUIDE.md) | Every lookup explained and how to read the results |
| [ANALYST_REMOTE_DB_GUIDE.md](ANALYST_REMOTE_DB_GUIDE.md) | Connecting to the shared (remote) database |
| [NOTE_COMMANDS.md](NOTE_COMMANDS.md) | Adding shared notes & tags (the `>>` commands + `annotate.py`) |
| [ADMIN_REMOTE_SERVER_GUIDE.md](ADMIN_REMOTE_SERVER_GUIDE.md) | Standing up the remote server with the setup script |
| [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) | Local + remote implementation/setup reference |
| [server_setup/](server_setup/) | The server automation script, portable SQL, and its README |

For more information on setup, configuration and features please see [The Wiki](https://github.com/cybersheepdog/Analyst-Tool/wiki).

## Author
* Jeremy Wiedner   [![Twitter](https://img.shields.io/twitter/follow/JeremyWiedner?style=social)](https://twitter.com/JeremyWiedner)

