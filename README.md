# Analyst-Tool
[![Build Status](https://img.shields.io/badge/platform-Windows-blue.svg)](https://shields.io/)

Linux support will be added in the future.

A python script in Jupyter Notebook to automate as much as possible an analyst's investigation and intelligence gathering for:
- IP addresses
- Hashes
- Domains
- Ports
- Windows Event IDs.  

Once configured simply copy one of the above items and program will do the rest based on the configured modules and present the information to the screen. 

In addition I want to make this tool to be beneficial to both new and seasoned analysts alike where it automatically pulls in useful information by simply copying to the clipboard. For more see the planned features & updates section.

### Requirements
- ipwhois
- OTXv2
- validators

## Setup & Configuration
- Install [Anaconda](https://www.anaconda.com/products/individual)
- Open Anaconda prompt and type:
- - ```conda update conda```
- Once the update finishes navigate to the directory where you cloned this repository
- In the Anacanda prompt type:
- ```pip install -r requirements.txt```
- **This is still a work in progress for documentation**

Current Modules Available:
- Abuse IP DB - Requires an API Key
- AlienVault OTX - Reaquires and API Key
- VirusTotal - Requires an API Key

NOTE:  It is recommended to at least configure the VirusTotal module.

## Sample Ouput:
### IP Address:
```
IP Analysis Report for 171.25.193.20:

VirusToal Detections:
	Malicious:                7
	Malware:                  6
	Suspicious:               2
	Phishing:                 1
	Spam:                     0
	Clean:                    63
	Undetected:               10
	Time Out:                 0
	https://www.virustotal.com/gui/ip-address/171.25.193.20

IP Information:
	Organization:             DFRI
	CIDR:                     171.25.193.0/24
	Range:                    171.25.193.0 - 171.25.193.255
	Country:                  Sweden
	Associated Email:
		Email:            No associated emails.
	Organization:             DFRI
	CIDR:                     171.25.193.0/24
	Range:                    171.25.193.0 - 171.25.193.255
	Country:                  None
	Associated Email:
		Email:            No associated emails.

	TOR Exit Node:            Yes

Abuse IP DB:
	Abuse Confidence Score:   100%
	Total Reports:            6094
	Last Reported:            2022-02-15T18:48:07+00:00
	Distinct Reporters:       501
	Usage Type:               Fixed Line ISP
	Domain:                   dfri.se
	https://www.abuseipdb.com/check/171.25.193.20

AlienVault OTX IP Report:
	Reputation:               None
	Passive DNS:              2 Domains
	Hostname:                 171.25.193.20
	  First Seen:             2018-09-23T22:00:00
	  Last Seen:              2018-09-23T22:00:00
	Hostname:                 tor-exit0-readme.dfri.se
	  First Seen:             2017-04-23T21:00:36
	  Last Seen:              2020-05-28T16:26:41
	https://otx.alienvault.com/indicator/ip/171.25.193.20
```
### Hash:
```
VirusTotal Hash Report for 7348761960b4743bd00487404c901ae6:
File Reputation:
	Malicious:                14
	Suspicious:               0
	Harmless:                 0
	Undetected:               43

File Threat Classification:
	trojan                    4

File Threat Name:
	boxter                    7

File Info:
	Signature:                File not signed
	Signers:                  N/A
	Signing Date:             N/A
	File Type:                Macintosh Disk Image
	Product:                  N/A
	Copyright:                N/A
	Decription:               N/A
	Creation Date:            N/A
	Last Modification Date:   2022-02-15 12:11:02

Submission Info:
	Last Submission:          2022-02-15 06:15:19
	Last Analysis:            2022-02-15 12:10:45
	First Submission:         2022-02-15 06:15:19
	Times Submitted:          1
https://www.virustotal.com/gui/file/7348761960b4743bd00487404c901ae6/detection
```

### Domain:
```
Domain Reputation for getfrontendlib7.xyz:
Last Analysis Stats:
	Malicious:                1
	Malware:                  7
	Suspicious:               1
	Phishing:                 0
	Spam:                     0
	Clean:                    70
	Undetected:               10
	Time Out:                 0

Domain Info:
	Creation Date:                 2022-01-24 19:00:00
	Last Update Date:              2022-01-24 19:00:00
	Last Modification Date:        2022-02-11 05:17:11

Certificate Info:
	Issuer:                        Cloudflare, Inc.
	Not After:                     2023-01-24 23:59:59
	Not Before:                    2022-01-25 00:00:00
https://www.virustotal.com/gui/domain/getfrontendlib7.xyz
```
## Planned features & updates
- [ ] IP Addresses:
- - [ ] Ability to check OTX if IP is in a pulse for specific contributors
- - [ ] Bulk IP Lookup
- [ ] Hashes:
- - [ ] Bulk hash lookup
- - [] Flag malicious imports
- - [ ] Brief description of what malicious import does
- - [ ] Additional context & lookups
- [ ]  Domains:
- - [ ] Bulk Domain lookup
- - [ ] Better domain validation
- - [ ] Additional context & lookups
- [ ] [Common Windows Security Identifier Decoding](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers)
- [ ] [Windows filename lookup](https://www.echotrail.io/)
- [ ] Bulk IP lookup
- [ ] Bulk Hash lookup
- [ ] Bulk domain lookup
- [ ] [CVE Detail lookup](https://nvd.nist.gov/vuln/detail/CVE-2022-23307)
- [ ] [MITRE ATT&CK Lookup](https://attack.mitre.org/)
- [ ] Sysmon ID Lookup & explanation
- [ ] Snort Sig lookup
- [ ] Suricata sig lookup
- [ ] Logging of daily activity/lookups
- [ ] Count of lookups with warning once a certain threshold is reached of daily allowances for that API
- [ ] Display info about WEVID's and Option codes.  Not just a link
- [ ] Display info about ports and not just a link.
- [ ] Color coding for expired certificates
- [ ] Color coding for newly created certificates
- [ ] Email reputation checks

## Author
* Jeremy Wiedner [@JeremyWiedner](https://twitter.com/JeremyWiedner)
