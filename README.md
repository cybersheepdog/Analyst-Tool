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
- Once this completes simply run jupyter notebook
- - If not run from the directory you cloned this repository to then navigate there now.
- - - It should look like the following:
- - - ![Jupyter Notebook Start Direcory](/graphics/start_directory.png)
- 

Current Modules Available:
- Abuse IP DB - Requires an API Key
- AlienVault OTX - Reaquires and API Key
- VirusTotal - Requires an API Key

NOTE:  It is recommended to at least configure the VirusTotal module.

## Sample Ouput:
### IP Address:

![Sample IP Address Output](/graphics/ip.png)

### Hash:

![Sample Hash Output](/graphics/hash.png)

### Domain:

![Sample Domain Output](/graphics/domain.png)

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
