# Analyst-Tool
[![Build Status](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue.svg)](https://shields.io/)
![Maintenance](https://img.shields.io/maintenance/yes/2025.svg?style=flat-square)
[![GitHub last commit](https://img.shields.io/github/last-commit/cybersheepdog/Analyst-Tool.svg?style=flat-square)](https://github.com/cybersheepdog/Analyst-Tool/commit/master)
![GitHub](https://img.shields.io/github/license/cybersheepdog/Analyst-Tool)

A python script in Jupyter Notebook to automate as much as possible (simply copy one of the following to your clipboard) an analyst's investigation and intelligence gathering for:
- Domains
- Hashes
- IP addresses
- Mitre ATT&CK Tactics, Techniques & Sub-Techniques
- Ports
- Windows Event IDs.
- Epoch timestamp conversion to human readable.
- OTX Pulse ID Lookup

Once configured simply copy one of the above items and program will do the rest based on the configured modules and present the information to the screen. 

In addition I want to make this tool to be beneficial to both new and seasoned analysts alike where it automatically presents useful information by simply copying something to the clipboard. The For more see the planned features & updates section.


## Sample Ouput:
### IP Address:

![Sample IP Address Output](/graphics/ip.png)

**Updated AlienVault OTX Output** Updated picture to follow
```
AlienVault OTX IP Report:
	dorkingbeauty1 Intel:     Yes
	Pulse Created:            2022-02-14T03:25:39.705000
	Pulse Modifed:            2022-02-14T03:25:39.705000
	Pulse:                    https://otx.alienvault.com/pulse/6209cbb3a50149391bd1040b


	pr0viehh Intel:           No
	Avertium Intel:           No

	Related Pulses:           50
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
#### C2Live Sample Output
![Sample C2Live Output](/graphics/c2live.png)

### Hash:

![Sample Hash Output](/graphics/hash.png)

### Domain:

![Sample Domain Output](/graphics/domain.png)


## Author
* Jeremy Wiedner   [![Twitter](https://img.shields.io/twitter/follow/JeremyWiedner?style=social)](https://twitter.com/JeremyWiedner)

