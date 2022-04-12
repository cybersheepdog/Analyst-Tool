# Analyst-Tool
[![Build Status](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue.svg)](https://shields.io/)
![Maintenance](https://img.shields.io/maintenance/yes/2022.svg?style=flat-square)
[![GitHub last commit](https://img.shields.io/github/last-commit/cybersheepdog/Analyst-Tool.svg?style=flat-square)](https://github.com/cybersheepdog/Analyst-Tool/commit/master)
![GitHub](https://img.shields.io/github/license/cybersheepdog/Analyst-Tool)

**Linux support** is here. The color coding works perfectly in the linux terminal. To run the tool in Linux without the need for Jupyter Notebook simply run:
```
python analyst_tool.py
```


A python script in Jupyter Notebook to automate as much as possible an analyst's investigation and intelligence gathering for:
- Domains
- Hashes
- IP addresses
- Mitre ATT&CK Tactics, Techniques & Sub-Techniques
- Ports
- Windows Event IDs.  

Once configured simply copy one of the above items and program will do the rest based on the configured modules and present the information to the screen. 

In addition I want to make this tool to be beneficial to both new and seasoned analysts alike where it automatically presents useful information by simply copying something to the clipboard. The For more see the planned features & updates section.

### Requirements
- attackcti
- ipwhois
- IPython
- OTXv2
- pyperclip
- validators

## Setup & Configuration
- Sign up for the free API's of any of the modules you wish to use
     - Current Modules Available:
          - Abuse IP DB - Requires an API Key
          - AlienVault OTX - Reaquires and API Key
          - VirusTotal - Requires an API Key
     - **NOTE:**  It is recommended to at least configure the VirusTotal module.
- Open the config.ini file and place your API Keys in the appropriate place
```
[ABUSE_IP_DB]
accept = application/json
key = API_KEY_GOES_HERE

[VIRUS_TOTAL]
accept = application/json
x-apikey = API_KEY_GOES_HERE
user = VIRUS_TOTAL_PROFILE_USER_NAME_GOES_HERE

[ALIEN_VAULT_OTX]
otx_api_key = API_KEY_GOES_HERE
server = https://otx.alienvault.com/

[OTX_INTEL]
intel_list = COMA,SEPERATED,LIST,OF,OTX,PULSE,AUTHORS,GOES,HERE
```
- Install [Anaconda](https://www.anaconda.com/products/individual)
- Open Anaconda prompt and type:
     - ```conda update conda```
- Once the update finishes navigate to the directory where you cloned this repository
- In the Anacanda prompt type:
     - ```pip install -r requirements.txt```
- Once this completes simply run jupyter notebook
     - If not run from the directory you cloned this repository to then navigate there now.
          - It should look like the following:
![Jupyter Notebook Start Direcory](/graphics/start_directory.png)
- Left click on the file named "Analyst Tool.ipynb"
- You will then be presented with the following which is the actual jupyter notebook:
![Jupyter Notebook Start Direcory](/graphics/run.png)
- To begin using the notebook you can run it in one of 2 ways:
- 1. Left click the Run button
- 2. Ensure the box with the code is highlighted in blue (done by left clicking once) and pressing "Shift + Enter"
- It is now running and you should see the following output
     - **Note:** This will only occurr the first time you run the notebook each time.  As it runs on a continuous loop to monitor your clipboard until killed.
- It will output the following
     - **Note** Your output may be different if you do not have all of the modules below configured.
![Jupyter Notebook Start Direcory](/graphics/1st_run.png)


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

### Hash:

![Sample Hash Output](/graphics/hash.png)

### Domain:

![Sample Domain Output](/graphics/domain.png)

## Planned features & updates
- [X] ~~Automatic epoch timestamp conversion~~
- [ ] [ ] IP Addresses:
     - [X] ~~Ability to check OTX if IP is in a pulse for specific contributors~~
     - [X] ~~Pulls out Mitre ATT&CK tags from the abbove pulses~~     	
     - [ ] Bulk IP Lookup
- [ ] Hashes:
     - [X] ~~Ability to check OTX if Hash is in a pulse for specific contributors~~
     - [X] ~~Pulls out Mitre ATT&CK tags from the abbove pulses~~   
     - [ ] Bulk hash lookup
     - [ ] Flag malicious imports
     - [ ] Brief description of what malicious import does
     - [ ] Additional context & lookups
     - [X] ~~OTX Support~~
- [ ]  Domains:
     - [X] ~~Ability to check OTX if Domain is in a pulse for specific contributors~~
     - [X] ~~Pulls out Mitre ATT&CK tags from the above pulses~~
     - [ ] Bulk Domain lookup
     - [ ] Better domain validation
     - [ ] Additional context & lookups
- [ ] URLs:
     - [ ] VirusTotal Support
     - [ ] AlienVault OTX Suppport
     - [ ] Ability to check OTX if URL is in a pulse for specific contributors
     - [ ] Pulls out Mitre ATT&CK tags from the above pulses
     - [ ] Additional context & lookuups
- [ ] [Common Windows Security Identifier Decoding](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers)
- [ ] [Windows filename lookup](https://www.echotrail.io/)
- [ ] [CVE Detail lookup](https://nvd.nist.gov/vuln/detail/CVE-2022-23307)
- [ ] [MITRE ATT&CK Lookup](https://attack.mitre.org/)
     - [X] ~~Tactic  Prints tactic details as well as a clickalbe link to Mitre~~
     - [X] ~~Technique: Prints technique as well as a clickable link to Mitre.~~
     - [X] ~~Sub Technique: Prints sub-technique as well as a clickable link to Mitre.~~
- [ ] Sysmon ID Lookup & explanation
- [ ] Snort Sig lookup
- [ ] Suricata sig lookup
- [ ] Logging of daily activity/lookups
- [ ] Count of lookups with warning once a certain threshold is reached of daily allowances for that API
     - [X] ~~Abuse IP DB~~
     - [X] ~~VirusTotal~~
- [ ] Display info about WEVID's and Option codes.  Not just a link
- [ ] Display info about ports and not just a link.
- [X] ~~AlienVault OTX Pulse ID lookup~~
- [ ] Color coding for expired certificates
- [ ] Color coding for newly created certificates
- [ ] Email reputation checks
- [X] ~~Linux Support~~

## Author
* Jeremy Wiedner   [![Twitter](https://img.shields.io/twitter/follow/JeremyWiedner?style=social)](https://twitter.com/JeremyWiedner)

