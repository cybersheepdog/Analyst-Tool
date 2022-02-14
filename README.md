# Analyst-Tool
A python script and Jupyter Notebook to automate as much as possible an analyst's investigation of IP addresses, hashes, domains, ports and Windows event IDs.  Once configured simply copy an IP addresse, hashe, domain, port or Windows event ID and the program will do the rest based on the configured modules.  

This tool currently only works in Windows.  Linux support will be added in the future.

To get the best experience it is recommended to use the Jupyter Notebook.

### Configuration
Current Modules Available:
- Abuse IP DB - Requires an API Key
- AlienVault OTX - Reaquires and API Key
- VirusTotal - Requires an API Key

NOTE:  It is recommended to at least configure the VirusTotal module.

See the config.ini file.  


### Requirements
- Python >= 3.0
- ipwhois
- OTXv2
- validators

Assuming you already have Python >= 3.0 on your system you can 

```
pip install -r requirement.txt
```

## Author
* Jeremy Wiedner [@JeremyWiedner](https://twitter.com/JeremyWiedner)
