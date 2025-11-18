# Analyst Tool
# Author: Jeremy Wiedner (@JeremyWiedner)
# License: BSD 3-Clause
# Purpose:  To help automate some of an analyst workflow as much as possible.  Simply copy an Domain, Hash, IP Address, Port # or Windows Event ID and the main script will pull the 
#coding: utf-8

# Python Standard Library Imports
import base64
import datetime
import ipaddress
import json
import logging
import re
import requests
import sys
import time

# 3rd Party Imports
from pyperclip import paste
import validators
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from ipwhois import IPWhois
from configparser import ConfigParser
from attackcti import attack_client
from IPython.display import display, Markdown
from pycti import OpenCTIApiClient

# Custom Imports
from c2live import get_c2live_config, query_c2live
from lols import *
from analyst_tool_abuseip import *
from analyst_tool_mitre import *
from analyst_tool_opencti import *
from analyst_tool_otx import *
from analyst_tool_utilities import *
from analyst_tool_virus_total import *


# disables python info printout to jupyter notebook
logging.disable(sys.maxsize)

# Regex to be used in the main loop of the Jupyter Notebook
epoch_regex = '^[0-9]{10,16}(\.[0-9]{0,6})?$'
otx_pulse_regex = '^[0-9a-fA-F]{24}$'
hash_validation_regex = '^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
port_wid_validation_regex = '^[0-9]{1,5}$'
ipv6_regex = '^([0-9a-fA-F]{0,4}:){6}[0-9a-fA-F]{0,4}$'

# Other Regex
# Regex to pull the created date out of whois info for a domain
creation_date_regex = 'created: ([0-9T:-]+)'

def analyst(terminal=0):
    """ The main function of the program.  Runs and infinite loop and checks the contents of the clipboard every 5 seconds to see if it has changed.  If so it then runs a series of checks to determine if it is one of the following:
    
    Hash (md5, sha1 or sha256)
    Port # or Windows EventID (requires user interaction to choose between the 2 or neither)
    Domain (lots of false positives here.  will trigger on things like first.last)
    Mitre Tactics, Techniques & SubTechniques
    Private IP address
    Public IP address
    None of the above

    Optional Parametr:
        terminal:
                Default 0 - allows markdown to be displayed in jupyter notebook output for Mitre ATT&CK funcitons
                Changing to 1 (or anything else) disables markdown and allows to print to terminal screen)    
    """
    abuse_ip_db_headers = create_abuse_ip_db_headers_from_config()
    opencti_headers = get_opencti_from_config()
    otx = create_av_otx_headers_from_config()
    otx_intel_list = get_otx_intel_list_from_config()
    virus_total_headers = create_virus_total_headers_from_config()
    vt_user = get_vt_user_from_config()
    c2live_headers = get_c2live_config()
    lolbas = get_lolbas_json(lolbas_url, filename, file_age, current_time, threshold_time)
    driver = get_loldriver_json(loldriver_url, filename2, file_age, current_time, threshold_time)
    lift = initialize_mitre()
    mitre_tactics = get_mitre_tactics_json(tactics_filename, file_age, current_time, threshold_time, lift)
    mitre_techniques = get_mitre_techniques_json(techniques_filename, file_age, current_time, threshold_time, lift)
    verify_mitre_initialized(mitre_techniques, mitre_tactics)
    print("Analyst Tool Initialized.")


    clipboard_contents = get_clipboard_contents()

    while True:

        try:
            check = get_clipboard_contents()
        except TypeError as e:
            print('\n\n\n' + str(e))
            pass
        else:   
            try:
                if check != clipboard_contents:
                    clipboard_contents = check     
                    if re.match(hash_validation_regex, clipboard_contents):
                        suspect_hash = clipboard_contents
                        print_virus_total_hash_results(suspect_hash, virus_total_headers, vt_user)
                        if opencti_headers == None:
                            pass
                        else:
                            opencti_hash_results = query_opencti(opencti_headers, suspect_hash)
                            if len(opencti_hash_results) == 0:
                                print(color.UNDERLINE + '\nOpenCTI Info:' + color.END)
                                print("\n" + suspect_hash + " Not found in OpenCTI")
                            else:
                                print_opencti_hash_results(opencti_hash_results, suspect_hash, opencti_headers)
                        print_alien_vault_hash_results(otx, suspect_hash, otx_intel_list)#, enterprise, mitre_techniques)
                    elif re.match(port_wid_validation_regex, clipboard_contents):
                        is_port_or_weivd(clipboard_contents)
                    elif get_lolbas_file_endings(lolbas, clipboard_contents):
                        lookup_lolbas(lolbas, clipboard_contents)
                    elif get_loldriver_file_endings(driver, clipboard_contents):
                         lookup_loldriver(driver, clipboard_contents)
                    elif validators.domain(clipboard_contents) == True:
                        suspect_domain = clipboard_contents
                        print_vt_domain_report(suspect_domain, virus_total_headers, vt_user)
                        if opencti_headers == None:
                            pass
                        else:
                            opencti_domain_results = query_opencti(opencti_headers, suspect_domain)
                            if len(opencti_domain_results) == 0:
                                print(color.UNDERLINE + '\nOpenCTI Info:' + color.END)
                                print("\nNot found in OpenCTI")
                            else:
                                print_opencti_domain_results(opencti_domain_results, opencti_headers)
                        print_alien_vault_domain_results(otx, suspect_domain, otx_intel_list)#, enterprise, mitre_techniques)
                    elif validators.url(clipboard_contents) == True:
                        suspect_url = clipboard_contents
                        print_virus_total_url_report(virus_total_headers, suspect_url)
                        if opencti_headers == None:
                            pass
                        else:
                            opencti_url_results = query_opencti(opencti_headers, suspect_url)
                            print_opencti_url_results(opencti_url_results, suspect_url)
                        print_alien_vault_url_results(otx, suspect_url, otx_intel_list)#, enterprise, mitre_techniques)
                    elif re.match(mitre_regex, clipboard_contents):
                        mitre = clipboard_contents.strip()
                        is_mitre_tactic_technique_sub_tecnique(mitre, mitre_tactics, mitre_techniques, terminal)
                    elif re.match(epoch_regex, clipboard_contents):
                        print_converted_epoch_timestamp(clipboard_contents)
                    elif re.match(otx_pulse_regex, clipboard_contents):
                        suspect_pulse = clipboard_contents
                        print_otx_pulse_info(suspect_pulse, otx, otx_intel_list)#, enterprise, mitre_techniques)
                    elif re.match(ipv6_regex, clipboard_contents):
                        suspect_ip = clipboard_contents.strip()
                        ip_whois(suspect_ip)
                    elif ipaddress.IPv4Address(clipboard_contents).is_private:
                        print('\n\n\nThis is an RFC1918 IP Address' +'\n\n\n')
                        pass
                    elif ipaddress.IPv4Address(clipboard_contents):
                        suspect_ip = clipboard_contents
                        get_ip_analysis_results(suspect_ip, virus_total_headers, abuse_ip_db_headers, otx, otx_intel_list, vt_user, opencti_headers)#enterprise, mitre_techniques)
                        query_c2live(suspect_ip, c2live_headers)
                    else: 
                        continue
            except:
                continue
               
        
        time.sleep(5)
        
def get_ip_analysis_results(suspect_ip, virus_total_headers, abuse_ip_db_headers, otx, otx_intel_list, vt_user, opencti_headers):#enterprise, mitre_techniques, opencti_headers):
    """ A function to call the various IP modules if they are enabled and display them in order.  
    
    This function requires the following 4 parameters:
        IP address:  Obtained automatically from the main script in the Juptyer Notebook.
        
        AbuseIPDB Headers: Obtained automatically from the config.ini file and  the create_abuse_ip_db_headers_from_config function.
        
        AlienVault OTX Headers: Obtained automatically from the config.ini file and  the create_av_otx_headers_from_config function.
        
        VirusTotal Headers: Obtained automatically from the config.ini file and  the create_virus_total_headers_from_config function.
      
        Otx intel list: derived from the function get_otx_intel_list_from_config

    Note:  The 3 header parameters are all required even if you have not configured and API Key.  The function will validate if they are configured and pass over the ones that are not.        
    
    """
    heading = "\n\n\nIP Analysis Report for " + suspect_ip + ":"
    print(color.BOLD + heading + color.END)

    if opencti_headers == None:
        print(color.UNDERLINE + '\nOpenCTI Info:' + color.END)
        print('\tOpenCTI not configured.')
    else:
        opencti_ip_results = query_opencti(opencti_headers, suspect_ip)
        if len(opencti_ip_results) == 0:
            print("\n" + suspect_ip + " Not found in OpenCTI")
        else:
            print_opencti_ip_results(opencti_ip_results, suspect_ip, countries, opencti_headers)

    if virus_total_headers == None:
        print(color.UNDERLINE + '\nVirusTotal Detections:' + color.END)
        print('\tVirus Total not configured.')
    else:
        get_vt_ip_results(suspect_ip, virus_total_headers, vt_user)

    print(color.UNDERLINE + '\nIP Information:' + color.END)

    try:
        ip_whois(suspect_ip)
    except:
        pass

    check_tor(suspect_ip)

    if abuse_ip_db_headers == None:
        print(color.UNDERLINE + '\nAbuse IP DB:' + color.END)
        print('\tAbuse IP DB not configured.')
    else:
        try:
            check_abuse_ip_db(suspect_ip, abuse_ip_db_headers)
        except:
            print('\tIssue with Abuse IP DB API.')

    if otx == None:
        print(color.UNDERLINE + '\nAlienVault OTX:' + color.END)
        print('\tAlienVault not configured.')
    else:
        print_alien_vault_ip_results(otx, suspect_ip, otx_intel_list)#, enterprise, mitre_techniques)
   
def ip_whois(suspect_ip):
    """  A function to query WhoIs for an IP address and print out information from the response.
    
    This function requires the following parameter:
        IP address:  Obtained automatically from the main script in the Juptyer Notebook.
    
    Sample Output:
        IP Information:
            Organization:             RU-ITRESHENIYA
            CIDR:                     45.145.66.0/23
            Range:                    45.145.66.0 - 45.145.67.255
            Country:                  Russian Federation (the)
            Associated Email:
                    Email:            abuse@hostway.ru


            Organization:             HOSTWAY route object
            CIDR:                     45.145.66.0/23
            Range:                    45.145.66.0 - 45.145.67.255
            Country:                  None
            Associated Email:
                    Email:            No associated emails.   
    """

    org_match = '([a-zA-Z0-9 .,_")(-]+)\n?'
    obj = IPWhois(suspect_ip)
    res = obj.lookup_whois()
    company_count = 0

    for line in res['nets']:
        if line['description'] != None:
            m = re.match(org_match, line['description'])
            org = m.group(1)
            company_count = company_count + 1
            print('\t{:<33} {}'.format(color.BOLD + 'Organization:' + color.END,org))
        elif  line['name'] != None:
            m = re.match(org_match, line['name'])
            org = m.group(1)
            company_count = company_count + 1
            print('\t{:<33} {}'.format(color.BOLD + 'Organization:' + color.END,org))
        else:
            print('\t{:<33} {}'.format(color.BOLD + 'Organization:' + color.END,'Org is blank in whois data.'))
        print('\t{:<25} {}'.format('CIDR:',line['cidr']))
        if line['range']:
            print('\t{:<25} {}'.format('Range:',line['range']))
        else:
            ip_range = ipaddress.ip_network(line['cidr'])
            ip_range = str(ip_range[0]) + ' - ' + str(ip_range[-1])
            print('\t{:<25} {}'.format('Range:',ip_range))
        country_code = line['country']
        print_country(country_code, countries)
        print('\tAssociated Email:')
        if line['emails'] == None:
            print('\t\t{:<17} {}'.format('Email:','No associated emails.'))
        else:
            for email in line['emails']:
                print('\t\t{:<17} {}'.format('Email:',email))
            #print('\n')
    if company_count == 0:
        print('\t{:<25} {}'.format('ASN Description:',res['asn_description']))
    else:
        pass
