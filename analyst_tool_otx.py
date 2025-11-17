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
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from configparser import ConfigParser
from IPython.display import display, Markdown


# Custom Imports
from analyst_tool_mitre import *

class color:
   """Used to to color code text ouptut in order to highlight key pieces of information.
      
      Usage Example:  print(color.PURPLE + 'Hello World' + color.END) 
      
   """
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[31m'
   ORANGE = '\033[33m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

def create_av_otx_headers_from_config():
    """ Creates a dictionary called av_otx_headers that contains the formatted header needed to submit an query to AlienVault Open Threat Exchange (OTX).
    
    Requires an AlientVault OTX API Key to use.  It is free to sign up for one but has restrictions on daily limits.
    
    Reads in the AlientVault OTX API Key from the config.ini file.
    
    Note:  You are not required to use this module.  If you do not wish to use it then you can leave the config file as is with otx_api_key = None
    
    Returns the AlienVault OTX API Headers in the form of:
        av_otx_headers = OTXv2(av_headers['otx_api_key'], server=av_headers['server'])
    """

    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
    except:
        print("Error with config.ini.")
    else:
        av_headers = config_object["ALIEN_VAULT_OTX"]

        if av_headers['otx_api_key']:
            av_otx_headers = OTXv2(av_headers['otx_api_key'], server=av_headers['server'])
            print("AlienVault OTX Configured.")
            return av_otx_headers
        else:
            print("AlienVault OTX not configured.")
            print("Please add your AlienVault OTX API Key to the config.ini file if you want to use this module.")
            av_otx_headers = ''


def determine_specific_otx_intel(otx_results, otx_intel_list):#, enterprise, mitre_techniques):
    """Takes a list of OTX users and checks the OTX query results to see if the suspect IP appears in any of their pulses.
    
    Required Parameters:
        OTX Results:  Derived from the "print_alien_vault_ip_results" function.
        
        OTX Intel List: Derived from the config.ini file and the function "get_otx_intel_list_from_config".  should be a comma seperated list like
                author1,author2,etc..
    
    """
    intel_pulse = ''
    intel_pulse_created = ''
    intel_pulse_updated = ''
    pulse_list = []
    author_list = []

    for pulse in otx_results['general']['pulse_info']['pulses']:
        if pulse['author']['username'] in otx_intel_list:
                intel_pulse = 'https://otx.alienvault.com/pulse/' + str(pulse['id'])
                print('\t{:<34} {}'.format(color.GREEN + pulse['author']['username'] + ' Intel:' + color.END,'Yes'))
                if pulse['TLP'] == 'white':
                    print("\t{:<25} {}".format("TLP:",pulse['TLP'].title()))
                elif pulse['TLP'] == 'green':
                    print("\t{:<25} {}".format("TLP:",color.GREEN + pulse['TLP'].title() + color.END))
                elif pulse['TLP'] == 'amber':
                    print("\t{:<25} {}".format("TLP:",color.YELLOW + pulse['TLP'].title() + color.END))
                elif pulse['TLP'] == 'red':
                   print("\t{:<25} {}".format("TLP:",color.RED + pulse['TLP'].title() + color.END))
                print('\t{:<25} {}'.format('Pulse Created:',pulse['created']))
                print('\t{:<25} {}'.format('Pulse Modifed:',pulse['modified']))
                print("\t{:<25} {}".format("Pulse Name:",pulse['name']))
                print('\t{:<25} {}'.format('Pulse:',intel_pulse))

                if len(pulse['tags']) == 0:
                    print('\t{:<33} {}'.format(color.UNDERLINE + 'Tags:' + color.END,'No tags in pulse'))
                elif len(pulse['tags']) <= 5:
                    print("\t" + color.UNDERLINE + 'Tags:' + color.END)
                    for tag in pulse['tags']:
                        print("\t   " + tag)
                else:
                    count = 0
                    print("\t" + color.UNDERLINE + 'Tags:' + color.END)
                    for tag in pulse['tags']:
                        if count <= 4:
                            print("\t   " + tag)
                            count = count + 1
                        else:
                            pass

                if len(pulse['malware_families']) == 0:
                    print('\t{:<33} {}'.format(color.UNDERLINE + 'Malware Families:' + color.END,'No malware families associated with this pulse'))
                elif len(pulse['malware_families']) <= 5:
                    print("\t" + color.UNDERLINE + 'Malware Families:' + color.END)
                    for malware in pulse['malware_families']:
                        print("\t   " + malware['display_name'])
                else:
                    count = 0
                    print("\t" + color.UNDERLINE + 'Malware Families:' + color.END)
                    for malware in pulse['malware_families']:
                        if count <= 4:
                            print("\t   " + malware['display_name'])
                            count = count + 1
                        else:
                            pass

                #if len(pulse['attack_ids']) == 0:
                #    print('\t{:<33} {}'.format(color.UNDERLINE + 'Mitre ATT&CK:' + color.END,'None Tagged in the Pulse'))
                #else:               
                #    print('\t' + color.UNDERLINE + 'Mitre ATT&CK:' + color.END)
                ##get_pulse_mitre_tags(pulse, enterprise, mitre_techniques)
                #    if pulse['attack_ids']:
                #        if len(pulse['attack_ids']) <= 5:
                #            get_pulse_mitre_tags(pulse, enterprise, mitre_techniques)
                #        else:
                #            count = 0
                #            for mitre in pulse['attack_ids']:
                #                if count <= 4:
                #                    is_otx_mitre_tactic_technique_sub_tecnique(mitre['id'], enterprise, mitre_techniques)
                #                    count = count + 1
                #                else:
                #                    pass  

                if len(pulse['references']) == 0:
                    print('\t{:<25} {}'.format(color.UNDERLINE + 'References:' + color.END,'No refrences cited for this pulse'))
                else:
                    print("\t" + color.UNDERLINE + "References:" + color.END)
                    if len(pulse['references']) <= 5:
                        for reference in pulse['references']:
                            print("\t   " + reference)
                    else:
                        count = 0
                        if count <= 4:
                            for reference in pulse['references']:
                                print("\t   " + reference)
                                count = count + 1
                        else:
                            pass

                print('\n')
                author_list.append(pulse['author']['username'])

    for author in otx_intel_list:
        if author in author_list:
            pass
        else:
            print('\t{:<25} {}'.format(author +  ' Intel:','No'))

def determine_subscribed_otx_intel(otx_results):#, enterprise, mitre_techniques):
    """Looks through the OTX results to see if any authors the owner of the API Key is subscribed to
    and then returns results for onlyt those along with Mitre Information.
    
    Required Parameters:
        OTX Results:  Derived from the "print_alien_vault_ip_results" function.
    
    """
    for pulse in otx_results['general']['pulse_info']['pulses']:
        if pulse['author']['is_subscribed']:
                intel_pulse = 'https://otx.alienvault.com/pulse/' + str(pulse['id'])
                print('\t{:<34} {}'.format(color.GREEN + pulse['author']['username'] + ' Intel:' + color.END,'Yes'))
                print('\t{:<25} {}'.format('Pulse Created:',pulse['created']))
                print('\t{:<25} {}'.format('Pulse Modifed:',pulse['modified']))
                print('\t{:<25} {}'.format('Pulse:',intel_pulse))
                #print('\tMitre ATT&CK:')
                #get_pulse_mitre_tags(pulse, enterprise, mitre_techniques)          
                print('\n')

def get_otx_intel_list_from_config():
    """
    Reads the config.ini file to pull out the list Intel providers and returns a list object of those providers.
    
    Reads in the AbuseIP DB API Key from the config.ini file.
    
    Note:  You are not required to use this module.  If you do not wish to use it then you can leave the config file as is with intel_list = None

    """
    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
    except:
        print("Error with config.ini.")
    else:
        intel_list = config_object["OTX_INTEL"]

    if intel_list['intel_list']:
        otx_intel_list = intel_list['intel_list'].split(",")
        for line in otx_intel_list:
            line = line.strip()
        print('OTX Intel Providers configured.')
        return otx_intel_list
    else:
        print('OTX Intel Providers not configured.')
        otx_intel_list = ''
        return otx_intel_list
        
def get_pulse_mitre_tags(pulse, enterprise, mitre_techniques):
    if pulse['attack_ids']:
        for mitre in pulse['attack_ids']:
            is_otx_mitre_tactic_technique_sub_tecnique(mitre['id'], enterprise, mitre_techniques)
    else:
        pass
        
def is_otx_mitre_tactic_technique_sub_tecnique(mitre, enterprise, mitre_techniques):
    mitre_tactic_regex = '^TA000[1-9]|TA001[0-1]|TA004[0,2-3]$'
    mitre_technique_regex = '^T[0-9]{4}$'
    mitre_sub_technique_regex = '^T[0-9]{4}\.[0-9]{3}$'

    if re.match(mitre_tactic_regex, mitre):
        mitre_tactic = mitre
        print_otx_mitre_tactic(mitre_tactic, enterprise)
    elif re.match(mitre_technique_regex, mitre):
        mitre_technique = mitre
        print_otx_mitre_technique(mitre_technique, mitre_techniques)
    elif re.match(mitre_sub_technique_regex, mitre):
        mitre_sub_technique = mitre
        mitre = mitre.split(".")
        mitre_technique = mitre[0]
        print_otx_mitre_sub_technique(mitre_sub_technique, mitre_techniques, mitre_technique)
    else:
        pass

def print_alien_vault_domain_results(otx, suspect_domain, otx_intel_list):#, enterprise, mitre_techniques):
    otx_domain_results = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, suspect_domain)
    print("\n" + color.UNDERLINE + 'AlienVault OTX Domain Report for:' + color.END + ' ' +  suspect_domain)

    if otx_intel_list == None:
        pass
    else:
        determine_specific_otx_intel(otx_domain_results, otx_intel_list)#, enterprise, mitre_techniques)    
    print("\t{:<25} {}".format("Related Pulses:",otx_domain_results['general']['pulse_info']['count']))
    print("https://otx.alienvault.com/indicator/domain/" + suspect_domain)


def print_alien_vault_hash_results(otx, suspect_hash, otx_intel_list):#, enterprise, mitre_techniques):
    """Takes the OTX Headers and suspect hash, pulls back inforamtion from OTX and prints it to the screen.
    
    This function requires the following 4 parameters:
        IP address:  Obtained automatically from the main script in the Juptyer Notebook.
             
        AlienVault OTX Headers: Obtained automatically from the config.ini file and  the create_av_otx_headers_from_config function.
    
    Sample Output:

    """
    md5_regex = '^[a-fA-F0-9]{32}$'
    sha1_regex = '^[a-fA-F0-9]{40}$'
    sha256_regex = '^[a-fA-F0-9]{64}$'

    if re.match(md5_regex, suspect_hash):
        otx_results = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_MD5, suspect_hash)
    elif re.match(sha1_regex, suspect_hash):
        otx_results = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_SHA1, suspect_hash)
    elif re.match(sha256_regex, suspect_hash):
        otx_results = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_SHA256, suspect_hash)
    else:
        print("Not an MD5, Sha1 or Sha256 hash.")

    print(color.UNDERLINE + "\nAlienVault OTX Hash Report:"+ color.END)

    if otx_intel_list == None:
        pass
    else:
        determine_specific_otx_intel(otx_results, otx_intel_list)#, enterprise, mitre_techniques)

    print("\t{:<25} {}".format("Related Pulses:",otx_results['general']['pulse_info']['count']))

    print("\n\tContacted Domains:")
    try:
        otx_results['analysis']['analysis']['plugins']['cuckoo']['result']['network']['domains']
    except:
        print("\tNo known concated domains or IPs.")
    else:
        for domain in otx_results['analysis']['analysis']['plugins']['cuckoo']['result']['network']['domains']:
            print("\t{:>10}".format("Details:"))
            if domain['domain'] == None:
                print("\t\t{:>16} {}".format("Domain:","None"))
            else:
                print("\t\t{:<16} {}".format("Domain:",domain['domain']))

            if domain['ip'] == None:
                print("\t\t{:<16} {}".format("IP:","None"))
            else:
                print("\t\t{:<16} {}".format("IP:",domain['ip']))

            if domain['whitelisted'] == False:
                print("\t\t{:<16} {:}".format("Whitelisted:","No"))
            else:
                print("\t\t{:<16} {}".format("Whitelisted:",domain['whitelisted']))

    print("\thttps://otx.alienvault.com/indicator/file/" + suspect_hash)

def print_alien_vault_ip_results(otx, suspect_ip, otx_intel_list):#, enterprise, mitre_techniques):
    """Takes the OTX Headers and suspect IP, pulls back inforamtion from OTX and prints it to the screen.
    
    This function requires the following 4 parameters:
        IP address:  Obtained automatically from the main script in the Juptyer Notebook.
             
        AlienVault OTX Headers: Obtained automatically from the config.ini file and  the create_av_otx_headers_from_config function.
    
    Sample Output:
        AlienVault OTX IP Report:
        Related Pulses:           17
        Reputation:               None
        Passive DNS:              1 Domains
        Hostname:                 bio4kobs.geekgalaxy.com
            First Seen:             2019-07-02T13:13:35
            Last Seen:              2019-07-11T13:45:12
        https://otx.alienvault.com/indicator/ip/178.239.21.165
    """
    otx_results = otx.get_indicator_details_full(IndicatorTypes.IPv4,suspect_ip)

    print(color.UNDERLINE + "\nAlienVault OTX IP Report:"+ color.END)

    if otx_intel_list == None:
        pass
    else:
        determine_specific_otx_intel(otx_results, otx_intel_list)#, enterprise, mitre_techniques)

    print("\n\t{:<25} {}".format("Related Pulses:",otx_results['general']['pulse_info']['count']))

    if otx_results['reputation']['reputation'] == None:
        print('\t{:<25} {}'.format('Reputation:','None'))
    else:
        print('\t{:<25} {}'.format('Reputation:',otx_results['reputation']['reputation']))

    print('\t{:<25} {}'.format('Passive DNS:', str(otx_results['passive_dns']['count']) + ' Domains'))
    if otx_results['passive_dns']['count'] <= 5:
        for host in otx_results['passive_dns']['passive_dns']:
            print("\t{:<33} {}".format(color.BOLD + 'Hostname:' + color.END,host['hostname']))
            print("\t  {:<23} {}".format('First Seen:',host['first']))
            print("\t  {:<23} {}".format('Last Seen:',host['last']))
    print("\thttps://otx.alienvault.com/indicator/ip/" + suspect_ip)

def print_alien_vault_url_results(otx, suspect_url, otx_intel_list):#, enterprise, mitre_techniques):
    otx_url_results = otx.get_indicator_details_full(IndicatorTypes.URL, suspect_url)
 
    sanitized_url = sanitize_url(suspect_url)

    print('\n' + color.UNDERLINE + 'AlienVault OTX URL Report for:' + color.END + ' ' + sanitized_url)
    if otx_intel_list == None:
        pass
    else:
        determine_specific_otx_intel(otx_url_results, otx_intel_list)#, enterprise, mitre_techniques)

    print("\t{:<25} {}".format("Related Pulses:",otx_url_results['general']['pulse_info']['count']))
    print("https://otx.alienvault.com/indicator/domain/" + suspect_url)
    
def print_otx_mitre_tactic(mitre_tactic, enterprise):
    """Searches through Mitre ATT&CK for a tactic and pulls the inforation out and prints to the screen.
    
    Requried Parameters:
         mitre_tactic - derived from the is_mitre_tactic_technique_sub_tecnique function
         enterprise - ditionary of mitre att&ck objects derived from mitre initializaiton in the analyst function

    Optional Parameter:
         terminal - leave set to 0 to display markdown in jupyter notebook
                    set to 1 in the analyst_tool.py file to disable parkdown for displaying in terminal
    
    """

    for tactics in enterprise['tactics']:
        for tactic in tactics['external_references']:
            if tactic['external_id'] == mitre_tactic:
                print("\t   {:<22} {}".format("Mitre Tactic: ",mitre_tactic))
                print("\t   " + tactics['name'] + ":")
                print("\t   " + tactic['url'] + "\n")

def print_otx_mitre_technique(mitre_technique, mitre_techniques):
    """Searches through Mitre ATT&CK for a Technique and pulls the inforation out and prints to the screen.
    
    Requried Parameters:
         mitre_techniqe - derived from the is_mitre_tactic_technique_sub_tecnique function
         mitre_techniques - list of mitre att&ck techniques derived from mitre initializaiton in the analyst function

    Optional Parameter:
         terminal - leave set to 0 to display markdown in jupyter notebook
                    set to 1 in the analyst_tool.py file to disable parkdown for displaying in terminal
    
    """

    for techniques in mitre_techniques:
        for technique in techniques['external_references']:
            try:
                technique['external_id'] == mitre_technique
            except:
                pass
            else:
                if technique['external_id'] == mitre_technique:
                    if len(technique['external_id']) <= 5:
                        print("\t   {:<22} {}".format("Mitre Tactic:",techniques['kill_chain_phases'][0]['phase_name'].title()))
                        print("\t   {:<18} {}".format("Mitre Technique:\t",technique['external_id']))
                        print("\t   " + techniques['name'])
                        print("\t   " + technique['url'] + "\n")
                    else:
                        count = 0
                        if count <= 4:
                            print("\t   {:<22} {}".format("Mitre Tactic:",techniques['kill_chain_phases'][0]['phase_name'].title()))
                            print("\t   {:<18} {}".format("Mitre Technique:\t",technique['external_id']))
                            print("\t   " + techniques['name'])
                            print("\t   " + technique['url'] + "\n")
                            count = count + 1

def print_otx_mitre_sub_technique(mitre_sub_technique, mitre_techniques, mitre_technique):
    """Searches through Mitre ATT&CK for a Sub-Technique and pulls the inforation out and prints to the screen.
    
    Requried Parameters:
         mitre_sub_technique - derived from the is_mitre_tactic_technique_sub_tecnique function
         mitre_techniques - list of mitre att&ck techniques derived from mitre initializaiton in the analyst function
         mitre_techniqe - derived from the is_mitre_tactic_technique_sub_tecnique function

    Optional Parameter:
         terminal - leave set to 0 to display markdown in jupyter notebook
                    set to 1 in the analyst_tool.py file to disable parkdown for displaying in terminal
    
    """
    for techniques in mitre_techniques:
        for technique in techniques['external_references']:
            try:
                technique['external_id'] == mitre_sub_technique
            except:
                pass
            else:
                if technique['external_id'] == mitre_sub_technique:
                    print("\t   {:<23} {}".format("Mitre Tactic:",techniques['kill_chain_phases'][0]['phase_name'].title()))
                    print("\t   {:<23} {}".format("Mitre Technique:",techniques['name']))
                    print("\t   {:<23} {}".format("Mitre Sub-Technique:",technique['external_id']))
                    print("\t   " + techniques['name'])
                    print("\t   " + technique['url'] + "\n")

def print_otx_pulse_info(suspect_pulse, otx, otx_intel_list):#, enterprise, mitre_techniques):
    otx_pulse_results = otx.get_pulse_details(suspect_pulse)
    print("\n\n\n" + color.BOLD + "AlientVault OTX Pulse Report for: " + color.END + suspect_pulse)
    print("https://otx.alienvault.com/pulse/" + suspect_pulse)
    if otx_pulse_results['author_name'] in otx_intel_list:
        print("\t{:<25} {}".format("Pulse Author:",color.GREEN + otx_pulse_results['author_name'] + color.END))
    else:
       print("\t{:<25} {}".format("Pulse Author:",otx_pulse_results['author_name']))
    print("\t{:<25} {}".format("Pulse Name:",otx_pulse_results['name']))
    print("\t{:<25} {}".format("TLP:",otx_pulse_results['TLP'].title()))
    print("\t{:<25} {}".format("Modified:",otx_pulse_results['modified']))
    print("\t{:<25} {}".format("Created:",otx_pulse_results['created']))


    if len(otx_pulse_results['tags']) == 0:
        print('\t{:<33} {}'.format(color.UNDERLINE + 'Tags:' + color.END,'No tags in pulse'))
    elif len(otx_pulse_results['tags']) <= 5:
            print("\t" + color.UNDERLINE + 'Tags:' + color.END)
            for tag in otx_pulse_results['tags']:
                print("\t   " + tag)
    else:
        count = 0
        print("\t" + color.UNDERLINE + 'Tags:' + color.END)
        for tag in otx_pulse_results['tags']:
            if count <= 4:
                print("\t   " + tag)
                count = count + 1
            else:
                pass

    if len(otx_pulse_results['malware_families']) == 0:
        print('\n\t{:<33} {}'.format(color.UNDERLINE + 'Malware Families:' + color.END,'No malware families associated with this pulse'))
    elif len(otx_pulse_results['malware_families']) <= 5:
            print("\n\t" + color.UNDERLINE + 'Malware Families:' + color.END)
            for malware in otx_pulse_results['malware_families']:
                print("\t   " + malware)
    else:
        count = 0
        print("\n\t" + color.UNDERLINE + 'Malware Families:' + color.END)
        for malware in otx_pulse_results['malware_families']:
            if count <= 4:
                print("\t   " + malware['display_name'])
                count = count + 1
            else:
                pass

    #if len(otx_pulse_results['attack_ids']) == 0:
    #    print('\n\t{:<25} {}'.format(color.UNDERLINE + 'Mitre ATT&CK:' + color.END,'No Mitre ATT&CK tags for this pulse'))
    #elif len(otx_pulse_results['attack_ids']) <= 5:
    #      print("\n\t" + color.UNDERLINE + 'Mitre ATT&CK:' + color.END)
    #      for attack in otx_pulse_results['attack_ids']:
    #          #print("\t   " + attack)
    #          is_otx_mitre_tactic_technique_sub_tecnique(attack, enterprise, mitre_techniques)
    #else:
    #    print("\n\t" + color.UNDERLINE + "Mitre ATT&CK:" + color.END)
    #    count = 0
    #    for attack in otx_pulse_results['attack_ids']:
    #        if count <= 4:
    #            #print("\t   " + attack)
    #            is_otx_mitre_tactic_technique_sub_tecnique(attack, enterprise, mitre_techniques)
    #            count = count + 1
    #        else:
    #            pass

    print(color.UNDERLINE + "\nDecription:" + color.END)
    print(otx_pulse_results['description'])

    if len(otx_pulse_results['references']) == 0:
        print('\n{:<25} {}'.format(color.UNDERLINE + 'References:' + color.END,'No refrences cited for this pulse'))
    elif len(otx_pulse_results['references']) <= 5:
        print("\n" + color.UNDERLINE + "References:" + color.END)
        for reference in otx_pulse_results['references']:
            print("\t" + reference)
    else:
        print("\n" + color.UNDERLINE + "References:" + color.END)
        count = 0
        for reference in otx_pulse_results['references']:
            if count <= 4:
                print("\t" + reference)
                count = count + 1
            else:
                pass
