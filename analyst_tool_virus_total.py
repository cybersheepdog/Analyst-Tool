# Python Standard Library Imports
import base64
import datetime
import json
import re
import requests

# 3rd Party Imports
from configparser import ConfigParser

# Custom Imports
from analyst_tool_utilities import *

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

def create_virus_total_headers_from_config():
    """ Creates a dictionary called virus_total_headers that contains the formatted header needed to submit an query to VirusTotal.
    
    Requires an VirusTotal API Key to use.  It is free to sign up for one but has restrictions on daily limits.
    
    Reads in the VirusTotal API Key from the config.ini file.
    
    Note:  You are not required to use this module but it is highly recommended as most of this tools current functionality is derived from VirusTotal.  If you do not wish to use it then you can leave the config file as is with x-apikey = None
    
    Returns VT API Headers in the form of:
        virus_total_headers = {
            'Accept': virus_total['accept'],
            'x-apikey': virus_total['x-apikey']
    
    """
    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
    except:
        print("Error with config.ini.")
    else:
        virus_total = config_object["VIRUS_TOTAL"]

        if virus_total['x-apikey']:
            virus_total_headers = {
            'Accept': virus_total['accept'],
            'x-apikey': virus_total['x-apikey']
        }
            print("VirusTotal configured.")
            return virus_total_headers
        else:
            print("VirusTotal not configured.")
            print("Please add your VirusTotal API Key to the config.ini file if you want to use this module.")
            virus_total_headers = ''

def get_vt_ip_results(suspect_ip, virus_total_headers, vt_user):
    """A fuction to form the api query for an IP address to VirusTotal and pull back the results.  It then calls a 2nd function to process those results.

    This function requires the following 2 parameters:
        IP address:  Obtained automatically from the main script in the Juptyer Notebook.
        
        VirusTotal Headers: Obtained automatically from the config.ini file and  the create_virus_total_headers_from_config function.
    
    Sample Output:
        VirusToal Detections:
           Malicious:                3
           Malware:                  3
           Suspicious:               0
           Phishing:                 0
           Spam:                     0
           Clean:                    72
           Undetected:               11
           Time Out:                 0
           https://www.virustotal.com/gui/ip-address/45.145.66.165
    """
    vt_ip_report = 'https://www.virustotal.com/api/v3/ip_addresses/SUSPECT_IP_ADDRESS'
    vt_ip_report = vt_ip_report.replace("SUSPECT_IP_ADDRESS", suspect_ip)
    response = requests.request("GET", vt_ip_report, headers=virus_total_headers)
    vt_ip_response = response.text
    vt_ip_response = json.loads(vt_ip_response)

    print(color.UNDERLINE + '\nVirusToal Detections:' + color.END)

    if vt_user == None:
        pass
    else:
        vt_api_count(virus_total_headers, vt_user)

    print_ip_detections(vt_ip_response)
    print("\thttps://www.virustotal.com/gui/ip-address/"+ suspect_ip)
    
def get_vt_user_from_config():
    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
    except:
        print("Error with config.ini.")
    else:
        vt = config_object["VIRUS_TOTAL"]
        if vt['user']:
            vt_user = vt['user']
            print('VirusTotal API usage alerts enabled for ' + vt_user)
            return vt_user
        else:
            print("No VT User.")
            print("Please add your VT username to the config.ini file if you would like to enable API Quota notifications")
            vt_user = ''
            return vt_user
            
def print_domain_detections(vt_domain_response):
    """ Takes the response from the virustotal api, counts the # of each categorey (malicious, suspicious, phishing, malware, spam, 'clean, unrated, time out)and then prints to screen with color coding.  Red = 10 or more detections in that category.  Oragne = 5 to 9 detections in that category.  
    
    This function requires the following parameter:
    
        vt_domain_response - Derived from the function        print_vt_domain_report
    
    Sample output:
        Last Analysis Stats:
            Malicious:                4
            Malware:                  2
            Suspicious:               1
            Phishing:                 8
            Spam:                     0
            Clean:                    66
            Undetected:               8
            Time Out:                 0
    """
    categories = [value for value in vt_domain_response['data']['attributes']['last_analysis_results'].values()]
    alert_categories = {'malicious': 0, 'suspicious': 0, 'phishing': 0, 'malware': 0, 'spam': 0, 'clean': 0, 'unrated': 0, 'time out': 0}
    for alert in categories:
        if alert['result'] in alert_categories:
            alert_categories[alert['result']] = alert_categories[alert['result']] + 1
        else:
            continue

    if alert_categories['malicious'] >= 10:
        print('\t{:<34} {}'.format(color.RED + 'Malicious:' + color.END,alert_categories['malicious']))
    elif alert_categories['malicious'] >= 5:
        print('\t{:<34} {}'.format(color.ORANGE + 'Malicious:' + color.END,alert_categories['malicious']))
    else:
        print('\t{:<25} {}'.format('Malicious:',alert_categories['malicious']))

    if alert_categories['malware'] >= 10:
        print('\t{:<31} {}'.format(color.RED + 'Malware:' + color.END,alert_categories['malware']))
    elif alert_categories['malware'] >= 5:
        print('\t{:<34} {}'.format(color.ORANGE + 'Malware:' + color.END,alert_categories['malware']))
    else:
        print('\t{:<25} {}'.format('Malware:',alert_categories['malware']))

    if alert_categories['suspicious'] >= 10:
        print('\t{:<31} {}'.format(color.RED + 'Suspicious:' + color.END,alert_categories['suspicious']))
    elif alert_categories['suspicious'] >= 5:
        print('\t{:<34} {}'.format(color.ORANGE + 'Suspicious:' + color.END,alert_categories['suspicious']))
    else:
        print('\t{:<25} {}'.format('Suspicious:',alert_categories['suspicious']))

    if alert_categories['phishing'] >= 10:
        print('\t{:<31} {}'.format(color.RED + 'Phishing:' + color.END,alert_categories['phishing']))
    elif alert_categories['phishing'] >= 5:
        print('\t{:<34} {}'.format(color.ORANGE + 'Phishing:' + color.END,alert_categories['phishing']))
    else:
        print('\t{:<25} {}'.format('Phishing:',alert_categories['phishing']))

    if alert_categories['spam'] >= 10:
        print('\t{:<31} {}'.format(color.RED + 'Spam:' + color.END,alert_categories['spam']))
    elif alert_categories['spam'] >= 5:
        print('\t{:<34} {}'.format(color.ORANGE + 'Spam:' + color.END,alert_categories['spam']))
    else:
        print('\t{:<25} {}'.format('Spam:',alert_categories['spam']))

    print('\t{:<25} {}'.format('Clean:',alert_categories['clean']))
    print('\t{:<25} {}'.format('Undetected:',alert_categories['unrated']))
    print('\t{:<25} {}'.format('Time Out:',alert_categories['time out']))

def print_ip_detections(vt_ip_response):
    """ Takes the response from the virustotal api, counts the # of each category (malicious, suspicious, phishing, malware, spam, 'clean, unrated, time out)and then prints to screen with color coding.  Red = 10 or more detections in that category.  Oragne = 5 to 9 detections in the (malicious, suspicious, phishing, malware, spam) categories.  
    
    This function requires the following parameter:
    
        vt_ip_response - Derived from the function        get_vt_ip_results
    
    Sample Output:
        Malicious:                3
        Malware:                  3
        Suspicious:               0
        Phishing:                 0
        Spam:                     0
        Clean:                    72
        Undetected:               11
        Time Out:                 0
    """
    categories = [value for value in vt_ip_response['data']['attributes']['last_analysis_results'].values()]
    alert_categories = {'malicious': 0, 'suspicious': 0, 'phishing': 0, 'malware': 0, 'spam': 0, 'clean': 0, 'unrated': 0, 'time out': 0}
    for alert in categories:
        if alert['result'] in alert_categories:
            alert_categories[alert['result']] = alert_categories[alert['result']] + 1
        else:
            continue

    if alert_categories['malicious'] >= 10:
        print('\t{:<34} {}'.format(color.RED + 'Malicious:' + color.END,alert_categories['malicious']))
    elif alert_categories['malicious'] >= 5:
        print('\t{:<34} {}'.format(color.ORANGE + 'Malicious:' + color.END,alert_categories['malicious']))
    else:
        print('\t{:<25} {}'.format('Malicious:',alert_categories['malicious']))

    if alert_categories['malware'] >= 10:
        print('\t{:<31} {}'.format(color.RED + 'Malware:' + color.END,alert_categories['malware']))
    elif alert_categories['malware'] >= 5:
        print('\t{:<34} {}'.format(color.ORANGE + 'Malware:' + color.END,alert_categories['malware']))
    else:
        print('\t{:<25} {}'.format('Malware:',alert_categories['malware']))

    if alert_categories['suspicious'] >= 10:
        print('\t{:<25} {}'.format(color.RED + 'Suspicious:' + color.END,alert_categories['suspicious']))
    elif alert_categories['suspicious'] >= 5:
        print('\t{:<25} {}'.format(color.ORANGE + 'Suspicious:' + color.END,alert_categories['suspicious']))
    else:
        print('\t{:<25} {}'.format('Suspicious:',alert_categories['suspicious']))

    if alert_categories['phishing'] >= 10:
        print('\t{:<25} {}'.format(color.RED + 'Phishing:' + color.END,alert_categories['phishing']))
    elif alert_categories['phishing'] >= 5:
        print('\t{:<25} {}'.format(color.ORANGE + 'Phishing:' + color.END,alert_categories['phishing']))
    else:
        print('\t{:<25} {}'.format('Phishing:',alert_categories['phishing']))

    if alert_categories['spam'] >= 10:
        print('\t{:<31} {}'.format(color.RED + 'Spam:' + color.END,alert_categories['spam']))
    elif alert_categories['spam'] >= 5:
        print('\t{:<34} {}'.format(color.ORANGE + 'Spam:' + color.END,alert_categories['spam']))
    else:
        print('\t{:<25} {}'.format('Spam:',alert_categories['spam']))

    print('\t{:<25} {}'.format('Clean:',alert_categories['clean']))
    print('\t{:<25} {}'.format('Undetected:',alert_categories['unrated']))
    print('\t{:<25} {}'.format('Time Out:',alert_categories['time out']))

def print_virus_total_hash_results(suspect_hash, virus_total_headers, vt_user):
    """Queries VirusTotal via the API for a suspect hash and prints the results to the screen.  For each hash it will color code output for the malicious and suspicious categories. Red = 10 or more detections in that category.  Oragne = 5 to 9 detections in the (malicious, suspicious, phishing, malware, spam) categories.  
    
    This function requires the following 2 parameters:
    
        Suspect Hash:  derived from matching clipboard contents against the hash_validation_regex
    
        Virus Total Headers:  derive from the create_virus_total_headers_from_config function.    
    
    Sample Output:
        VirusTotal Hash Report for 82c8db5f3a0fab2062df72c228ef5889:
            File Reputation:
                Malicious:                36
                Suspicious:               0
                Harmless:                 0
                Undetected:               26

            File Threat Classification:
                trojan                    19

            File Threat Name:
                linux                     25
                mirai                     22
                smlem                     2

            File Info:
                Signature:                File not signed
                Signers:                  N/A
                Signing Date:             N/A
                File Type:                ELF
                Product:                  N/A
                Copyright:                N/A
                Decription:               N/A
                Creation Date:            N/A
                Last Modification Date:   2022-02-13 14:38:27

            Submission Info:
                Last Submission:          2022-02-13 14:33:19
                Last Analysis:            2022-02-13 14:33:19
                First Submission:         2022-02-13 14:33:19
                Times Submitted:          1
             https://www.virustotal.com/gui/file/82c8db5f3a0fab2062df72c228ef5889/detection
    """
    vt_hash_url = 'https://www.virustotal.com/gui/file/SUSPECT_HASH/detection'
    vt_hash_report = "https://www.virustotal.com/api/v3/files/SUSPECT_HASH"
    vt_hash_report = vt_hash_report.replace("SUSPECT_HASH", suspect_hash)
    vt_hash_url = vt_hash_url.replace("SUSPECT_HASH", suspect_hash)
    heading = "\n\n\nVirusTotal Hash Report for " + suspect_hash + ":"
    print(color.BOLD + heading + color.END)

    if vt_user == None:
        pass
    else:
        vt_api_count(virus_total_headers, vt_user)

    response = requests.request("GET", vt_hash_report, headers=virus_total_headers)

    vt_hash_response = json.loads(response.text)

    try:
        vt_hash_response['data']
    except:
        print(color.UNDERLINE + 'File Reputation:' + color.END)
        print('\tFile hash not found in VirusTotal')
    else:
        print(color.UNDERLINE + 'File Reputation:' + color.END)

        if vt_hash_response['data']['attributes']['last_analysis_stats']['malicious'] >= 10:
            print('\t{:<34} {}'.format(color.RED + 'Malicious:' + color.END,vt_hash_response['data']['attributes']['last_analysis_stats']['malicious']))
        elif vt_hash_response['data']['attributes']['last_analysis_stats']['malicious'] >= 5:
            print('\t{:<25} {}'.format(color.ORANGE + 'Malicious:' + color.END,vt_hash_response['data']['attributes']['last_analysis_stats']['malicious']))
        else:
            print('\t{:<25} {}'.format('Malicious:',vt_hash_response['data']['attributes']['last_analysis_stats']['malicious']))


        if vt_hash_response['data']['attributes']['last_analysis_stats']['suspicious'] >= 10:
            print('\t{:<25} {}'.format(color.RED + 'Suspicious:' + color.END,vt_hash_response['data']['attributes']['last_analysis_stats']['suspicious']))
        elif vt_hash_response['data']['attributes']['last_analysis_stats']['suspicious'] >= 5:
            print('\t{:<25} {}'.format(color.ORANGE + 'Suspicious:' + color.END,vt_hash_response['data']['attributes']['last_analysis_stats']['suspicious']))
        else:
            print('\t{:<25} {}'.format('Suspicious:',vt_hash_response['data']['attributes']['last_analysis_stats']['suspicious']))

        print('\t{:<25} {}'.format('Harmless:',vt_hash_response['data']['attributes']['last_analysis_stats']['harmless']))
        print('\t{:<25} {}'.format('Undetected:',vt_hash_response['data']['attributes']['last_analysis_stats']['undetected']))

        print(color.UNDERLINE + '\nFile Threat Classification:' + color.END)
        try:
            vt_hash_response['data']['attributes']['popular_threat_classification']['popular_threat_category']
        except KeyError:
            print('\tThis hash does not have a Threat Classification')
        else:
            for line in vt_hash_response['data']['attributes']['popular_threat_classification']['popular_threat_category']:
                print('\t{:<25} {}'.format(line['value'],line['count']))

        print(color.UNDERLINE + '\nFile Threat Name:' + color.END)
        try:
            vt_hash_response['data']['attributes']['popular_threat_classification']['popular_threat_name']
        except KeyError:
            print('\tThis hash does not have an associated Threat Name.')
        else:
            for line in vt_hash_response['data']['attributes']['popular_threat_classification']['popular_threat_name']:
                print('\t{:<25} {}'.format(line['value'],line['count']))

        print(color.UNDERLINE + '\nFile Info:' + color.END)
        try:
            vt_hash_response['data']['attributes']['signature_info']['verified']
        except KeyError:
            print('\t{:<25} {}'.format('Signature:','File not signed'))
        else:
            print('\t{:<25} {}'.format('Signature:',vt_hash_response['data']['attributes']['signature_info']['verified']))

        try:
            vt_hash_response['data']['attributes']['signature_info']['signers details']
        except KeyError:
            print('\t{:<25} {}'.format('Signers:','N/A'))
        else:
            print('\n\tSigner(s):')
            for line in vt_hash_response['data']['attributes']['signature_info']['signers details']:
                if line['status'] == 'Valid':
                    print('\t\t{:<50} {:<25}'.format(line['name'],line['status']))
                else:
                    print('\t\t{:<50} {:<25}'.format(line['name'],'Not Valid'))

        try:
            vt_hash_response['data']['attributes']['signature_info']['signing date']
        except KeyError as e:
            print('\t{:<25} {}'.format('Signing Date:','N/A'))
        else:
             print('\n\t{:<25} {}'.format('Signing Date:',vt_hash_response['data']['attributes']['signature_info']['signing date']))

        try:
            vt_hash_response['data']['attributes']['type_description']
        except KeyError as e:
            print('\t{:<25} {}'.format('File Type:','N/A'))
        else:
            print('\t{:<25} {}'.format('File Type:',vt_hash_response['data']['attributes']['type_description']))

        try:
            vt_hash_response['data']['attributes']['signature_info']['product']
        except KeyError as e:
            print('\t{:<25} {}'.format('Product:','N/A'))
        else:
            print('\t{:<25} {}'.format('Product:',vt_hash_response['data']['attributes']['signature_info']['product']))

        try:
            vt_hash_response['data']['attributes']['signature_info']['copyright']
        except KeyError as e:
            print('\t{:<25} {}'.format('Copyright:','N/A'))
        else:
            print('\t{:<25} {}'.format('Copyright:',vt_hash_response['data']['attributes']['signature_info']['copyright']))

        try:
            vt_hash_response['data']['attributes']['signature_info']['description']
        except KeyError as e:
            print('\t{:<25} {}'.format('Decription:','N/A'))
        else:
            print('\t{:<25} {}'.format('Decription:',vt_hash_response['data']['attributes']['signature_info']['description']))

        try:
            vt_hash_response['data']['attributes']['creation_date']
        except KeyError as e:
            print('\t{:<25} {}'.format('Creation Date:','N/A'))
        else:
            print('\t{:<25} {}'.format('Creation Date:',datetime.datetime.fromtimestamp(vt_hash_response['data']['attributes']['creation_date'])))

        try:
            vt_hash_response['data']['attributes']['last_modification_date']
        except KeyError as e:
            print('\t{:<25} {}'.format('Last Modification Date:','N/A'))
        else:
             print('\t{:<25} {}'.format('Last Modification Date:',datetime.datetime.fromtimestamp(vt_hash_response['data']['attributes']['last_modification_date'])))

        print(color.UNDERLINE + '\nSubmission Info:' + color.END)

        try:
            vt_hash_response['data']['attributes']['last_submission_date']
        except KeyError as e:
            print('\t{:<25} {}'.format('Last Submission:','N/A'))
        else:
            print('\t{:<25} {}'.format('Last Submission:',datetime.datetime.fromtimestamp(vt_hash_response['data']['attributes']['last_submission_date'])))

        try:
            vt_hash_response['data']['attributes']['last_analysis_date']
        except KeyError as e:
            print('\t{:<25} {}'.format('Last Analysis:','N/A'))
        else:
            print('\t{:<25} {}'.format('Last Analysis:',datetime.datetime.fromtimestamp(vt_hash_response['data']['attributes']['last_analysis_date'])))

        try:
            vt_hash_response['data']['attributes']['first_submission_date']
        except KeyError as e:
            print('\t{:<25} {}'.format('First Submission:','N/A'))
        else:
            print('\t{:<25} {}'.format('First Submission:',datetime.datetime.fromtimestamp(vt_hash_response['data']['attributes']['first_submission_date'])))

        try:
            vt_hash_response['data']['attributes']['times_submitted']
        except KeyError as e:
            print('\t{:<25} {}'.format('Times Submitted:','N/A'))
        else:
            print('\t{:<25} {}'.format('Times Submitted:',vt_hash_response['data']['attributes']['times_submitted']))
        print(vt_hash_url)

def print_vt_domain_report(suspect_domain, virus_total_headers, vt_user):
    """ Queries VirusTotal via the API and prints the specified information to the screen.
    
    This funciton requires the following 2 parameters:
    
        Supect Domain - Derived from checking the clipboard contents agaisnt validators.domain.

        VirusTotal Headers - dereived from the create_virus_total_headers_from_config function
        
    Sample Output:
        Domain Reputation for kamery112.xyz:
        Last Analysis Stats:
            Malicious:                4
            Malware:                  2
            Suspicious:               1
            Phishing:                 8
            Spam:                     0
            Clean:                    66
            Undetected:               8
            Time Out:                 0

        Domain Info:
            Creation Date:                 2021-12-04 19:00:00
            Last Update Date:              2021-12-04 19:00:00
            Last Modification Date:        2022-02-08 21:35:04

        Certificate Info:
            Issuer:                        GoGetSSL
            Not After:                     2022-11-20 23:59:59
            Not Before:                    2021-10-20 00:00:00
        https://www.virustotal.com/gui/domain/kamery112.xyz
    """

    creation_date_regex = '(created|Creation Date): ([0-9T:-]+)Z?\\n'
    vt_domain_report = "https://www.virustotal.com/api/v3/domains/SUSPECT_DOMAIN"
    vt_domain_report = vt_domain_report.replace("SUSPECT_DOMAIN", suspect_domain)
    response = requests.request("GET", vt_domain_report, headers=virus_total_headers)
    vt_domain_response = response.text
    vt_domain_response = json.loads(vt_domain_response)

    try:
        vt_domain_response['data']
    except:
        print('\n\n\n' + color.BOLD + 'Domain Reputation for ' + suspect_domain + ':' + color.END)
        print('\tDomain not found in VirusTotal')
    else:
        print('\n\n\n' + color.BOLD + 'Domain Reputation for ' + suspect_domain + ':' + color.END)

    if vt_user == None:
        pass
    else:
        vt_api_count(virus_total_headers, vt_user)

    print(color.UNDERLINE + 'Last Analysis Stats:' + color.END)
    print_domain_detections(vt_domain_response)
    print(color.UNDERLINE + '\nDomain Info:' + color.END)

    try:
        vt_domain_response['data']['attributes']['creation_date']
    except:
        try:
            vt_domain_response['data']['attributes']['whois']
        except:
            print('\t{:<30} {}'.format('Creation Date:','No Date in VT'))
        else:
            if re.search(creation_date_regex, vt_domain_response['data']['attributes']['whois']) != None:
                m =  m = re.search(creation_date_regex, vt_domain_response['data']['attributes']['whois'])
                cd = m.group(2)
                print('\t{:<30} {}'.format('Creation Date:',cd))
            else:
                print('\t{:<30} {}'.format('Creation Date:','No Date in VT'))
    else:
        datetime.datetime.fromtimestamp(vt_domain_response['data']['attributes']['creation_date'])
        print('\t{:<30} {}'.format('Creation Date:',datetime.datetime.fromtimestamp(vt_domain_response['data']['attributes']['creation_date'])))

    try:
        vt_domain_response['data']['attributes']['last_update_date']
    except:
        print('\t{:<30} {}'.format('Last Update Date:','No Data'))
    else:
        print('\t{:<30} {}'.format('Last Update Date:',datetime.datetime.fromtimestamp(vt_domain_response['data']['attributes']['last_update_date'])))

    try:
        vt_domain_response['data']['attributes']['last_modification_date']
    except:
        print('\t{:<30} {}'.format('Last Modification Date:','No Data'))
    else:
        print('\t{:<30} {}'.format('Last Modification Date:',datetime.datetime.fromtimestamp(vt_domain_response['data']['attributes']['last_modification_date'])))

    print(color.UNDERLINE + '\nCertificate Info:' + color.END)
    try:
        vt_domain_response['data']['attributes']['last_https_certificate']['issuer']['O']
    except:
        print('\t{:<30} {}'.format('Issuer:','No Data'))
    else:
        print('\t{:<30} {}'.format('Issuer:',vt_domain_response['data']['attributes']['last_https_certificate']['issuer']['O']))

    try:
        vt_domain_response['data']['attributes']['last_https_certificate']['validity']['not_after']
    except:
        print('\t{:<30} {}'.format('Not After:','No Data'))
    else:
        print('\t{:<30} {}'.format('Not After:',vt_domain_response['data']['attributes']['last_https_certificate']['validity']['not_after']))

    try:
        vt_domain_response['data']['attributes']['last_https_certificate']['validity']['not_before']
    except:
        print('\t{:<30} {}'.format('Not Before:','No Data'))
    else:
        print('\t{:<30} {}'.format('Not Before:',vt_domain_response['data']['attributes']['last_https_certificate']['validity']['not_before']))
    print("https://www.virustotal.com/gui/domain/"+ suspect_domain)

def print_virus_total_url_report(virus_total_headers, suspect_url):
    """

    """
    URL_ID = base64.urlsafe_b64encode(suspect_url.encode()).decode().strip("=")
    vt_url_report = 'https://www.virustotal.com/api/v3/urls/URL_ID'
    vt_url_report = vt_url_report.replace("URL_ID", URL_ID)
    response = requests.request("GET", vt_url_report, headers=virus_total_headers)
    vt_url_response = response.text
    vt_url_response = json.loads(vt_url_response)

    sanitized_url = sanitize_url(suspect_url)

    print(color.UNDERLINE + "\nVirusTotal URL Report for:" + color.END + " " + sanitized_url)

    print_ip_detections(vt_url_response)
    vt_url_report = 'https://www.virustotal.com/gui/url/' + vt_url_response['data']['id']
    print('\n')
    print_lists(vt_url_response['data']['attributes']['tags'],"Tags")
    print_lists( vt_url_response['data']['attributes']['threat_names'],"Threat Name")
    print('\n')
    last_analysis_date = vt_url_response['data']['attributes']['last_analysis_date']
    print("\t{:<25} {}".format("Last Analysis Date:",datetime.datetime.fromtimestamp(last_analysis_date)))
    first_submission_date = vt_url_response['data']['attributes']['first_submission_date']
    print("\t{:<25} {}".format("First Submission Date:",datetime.datetime.fromtimestamp(first_submission_date)))
    last_submission_date = vt_url_response['data']['attributes']['last_submission_date']
    print("\t{:<25} {}".format("Last Submission Date:",datetime.datetime.fromtimestamp(last_submission_date)))
    print("\t{:<25} {}".format("Times Submitted:",vt_url_response['data']['attributes']['times_submitted']))
    print(vt_url_report)
    print('\n')

def vt_api_count(virus_total_headers, vt_user):
    vt_api_count_url = "https://www.virustotal.com/api/v3/users/VT_ID/overall_quotas"
    vt_api_count_url = vt_api_count_url.replace("VT_ID", vt_user)
    response = requests.request("GET", vt_api_count_url, headers=virus_total_headers)
    api_response = response.text
    api_usage = json.loads(api_response)
    vt_count = api_usage['data']['api_requests_daily']['user']['used']

    if vt_count == 500:
        print(color.BOLD + "You have reached 100% of your 500 daily VT API Queries!" + color.END)
    elif vt_count == 475:
        print(color.BOLD + "You have reached 95% of your 500 daily VT API Queries" + color.END)
    elif vt_count == 375:
        print(color.BOLD + "You have reached 75% of your 500 daily VT API Queries!" + color.END)
    elif vt_count == 250:
        print(color.BOLD + "You have reached 50% of your 500 daily VT API Queries!" + color.END)
    else:
        pass
