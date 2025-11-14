# Python Standard Library Imports
import json
import re
import requests


# 3rd Party Imports
from configparser import ConfigParser
from pycti import OpenCTIApiClient

# Custom Imports

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

def get_opencti_from_config():
    """ Creates a dictionary called opencti_headers that contains the formatted header needed to submit an query to OpenCTI for an atomic indicator.
    
    Requires an OpenCTI API Key to use. 
    
    Reads in the OpenCTI API Key from the config.ini file.
    
    Note:  You are not required to use this module.  If you do not wish to use it then you can leave the config file as is with opencti_api_toekn = None
    
    Returns the OpenCTI API Headers in the form of:
        opencti_headers = OTXv2(av_headers['otx_api_key'], server=av_headers['server'])
    """
    
    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
    except:
        print("Error with config.ini.")
    else:
        cti_headers = config_object["OPEN_CTI"]

        if cti_headers['opencti_api_token']:
            opencti_api_url = cti_headers['opencti_api_url']
            opencti_api_token = cti_headers['opencti_api_token']
            opencti_headers = opencti_api_url + "," + opencti_api_token
            print("OpenCTI Configured.")
            return opencti_headers
        else:
            print("OpenCTI not configured.")
            print("Please add your OpenCTI API Key to the config.ini file if you want to use this module.")
            opencti_headers = ''

def print_opencti_domain_results(opencti_domain_results, suspect_indicator, opencti_headers):
    """Docstring Placeholder"""
    # blank list to hold tags for indicator
    keywords = []
    sanitized_domain = suspect_indicator.replace(".", "[.]")

    # get key information and assign to variables for use in printing to screen
    for item in opencti_domain_results:
        item_id = item['id']
        link_url = opencti_headers.split(",")[0][:-8] + "/dashboard/observations/indicators/" + item_id
        source = item['createdBy']['name']
        active = item['revoked']
        confidence = item['confidence']
        malicious_score = item['x_opencti_score']

    for item in opencti_domain_results:
        line = item['objectMarking']
        for section in line:
            tlp = section['definition']
    for item in opencti_domain_results:
        line = item['objectLabel']
        for section in line:
            keywords.append(section['value'])

    #Format and print informationt to screeen
    print(color.UNDERLINE + '\nOpenCTI Info:' + color.END + " " + sanitized_domain)

    # Color Coded active indicator
    # value is revoked so if true it is inactive.  if false it is active.
    if active == False:
        print('\t{:<34} {}'.format(color.GREEN + 'Active:' + color.END,'Yes'))
    elif active == True:
        print('\t{:<34} {}'.format(color.RED + 'Active:' + color.END,'No'))
    else:
        print('\t{:<25} {}'.format('Active:', active))


    # Color coded malicious score
    if int(malicious_score) >= 75:
        print('\t{:<34} {}'.format(color.RED + 'Malicious:' + color.END,malicious_score))
    elif int(malicious_score) >= 50:
        print('\t{:<34} {}'.format(color.ORANGE + 'Malicious:' + color.END,malicious_score))
    else:
        print('\t{:<25} {}'.format('Malicious:',malicious_score))

    # Color coded OpenCTI Confidence Score
    if int(confidence) >= 75:
        print('\t{:<34} {}'.format(color.RED + 'Confidence:' + color.END,'High'))
    elif int(confidence) >= 50:
        print('\t{:<34} {}'.format(color.ORANGE + 'Confidence:' + color.END,'Medium'))
    else:
        print('\t{:<25} {}'.format('Confidence:','Low'))

    # Print source information:
    print('\t{:<25} {}'.format('Source:', source))

    print("\t" + color.UNDERLINE + 'Tags:' + color.END)
    count = 0
    for tag in keywords:
        if count <= 4:
            print("\t   " + tag)
            count = count + 1
        else:
            pass

    if tlp == "RED":
        print('\t{:<34} {}'.format(color.RED + 'TLP:' + color.END,'Red'))
    elif tlp == "AMBER":
        print('\t{:<34} {}'.format(color.ORANGE + 'TLP:' + color.END,'Amber'))
    elif tlp == "GREEN":
        print('\t{:<34} {}'.format(color.GREEN + 'TLP:' + color.END,'Green'))
    else:
        print('\t{:<25} {}'.format('TLP:','Clear'))

    print('\t{:<25}'.format(link_url))

def print_opencti_hash_results(opencti_hash_results, suspect_indicator, opencti_headers):
    """Docstring Placeholder"""
    # blank list to hold tags for indicator
    keywords = []

    # get key information and assign to variables for use in printing to screen
    for item in opencti_hash_results:
        item_id = item['id']
        link_url = opencti_headers.split(",")[0][:-8] + "/dashboard/observations/indicators/" + item_id
        source = item['createdBy']['name']
        active = item['revoked']
        confidence = item['confidence']
        malicious_score = item['x_opencti_score']
        if "file:hashes" in item['pattern']:
            rule = "No yara rule in OpenCTI"
        else:
            rule = item['pattern'].replace("\n","\n\t\t\t\t")

    for item in opencti_hash_results:
        line = item['objectMarking']
        for section in line:
            tlp = section['definition']
    for item in opencti_hash_results:
        line = item['objectLabel']
        for section in line:
            keywords.append(section['value'])

    #Format and print informationt to screeen
    print(color.UNDERLINE + '\nOpenCTI Info:' + color.END + " " + suspect_indicator)

    # Color Coded active indicator
    # value is revoked so if true it is inactive.  if false it is active.
    if active == False:
        print('\t{:<34} {}'.format(color.GREEN + 'Active:' + color.END,'Yes'))
    elif active == True:
        print('\t{:<34} {}'.format(color.RED + 'Active:' + color.END,'No'))
    else:
        print('\t{:<25} {}'.format('Active:', active))


    # Color coded malicious score
    if int(malicious_score) >= 75:
        print('\t{:<34} {}'.format(color.RED + 'Malicious:' + color.END,malicious_score))
    elif int(malicious_score) >= 50:
        print('\t{:<34} {}'.format(color.ORANGE + 'Malicious:' + color.END,malicious_score))
    else:
        print('\t{:<25} {}'.format('Malicious:',malicious_score))

    # Color coded OpenCTI Confidence Score
    if int(confidence) >= 75:
        print('\t{:<34} {}'.format(color.RED + 'Confidence:' + color.END,'High'))
    elif int(confidence) >= 50:
        print('\t{:<34} {}'.format(color.ORANGE + 'Confidence:' + color.END,'Medium'))
    else:
        print('\t{:<25} {}'.format('Confidence:','Low'))

    # Print source information:
    print('\t{:<25} {}'.format('Source:', source))

    print("\t" + color.UNDERLINE + 'Tags:' + color.END)
    count = 0
    for tag in keywords:
        if count <= 4:
            print("\t   " + tag)
            count = count + 1
        else:
            pass

    if tlp == "RED":
        print('\t{:<34} {}'.format(color.RED + 'TLP:' + color.END,'Red'))
    elif tlp == "AMBER":
        print('\t{:<34} {}'.format(color.ORANGE + 'TLP:' + color.END,'Amber'))
    elif tlp == "GREEN":
        print('\t{:<34} {}'.format(color.GREEN + 'TLP:' + color.END,'Green'))
    else:
        print('\t{:<25} {}'.format('TLP:','Clear'))

    print('\t{:<25} {}'.format('Rule:',rule))

    print('\t{:<25}'.format(link_url))
    
def print_opencti_ip_results(opencti_ip_results, suspect_indicator, countries, opencti_headers):
    """Docstring Placeholder"""
    # blank list to hold tags for indicator
    keywords = []
    assoc_regex = "\\n"

    # get key information and assign to variables for use in printing to screen
    for item in opencti_ip_results:
        item_id = item['id']
        link_url = opencti_headers.split(",")[0][:-8] + "/dashboard/observations/indicators/" + item_id
        #source = item['createdBy']['name']
        source = item['creators'][0]['name']
        active = item['revoked']
        confidence = item['confidence']
        malicious_score = item['x_opencti_score']
        #opencti_whois = item['description']
        #if item['description'] == '':
        #    association = "No info in OpenCTI"
        #    country_code = ""
        #    asn = "No info in OpenCTI"
        #    org = "No info in OpenCTI"
        #    opencti_whois = ''
        #else:
        #    if re.search(assoc_regex, opencti_whois):
        #        try:
        #            opencti_whois = opencti_whois.split("\n")
        #        except:
        #            openci_whois = ""
        #        try:
        #            association = opencti_whois[0]
        #        except:
        #            association = ""
        #        try:
        #            other_whois = opencti_whois[1]
        #        except:
        #            other_whois = ""
        #        try:
        #            other_whois = other_whois.split()
        #        except:
        #            other_whois = ""
        #        try:
        #            country_code = other_whois[0].split("=")[1]
        #        except:
        #            country_code = ""
        #        try:
        #            asn = other_whois[1].split("=")[1]
        #        except:
        #            asn = ""
        #        try:
        #            org = other_whois[2:]
        #        except:
        #            org = ""
        #        try:
        #            org = " ".join(org)
        #        except:
        #            org = ""
        #    else:
        #        try:
        #            opencti_whois = opencti_whois.split()
        #        except:
        #            opencti_whois = ""
        #        association = "None"
        #        try:
        #            country_code = opencti_whois[0].split("=")[1]
        #        except:
        #            country_code = ""
        #        try:
        #            asn = opencti_whois[1].split("=")[1]
        #        except:
        #            asn = ""
        #        try:
        #            org = opencti_whois[2:]
        #        except:
        #            org = ""
        #        try:
        #            org = " ".join(org)
        #        except:
        #            org = ""


    for item in opencti_ip_results:
        line = item['objectMarking']
        for section in line:
            tlp = section['definition']
    for item in opencti_ip_results:
        line = item['objectLabel']
        for section in line:
            keywords.append(section['value'])

    #Format and print informationt to screeen
    print(color.UNDERLINE + '\nOpenCTI Info:' + color.END + " " + suspect_indicator)

    # Color Coded active indicator
    # value is revoked so if true it is inactive.  if false it is active.
    if active == False:
        print('\t{:<34} {}'.format(color.GREEN + 'Active:' + color.END,'Yes'))
    elif active == True:
        print('\t{:<34} {}'.format(color.RED + 'Active:' + color.END,'No'))
    else:
        print('\t{:<25} {}'.format('Active:', active))


    # Color coded malicious score
    if int(malicious_score) >= 75:
        print('\t{:<34} {}'.format(color.RED + 'Malicious:' + color.END,malicious_score))
    elif int(malicious_score) >= 50:
        print('\t{:<34} {}'.format(color.ORANGE + 'Malicious:' + color.END,malicious_score))
    else:
        print('\t{:<25} {}'.format('Malicious:',malicious_score))

    # Color coded OpenCTI Confidence Score
    if int(confidence) >= 75:
        print('\t{:<34} {}'.format(color.RED + 'Confidence:' + color.END,'High'))
    elif int(confidence) >= 50:
        print('\t{:<34} {}'.format(color.ORANGE + 'Confidence:' + color.END,'Medium'))
    else:
        print('\t{:<25} {}'.format('Confidence:','Low'))

    # Print source information:
    print('\t{:<25} {}'.format('Source:', source))

    #OpenCTI Whois
    #print("\t" + color.UNDERLINE + 'Whois Info:' + color.END)
    #print('\t{:<18} {}'.format('\tAssociation:', association))
    #if country_code == None:
    #    country = country_code
    #else:
    #    country_code = country_code.upper()
    #    country = country_code

    #for line in countries:
    #    if country_code == line['Alpha-2 code']:
    #        country = line['Country']
    #    else:
    #        pass

    #if country != '':
    #    print('\t{:<18} {}'.format('\tCountry:',country))
    #else:
    #    print('\t\t{:<17} {}'.format('Country:','No info in OpenCTI'))
    #print('\t{:<18} {}'.format('\tASN:', asn))
    #print('\t{:<18} {}'.format('\tOrg:', org))

    print("\t" + color.UNDERLINE + 'Tags:' + color.END)
    count = 0
    for tag in keywords:
        if count <= 4:
            print("\t\t\t\t  " + tag)
            count = count + 1
        else:
            pass

    if tlp == "RED":
        print('\t{:<34} {}'.format(color.RED + 'TLP:' + color.END,'Red'))
    elif tlp == "AMBER":
        print('\t{:<34} {}'.format(color.ORANGE + 'TLP:' + color.END,'Amber'))
    elif tlp == "GREEN":
        print('\t{:<34} {}'.format(color.GREEN + 'TLP:' + color.END,'Green'))
    else:
        print('\t{:<25} {}'.format('TLP:','Clear'))

    print('\t{:<25}'.format(link_url))

def print_opencti_url_results(opencti_url_results, suspect_indicator, opencti_headers):
    """Docstring Placeholder"""
    # blank list to hold tags for indicator
    keywords = []
    #sanitize url
    sanitized_url = suspect_indicator.replace("http","hXXP")
    #Format and print informationt to screeen
    print(color.UNDERLINE + '\nOpenCTI Info:' + color.END + " " + sanitized_url)

    url_results = []
    for item in opencti_url_results:
        if item['name'] == suspect_indicator:
            url_results.append(item)

    if not url_results:
        opencti_url_results = []

        print('\n\tURL not found in OpenCTI')
    else:
        opencti_url_results = url_results

        # get key information and assign to variables for use in printing to screen
        for item in opencti_url_results:
            item_id = item['id']
            link_url = opencti_headers.split(",")[0][:-8] + "/dashboard/observations/indicators/" + item_id
            source = item['createdBy']['name']
            active = item['revoked']
            confidence = item['confidence']
            malicious_score = item['x_opencti_score']

        for item in opencti_url_results:
            line = item['objectMarking']
            for section in line:
                tlp = section['definition']
        for item in opencti_url_results:
            line = item['objectLabel']
            for section in line:
                keywords.append(section['value'])

        # Color Coded active indicator
        # value is revoked so if true it is inactive.  if false it is active.
        if active == False:
            print('\t{:<34} {}'.format(color.GREEN + 'Active:' + color.END,'Yes'))
        elif active == True:
            print('\t{:<34} {}'.format(color.RED + 'Active:' + color.END,'No'))
        else:
            print('\t{:<25} {}'.format('Active:', active))

        # Color coded malicious score
        if int(malicious_score) >= 75:
            print('\t{:<34} {}'.format(color.RED + 'Malicious:' + color.END,malicious_score))
        elif int(malicious_score) >= 50:
            print('\t{:<34} {}'.format(color.ORANGE + 'Malicious:' + color.END,malicious_score))
        else:
            print('\t{:<25} {}'.format('Malicious:',malicious_score))

        # Color coded OpenCTI Confidence Score
        if int(confidence) >= 75:
            print('\t{:<34} {}'.format(color.RED + 'Confidence:' + color.END,'High'))
        elif int(confidence) >= 50:
            print('\t{:<34} {}'.format(color.ORANGE + 'Confidence:' + color.END,'Medium'))
        else:
            print('\t{:<25} {}'.format('Confidence:','Low'))

        # Print source information:
        print('\t{:<25} {}'.format('Source:', source))

        print("\t" + color.UNDERLINE + 'Tags:' + color.END)
        count = 0
        for tag in keywords:
            if count <= 4:
                print("\t   " + tag)
                count = count + 1
            else:
                pass

        if tlp == "RED":
            print('\t{:<34} {}'.format(color.RED + 'TLP:' + color.END,'Red'))
        elif tlp == "AMBER":
            print('\t{:<34} {}'.format(color.ORANGE + 'TLP:' + color.END,'Amber'))
        elif tlp == "GREEN":
            print('\t{:<34} {}'.format(color.GREEN + 'TLP:' + color.END,'Green'))
        else:
            print('\t{:<25} {}'.format('TLP:','Clear'))

        print('\t{:<25}'.format(link_url))

def query_opencti(opencti_headers, suspect_indicator):
    """docstring"""
    #coding: utf-8
    opencti_headers = opencti_headers.split(",")
    cti_api_url = opencti_headers[0]
    #print(cti_api_url)
    cti_api_token = opencti_headers[1]
    #print(cti_api_token)

    #OpenCTI client initialization
    opencti_api_client = OpenCTIApiClient(cti_api_url, cti_api_token)

    #submit query to OpenCTI
    opencti_results = opencti_api_client.indicator.list(search=suspect_indicator)
    return opencti_results
