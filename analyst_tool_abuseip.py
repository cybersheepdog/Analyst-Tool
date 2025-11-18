# Python Standard Library Imports
import base64
import datetime
import json
import logging
import re
import requests
import sys
import time

# 3rd Party Imports
from ipwhois import IPWhois
from configparser import ConfigParser
from IPython.display import display, Markdown


# Custom Imports
from analyst_tool_utilities import *

def check_abuse_ip_db(suspect_ip, abuse_ip_db_headers):
    """ Used to Automatically pull down and present relevant information from AbuseIPDB (https://www.abuseipdb.com/) of an IP address and print the information to the screen.  Requires an AbuseIP DB API-Key which is free but subject to daily limits.  Uses their APIv2.

    This funciton takes the followiong two parameters:
    
        IP address:  Obtained automatically from the main script in the Juptyer Notebook.
        
        AbuseIPDB Headers: Obtained automatically from the config.ini file and  the create_abuse_ip_db_headers_from_config function. 
            ifniques['x_mitre_detection'])terminal = 0:
    
    Sample Output:
        Abuse IP DB:
            Abuse Confidence Score:   97%
            Total Reports:            53
            Last Reported:            2022-02-13T17:22:12+00:00
            Distinct Reporters:       14
            Usage Type:               Fixed Line ISP
            Domain:                   inter.com.ru
            https://www.abuseipdb.com/check/45.145.66.165
    """
    # Set variable for the current API Url
    abuse_ip_db_url = 'https://api.abuseipdb.com/api/v2/check'
    # Set variable for the max age in days to look back.  Their site asks no further back than 90 days in most cases.
    days = '90'
    # Format a clickable link to print along with the results in order to see additional information not printed to the screen or to verify the information is accurate.  Trust but verify.
    abuse_ip_link_url = 'https://www.abuseipdb.com/check/SUSPECT_IP_ADDRESS'
    # Takes the link above and replaces SUSPECT_IP_ADDRESS with the IP Address from the clipboard to format a clickable link and to print along with the results in order to see additional information not printed to the screen or to verify the information is accurate.  Trust but verify.
    abuse_ip_link_url = abuse_ip_link_url.replace("SUSPECT_IP_ADDRESS", suspect_ip)
    # Formats the query string to submit via the API.
    querystring = {
        'ipAddress': suspect_ip,
        'maxAgeInDays': days
    }

    abuse_ip_response = requests.request(method='GET', url=abuse_ip_db_url, headers=abuse_ip_db_headers , params=querystring)

    abuse_ip_report = json.loads(abuse_ip_response.text)

    print(color.UNDERLINE + '\nAbuse IP DB:' + color.END)

    abuse_api_count = abuse_ip_response.headers['X-RateLimit-Remaining']
    if abuse_api_count == 0:
        print(color.BOLD + "You have reached 100% of your 1000 daily Abuse IP DB API Queries!" + color.END)
    elif abuse_api_count == 50:
        print(color.BOLD + "You have reached 95% of your 1000 daily Abuse IP DB API Queries" + color.END)
    elif abuse_api_count == 250:
        print(color.BOLD + "You have reached 75% of your 1000 daily Abuse IP DB API Queries!" + color.END)
    else:
        pass

    if abuse_ip_report['data']['abuseConfidenceScore'] >= 70:
        print('\t{:<34} {}%'.format(color.RED + 'Abuse Confidence Score:' + color.END,abuse_ip_report['data']['abuseConfidenceScore'] ))
    elif abuse_ip_report['data']['abuseConfidenceScore'] >= 40:
        print('\t{:<34} {}%'.format(color.ORANGE + 'Abuse Confidence Score:' + color.END,abuse_ip_report['data']['abuseConfidenceScore'] ))
    else:
        print('\t{:<25} {}%'.format('Abuse Confidence Score:',abuse_ip_report['data']['abuseConfidenceScore'] ))
    print('\t{:<25} {}'.format('Total Reports:',abuse_ip_report['data']['totalReports'] ))
    print('\t{:<25} {}'.format('Last Reported:',abuse_ip_report['data']['lastReportedAt'] ))
    print('\t{:<25} {}'.format('Distinct Reporters:',abuse_ip_report['data']['numDistinctUsers'] ))
    print('\t{:<25} {}'.format('Usage Type:',abuse_ip_report['data']['usageType'] ))
    print('\t{:<25} {}'.format('Domain:',abuse_ip_report['data']['domain'] ))
    print('\t' + abuse_ip_link_url)

def create_abuse_ip_db_headers_from_config():
    """ Creates a dictionary called abuse_ip_db_headers that contains the formatted header needed to submit an query to AbuseIP DB.
    
    Requires an AbuseIP DB API Key to use.  It is free to sign up for one but has restrictions on daily limits.
    
    Reads in the AbuseIP DB API Key from the config.ini file.
    
    Note:  You are not required to use this module.  If you do not wish to use it then you can leave the config file as is with key = None
    
    Returns the Abuse IP DB API headers in the format of:
         abuse_ip_db_headers = {
            'Accept': abuse_headers['accept'],
            'Key': abuse_headers['key']
    """
    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
    except:
        print("Error with config.ini.")
    else:
        abuse_headers = config_object["ABUSE_IP_DB"]

        if abuse_headers['key']:
            abuse_ip_db_headers = {
            'Accept': abuse_headers['accept'],
            'Key': abuse_headers['key']
        }
            print("Abuse IP DB Configured.")
            return abuse_ip_db_headers
        else:
            print("Abuse IP DB not configured.")
            print("Please add your Abuse IP DB API Key to the config.ini file if you want to use this module.")
            abuse_ip_db_headers = ''
