# Python Standard Library Imports
import json
import requests
import threading

# 3rd Party Imports
from configparser import ConfigParser

# Custom Imports
from analyst_tool_utilities import *

# PERFORMANCE MODIFICATION: per-thread Session for HTTP keep-alive connection reuse.
_thread_local = threading.local()

def _get_session():
    if not hasattr(_thread_local, 'session'):
        _thread_local.session = requests.Session()
    return _thread_local.session

_TIMEOUT = 10  # seconds


def check_abuse_ip_db(suspect_ip, abuse_ip_db_headers):
    """Query AbuseIPDB and print the results to the screen.

    Uses a persistent per-thread Session (keep-alive) and a 10s timeout.

    Sample Output:
        Abuse IP DB:
            Abuse Confidence Score: 97%
            Total Reports:          53
            Last Reported:          2022-02-13T17:22:12+00:00
            Distinct Reporters:     14
            Usage Type:             Fixed Line ISP
            Domain:                 inter.com.ru
            https://www.abuseipdb.com/check/45.145.66.165
    """
    abuse_ip_db_url  = 'https://api.abuseipdb.com/api/v2/check'
    abuse_ip_link    = 'https://www.abuseipdb.com/check/' + suspect_ip
    days             = '90'

    querystring = {
        'ipAddress':    suspect_ip,
        'maxAgeInDays': days
    }

    session = _get_session()
    abuse_ip_response = session_get(
        session,
        abuse_ip_db_url,
        headers=abuse_ip_db_headers,
        params=querystring,
        timeout=_TIMEOUT
    )
    abuse_ip_report = json.loads(abuse_ip_response.text)

    print(color.UNDERLINE + '\nAbuse IP DB:' + color.END)

    # Quota warning
    abuse_api_remaining = int(abuse_ip_response.headers.get('X-RateLimit-Remaining', 9999))
    if abuse_api_remaining == 0:
        print(color.BOLD + "You have reached 100% of your 1000 daily Abuse IP DB API Queries!" + color.END)
    elif abuse_api_remaining <= 50:
        print(color.BOLD + "You have reached 95% of your 1000 daily Abuse IP DB API Queries" + color.END)
    elif abuse_api_remaining <= 250:
        print(color.BOLD + "You have reached 75% of your 1000 daily Abuse IP DB API Queries!" + color.END)

    score = abuse_ip_report['data']['abuseConfidenceScore']
    if score >= 70:
        print('\t{:<34} {}%'.format(color.RED    + 'Abuse Confidence Score:' + color.END, score))
    elif score >= 40:
        print('\t{:<34} {}%'.format(color.ORANGE + 'Abuse Confidence Score:' + color.END, score))
    else:
        print('\t{:<25} {}%'.format('Abuse Confidence Score:', score))

    print('\t{:<25} {}'.format('Total Reports:',      abuse_ip_report['data']['totalReports']))
    print('\t{:<25} {}'.format('Last Reported:',      abuse_ip_report['data']['lastReportedAt']))
    print('\t{:<25} {}'.format('Distinct Reporters:', abuse_ip_report['data']['numDistinctUsers']))
    print('\t{:<25} {}'.format('Usage Type:',         abuse_ip_report['data']['usageType']))
    print('\t{:<25} {}'.format('Domain:',             abuse_ip_report['data']['domain']))
    print('\t' + abuse_ip_link)


def create_abuse_ip_db_headers_from_config():
    """Create and return the AbuseIPDB header dict from config.ini.

    Returns the header dict, or None if not configured.
    """
    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
    except Exception:
        print("Error with config.ini.")
        return None

    abuse_headers = config_object["ABUSE_IP_DB"]
    if abuse_headers['key']:
        abuse_ip_db_headers = {
            'Accept': abuse_headers['accept'],
            'Key':    abuse_headers['key']
        }
        print("Abuse IP DB Configured.")
        return abuse_ip_db_headers
    else:
        print("Abuse IP DB not configured.")
        print("Please add your Abuse IP DB API Key to the config.ini file if you want to use this module.")
        return None
