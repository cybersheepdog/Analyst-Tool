# Python Standard Library Imports
import base64
import datetime
import json
import re
import requests
import threading

# 3rd Party Imports
from configparser import ConfigParser

# Custom Imports
from analyst_tool_utilities import *

# PERFORMANCE MODIFICATION: per-thread Session for HTTP keep-alive connection reuse.
# Each thread gets its own Session (thread-safe), avoiding repeated TCP handshakes.
_thread_local = threading.local()

def _get_session():
    if not hasattr(_thread_local, 'session'):
        _thread_local.session = requests.Session()
    return _thread_local.session

# Default network timeout (seconds) for all VT requests.
_TIMEOUT = 10


class color:
    """Used to color code text output in order to highlight key pieces of information.

    Usage Example: print(color.PURPLE + 'Hello World' + color.END)
    """
    PURPLE   = '\033[95m'
    CYAN     = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE     = '\033[94m'
    GREEN    = '\033[92m'
    YELLOW   = '\033[93m'
    RED      = '\033[31m'
    ORANGE   = '\033[33m'
    BOLD     = '\033[1m'
    UNDERLINE = '\033[4m'
    END      = '\033[0m'


def create_virus_total_headers_from_config():
    """Creates the VT API header dict from config.ini.

    Returns virus_total_headers dict, or None if not configured.
    """
    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
    except Exception:
        print("Error with config.ini.")
        return None

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
        return None


def get_vt_user_from_config():
    """Reads the VT username from config.ini for API quota notifications."""
    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
    except Exception:
        print("Error with config.ini.")
        return None

    vt = config_object["VIRUS_TOTAL"]
    if vt['user']:
        vt_user = vt['user']
        print('VirusTotal API usage alerts enabled for ' + vt_user)
        return vt_user
    else:
        print("No VT User.")
        print("Please add your VT username to the config.ini file if you would like to enable API Quota notifications")
        return None


def get_vt_ip_results(suspect_ip, virus_total_headers, vt_user):
    """Query VirusTotal for an IP address and print the results.

    Uses a persistent per-thread Session (keep-alive) and a 10s timeout.

    Sample Output:
        VirusTotal Detections:
            Malicious:    3
            Malware:      3
            Suspicious:   0
            Phishing:     0
            Spam:         0
            Clean:        72
            Undetected:   11
            Time Out:     0
    """
    vt_ip_report = 'https://www.virustotal.com/api/v3/ip_addresses/' + suspect_ip
    session = _get_session()
    response = session.get(vt_ip_report, headers=virus_total_headers, timeout=_TIMEOUT)
    vt_ip_response = json.loads(response.text)

    print(color.UNDERLINE + '\nVirusToal Detections:' + color.END)
    if vt_user:
        vt_api_count(virus_total_headers, vt_user)
    print_ip_detections(vt_ip_response)
    print("\thttps://www.virustotal.com/gui/ip-address/" + suspect_ip)


def print_domain_detections(vt_domain_response):
    """Count and print VT domain analysis categories with color coding.

    Red  >= 10 detections, Orange >= 5 detections in a category.
    """
    categories = [v for v in vt_domain_response['data']['attributes']['last_analysis_results'].values()]
    alert_categories = {'malicious': 0, 'suspicious': 0, 'phishing': 0,
                        'malware': 0, 'spam': 0, 'clean': 0, 'unrated': 0, 'time out': 0}
    for alert in categories:
        if alert['result'] in alert_categories:
            alert_categories[alert['result']] += 1

    def _print(label, key, width_red=34, width_orange=34):
        val = alert_categories[key]
        if val >= 10:
            print('\t{:<{w}} {}'.format(color.RED + label + color.END, val, w=width_red))
        elif val >= 5:
            print('\t{:<{w}} {}'.format(color.ORANGE + label + color.END, val, w=width_orange))
        else:
            print('\t{:<25} {}'.format(label, val))

    _print('Malicious:', 'malicious')
    _print('Malware:',   'malware',   31, 34)
    _print('Suspicious:','suspicious',31, 34)
    _print('Phishing:',  'phishing',  31, 34)
    _print('Spam:',      'spam',      31, 34)
    print('\t{:<25} {}'.format('Clean:',      alert_categories['clean']))
    print('\t{:<25} {}'.format('Undetected:', alert_categories['unrated']))
    print('\t{:<25} {}'.format('Time Out:',   alert_categories['time out']))


def print_ip_detections(vt_ip_response):
    """Count and print VT IP analysis categories with color coding.

    Red  >= 10 detections, Orange >= 5 detections in a category.
    """
    categories = [v for v in vt_ip_response['data']['attributes']['last_analysis_results'].values()]
    alert_categories = {'malicious': 0, 'suspicious': 0, 'phishing': 0,
                        'malware': 0, 'spam': 0, 'clean': 0, 'unrated': 0, 'time out': 0}
    for alert in categories:
        if alert['result'] in alert_categories:
            alert_categories[alert['result']] += 1

    # Malicious
    val = alert_categories['malicious']
    if val >= 10:
        print('\t{:<34} {}'.format(color.RED + 'Malicious:' + color.END, val))
    elif val >= 5:
        print('\t{:<34} {}'.format(color.ORANGE + 'Malicious:' + color.END, val))
    else:
        print('\t{:<25} {}'.format('Malicious:', val))

    # Malware
    val = alert_categories['malware']
    if val >= 10:
        print('\t{:<31} {}'.format(color.RED + 'Malware:' + color.END, val))
    elif val >= 5:
        print('\t{:<34} {}'.format(color.ORANGE + 'Malware:' + color.END, val))
    else:
        print('\t{:<25} {}'.format('Malware:', val))

    # Suspicious
    val = alert_categories['suspicious']
    if val >= 10:
        print('\t{:<25} {}'.format(color.RED + 'Suspicious:' + color.END, val))
    elif val >= 5:
        print('\t{:<25} {}'.format(color.ORANGE + 'Suspicious:' + color.END, val))
    else:
        print('\t{:<25} {}'.format('Suspicious:', val))

    # Phishing
    val = alert_categories['phishing']
    if val >= 10:
        print('\t{:<25} {}'.format(color.RED + 'Phishing:' + color.END, val))
    elif val >= 5:
        print('\t{:<25} {}'.format(color.ORANGE + 'Phishing:' + color.END, val))
    else:
        print('\t{:<25} {}'.format('Phishing:', val))

    # Spam
    val = alert_categories['spam']
    if val >= 10:
        print('\t{:<31} {}'.format(color.RED + 'Spam:' + color.END, val))
    elif val >= 5:
        print('\t{:<34} {}'.format(color.ORANGE + 'Spam:' + color.END, val))
    else:
        print('\t{:<25} {}'.format('Spam:', val))

    print('\t{:<25} {}'.format('Clean:',      alert_categories['clean']))
    print('\t{:<25} {}'.format('Undetected:', alert_categories['unrated']))
    print('\t{:<25} {}'.format('Time Out:',   alert_categories['time out']))


def print_virus_total_hash_results(suspect_hash, virus_total_headers, vt_user):
    """Query VirusTotal for a hash and print a formatted report.

    Uses a persistent per-thread Session and a 10s timeout.
    """
    vt_hash_report = "https://www.virustotal.com/api/v3/files/" + suspect_hash
    vt_hash_url    = "https://www.virustotal.com/gui/file/" + suspect_hash + "/detection"

    heading = "\n\n\nVirusTotal Hash Report for " + suspect_hash + ":"
    print(color.BOLD + heading + color.END)

    if vt_user:
        vt_api_count(virus_total_headers, vt_user)

    session = _get_session()
    response = session.get(vt_hash_report, headers=virus_total_headers, timeout=_TIMEOUT)
    vt_hash_response = json.loads(response.text)

    try:
        vt_hash_response['data']
    except Exception:
        print(color.UNDERLINE + 'File Reputation:' + color.END)
        print('\tFile hash not found in VirusTotal')
        return

    attrs = vt_hash_response['data']['attributes']

    # ── File Reputation ───────────────────────────────────────────────────────
    print(color.UNDERLINE + 'File Reputation:' + color.END)
    mal = attrs['last_analysis_stats']['malicious']
    sus = attrs['last_analysis_stats']['suspicious']

    if mal >= 10:
        print('\t{:<34} {}'.format(color.RED + 'Malicious:' + color.END, mal))
    elif mal >= 5:
        print('\t{:<25} {}'.format(color.ORANGE + 'Malicious:' + color.END, mal))
    else:
        print('\t{:<25} {}'.format('Malicious:', mal))

    if sus >= 10:
        print('\t{:<25} {}'.format(color.RED + 'Suspicious:' + color.END, sus))
    elif sus >= 5:
        print('\t{:<25} {}'.format(color.ORANGE + 'Suspicious:' + color.END, sus))
    else:
        print('\t{:<25} {}'.format('Suspicious:', sus))

    print('\t{:<25} {}'.format('Harmless:',   attrs['last_analysis_stats']['harmless']))
    print('\t{:<25} {}'.format('Undetected:', attrs['last_analysis_stats']['undetected']))

    # ── File Threat Classification ────────────────────────────────────────────
    print(color.UNDERLINE + '\nFile Threat Classification:' + color.END)
    try:
        cats = attrs['popular_threat_classification']['popular_threat_category']
    except KeyError:
        print('\tThis hash does not have a Threat Classification')
    else:
        for line in cats:
            print('\t{:<25} {}'.format(line['value'], line['count']))

    # ── File Threat Name ──────────────────────────────────────────────────────
    print(color.UNDERLINE + '\nFile Threat Name:' + color.END)
    try:
        names = attrs['popular_threat_classification']['popular_threat_name']
    except KeyError:
        print('\tThis hash does not have an associated Threat Name.')
    else:
        for line in names:
            print('\t{:<25} {}'.format(line['value'], line['count']))

    # ── File Info ─────────────────────────────────────────────────────────────
    print(color.UNDERLINE + '\nFile Info:' + color.END)

    sig = attrs.get('signature_info', {})

    print('\t{:<25} {}'.format('Signature:', sig.get('verified', 'File not signed')))

    signers = sig.get('signers details')
    if signers:
        print('\n\tSigner(s):')
        for s in signers:
            status = s['status'] if s['status'] == 'Valid' else 'Not Valid'
            print('\t\t{:<50} {:<25}'.format(s['name'], status))
    else:
        print('\t{:<25} {}'.format('Signers:', 'N/A'))

    print('\t{:<25} {}'.format('Signing Date:',         sig.get('signing date', 'N/A')))
    print('\t{:<25} {}'.format('File Type:',             attrs.get('type_description', 'N/A')))
    print('\t{:<25} {}'.format('Product:',               sig.get('product', 'N/A')))
    print('\t{:<25} {}'.format('Copyright:',             sig.get('copyright', 'N/A')))
    print('\t{:<25} {}'.format('Decription:',            sig.get('description', 'N/A')))

    creation = attrs.get('creation_date')
    print('\t{:<25} {}'.format('Creation Date:',
                               datetime.datetime.fromtimestamp(creation) if creation else 'N/A'))

    mod = attrs.get('last_modification_date')
    print('\t{:<25} {}'.format('Last Modification Date:',
                               datetime.datetime.fromtimestamp(mod) if mod else 'N/A'))

    # ── Submission Info ───────────────────────────────────────────────────────
    print(color.UNDERLINE + '\nSubmission Info:' + color.END)

    for label, key in [('Last Submission:',  'last_submission_date'),
                       ('Last Analysis:',    'last_analysis_date'),
                       ('First Submission:', 'first_submission_date')]:
        val = attrs.get(key)
        print('\t{:<25} {}'.format(label,
                                   datetime.datetime.fromtimestamp(val) if val else 'N/A'))

    print('\t{:<25} {}'.format('Times Submitted:', attrs.get('times_submitted', 'N/A')))
    print(vt_hash_url)


def print_vt_domain_report(suspect_domain, virus_total_headers, vt_user):
    """Query VirusTotal for a domain and print a formatted report.

    Uses a persistent per-thread Session and a 10s timeout.
    """
    creation_date_regex_local = r'(created|Creation Date): ([0-9T:-]+)Z?\n'
    vt_domain_report = "https://www.virustotal.com/api/v3/domains/" + suspect_domain

    session = _get_session()
    response = session.get(vt_domain_report, headers=virus_total_headers, timeout=_TIMEOUT)
    vt_domain_response = json.loads(response.text)

    try:
        vt_domain_response['data']
    except Exception:
        print('\n\n\n' + color.BOLD + 'Domain Reputation for ' + suspect_domain + ':' + color.END)
        print('\tDomain not found in VirusTotal')
        return

    print('\n\n\n' + color.BOLD + 'Domain Reputation for ' + suspect_domain + ':' + color.END)

    if vt_user:
        vt_api_count(virus_total_headers, vt_user)

    attrs = vt_domain_response['data']['attributes']

    print(color.UNDERLINE + 'Last Analysis Stats:' + color.END)
    print_domain_detections(vt_domain_response)

    print(color.UNDERLINE + '\nDomain Info:' + color.END)

    creation = attrs.get('creation_date')
    if creation:
        print('\t{:<30} {}'.format('Creation Date:',
                                   datetime.datetime.fromtimestamp(creation)))
    else:
        whois_data = attrs.get('whois', '')
        m = re.search(creation_date_regex_local, whois_data) if whois_data else None
        cd = m.group(2) if m else 'No Date in VT'
        print('\t{:<30} {}'.format('Creation Date:', cd))

    last_update = attrs.get('last_update_date')
    print('\t{:<30} {}'.format('Last Update Date:',
                               datetime.datetime.fromtimestamp(last_update) if last_update else 'No Data'))

    last_mod = attrs.get('last_modification_date')
    print('\t{:<30} {}'.format('Last Modification Date:',
                               datetime.datetime.fromtimestamp(last_mod) if last_mod else 'No Data'))

    print(color.UNDERLINE + '\nCertificate Info:' + color.END)
    cert = attrs.get('last_https_certificate', {})
    print('\t{:<30} {}'.format('Issuer:',
                               cert.get('issuer', {}).get('O', 'No Data')))
    validity = cert.get('validity', {})
    print('\t{:<30} {}'.format('Not After:',  validity.get('not_after',  'No Data')))
    print('\t{:<30} {}'.format('Not Before:', validity.get('not_before', 'No Data')))

    print("https://www.virustotal.com/gui/domain/" + suspect_domain)


def print_virus_total_url_report(virus_total_headers, suspect_url):
    """Query VirusTotal for a URL and print a formatted report.

    Uses a persistent per-thread Session and a 10s timeout.
    """
    URL_ID = base64.urlsafe_b64encode(suspect_url.encode()).decode().strip("=")
    vt_url_report = 'https://www.virustotal.com/api/v3/urls/' + URL_ID

    session = _get_session()
    response = session.get(vt_url_report, headers=virus_total_headers, timeout=_TIMEOUT)
    vt_url_response = json.loads(response.text)

    sanitized_url = sanitize_url(suspect_url)
    print(color.UNDERLINE + "\nVirusTotal URL Report for:" + color.END + " " + sanitized_url)
    print_ip_detections(vt_url_response)

    vt_url_link = 'https://www.virustotal.com/gui/url/' + vt_url_response['data']['id']
    print('\n')
    print_lists(vt_url_response['data']['attributes']['tags'],         "Tags")
    print_lists(vt_url_response['data']['attributes']['threat_names'], "Threat Name")
    print('\n')

    url_attrs = vt_url_response['data']['attributes']
    print("\t{:<25} {}".format("Last Analysis Date:",
                               datetime.datetime.fromtimestamp(url_attrs['last_analysis_date'])))
    print("\t{:<25} {}".format("First Submission Date:",
                               datetime.datetime.fromtimestamp(url_attrs['first_submission_date'])))
    print("\t{:<25} {}".format("Last Submission Date:",
                               datetime.datetime.fromtimestamp(url_attrs['last_submission_date'])))
    print("\t{:<25} {}".format("Times Submitted:", url_attrs['times_submitted']))
    print(vt_url_link)
    print('\n')


def vt_api_count(virus_total_headers, vt_user):
    """Check and warn about daily VT API quota usage."""
    url = "https://www.virustotal.com/api/v3/users/" + vt_user + "/overall_quotas"
    session = _get_session()
    response = session.get(url, headers=virus_total_headers, timeout=_TIMEOUT)
    api_usage = json.loads(response.text)
    vt_count = api_usage['data']['api_requests_daily']['user']['used']

    if vt_count >= 500:
        print(color.BOLD + "You have reached 100% of your 500 daily VT API Queries!" + color.END)
    elif vt_count >= 475:
        print(color.BOLD + "You have reached 95% of your 500 daily VT API Queries" + color.END)
    elif vt_count >= 375:
        print(color.BOLD + "You have reached 75% of your 500 daily VT API Queries!" + color.END)
    elif vt_count >= 250:
        print(color.BOLD + "You have reached 50% of your 500 daily VT API Queries!" + color.END)
