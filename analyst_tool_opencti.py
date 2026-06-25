# Python Standard Library Imports
import re
import threading

# 3rd Party Imports
from configparser import ConfigParser
from pycti import OpenCTIApiClient

# Custom Imports
from analyst_tool_utilities import *

# PERFORMANCE MODIFICATION:
# The original code called OpenCTIApiClient(url, token) on every single query,
# which re-establishes the GraphQL connection and re-authenticates each time.
# We cache the client in a module-level dict keyed by (url, token) so the
# connection is reused across lookups within the same session.
# This is thread-safe because dict reads/writes of a single key are atomic in CPython.

_opencti_client_cache = {}
_opencti_cache_lock = threading.Lock()


def _get_opencti_client(url, token):
    """Return a cached OpenCTIApiClient, creating one if needed."""
    key = (url, token)
    if key not in _opencti_client_cache:
        with _opencti_cache_lock:
            # Double-checked locking
            if key not in _opencti_client_cache:
                verify = get_ssl_verify_from_config()
                try:
                    _opencti_client_cache[key] = OpenCTIApiClient(
                        url, token, ssl_verify=verify)
                except TypeError:
                    # Older pycti without ssl_verify kwarg — preserve original call.
                    _opencti_client_cache[key] = OpenCTIApiClient(url, token)
    return _opencti_client_cache[key]


def get_opencti_from_config():
    """Read OpenCTI credentials from config.ini and return a combined header string."""
    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
    except Exception:
        print("Error with config.ini.")
        return None

    cti_headers = config_object["OPEN_CTI"]
    if cti_headers['opencti_api_token']:
        opencti_headers = cti_headers['opencti_api_url'] + "," + cti_headers['opencti_api_token']
        print("OpenCTI Configured.")
        return opencti_headers
    else:
        print("OpenCTI not configured.")
        print("Please add your OpenCTI API Key to the config.ini file if you want to use this module.")
        return None


def query_opencti(opencti_headers, suspect_indicator):
    """Query OpenCTI for a suspect indicator using a cached client connection.

    The original code created a new OpenCTIApiClient on every call, which
    re-authenticates against the GraphQL endpoint each time (~0.5-1s overhead).
    This version reuses the authenticated client across all lookups.
    """
    parts       = opencti_headers.split(",")
    cti_api_url = parts[0]
    cti_api_token = parts[1]

    client = _get_opencti_client(cti_api_url, cti_api_token)
    return client.indicator.list(search=suspect_indicator)

def _print_tlp(tlp):
    if tlp == "RED":
        print('\t{:<34} {}'.format(color.RED    + 'TLP:' + color.END, 'Red'))
    elif tlp == "AMBER":
        print('\t{:<34} {}'.format(color.ORANGE + 'TLP:' + color.END, 'Amber'))
    elif tlp == "GREEN":
        print('\t{:<34} {}'.format(color.GREEN  + 'TLP:' + color.END, 'Green'))
    else:
        print('\t{:<25} {}'.format('TLP:', 'Clear'))


def _print_active(active):
    if active is False:
        print('\t{:<34} {}'.format(color.GREEN + 'Active:' + color.END, 'Yes'))
    elif active is True:
        print('\t{:<34} {}'.format(color.RED   + 'Active:' + color.END, 'No'))
    else:
        print('\t{:<25} {}'.format('Active:', active))


def _print_malicious(score):
    score = int(score)
    if score >= 75:
        print('\t{:<34} {}'.format(color.RED    + 'Malicious:' + color.END, score))
    elif score >= 50:
        print('\t{:<34} {}'.format(color.ORANGE + 'Malicious:' + color.END, score))
    else:
        print('\t{:<25} {}'.format('Malicious:', score))


def _print_confidence(confidence):
    c = int(confidence)
    if c >= 75:
        print('\t{:<34} {}'.format(color.RED    + 'Confidence:' + color.END, 'High'))
    elif c >= 50:
        print('\t{:<34} {}'.format(color.ORANGE + 'Confidence:' + color.END, 'Medium'))
    else:
        print('\t{:<25} {}'.format('Confidence:', 'Low'))


def _print_tags(keywords, limit=5):
    print("\t" + color.UNDERLINE + 'Tags:' + color.END)
    for tag in keywords[:limit]:
        print("\t " + tag)


def _extract_common_fields(results, opencti_headers):
    """Extract fields shared across all indicator types."""
    item = results[0]  # use first result for scalar fields
    item_id       = item['id']
    base_url      = opencti_headers.split(",")[0][:-8]
    link_url      = base_url + "/dashboard/observations/indicators/" + item_id
    source        = item.get('createdBy', {}).get('name', 'Unknown') if item.get('createdBy') else 'Unknown'
    active        = item['revoked']
    confidence    = item['confidence']
    malicious_score = item['x_opencti_score']

    # TLP — from objectMarking across all results
    tlp = 'Clear'
    for r in results:
        for marking in r.get('objectMarking', []):
            tlp = marking.get('definition', 'Clear')

    # Tags — from objectLabel across all results
    keywords = []
    for r in results:
        for label in r.get('objectLabel', []):
            keywords.append(label['value'])

    return link_url, source, active, confidence, malicious_score, tlp, keywords


def print_opencti_ip_results(opencti_ip_results, suspect_indicator, countries, opencti_headers):
    link_url, source, active, confidence, malicious_score, tlp, keywords = \
        _extract_common_fields(opencti_ip_results, opencti_headers)

    print(color.UNDERLINE + '\nOpenCTI Info:' + color.END + " " + suspect_indicator)
    _print_active(active)
    _print_malicious(malicious_score)
    _print_confidence(confidence)
    print('\t{:<25} {}'.format('Source:', source))
    _print_tags(keywords)
    _print_tlp(tlp)
    print('\t{:<25}'.format(link_url))


def print_opencti_domain_results(opencti_domain_results, opencti_headers, suspect_indicator=None):
    link_url, source, active, confidence, malicious_score, tlp, keywords = \
        _extract_common_fields(opencti_domain_results, opencti_headers)

    label = suspect_indicator or ''
    sanitized = label.replace(".", "[.]")
    print(color.UNDERLINE + '\nOpenCTI Info:' + color.END + (" " + sanitized if sanitized else ""))
    _print_active(active)
    _print_malicious(malicious_score)
    _print_confidence(confidence)
    print('\t{:<25} {}'.format('Source:', source))
    _print_tags(keywords)
    _print_tlp(tlp)
    print('\t{:<25}'.format(link_url))


def print_opencti_hash_results(opencti_hash_results, suspect_indicator, opencti_headers):
    link_url, source, active, confidence, malicious_score, tlp, keywords = \
        _extract_common_fields(opencti_hash_results, opencti_headers)

    # Determine if pattern is a YARA rule or just a hash pattern
    pattern = opencti_hash_results[0].get('pattern', '')
    if "file:hashes" in pattern:
        rule = "No yara rule in OpenCTI"
    else:
        rule = pattern.replace("\n", "\n\t\t\t\t")

    print(color.UNDERLINE + '\nOpenCTI Info:' + color.END + " " + suspect_indicator)
    _print_active(active)
    _print_malicious(malicious_score)
    _print_confidence(confidence)
    print('\t{:<25} {}'.format('Source:', source))
    _print_tags(keywords)
    _print_tlp(tlp)
    print('\t{:<25} {}'.format('Rule:', rule))
    print('\t{:<25}'.format(link_url))


def print_opencti_url_results(opencti_url_results, suspect_indicator, opencti_headers=None):
    sanitized_url = suspect_indicator.replace("http", "hXXP")
    print(color.UNDERLINE + '\nOpenCTI Info:' + color.END + " " + sanitized_url)

    # Filter to exact URL match
    url_results = [item for item in opencti_url_results
                   if item.get('name') == suspect_indicator]

    if not url_results:
        print('\n\tURL not found in OpenCTI')
        return

    if opencti_headers is None:
        return

    link_url, source, active, confidence, malicious_score, tlp, keywords = \
        _extract_common_fields(url_results, opencti_headers)

    _print_active(active)
    _print_malicious(malicious_score)
    _print_confidence(confidence)
    print('\t{:<25} {}'.format('Source:', source))
    _print_tags(keywords)
    _print_tlp(tlp)
    print('\t{:<25}'.format(link_url))
