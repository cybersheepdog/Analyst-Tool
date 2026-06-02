# Python Standard Library Imports
import datetime
import ipaddress
import os
import re
import requests
import threading
import time

# 3rd Party Imports
import validators
from pyperclip import paste

# Custom Imports
from analyst_tool_virus_total import *

# ─────────────────────────────────────────────────────────────────────────────
# Country data
# ─────────────────────────────────────────────────────────────────────────────

_countries_raw = [
    {'Country': 'Afghanistan', 'Alpha-2 code': 'AF'}, {'Country': 'Åland Islands', 'Alpha-2 code': 'AX'},
    {'Country': 'Albania', 'Alpha-2 code': 'AL'}, {'Country': 'Algeria', 'Alpha-2 code': 'DZ'},
    {'Country': 'American Samoa', 'Alpha-2 code': 'AS'}, {'Country': 'Andorra', 'Alpha-2 code': 'AD'},
    {'Country': 'Angola', 'Alpha-2 code': 'AO'}, {'Country': 'Anguilla', 'Alpha-2 code': 'AI'},
    {'Country': 'Antarctica', 'Alpha-2 code': 'AQ'}, {'Country': 'Antigua and Barbuda', 'Alpha-2 code': 'AG'},
    {'Country': 'Argentina', 'Alpha-2 code': 'AR'}, {'Country': 'Armenia', 'Alpha-2 code': 'AM'},
    {'Country': 'Aruba', 'Alpha-2 code': 'AW'}, {'Country': 'Australia', 'Alpha-2 code': 'AU'},
    {'Country': 'Austria', 'Alpha-2 code': 'AT'}, {'Country': 'Azerbaijan', 'Alpha-2 code': 'AZ'},
    {'Country': 'Bahamas (the)', 'Alpha-2 code': 'BS'}, {'Country': 'Bahrain', 'Alpha-2 code': 'BH'},
    {'Country': 'Bangladesh', 'Alpha-2 code': 'BD'}, {'Country': 'Barbados', 'Alpha-2 code': 'BB'},
    {'Country': 'Belarus', 'Alpha-2 code': 'BY'}, {'Country': 'Belgium', 'Alpha-2 code': 'BE'},
    {'Country': 'Belize', 'Alpha-2 code': 'BZ'}, {'Country': 'Benin', 'Alpha-2 code': 'BJ'},
    {'Country': 'Bermuda', 'Alpha-2 code': 'BM'}, {'Country': 'Bhutan', 'Alpha-2 code': 'BT'},
    {'Country': 'Bolivia (Plurinational State of)', 'Alpha-2 code': 'BO'},
    {'Country': 'Bonaire, Sint Eustatius and Saba', 'Alpha-2 code': 'BQ'},
    {'Country': 'Bosnia and Herzegovina', 'Alpha-2 code': 'BA'}, {'Country': 'Botswana', 'Alpha-2 code': 'BW'},
    {'Country': 'Bouvet Island', 'Alpha-2 code': 'BV'}, {'Country': 'Brazil', 'Alpha-2 code': 'BR'},
    {'Country': 'British Indian Ocean Territory (the)', 'Alpha-2 code': 'IO'},
    {'Country': 'Brunei Darussalam', 'Alpha-2 code': 'BN'}, {'Country': 'Bulgaria', 'Alpha-2 code': 'BG'},
    {'Country': 'Burkina Faso', 'Alpha-2 code': 'BF'}, {'Country': 'Burundi', 'Alpha-2 code': 'BI'},
    {'Country': 'Cabo Verde', 'Alpha-2 code': 'CV'}, {'Country': 'Cambodia', 'Alpha-2 code': 'KH'},
    {'Country': 'Cameroon', 'Alpha-2 code': 'CM'}, {'Country': 'Canada', 'Alpha-2 code': 'CA'},
    {'Country': 'Cayman Islands (the)', 'Alpha-2 code': 'KY'},
    {'Country': 'Central African Republic (the)', 'Alpha-2 code': 'CF'},
    {'Country': 'Chad', 'Alpha-2 code': 'TD'}, {'Country': 'Chile', 'Alpha-2 code': 'CL'},
    {'Country': 'China', 'Alpha-2 code': 'CN'}, {'Country': 'Christmas Island', 'Alpha-2 code': 'CX'},
    {'Country': 'Cocos (Keeling) Islands (the)', 'Alpha-2 code': 'CC'},
    {'Country': 'Colombia', 'Alpha-2 code': 'CO'}, {'Country': 'Comoros (the)', 'Alpha-2 code': 'KM'},
    {'Country': 'Congo (the Democratic Republic of the)', 'Alpha-2 code': 'CD'},
    {'Country': 'Congo (the)', 'Alpha-2 code': 'CG'}, {'Country': 'Cook Islands (the)', 'Alpha-2 code': 'CK'},
    {'Country': 'Costa Rica', 'Alpha-2 code': 'CR'}, {"Country": "Côte d'Ivoire", 'Alpha-2 code': 'CI'},
    {'Country': 'Croatia', 'Alpha-2 code': 'HR'}, {'Country': 'Cuba', 'Alpha-2 code': 'CU'},
    {'Country': 'Curaçao', 'Alpha-2 code': 'CW'}, {'Country': 'Cyprus', 'Alpha-2 code': 'CY'},
    {'Country': 'Czechia', 'Alpha-2 code': 'CZ'}, {'Country': 'Denmark', 'Alpha-2 code': 'DK'},
    {'Country': 'Djibouti', 'Alpha-2 code': 'DJ'}, {'Country': 'Dominica', 'Alpha-2 code': 'DM'},
    {'Country': 'Dominican Republic (the)', 'Alpha-2 code': 'DO'}, {'Country': 'Ecuador', 'Alpha-2 code': 'EC'},
    {'Country': 'Egypt', 'Alpha-2 code': 'EG'}, {'Country': 'El Salvador', 'Alpha-2 code': 'SV'},
    {'Country': 'Equatorial Guinea', 'Alpha-2 code': 'GQ'}, {'Country': 'Eritrea', 'Alpha-2 code': 'ER'},
    {'Country': 'Estonia', 'Alpha-2 code': 'EE'}, {'Country': 'Eswatini', 'Alpha-2 code': 'SZ'},
    {'Country': 'Ethiopia', 'Alpha-2 code': 'ET'},
    {'Country': 'Falkland Islands (the) [Malvinas]', 'Alpha-2 code': 'FK'},
    {'Country': 'Faroe Islands (the)', 'Alpha-2 code': 'FO'}, {'Country': 'Fiji', 'Alpha-2 code': 'FJ'},
    {'Country': 'Finland', 'Alpha-2 code': 'FI'}, {'Country': 'France', 'Alpha-2 code': 'FR'},
    {'Country': 'French Guiana', 'Alpha-2 code': 'GF'}, {'Country': 'French Polynesia', 'Alpha-2 code': 'PF'},
    {'Country': 'French Southern Territories (the)', 'Alpha-2 code': 'TF'},
    {'Country': 'Gabon', 'Alpha-2 code': 'GA'}, {'Country': 'Gambia (the)', 'Alpha-2 code': 'GM'},
    {'Country': 'Georgia', 'Alpha-2 code': 'GE'}, {'Country': 'Germany', 'Alpha-2 code': 'DE'},
    {'Country': 'Ghana', 'Alpha-2 code': 'GH'}, {'Country': 'Gibraltar', 'Alpha-2 code': 'GI'},
    {'Country': 'Greece', 'Alpha-2 code': 'GR'}, {'Country': 'Greenland', 'Alpha-2 code': 'GL'},
    {'Country': 'Grenada', 'Alpha-2 code': 'GD'}, {'Country': 'Guadeloupe', 'Alpha-2 code': 'GP'},
    {'Country': 'Guam', 'Alpha-2 code': 'GU'}, {'Country': 'Guatemala', 'Alpha-2 code': 'GT'},
    {'Country': 'Guernsey', 'Alpha-2 code': 'GG'}, {'Country': 'Guinea', 'Alpha-2 code': 'GN'},
    {'Country': 'Guinea-Bissau', 'Alpha-2 code': 'GW'}, {'Country': 'Guyana', 'Alpha-2 code': 'GY'},
    {'Country': 'Haiti', 'Alpha-2 code': 'HT'},
    {'Country': 'Heard Island and McDonald Islands', 'Alpha-2 code': 'HM'},
    {'Country': 'Holy See (the)', 'Alpha-2 code': 'VA'}, {'Country': 'Honduras', 'Alpha-2 code': 'HN'},
    {'Country': 'Hong Kong', 'Alpha-2 code': 'HK'}, {'Country': 'Hungary', 'Alpha-2 code': 'HU'},
    {'Country': 'Iceland', 'Alpha-2 code': 'IS'}, {'Country': 'India', 'Alpha-2 code': 'IN'},
    {'Country': 'Indonesia', 'Alpha-2 code': 'ID'}, {'Country': 'Iran (Islamic Republic of)', 'Alpha-2 code': 'IR'},
    {'Country': 'Iraq', 'Alpha-2 code': 'IQ'}, {'Country': 'Ireland', 'Alpha-2 code': 'IE'},
    {'Country': 'Isle of Man', 'Alpha-2 code': 'IM'}, {'Country': 'Israel', 'Alpha-2 code': 'IL'},
    {'Country': 'Italy', 'Alpha-2 code': 'IT'}, {'Country': 'Jamaica', 'Alpha-2 code': 'JM'},
    {'Country': 'Japan', 'Alpha-2 code': 'JP'}, {'Country': 'Jersey', 'Alpha-2 code': 'JE'},
    {'Country': 'Jordan', 'Alpha-2 code': 'JO'}, {'Country': 'Kazakhstan', 'Alpha-2 code': 'KZ'},
    {'Country': 'Kenya', 'Alpha-2 code': 'KE'}, {'Country': 'Kiribati', 'Alpha-2 code': 'KI'},
    {"Country": "Korea (the Democratic People's Republic of)", 'Alpha-2 code': 'KP'},
    {'Country': 'Korea (the Republic of)', 'Alpha-2 code': 'KR'}, {'Country': 'Kuwait', 'Alpha-2 code': 'KW'},
    {'Country': 'Kyrgyzstan', 'Alpha-2 code': 'KG'},
    {"Country": "Lao People's Democratic Republic (the)", 'Alpha-2 code': 'LA'},
    {'Country': 'Latvia', 'Alpha-2 code': 'LV'}, {'Country': 'Lebanon', 'Alpha-2 code': 'LB'},
    {'Country': 'Lesotho', 'Alpha-2 code': 'LS'}, {'Country': 'Liberia', 'Alpha-2 code': 'LR'},
    {'Country': 'Libya', 'Alpha-2 code': 'LY'}, {'Country': 'Liechtenstein', 'Alpha-2 code': 'LI'},
    {'Country': 'Lithuania', 'Alpha-2 code': 'LT'}, {'Country': 'Luxembourg', 'Alpha-2 code': 'LU'},
    {'Country': 'Macao', 'Alpha-2 code': 'MO'}, {'Country': 'Republic of North Macedonia', 'Alpha-2 code': 'MK'},
    {'Country': 'Madagascar', 'Alpha-2 code': 'MG'}, {'Country': 'Malawi', 'Alpha-2 code': 'MW'},
    {'Country': 'Malaysia', 'Alpha-2 code': 'MY'}, {'Country': 'Maldives', 'Alpha-2 code': 'MV'},
    {'Country': 'Mali', 'Alpha-2 code': 'ML'}, {'Country': 'Malta', 'Alpha-2 code': 'MT'},
    {'Country': 'Marshall Islands (the)', 'Alpha-2 code': 'MH'}, {'Country': 'Martinique', 'Alpha-2 code': 'MQ'},
    {'Country': 'Mauritania', 'Alpha-2 code': 'MR'}, {'Country': 'Mauritius', 'Alpha-2 code': 'MU'},
    {'Country': 'Mayotte', 'Alpha-2 code': 'YT'}, {'Country': 'Mexico', 'Alpha-2 code': 'MX'},
    {'Country': 'Micronesia (Federated States of)', 'Alpha-2 code': 'FM'},
    {'Country': 'Moldova (the Republic of)', 'Alpha-2 code': 'MD'}, {'Country': 'Monaco', 'Alpha-2 code': 'MC'},
    {'Country': 'Mongolia', 'Alpha-2 code': 'MN'}, {'Country': 'Montenegro', 'Alpha-2 code': 'ME'},
    {'Country': 'Montserrat', 'Alpha-2 code': 'MS'}, {'Country': 'Morocco', 'Alpha-2 code': 'MA'},
    {'Country': 'Mozambique', 'Alpha-2 code': 'MZ'}, {'Country': 'Myanmar', 'Alpha-2 code': 'MM'},
    {'Country': 'Namibia', 'Alpha-2 code': 'NA'}, {'Country': 'Nauru', 'Alpha-2 code': 'NR'},
    {'Country': 'Nepal', 'Alpha-2 code': 'NP'}, {'Country': 'Netherlands (the)', 'Alpha-2 code': 'NL'},
    {'Country': 'New Caledonia', 'Alpha-2 code': 'NC'}, {'Country': 'New Zealand', 'Alpha-2 code': 'NZ'},
    {'Country': 'Nicaragua', 'Alpha-2 code': 'NI'}, {'Country': 'Niger (the)', 'Alpha-2 code': 'NE'},
    {'Country': 'Nigeria', 'Alpha-2 code': 'NG'}, {'Country': 'Niue', 'Alpha-2 code': 'NU'},
    {'Country': 'Norfolk Island', 'Alpha-2 code': 'NF'},
    {'Country': 'Northern Mariana Islands (the)', 'Alpha-2 code': 'MP'},
    {'Country': 'Norway', 'Alpha-2 code': 'NO'}, {'Country': 'Oman', 'Alpha-2 code': 'OM'},
    {'Country': 'Pakistan', 'Alpha-2 code': 'PK'}, {'Country': 'Palau', 'Alpha-2 code': 'PW'},
    {'Country': 'Palestine, State of', 'Alpha-2 code': 'PS'}, {'Country': 'Panama', 'Alpha-2 code': 'PA'},
    {'Country': 'Papua New Guinea', 'Alpha-2 code': 'PG'}, {'Country': 'Paraguay', 'Alpha-2 code': 'PY'},
    {'Country': 'Peru', 'Alpha-2 code': 'PE'}, {'Country': 'Philippines (the)', 'Alpha-2 code': 'PH'},
    {'Country': 'Pitcairn', 'Alpha-2 code': 'PN'}, {'Country': 'Poland', 'Alpha-2 code': 'PL'},
    {'Country': 'Portugal', 'Alpha-2 code': 'PT'}, {'Country': 'Puerto Rico', 'Alpha-2 code': 'PR'},
    {'Country': 'Qatar', 'Alpha-2 code': 'QA'}, {'Country': 'Réunion', 'Alpha-2 code': 'RE'},
    {'Country': 'Romania', 'Alpha-2 code': 'RO'}, {'Country': 'Russian Federation (the)', 'Alpha-2 code': 'RU'},
    {'Country': 'Rwanda', 'Alpha-2 code': 'RW'}, {'Country': 'Saint Barthélemy', 'Alpha-2 code': 'BL'},
    {'Country': 'Saint Helena, Ascension and Tristan da Cunha', 'Alpha-2 code': 'SH'},
    {'Country': 'Saint Kitts and Nevis', 'Alpha-2 code': 'KN'}, {'Country': 'Saint Lucia', 'Alpha-2 code': 'LC'},
    {'Country': 'Saint Martin (French part)', 'Alpha-2 code': 'MF'},
    {'Country': 'Saint Pierre and Miquelon', 'Alpha-2 code': 'PM'},
    {'Country': 'Saint Vincent and the Grenadines', 'Alpha-2 code': 'VC'},
    {'Country': 'Samoa', 'Alpha-2 code': 'WS'}, {'Country': 'San Marino', 'Alpha-2 code': 'SM'},
    {'Country': 'Sao Tome and Principe', 'Alpha-2 code': 'ST'}, {'Country': 'Saudi Arabia', 'Alpha-2 code': 'SA'},
    {'Country': 'Senegal', 'Alpha-2 code': 'SN'}, {'Country': 'Serbia', 'Alpha-2 code': 'RS'},
    {'Country': 'Seychelles', 'Alpha-2 code': 'SC'}, {'Country': 'Sierra Leone', 'Alpha-2 code': 'SL'},
    {'Country': 'Singapore', 'Alpha-2 code': 'SG'}, {'Country': 'Sint Maarten (Dutch part)', 'Alpha-2 code': 'SX'},
    {'Country': 'Slovakia', 'Alpha-2 code': 'SK'}, {'Country': 'Slovenia', 'Alpha-2 code': 'SI'},
    {'Country': 'Solomon Islands', 'Alpha-2 code': 'SB'}, {'Country': 'Somalia', 'Alpha-2 code': 'SO'},
    {'Country': 'South Africa', 'Alpha-2 code': 'ZA'},
    {'Country': 'South Georgia and the South Sandwich Islands', 'Alpha-2 code': 'GS'},
    {'Country': 'South Sudan', 'Alpha-2 code': 'SS'}, {'Country': 'Spain', 'Alpha-2 code': 'ES'},
    {'Country': 'Sri Lanka', 'Alpha-2 code': 'LK'}, {'Country': 'Sudan (the)', 'Alpha-2 code': 'SD'},
    {'Country': 'Suriname', 'Alpha-2 code': 'SR'}, {'Country': 'Svalbard and Jan Mayen', 'Alpha-2 code': 'SJ'},
    {'Country': 'Sweden', 'Alpha-2 code': 'SE'}, {'Country': 'Switzerland', 'Alpha-2 code': 'CH'},
    {'Country': 'Syrian Arab Republic', 'Alpha-2 code': 'SY'},
    {'Country': 'Taiwan (Province of China)', 'Alpha-2 code': 'TW'},
    {'Country': 'Tajikistan', 'Alpha-2 code': 'TJ'}, {'Country': 'Tanzania, United Republic of', 'Alpha-2 code': 'TZ'},
    {'Country': 'Thailand', 'Alpha-2 code': 'TH'}, {'Country': 'Timor-Leste', 'Alpha-2 code': 'TL'},
    {'Country': 'Togo', 'Alpha-2 code': 'TG'}, {'Country': 'Tokelau', 'Alpha-2 code': 'TK'},
    {'Country': 'Tonga', 'Alpha-2 code': 'TO'}, {'Country': 'Trinidad and Tobago', 'Alpha-2 code': 'TT'},
    {'Country': 'Tunisia', 'Alpha-2 code': 'TN'}, {'Country': 'Turkey', 'Alpha-2 code': 'TR'},
    {'Country': 'Turkmenistan', 'Alpha-2 code': 'TM'},
    {'Country': 'Turks and Caicos Islands (the)', 'Alpha-2 code': 'TC'},
    {'Country': 'Tuvalu', 'Alpha-2 code': 'TV'}, {'Country': 'Uganda', 'Alpha-2 code': 'UG'},
    {'Country': 'Ukraine', 'Alpha-2 code': 'UA'}, {'Country': 'United Arab Emirates (the)', 'Alpha-2 code': 'AE'},
    {'Country': 'United Kingdom of Great Britain and Northern Ireland (the)', 'Alpha-2 code': 'GB'},
    {'Country': 'United States Minor Outlying Islands (the)', 'Alpha-2 code': 'UM'},
    {'Country': 'United States of America (the)', 'Alpha-2 code': 'US'},
    {'Country': 'Uruguay', 'Alpha-2 code': 'UY'}, {'Country': 'Uzbekistan', 'Alpha-2 code': 'UZ'},
    {'Country': 'Vanuatu', 'Alpha-2 code': 'VU'}, {'Country': 'Venezuela (Bolivarian Republic of)', 'Alpha-2 code': 'VE'},
    {'Country': 'Viet Nam', 'Alpha-2 code': 'VN'}, {'Country': 'Virgin Islands (British)', 'Alpha-2 code': 'VG'},
    {'Country': 'Virgin Islands (U.S.)', 'Alpha-2 code': 'VI'}, {'Country': 'Wallis and Futuna', 'Alpha-2 code': 'WF'},
    {'Country': 'Western Sahara', 'Alpha-2 code': 'EH'}, {'Country': 'Yemen', 'Alpha-2 code': 'YE'},
    {'Country': 'Zambia', 'Alpha-2 code': 'ZM'}, {'Country': 'Zimbabwe', 'Alpha-2 code': 'ZW'},
]

# O(1) lookup dict — built once at import, never rebuilt
_country_lookup = {c['Alpha-2 code']: c['Country'] for c in _countries_raw}

# Keep the original `countries` list for any code that still iterates it directly
countries = _countries_raw


# ─────────────────────────────────────────────────────────────────────────────
# TOR exit node cache — loaded once into memory, refreshed when stale
# ─────────────────────────────────────────────────────────────────────────────

tor_exit_nodes_filename = "tor_exit_nodes.txt"
_TOR_URL                = "https://www.dan.me.uk/torlist/?exit"
_TOR_MAX_AGE_SECONDS    = 45 * 60   # 45 minutes

# In-memory cache: a set of IPs + the timestamp they were loaded
_tor_cache: set        = set()
_tor_cache_loaded_at: float = 0.0
_tor_cache_lock        = threading.Lock()
_tor_session           = requests.Session()


def _load_tor_list_from_file() -> set:
    """Read the on-disk tor exit node file and return a set of IPs."""
    try:
        with open(tor_exit_nodes_filename, 'r') as f:
            return set(f.read().splitlines())
    except OSError:
        return set()


def _fetch_and_save_tor_list() -> set:
    """Download a fresh tor exit node list, save it, and return a set of IPs."""
    try:
        response = _tor_session.get(_TOR_URL, timeout=10)
        if response.status_code == 200:
            ips = set(response.text.splitlines())
            with open(tor_exit_nodes_filename, 'w') as f:
                f.write(response.text)
            return ips
    except Exception:
        pass
    return set()


def _get_tor_set() -> set:
    """Return the current (possibly cached) set of Tor exit node IPs.

    Loads from memory if fresh, from disk if the memory cache is stale but
    the file is still within the 45-minute window, or fetches from the network
    if the file is also stale or missing.
    """
    global _tor_cache, _tor_cache_loaded_at

    now = time.time()
    # Fast path: in-memory cache is fresh — no lock needed for a read
    if now - _tor_cache_loaded_at < _TOR_MAX_AGE_SECONDS and _tor_cache:
        return _tor_cache

    with _tor_cache_lock:
        # Re-check inside lock (another thread may have refreshed)
        if now - _tor_cache_loaded_at < _TOR_MAX_AGE_SECONDS and _tor_cache:
            return _tor_cache

        # Check if on-disk file is still fresh
        file_fresh = False
        if os.path.isfile(tor_exit_nodes_filename):
            mod_time = os.path.getmtime(tor_exit_nodes_filename)
            file_fresh = (now - mod_time) < _TOR_MAX_AGE_SECONDS

        if file_fresh:
            new_set = _load_tor_list_from_file()
        else:
            new_set = _fetch_and_save_tor_list()
            if not new_set and os.path.isfile(tor_exit_nodes_filename):
                # Fall back to stale file if fetch failed
                new_set = _load_tor_list_from_file()

        _tor_cache = new_set
        _tor_cache_loaded_at = now
        return _tor_cache

class color:
    """Used to color code text output to highlight key pieces of information.

    Usage Example: print(color.PURPLE + 'Hello World' + color.END)
    """
    PURPLE    = '\033[95m'
    CYAN      = '\033[96m'
    DARKCYAN  = '\033[36m'
    BLUE      = '\033[94m'
    GREEN     = '\033[92m'
    YELLOW    = '\033[93m'
    RED       = '\033[31m'
    ORANGE    = '\033[33m'
    BOLD      = '\033[1m'
    UNDERLINE = '\033[4m'
    END       = '\033[0m'

def check_tor(suspect_ip):
    """Check if an IP is a known Tor exit node and print the result.

    Uses an in-memory set cache (O(1) lookup) refreshed every 45 minutes.
    Falls back to the stale on-disk file if the network fetch fails.

    Sample output:
        TOR Exit Node: No
    """
    tor_set = _get_tor_set()

    if suspect_ip in tor_set:
        print("\t{:<34} {}".format(color.GREEN + 'TOR Exit Node:' + color.END, "Yes"))
    else:
        print("\t{:<25} {}".format('TOR Exit Node:', "No"))


def get_clipboard_contents():
    """Return the current clipboard contents, stripped of whitespace."""
    try:
        return paste().strip()
    except Exception:
        pass


def is_ip_address(clipboard_contents):
    """Determine if clipboard_contents is an IP address.

    Prints a message for RFC1918 addresses; returns the IP string for public ones.
    """
    try:
        addr = ipaddress.IPv4Address(clipboard_contents)
        if addr.is_private:
            print('This is an RFC1918 IP Address')
        else:
            return clipboard_contents
    except Exception:
        pass


def is_port_or_weivd(pwid):
    """Print port and Windows Event ID reference links for a numeric string."""
    print(f"\nPort: {open_port_page(pwid)}")
    print(f"WEVID: {open_wid_page(pwid)}")


def open_port_page(port):
    """Return a Speedguide.net URL for the given port number."""
    return f'https://www.speedguide.net/port.php?port={port}'


def open_wid_page(wevid):
    """Return an UltimateWindowsSecurity.com URL for the given Windows Event ID."""
    return f'https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={wevid}'


def print_converted_epoch_timestamp(clipboard_contents):
    """Convert an epoch timestamp string to a human-readable datetime and print it."""
    s = clipboard_contents

    # Determine float value based on length/format
    if re.match(r'^[0-9]{10,16}$', s):
        if len(s) == 10:
            ts = float(s)
        else:
            ts = float(s[:10] + '.' + s[10:])
    else:
        # Already has a decimal point (matched by epoch_regex)
        ts = float(s)

    try:
        result = datetime.datetime.fromtimestamp(ts)
    except ValueError as e:
        print(e)
    else:
        print("\n\n\n")
        print(result)


def print_country(country_code, countries=None):
    """Print the full country name for a 2-character ISO Alpha-2 country code.

    Uses an O(1) dict lookup instead of iterating 249 entries each call.

    Sample Output:
        Country: United States of America (the)
    """
    if country_code is None:
        print('\t{:<25} {}'.format('Country:', 'None'))
        return

    code = country_code.upper()
    name = _country_lookup.get(code, '')

    if name:
        print('\t{:<25} {}'.format('Country:', name))
    else:
        print('\t{:<25} {}'.format('Country:', 'No Country in whois record'))


def print_lists(attribute_list, name):
    """Print a list with a heading, capped at 5 items.

    Example Usage: print_lists(vt_url_response['data']['attributes']['tags'], "Tags")
    """
    if not attribute_list:
        return

    print("\t" + color.UNDERLINE + name + color.END + ":")
    for line in attribute_list[:5]:
        print("\t " + line)


def sanitize_url(suspect_url):
    """Replace http/https scheme with hxxp/hxxps for safe display."""
    if suspect_url.startswith('https'):
        return 'hxxps:' + suspect_url[6:]
    elif suspect_url.startswith('http'):
        return 'hxxp:' + suspect_url[5:]
    return 'hxxp:' + suspect_url
