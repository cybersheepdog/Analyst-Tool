# Python Standard Library Imports
import bisect
import datetime
import ipaddress
import os
import re
import requests
import threading
import time
import warnings
from configparser import ConfigParser
from urllib.parse import urlparse

# 3rd Party Imports
import validators
from pyperclip import paste

# Custom Imports

# ─────────────────────────────────────────────────────────────────────────────
# SSL verification handling (shared by all modules)
#
# Default behaviour is unchanged: TLS certificates are verified (verify=True).
# Setting `ssl_verify = false` under a [GENERAL] section in config.ini turns on
# an opt-in insecure fallback: requests that fail with an SSLError are retried
# once with verify=False, and the API clients are constructed without TLS
# verification. This is intended for environments behind a TLS-intercepting
# proxy or using self-signed certs. Leave it true unless you need it.
# ─────────────────────────────────────────────────────────────────────────────

try:  # urllib3 ships with requests; guard just in case
    from urllib3.exceptions import InsecureRequestWarning
except Exception:  # pragma: no cover
    InsecureRequestWarning = None

# Cache the flag so we don't re-read config.ini on every single request.
_ssl_verify_cache = None


def get_ssl_verify_from_config():
    """Return True if TLS certificates should be verified (the default).

    Reads [GENERAL] ssl_verify from config.ini. A missing section/key, an
    unreadable file, or any value other than false/0/no/off yields True, so
    the secure default is preserved unless the user explicitly opts out.

    The first time insecure mode is detected, InsecureRequestWarning is
    silenced globally so the console isn't flooded across the many parallel
    lookups.
    """
    global _ssl_verify_cache
    if _ssl_verify_cache is not None:
        return _ssl_verify_cache

    verify = True
    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
        value = config_object.get("GENERAL", "ssl_verify", fallback="true")
        verify = str(value).strip().lower() not in ("false", "0", "no", "off")
    except Exception:
        verify = True

    if not verify and InsecureRequestWarning is not None:
        warnings.simplefilter("ignore", InsecureRequestWarning)

    _ssl_verify_cache = verify
    return _ssl_verify_cache


def session_get(session, url, **kwargs):
    """GET wrapper that honours the configured SSL-verify policy.

    - ssl_verify = true (default): a normal verified request — behaviour is
      identical to calling session.get(url, **kwargs) directly.
    - ssl_verify = false: try the verified request first; only if it raises an
      SSLError, retry the same request once with verify=False.

    An explicit `verify` passed by the caller is always respected.
    """
    if "verify" in kwargs:
        return session.get(url, **kwargs)

    if get_ssl_verify_from_config():
        return session.get(url, **kwargs)

    try:
        return session.get(url, verify=True, **kwargs)
    except requests.exceptions.SSLError:
        return session.get(url, verify=False, **kwargs)

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
        response = session_get(_tor_session, _TOR_URL, timeout=10)
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


# ─────────────────────────────────────────────────────────────────────────────
# VPN provider detection — X4BNet public VPN IP-range list (no API key required)
#
# Mirrors the Tor exit-node cache: load once into memory, refresh when stale.
# Unlike the Tor list (individual IPs), this list is made of CIDR *ranges*, so
# we keep a sorted list of (start_int, end_int) tuples (collapsed to remove
# overlaps) and bisect on lookup — O(log n) instead of scanning every range.
#
# Source: https://github.com/X4BNet/lists_vpn  (output/vpn/ipv4.txt, updated daily)
# Detection is heuristic and IPv4-only: it flags IPs in known commercial VPN
# networks. Pair it with the WhoIs org/ASN for attribution.
# ─────────────────────────────────────────────────────────────────────────────

vpn_networks_filename = "vpn_networks.txt"
_VPN_URL              = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"
_VPN_MAX_AGE_SECONDS  = 24 * 60 * 60   # 24 hours (X4BNet refreshes daily)

# In-memory cache: a sorted list of (start_int, end_int) ranges + load timestamp.
_vpn_ranges: list      = []
_vpn_loaded_at: float  = 0.0
_vpn_lock              = threading.Lock()
_vpn_session           = requests.Session()


def _parse_vpn_ranges(text: str) -> list:
    """Parse CIDR lines into a sorted, non-overlapping list of (start, end) ints."""
    nets = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if net.version != 4:
            continue
        nets.append(net)

    try:
        collapsed = ipaddress.collapse_addresses(nets)
    except Exception:
        collapsed = nets

    ranges = [(int(n.network_address), int(n.broadcast_address)) for n in collapsed]
    ranges.sort()
    return ranges


def _load_vpn_ranges_from_file() -> list:
    """Read the on-disk VPN network file and return parsed ranges."""
    try:
        with open(vpn_networks_filename, 'r') as f:
            return _parse_vpn_ranges(f.read())
    except OSError:
        return []


def _fetch_and_save_vpn_list() -> list:
    """Download a fresh X4BNet VPN list, save it, and return parsed ranges."""
    try:
        response = session_get(_vpn_session, _VPN_URL, timeout=15)
        if response.status_code == 200:
            with open(vpn_networks_filename, 'w') as f:
                f.write(response.text)
            return _parse_vpn_ranges(response.text)
    except Exception:
        pass
    return []


def _get_vpn_ranges() -> list:
    """Return the current (possibly cached) sorted VPN ranges.

    In-memory if fresh, on-disk if the memory cache is stale but the file is
    within the 24-hour window, otherwise fetched from the network (falling back
    to a stale file if the fetch fails).
    """
    global _vpn_ranges, _vpn_loaded_at

    now = time.time()
    if now - _vpn_loaded_at < _VPN_MAX_AGE_SECONDS and _vpn_ranges:
        return _vpn_ranges

    with _vpn_lock:
        if now - _vpn_loaded_at < _VPN_MAX_AGE_SECONDS and _vpn_ranges:
            return _vpn_ranges

        file_fresh = False
        if os.path.isfile(vpn_networks_filename):
            mod_time = os.path.getmtime(vpn_networks_filename)
            file_fresh = (now - mod_time) < _VPN_MAX_AGE_SECONDS

        if file_fresh:
            new_ranges = _load_vpn_ranges_from_file()
        else:
            new_ranges = _fetch_and_save_vpn_list()
            if not new_ranges and os.path.isfile(vpn_networks_filename):
                new_ranges = _load_vpn_ranges_from_file()

        _vpn_ranges = new_ranges
        _vpn_loaded_at = now
        return _vpn_ranges


def is_vpn_ip(suspect_ip) -> bool:
    """Return True if suspect_ip falls within a known VPN provider range.

    Uses a bisect over the sorted, non-overlapping range list (O(log n)).
    Returns False for non-IPv4 input or when the list is unavailable.
    """
    try:
        ip_int = int(ipaddress.ip_address(suspect_ip.strip()))
    except ValueError:
        return False

    ranges = _get_vpn_ranges()
    if not ranges:
        return False

    # Largest range whose start <= ip_int; then confirm ip_int <= its end.
    # The float('inf') sentinel makes every range with start == ip_int sort
    # before the key, so the network address of a range still matches.
    idx = bisect.bisect_right(ranges, (ip_int, float('inf'))) - 1
    if idx >= 0:
        start, end = ranges[idx]
        if start <= ip_int <= end:
            return True
    return False


# Known VPN providers, matched (case-insensitive substring) against the WhoIs
# Organization / ASN description. This catches IPs that the X4BNet list misses
# (e.g. many NordVPN exit IPs) because the network's registrant is the VPN brand.
# (keyword, display name) — checked in order; the generic "vpn" catch-all is last.
_VPN_PROVIDERS = [
    ("tefincom", "NordVPN"), ("nordvpn", "NordVPN"),
    ("mullvad", "Mullvad"),
    ("protonvpn", "Proton VPN"), ("proton ag", "Proton VPN"),
    ("expressvpn", "ExpressVPN"), ("express vpn", "ExpressVPN"),
    ("surfshark", "Surfshark"),
    ("private internet access", "Private Internet Access"),
    ("privateinternetaccess", "Private Internet Access"),
    ("cyberghost", "CyberGhost"),
    ("ipvanish", "IPVanish"),
    ("windscribe", "Windscribe"),
    ("golden frog", "VyprVPN"), ("vyprvpn", "VyprVPN"),
    ("torguard", "TorGuard"),
    ("gz systems", "PureVPN"), ("purevpn", "PureVPN"),
    ("hide.me", "hide.me"),
    ("perfect privacy", "Perfect Privacy"),
    ("azirevpn", "AzireVPN"),
    ("ovpn.com", "OVPN"),
    ("vpn", "VPN provider"),
]


def vpn_provider_from_text(text):
    """Return a known VPN provider name if `text` (a WhoIs org/ASN string)
    matches one, else None."""
    if not text:
        return None
    low = text.lower()
    for keyword, name in _VPN_PROVIDERS:
        if keyword in low:
            return name
    return None


def check_vpn(suspect_ip, org_text=None):
    """Check if an IP is a VPN and print the result (colour-coded orange).

    Two signals: the X4BNet VPN IP-range list, and — when `org_text` (the WhoIs
    Organization / ASN description) is supplied — a known-VPN-provider name match,
    which catches IPs the list misses (e.g. NordVPN / Tefincom).

    Sample output:
        VPN Provider: Yes (NordVPN — WhoIs org)
    """
    if is_vpn_ip(suspect_ip):
        print("\t{:<34} {}".format(color.ORANGE + 'VPN Provider:' + color.END,
                                   color.ORANGE + 'Yes' + color.END))
        return

    provider = vpn_provider_from_text(org_text)
    if provider:
        print("\t{:<34} {}".format(
            color.ORANGE + 'VPN Provider:' + color.END,
            color.ORANGE + 'Yes (' + provider + ' — WhoIs org)' + color.END))
        return

    print("\t{:<25} {}".format('VPN Provider:', "No"))


# ─────────────────────────────────────────────────────────────────────────────
# Datacenter / hosting detection — X4BNet datacenter IP-range list (no API key)
#
# Same mechanism as the VPN check (CIDR ranges + bisect), but against the much
# larger datacenter/hosting list. Most commercial VPNs and proxies egress from
# datacenter space, so this is a useful "non-residential source" signal.
# Source: https://github.com/X4BNet/lists_vpn  (output/datacenter/ipv4.txt)
# ─────────────────────────────────────────────────────────────────────────────

datacenter_networks_filename = "datacenter_networks.txt"
_DATACENTER_URL              = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt"
_DATACENTER_MAX_AGE_SECONDS  = 24 * 60 * 60

_datacenter_ranges: list      = []
_datacenter_loaded_at: float  = 0.0
_datacenter_lock              = threading.Lock()
_datacenter_session           = requests.Session()


def _load_datacenter_ranges_from_file() -> list:
    try:
        with open(datacenter_networks_filename, 'r') as f:
            return _parse_vpn_ranges(f.read())   # same CIDR parser as the VPN list
    except OSError:
        return []


def _fetch_and_save_datacenter_list() -> list:
    try:
        response = session_get(_datacenter_session, _DATACENTER_URL, timeout=20)
        if response.status_code == 200:
            with open(datacenter_networks_filename, 'w') as f:
                f.write(response.text)
            return _parse_vpn_ranges(response.text)
    except Exception:
        pass
    return []


def _get_datacenter_ranges() -> list:
    global _datacenter_ranges, _datacenter_loaded_at
    now = time.time()
    if now - _datacenter_loaded_at < _DATACENTER_MAX_AGE_SECONDS and _datacenter_ranges:
        return _datacenter_ranges
    with _datacenter_lock:
        if now - _datacenter_loaded_at < _DATACENTER_MAX_AGE_SECONDS and _datacenter_ranges:
            return _datacenter_ranges
        file_fresh = False
        if os.path.isfile(datacenter_networks_filename):
            file_fresh = (now - os.path.getmtime(datacenter_networks_filename)) < _DATACENTER_MAX_AGE_SECONDS
        if file_fresh:
            new_ranges = _load_datacenter_ranges_from_file()
        else:
            new_ranges = _fetch_and_save_datacenter_list()
            if not new_ranges and os.path.isfile(datacenter_networks_filename):
                new_ranges = _load_datacenter_ranges_from_file()
        _datacenter_ranges = new_ranges
        _datacenter_loaded_at = now
        return _datacenter_ranges


def is_datacenter_ip(suspect_ip) -> bool:
    """Return True if suspect_ip falls within a known datacenter/hosting range."""
    try:
        ip_int = int(ipaddress.ip_address(suspect_ip.strip()))
    except ValueError:
        return False
    ranges = _get_datacenter_ranges()
    if not ranges:
        return False
    idx = bisect.bisect_right(ranges, (ip_int, float('inf'))) - 1
    if idx >= 0:
        start, end = ranges[idx]
        if start <= ip_int <= end:
            return True
    return False


def check_datacenter(suspect_ip):
    """Print whether an IP is in known datacenter/hosting space (yellow on match)."""
    if is_datacenter_ip(suspect_ip):
        print("\t{:<34} {}".format(color.YELLOW + 'Datacenter/Hosting:' + color.END,
                                   color.YELLOW + 'Yes' + color.END))
    else:
        print("\t{:<25} {}".format('Datacenter/Hosting:', "No"))


# ─────────────────────────────────────────────────────────────────────────────
# Refang — turn a defanged indicator back into a real one before detection
# ─────────────────────────────────────────────────────────────────────────────

def refang(value):
    """Re-fang a defanged indicator so the detection regexes match it.

    Handles the common defang styles analysts copy from reports/emails:
        hxxps://evil[.]com   ->  https://evil.com
        8[.]8[.]8[.]8        ->  8.8.8.8
        bad(dot)domain(dot)com -> bad.domain.com
        user[at]evil[.]com   ->  user@evil.com

    Conservative: it only rewrites well-known defang tokens, so ordinary
    indicators pass through unchanged.
    """
    if not value:
        return value
    s = value
    s = re.sub(r'(?i)hxxp', 'http', s)                       # hxxp(s) -> http(s)
    s = re.sub(r'\[\.\]|\(\.\)|\{\.\}', '.', s)              # [.] (.) {.}
    s = re.sub(r'(?i)\[dot\]|\(dot\)|\{dot\}', '.', s)       # [dot] (dot) {dot}
    s = re.sub(r'(?i)\s+dot\s+', '.', s)                     # " dot "
    s = re.sub(r'\[@\]|\(@\)|\{@\}', '@', s)                 # [@] (@) {@}
    s = re.sub(r'(?i)\[at\]|\(at\)|\{at\}', '@', s)          # [at] (at) {at}
    s = s.replace('[://]', '://').replace('[:]', ':').replace('[/]', '/')
    return s.strip()


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


# ─────────────────────────────────────────────────────────────────────────────
# Domain exclusions — skip domain/URL lookups for configured domains
#
# Lets you stop the clipboard monitor from looking up domains/URLs you copy on
# purpose — e.g. a reference link the tool itself printed (Ultimate Windows
# Security, SpeedGuide, VirusTotal GUI, etc.). Subdomains of an excluded domain
# are matched too, so "ultimatewindowssecurity.com" also covers
# "www.ultimatewindowssecurity.com".
# ─────────────────────────────────────────────────────────────────────────────

def get_excluded_domains_from_config(path="config.ini"):
    """Return the lowercased list of domains to skip for domain/URL lookups."""
    config_object = ConfigParser()
    try:
        config_object.read(path)
        raw = config_object.get("EXCLUSIONS", "domains", fallback="")
    except Exception:
        raw = ""
    return [d.strip().lower().lstrip('.') for d in raw.split(',') if d.strip()]


def _hostname_of(value):
    """Extract the lowercase hostname from a domain or URL string."""
    v = (value or "").strip()
    if not v:
        return ""
    parsed = urlparse(v if "://" in v else "//" + v)
    host = parsed.hostname or ""
    return host.lower().rstrip(".")


def is_excluded_domain(value, excluded):
    """True if value's host equals, or is a subdomain of, any excluded domain."""
    if not excluded:
        return False
    host = _hostname_of(value)
    if not host:
        return False
    for d in excluded:
        if host == d or host.endswith("." + d):
            return True
    return False
