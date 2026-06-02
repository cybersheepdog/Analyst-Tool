# Analyst Tool
# Author: Jeremy Wiedner (@JeremyWiedner)
# License: BSD 3-Clause
# Purpose: To help automate some of an analyst workflow as much as possible. Simply copy a Domain, Hash, IP Address, Port # or Windows Event ID and the main script will pull the
#coding: utf-8

# Python Standard Library Imports
import ipaddress
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# 3rd Party Imports
import validators
from ipwhois import IPWhois
from pyperclip import paste

# Custom Imports
from analyst_tool_abuseip import *
from analyst_tool_c2live import get_c2live_config, query_c2live
from analyst_tool_lols import *
from analyst_tool_mitre import *
from analyst_tool_opencti import *
from analyst_tool_otx import *
from analyst_tool_utilities import *
from analyst_tool_virus_total import *
from analyst_tool_shodan import *

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

# Thread-local storage so each thread gets its own requests.Session (HTTP keep-alive)
_thread_local = threading.local()

def _get_session():
    """Return a per-thread requests.Session with a default 10s timeout."""
    if not hasattr(_thread_local, 'session'):
        _thread_local.session = requests.Session()
    return _thread_local.session


def analyst(terminal=0):
    """ The main function of the program.  Runs an infinite loop and checks the contents of
    the clipboard every 1-3 seconds (adaptive) to see if it has changed.  If so it then runs
    a series of checks to determine if it is one of the following:

        Hash (md5, sha1 or sha256)
        Port # or Windows EventID (requires user interaction to choose between the 2 or neither)
        Domain (lots of false positives here. will trigger on things like first.last)
        Mitre Tactics, Techniques & SubTechniques
        Private IP address
        Public IP address
        None of the above

    Optional Parameter:
        terminal:
            Default 0 - allows markdown to be displayed in jupyter notebook output for Mitre ATT&CK functions
            Changing to 1 (or anything else) disables markdown and allows to print to terminal screen)

    PERFORMANCE NOTES:
        - API calls for each indicator are dispatched concurrently (ThreadPoolExecutor).
        - Sleep is adaptive: 1s when idle, 3s after a lookup fires, to improve responsiveness.
        - MITRE data is only re-initialized via attack_client() when the on-disk JSON cache is stale.
        - All network calls carry a 10s timeout to prevent indefinite hangs on slow/downed services.
    """

    abuse_ip_db_headers = create_abuse_ip_db_headers_from_config()
    opencti_headers     = get_opencti_from_config()
    otx                 = create_av_otx_headers_from_config()
    otx_intel_list      = get_otx_intel_list_from_config()
    virus_total_headers = create_virus_total_headers_from_config()
    vt_user             = get_vt_user_from_config()
    c2live_headers      = get_c2live_config()
    shodan_headers      = get_shodan_from_config()

    lolbas = get_lolbas_json(lolbas_url, filename, file_age, current_time, threshold_time)
    driver = get_loldriver_json(loldriver_url, filename2, file_age, current_time, threshold_time)

    # --- MITRE loading ---
    # AsyncAnalystToolMitre handles its own cache check internally.
    # It reads from the on-disk JSON if fresh (90-day window), or calls
    # attack_client() only when the cache is stale. No wrapper needed here.
    mitre = AsyncAnalystToolMitre(terminal=terminal)
    mitre_tactics    = mitre.mitre_tactics
    mitre_techniques = mitre.mitre_techniques

    print("Analyst Tool Initialized.")

    clipboard_contents = get_clipboard_contents()
    sleep_time = 1  # adaptive: 1s idle, 3s after a lookup

    while True:
        try:
            check = get_clipboard_contents()
        except TypeError as e:
            print('\n\n\n' + str(e))
            time.sleep(sleep_time)
            continue

        try:
            if check != clipboard_contents:
                clipboard_contents = check
                matched = True  # track whether a lookup fired

                # ── Hash ──────────────────────────────────────────────────────────────
                if re.match(hash_validation_regex, clipboard_contents):
                    suspect_hash = clipboard_contents
                    _lookup_hash_parallel(
                        suspect_hash, virus_total_headers, vt_user,
                        opencti_headers, otx, otx_intel_list
                    )

                # ── Port / Windows Event ID ───────────────────────────────────────────
                elif re.match(port_wid_validation_regex, clipboard_contents):
                    is_port_or_weivd(clipboard_contents)

                # ── LOLBas ────────────────────────────────────────────────────────────
                elif get_lolbas_file_endings(lolbas, clipboard_contents):
                    lookup_lolbas(lolbas, clipboard_contents)

                # ── LOLDriver ─────────────────────────────────────────────────────────
                elif get_loldriver_file_endings(driver, clipboard_contents):
                    lookup_loldriver(driver, clipboard_contents)

                # ── Domain ────────────────────────────────────────────────────────────
                elif validators.domain(clipboard_contents) == True:
                    suspect_domain = clipboard_contents
                    _lookup_domain_parallel(
                        suspect_domain, virus_total_headers, vt_user,
                        opencti_headers, otx, otx_intel_list
                    )

                # ── URL ───────────────────────────────────────────────────────────────
                elif validators.url(clipboard_contents) == True:
                    suspect_url = clipboard_contents
                    _lookup_url_parallel(
                        suspect_url, virus_total_headers,
                        opencti_headers, otx, otx_intel_list
                    )

                # ── MITRE ─────────────────────────────────────────────────────────────
                elif re.match(mitre_regex, clipboard_contents):
                    import asyncio
                    asyncio.run(mitre.lookup(clipboard_contents.strip()))

                # ── Epoch timestamp ───────────────────────────────────────────────────
                elif re.match(epoch_regex, clipboard_contents):
                    print_converted_epoch_timestamp(clipboard_contents)

                # ── OTX Pulse ID ──────────────────────────────────────────────────────
                elif re.match(otx_pulse_regex, clipboard_contents):
                    suspect_pulse = clipboard_contents
                    print_otx_pulse_info(suspect_pulse, otx, otx_intel_list)

                # ── IPv6 ──────────────────────────────────────────────────────────────
                elif re.match(ipv6_regex, clipboard_contents):
                    suspect_ip = clipboard_contents.strip()
                    ip_whois(suspect_ip)

                # ── Private IPv4 ──────────────────────────────────────────────────────
                elif ipaddress.IPv4Address(clipboard_contents).is_private:
                    print('\n\n\nThis is an RFC1918 IP Address' + '\n\n\n')

                # ── Public IPv4 ───────────────────────────────────────────────────────
                elif ipaddress.IPv4Address(clipboard_contents):
                    suspect_ip = clipboard_contents
                    get_ip_analysis_results(
                        suspect_ip, virus_total_headers, abuse_ip_db_headers,
                        otx, otx_intel_list, vt_user, opencti_headers, shodan_headers
                    )
                    query_c2live(suspect_ip, c2live_headers)

                else:
                    matched = False

                sleep_time = 3 if matched else 1
            else:
                sleep_time = 1

        except Exception:
            sleep_time = 1

        time.sleep(sleep_time)


# ─────────────────────────────────────────────────────────────────────────────
# Parallel lookup helpers
# Each helper fans out the API calls for one indicator type concurrently.
# Print order is non-deterministic (first-to-finish prints first).
# ─────────────────────────────────────────────────────────────────────────────

def _run_parallel(tasks, max_workers=None):
    """Execute a list of zero-argument callables concurrently.
    Exceptions inside individual tasks are caught and printed so one
    misbehaving service never blocks the others from printing.
    """
    if max_workers is None:
        max_workers = len(tasks)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(t): getattr(t, '__name__', repr(t)) for t in tasks}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as exc:
                print(f"\t[error in {futures[future]}]: {exc}")


def _lookup_hash_parallel(suspect_hash, virus_total_headers, vt_user,
                           opencti_headers, otx, otx_intel_list):
    """Fire VT, OpenCTI, and OTX hash lookups concurrently."""

    def _vt():
        if virus_total_headers:
            print_virus_total_hash_results(suspect_hash, virus_total_headers, vt_user)
        else:
            print(color.UNDERLINE + '\nVirusTotal:' + color.END)
            print('\tVirusTotal not configured.')

    def _opencti():
        if opencti_headers:
            results = query_opencti(opencti_headers, suspect_hash)
            if len(results) == 0:
                print(color.UNDERLINE + '\nOpenCTI Info:' + color.END)
                print("\n" + suspect_hash + " Not found in OpenCTI")
            else:
                print_opencti_hash_results(results, suspect_hash, opencti_headers)

    def _otx():
        if otx:
            print_alien_vault_hash_results(otx, suspect_hash, otx_intel_list)

    _run_parallel([_vt, _opencti, _otx])


def _lookup_domain_parallel(suspect_domain, virus_total_headers, vt_user,
                             opencti_headers, otx, otx_intel_list):
    """Fire VT, OpenCTI, and OTX domain lookups concurrently."""

    def _vt():
        print_vt_domain_report(suspect_domain, virus_total_headers, vt_user)

    def _opencti():
        if opencti_headers:
            results = query_opencti(opencti_headers, suspect_domain)
            if len(results) == 0:
                print(color.UNDERLINE + '\nOpenCTI Info:' + color.END)
                print("\nNot found in OpenCTI")
            else:
                print_opencti_domain_results(results, opencti_headers)

    def _otx():
        if otx:
            print_alien_vault_domain_results(otx, suspect_domain, otx_intel_list)

    _run_parallel([_vt, _opencti, _otx])


def _lookup_url_parallel(suspect_url, virus_total_headers,
                          opencti_headers, otx, otx_intel_list):
    """Fire VT, OpenCTI, and OTX URL lookups concurrently."""

    def _vt():
        print_virus_total_url_report(virus_total_headers, suspect_url)

    def _opencti():
        if opencti_headers:
            results = query_opencti(opencti_headers, suspect_url)
            print_opencti_url_results(results, suspect_url)

    def _otx():
        if otx:
            print_alien_vault_url_results(otx, suspect_url, otx_intel_list)

    _run_parallel([_vt, _opencti, _otx])


# ─────────────────────────────────────────────────────────────────────────────
# IP analysis
# ─────────────────────────────────────────────────────────────────────────────

def get_ip_analysis_results(suspect_ip, virus_total_headers, abuse_ip_db_headers,
                             otx, otx_intel_list, vt_user, opencti_headers, shodan_headers):
    """ A function to call the various IP modules concurrently and display them.

    All enabled services (VirusTotal, Shodan, WhoIs, Tor check, AbuseIPDB,
    AlienVault OTX, OpenCTI) are queried at the same time via a thread pool,
    so total wall-clock time equals the slowest single service rather than
    the sum of all services.

    This function requires the following parameters:
        IP address              - Obtained automatically from the main loop.
        virus_total_headers     - From create_virus_total_headers_from_config().
        abuse_ip_db_headers     - From create_abuse_ip_db_headers_from_config().
        otx                     - From create_av_otx_headers_from_config().
        otx_intel_list          - From get_otx_intel_list_from_config().
        vt_user                 - From get_vt_user_from_config().
        opencti_headers         - From get_opencti_from_config().
        shodan_headers          - From get_shodan_from_config().
    """
    heading = "\n\n\nIP Analysis Report for " + suspect_ip + ":"
    print(color.BOLD + heading + color.END)

    def _opencti():
        if opencti_headers is None:
            print(color.UNDERLINE + '\nOpenCTI Info:' + color.END)
            print('\tOpenCTI not configured.')
        else:
            results = query_opencti(opencti_headers, suspect_ip)
            if len(results) == 0:
                print(color.UNDERLINE + '\nOpenCTI Info:' + color.END)
                print("\n" + suspect_ip + " Not found in OpenCTI")
            else:
                print_opencti_ip_results(results, suspect_ip, countries, opencti_headers)

    def _vt():
        if virus_total_headers is None:
            print(color.UNDERLINE + '\nVirusTotal Detections:' + color.END)
            print('\tVirus Total not configured.')
        else:
            get_vt_ip_results(suspect_ip, virus_total_headers, vt_user)

    def _shodan():
        if shodan_headers is None:
            print(color.UNDERLINE + '\n Shodan:' + color.END)
            print('\tShodan not configured.')
        else:
            get_print_shodan_ip_results(shodan_headers, suspect_ip)

    def _whois_tor():
        print(color.UNDERLINE + '\nIP Information:' + color.END)
        try:
            ip_whois(suspect_ip)
        except Exception:
            pass
        check_tor(suspect_ip)

    def _abuseipdb():
        if abuse_ip_db_headers is None:
            print(color.UNDERLINE + '\nAbuse IP DB:' + color.END)
            print('\tAbuse IP DB not configured.')
        else:
            try:
                check_abuse_ip_db(suspect_ip, abuse_ip_db_headers)
            except Exception:
                print('\tIssue with Abuse IP DB API.')

    def _otx():
        if otx is None:
            print(color.UNDERLINE + '\nAlienVault OTX:' + color.END)
            print('\tAlienVault not configured.')
        else:
            print_alien_vault_ip_results(otx, suspect_ip, otx_intel_list)

    _run_parallel([_opencti, _vt, _shodan, _whois_tor, _abuseipdb, _otx], max_workers=6)


# ─────────────────────────────────────────────────────────────────────────────
# ip_whois
# ─────────────────────────────────────────────────────────────────────────────

def ip_whois(suspect_ip):
    """ A function to query WhoIs for an IP address and print out information from the response.

    This function requires the following parameter:
        IP address: Obtained automatically from the main script.

    Sample Output:
        IP Information:
            Organization:             RU-ITRESHENIYA
            CIDR:                     45.145.66.0/23
            Range:                    45.145.66.0 - 45.145.67.255
            Country:                  Russian Federation (the)
            Associated Email:
                Email:                abuse@hostway.ru
    """
    org_match = '([a-zA-Z0-9 .,_")(-]+)\n?'
    obj = IPWhois(suspect_ip)
    res = obj.lookup_whois()
    company_count = 0

    for line in res['nets']:
        if line['description'] is not None:
            m = re.match(org_match, line['description'])
            org = m.group(1)
            company_count += 1
            print('\t{:<33} {}'.format(color.BOLD + 'Organization:' + color.END, org))
        elif line['name'] is not None:
            m = re.match(org_match, line['name'])
            org = m.group(1)
            company_count += 1
            print('\t{:<33} {}'.format(color.BOLD + 'Organization:' + color.END, org))
        else:
            print('\t{:<33} {}'.format(color.BOLD + 'Organization:' + color.END,
                                       'Org is blank in whois data.'))

        print('\t{:<25} {}'.format('CIDR:', line['cidr']))
        if line['range']:
            print('\t{:<25} {}'.format('Range:', line['range']))
        else:
            ip_range = ipaddress.ip_network(line['cidr'])
            ip_range = str(ip_range[0]) + ' - ' + str(ip_range[-1])
            print('\t{:<25} {}'.format('Range:', ip_range))

        country_code = line['country']
        print_country(country_code, countries)

        print('\tAssociated Email:')
        if line['emails'] is None:
            print('\t\t{:<17} {}'.format('Email:', 'No associated emails.'))
        else:
            for email in line['emails']:
                print('\t\t{:<17} {}'.format('Email:', email))

    if company_count == 0:
        print('\t{:<25} {}'.format('ASN Description:', res['asn_description']))
