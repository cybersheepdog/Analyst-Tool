# Python Standard Library Imports
import re
import threading

# 3rd Party Imports
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from configparser import ConfigParser

# Custom Imports
from analyst_tool_mitre import *
from analyst_tool_utilities import *

def create_av_otx_headers_from_config():
    """Create and return an OTXv2 client from config.ini, or None if not configured."""
    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
    except Exception:
        print("Error with config.ini.")
        return None

    av_headers = config_object["ALIEN_VAULT_OTX"]
    if av_headers['otx_api_key']:
        verify = get_ssl_verify_from_config()
        try:
            av_otx_headers = OTXv2(av_headers['otx_api_key'],
                                   server=av_headers['server'], verify=verify)
        except TypeError:
            # Older OTXv2 builds don't accept a verify kwarg — preserve original call.
            av_otx_headers = OTXv2(av_headers['otx_api_key'], server=av_headers['server'])
        print("AlienVault OTX Configured.")
        return av_otx_headers
    else:
        print("AlienVault OTX not configured.")
        print("Please add your AlienVault OTX API Key to the config.ini file if you want to use this module.")
        return None


def get_otx_intel_list_from_config():
    """Read the OTX intel provider list from config.ini and return as a list."""
    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
    except Exception:
        print("Error with config.ini.")
        return None

    intel_list = config_object["OTX_INTEL"]
    if intel_list['intel_list']:
        otx_intel_list = [x.strip() for x in intel_list['intel_list'].split(",")]
        print('OTX Intel Providers configured.')
        return otx_intel_list
    else:
        print('OTX Intel Providers not configured.')
        return None

def _get_otx_ip_data(otx, suspect_ip):
    """Fetch only the OTX sections used for IP display (3 calls instead of 8)."""
    general     = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, suspect_ip, 'general')
    reputation  = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, suspect_ip, 'reputation')
    passive_dns = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, suspect_ip, 'passive_dns')
    # Merge into a dict that matches the shape get_indicator_details_full() returned
    return {'general': general, 'reputation': reputation, 'passive_dns': passive_dns}


def _get_otx_domain_data(otx, suspect_domain):
    """Fetch only the OTX sections used for domain display (1 call instead of 8)."""
    general = otx.get_indicator_details_by_section(IndicatorTypes.DOMAIN, suspect_domain, 'general')
    return {'general': general}


def _get_otx_hash_data(otx, suspect_hash):
    """Fetch only the OTX sections used for hash display (2 calls instead of 8)."""
    md5_regex    = r'^[a-fA-F0-9]{32}$'
    sha1_regex   = r'^[a-fA-F0-9]{40}$'
    sha256_regex = r'^[a-fA-F0-9]{64}$'

    if re.match(md5_regex, suspect_hash):
        itype = IndicatorTypes.FILE_HASH_MD5
    elif re.match(sha1_regex, suspect_hash):
        itype = IndicatorTypes.FILE_HASH_SHA1
    elif re.match(sha256_regex, suspect_hash):
        itype = IndicatorTypes.FILE_HASH_SHA256
    else:
        print("Not an MD5, SHA1, or SHA256 hash.")
        return None

    general  = otx.get_indicator_details_by_section(itype, suspect_hash, 'general')
    analysis = otx.get_indicator_details_by_section(itype, suspect_hash, 'analysis')
    return {'general': general, 'analysis': analysis}


def _get_otx_url_data(otx, suspect_url):
    """Fetch only the OTX sections used for URL display (1 call instead of 8)."""
    general = otx.get_indicator_details_by_section(IndicatorTypes.URL, suspect_url, 'general')
    return {'general': general}


# ─────────────────────────────────────────────────────────────────────────────
# Public print functions (called from analyst.py worker threads)
# ─────────────────────────────────────────────────────────────────────────────

def print_alien_vault_ip_results(otx, suspect_ip, otx_intel_list):
    """Query OTX for an IP and print results. Uses targeted section fetches."""
    otx_results = _get_otx_ip_data(otx, suspect_ip)

    print(color.UNDERLINE + "\nAlienVault OTX IP Report:" + color.END)

    if otx_intel_list:
        determine_specific_otx_intel(otx_results, otx_intel_list)

    print("\n\t{:<25} {}".format("Related Pulses:",
                                 otx_results['general']['pulse_info']['count']))

    rep = otx_results['reputation'].get('reputation')
    print('\t{:<25} {}'.format('Reputation:', rep if rep else 'None'))

    pdns = otx_results['passive_dns']
    print('\t{:<25} {}'.format('Passive DNS:', str(pdns['count']) + ' Domains'))

    if pdns['count'] <= 5:
        for host in pdns['passive_dns']:
            print("\t{:<33} {}".format(color.BOLD + 'Hostname:' + color.END, host['hostname']))
            print("\t {:<23} {}".format('First Seen:', host['first']))
            print("\t {:<23} {}".format('Last Seen:',  host['last']))

    print("\thttps://otx.alienvault.com/indicator/ip/" + suspect_ip)


def print_alien_vault_domain_results(otx, suspect_domain, otx_intel_list):
    """Query OTX for a domain and print results. Uses targeted section fetches."""
    otx_results = _get_otx_domain_data(otx, suspect_domain)

    print("\n" + color.UNDERLINE + 'AlienVault OTX Domain Report for:' + color.END
          + ' ' + suspect_domain)

    if otx_intel_list:
        determine_specific_otx_intel(otx_results, otx_intel_list)

    print("\t{:<25} {}".format("Related Pulses:",
                               otx_results['general']['pulse_info']['count']))
    print("https://otx.alienvault.com/indicator/domain/" + suspect_domain)


def print_alien_vault_hash_results(otx, suspect_hash, otx_intel_list):
    """Query OTX for a hash and print results. Uses targeted section fetches."""
    otx_results = _get_otx_hash_data(otx, suspect_hash)
    if otx_results is None:
        return

    print(color.UNDERLINE + "\nAlienVault OTX Hash Report:" + color.END)

    if otx_intel_list:
        determine_specific_otx_intel(otx_results, otx_intel_list)

    print("\t{:<25} {}".format("Related Pulses:",
                               otx_results['general']['pulse_info']['count']))

    print("\n\tContacted Domains:")
    try:
        domains = (otx_results['analysis']['analysis']['plugins']
                   ['cuckoo']['result']['network']['domains'])
    except (KeyError, TypeError):
        print("\tNo known contacted domains or IPs.")
    else:
        for domain in domains:
            print("\t{:>10}".format("Details:"))
            print("\t\t{:<16} {}".format("Domain:", domain['domain'] or "None"))
            print("\t\t{:<16} {}".format("IP:",     domain['ip']     or "None"))
            print("\t\t{:<16} {}".format("Whitelisted:",
                                         "No" if domain['whitelisted'] is False
                                         else str(domain['whitelisted'])))

    print("\thttps://otx.alienvault.com/indicator/file/" + suspect_hash)


def print_alien_vault_url_results(otx, suspect_url, otx_intel_list):
    """Query OTX for a URL and print results. Uses targeted section fetches."""
    otx_results = _get_otx_url_data(otx, suspect_url)
    sanitized_url = sanitize_url(suspect_url)

    print('\n' + color.UNDERLINE + 'AlienVault OTX URL Report for:' + color.END
          + ' ' + sanitized_url)

    if otx_intel_list:
        determine_specific_otx_intel(otx_results, otx_intel_list)

    print("\t{:<25} {}".format("Related Pulses:",
                               otx_results['general']['pulse_info']['count']))
    print("https://otx.alienvault.com/indicator/domain/" + suspect_url)


def print_otx_pulse_info(suspect_pulse, otx, otx_intel_list):
    """Fetch and print OTX pulse details."""
    otx_pulse_results = otx.get_pulse_details(suspect_pulse)

    print("\n\n\n" + color.BOLD + "AlienVault OTX Pulse Report for: "
          + color.END + suspect_pulse)
    print("https://otx.alienvault.com/pulse/" + suspect_pulse)

    author = otx_pulse_results['author_name']
    if otx_intel_list and author in otx_intel_list:
        print("\t{:<25} {}".format("Pulse Author:", color.GREEN + author + color.END))
    else:
        print("\t{:<25} {}".format("Pulse Author:", author))

    print("\t{:<25} {}".format("Pulse Name:", otx_pulse_results['name']))
    print("\t{:<25} {}".format("TLP:",        otx_pulse_results['TLP'].title()))
    print("\t{:<25} {}".format("Modified:",   otx_pulse_results['modified']))
    print("\t{:<25} {}".format("Created:",    otx_pulse_results['created']))

    _print_limited_list(otx_pulse_results['tags'],            'Tags',             5)
    _print_limited_list([m if isinstance(m, str) else m.get('display_name', '')
                         for m in otx_pulse_results['malware_families']],
                        'Malware Families', 5, prefix='\n')

    print(color.UNDERLINE + "\nDescription:" + color.END)
    print(otx_pulse_results['description'])

    refs = otx_pulse_results['references']
    if not refs:
        print('\n{:<25} {}'.format(color.UNDERLINE + 'References:' + color.END,
                                   'No references cited for this pulse'))
    else:
        print("\n" + color.UNDERLINE + "References:" + color.END)
        for ref in refs[:5]:
            print("\t" + ref)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _print_limited_list(items, label, max_items, prefix=''):
    """Print a labelled list, capped at max_items entries."""
    if not items:
        print(f'{prefix}\t{color.UNDERLINE}{label}:{color.END} None')
        return
    print(f'{prefix}\t{color.UNDERLINE}{label}:{color.END}')
    for item in items[:max_items]:
        print("\t " + str(item))


def determine_specific_otx_intel(otx_results, otx_intel_list):
    """Check pulse authors against the configured intel list and print matches."""
    author_list = []

    for pulse in otx_results['general']['pulse_info']['pulses']:
        username = pulse['author']['username']
        if username not in otx_intel_list:
            continue

        intel_pulse = 'https://otx.alienvault.com/pulse/' + str(pulse['id'])
        print('\t{:<34} {}'.format(color.GREEN + username + ' Intel:' + color.END, 'Yes'))

        tlp = pulse.get('TLP', '')
        if tlp == 'white':
            print("\t{:<25} {}".format("TLP:", tlp.title()))
        elif tlp == 'green':
            print("\t{:<25} {}".format("TLP:", color.GREEN + tlp.title() + color.END))
        elif tlp == 'amber':
            print("\t{:<25} {}".format("TLP:", color.YELLOW + tlp.title() + color.END))
        elif tlp == 'red':
            print("\t{:<25} {}".format("TLP:", color.RED + tlp.title() + color.END))

        print('\t{:<25} {}'.format('Pulse Created:', pulse['created']))
        print('\t{:<25} {}'.format('Pulse Modified:', pulse['modified']))
        print("\t{:<25} {}".format("Pulse Name:", pulse['name']))
        print('\t{:<25} {}'.format('Pulse:', intel_pulse))

        _print_limited_list(pulse.get('tags', []),   'Tags',             5)
        _print_limited_list([m['display_name'] for m in pulse.get('malware_families', [])],
                            'Malware Families', 5)
        _print_limited_list(pulse.get('references', []), 'References',   5)
        print('\n')

        author_list.append(username)

    for author in otx_intel_list:
        if author not in author_list:
            print('\t{:<25} {}'.format(author + ' Intel:', 'No'))


def determine_subscribed_otx_intel(otx_results):
    """Print results for OTX authors the API key owner is subscribed to."""
    for pulse in otx_results['general']['pulse_info']['pulses']:
        if pulse['author']['is_subscribed']:
            intel_pulse = 'https://otx.alienvault.com/pulse/' + str(pulse['id'])
            print('\t{:<34} {}'.format(
                color.GREEN + pulse['author']['username'] + ' Intel:' + color.END, 'Yes'))
            print('\t{:<25} {}'.format('Pulse Created:', pulse['created']))
            print('\t{:<25} {}'.format('Pulse Modified:', pulse['modified']))
            print('\t{:<25} {}'.format('Pulse:', intel_pulse))
            print('\n')


# MITRE helpers (unchanged logic, kept for compatibility)
def get_pulse_mitre_tags(pulse, enterprise, mitre_techniques):
    if pulse['attack_ids']:
        for mitre in pulse['attack_ids']:
            is_otx_mitre_tactic_technique_sub_tecnique(mitre['id'], enterprise, mitre_techniques)


def is_otx_mitre_tactic_technique_sub_tecnique(mitre, enterprise, mitre_techniques):
    mitre_tactic_regex        = r'^TA000[1-9]|TA001[0-1]|TA004[0,2-3]$'
    mitre_technique_regex     = r'^T[0-9]{4}$'
    mitre_sub_technique_regex = r'^T[0-9]{4}\.[0-9]{3}$'

    if re.match(mitre_tactic_regex, mitre):
        print_otx_mitre_tactic(mitre, enterprise)
    elif re.match(mitre_technique_regex, mitre):
        print_otx_mitre_technique(mitre, mitre_techniques)
    elif re.match(mitre_sub_technique_regex, mitre):
        parts = mitre.split(".")
        print_otx_mitre_sub_technique(mitre, mitre_techniques, parts[0])


def print_otx_mitre_tactic(mitre_tactic, enterprise):
    for tactics in enterprise['tactics']:
        for tactic in tactics['external_references']:
            if tactic['external_id'] == mitre_tactic:
                print("\t {:<22} {}".format("Mitre Tactic: ", mitre_tactic))
                print("\t " + tactics['name'] + ":")
                print("\t " + tactic['url'] + "\n")


def print_otx_mitre_technique(mitre_technique, mitre_techniques):
    for techniques in mitre_techniques:
        for technique in techniques['external_references']:
            try:
                if technique['external_id'] == mitre_technique:
                    if len(technique['external_id']) <= 5:
                        print("\t {:<22} {}".format(
                            "Mitre Tactic:",
                            techniques['kill_chain_phases'][0]['phase_name'].title()))
                        print("\t {:<18} {}".format(
                            "Mitre Technique:\t", technique['external_id']))
                        print("\t " + techniques['name'])
                        print("\t " + technique['url'] + "\n")
            except Exception:
                pass


def print_otx_mitre_sub_technique(mitre_sub_technique, mitre_techniques, mitre_technique):
    for techniques in mitre_techniques:
        for technique in techniques['external_references']:
            try:
                if technique['external_id'] == mitre_sub_technique:
                    print("\t {:<23} {}".format(
                        "Mitre Tactic:",
                        techniques['kill_chain_phases'][0]['phase_name'].title()))
                    print("\t {:<23} {}".format("Mitre Technique:", techniques['name']))
                    print("\t {:<23} {}".format("Mitre Sub-Technique:", technique['external_id']))
                    print("\t " + techniques['name'])
                    print("\t " + technique['url'] + "\n")
            except Exception:
                pass
