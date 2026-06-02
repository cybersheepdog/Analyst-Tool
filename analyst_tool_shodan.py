# Python Standard Library Imports
import threading

# 3rd Party Imports
from configparser import ConfigParser
from shodan import Shodan

# Custom Imports
from analyst_tool_utilities import *

def get_shodan_from_config():
    """Read the Shodan API key from config.ini and return a header dict, or None."""
    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
    except Exception:
        print("Error with config.ini.")
        return None

    shodan_cfg = config_object["SHODAN"]
    if shodan_cfg['shodan_api_key']:
        print("Shodan Configured.")
        return {"api-key": shodan_cfg['shodan_api_key']}
    else:
        print("Shodan not configured.")
        print("Please add your Shodan API Key to the config.ini file if you want to use this module.")
        return None


def get_print_shodan_ip_results(shodan_headers, suspect_ip):
    """Query Shodan for an IP and print a formatted report.

    Sample Output:
        Shodan IP Results for: 1.2.3.4
            Last Seen:    2024-01-01
            Open Ports:   80, 443
            Domains:      example[.]com
            Hostnames:    host.example[.]com
    """
    api     = Shodan(shodan_headers['api-key'])
    results = api.host(suspect_ip)

    print(color.UNDERLINE + '\nShodan IP Results for:' + color.END + f" {suspect_ip}")
    print('\n\t{:<25} {}'.format('Last Seen:', results['last_update']))

    # Open ports
    ports = results.get('ports', [])
    if isinstance(ports, list) and ports:
        print('\tOpen Ports:')
        for port in ports:
            print('\t{:<25} {}'.format('', port))
    else:
        print('\n\t{:<25} {}'.format('Open Ports:', 'None'))

    # Domains
    domains = results.get('domains', [])
    if isinstance(domains, list) and domains:
        print('\n\tDomains:')
        for domain in domains:
            print('\t{:<25} {}'.format('', domain.replace('.', '[.]')))
    else:
        print('\n\t{:<25} {}'.format('Domains:', 'None'))

    # Hostnames
    hostnames = results.get('hostnames', [])
    if isinstance(hostnames, list) and hostnames:
        print('\n\tHostnames:')
        for host in hostnames:
            print('\t{:<25} {}'.format('', host.replace('.', '[.]')))
    else:
        print('\n\t{:<25} {}'.format('Hostnames:', 'None'))

    # Cobalt Strike beacon detection
    cs = is_cobalt_strike_beacon(results['data'])
    if cs == 1:
        for item in results['data']:
            try:
                cs_beacon = item['cobalt_strike_beacon']
                print("\t{:<34} {}".format(
                    color.GREEN + 'Cobalt Strike Beacon:' + color.END, "Yes"))
                x86 = cs_beacon['x86']
                print('\t {:<21} {}'.format('Port:',          x86['port']))
                print('\t {:<21} {}'.format('Beacon Type:',   x86['beacon_type']))
                print('\t {:<21} {}'.format('Spawn To x86:',  x86['post-ex.spawnto_x86']))
                print('\t {:<21} {}'.format('Sleep Time:',    x86['sleeptime']))
                print('\t {:<21} {}'.format('Spawn To x64:',  x86['post-ex.spawnto_x64']))
                print('\t {:<21} {}'.format('Get URI:',       x86['http-get.uri']))
                print('\t {:<21} {}'.format('Watermark:',     x86['watermark']))
                print('\t {:<21} {}'.format(
                    'File Hash:',
                    f"https://www.virustotal.com/gui/file/{x86['process-inject.stub']}"))
            except Exception:
                pass
    elif cs == 2:
        for item in results['data']:
            try:
                if item.get('product') == 'Cobalt Strike Beacon':
                    print("\t{:<34} {}".format(
                        color.GREEN + 'Cobalt Strike Beacon:' + color.END,
                        "Yes, but no config info."))
            except Exception:
                pass
    else:
        print('\n\t{:<25} {}'.format('Cobalt Strike Beacon:', 'No'))

    print(f"\n\thttps://www.shodan.io/host/{suspect_ip}")


def is_cobalt_strike_beacon(data):
    """Scan Shodan data list for Cobalt Strike beacon evidence.

    Returns:
        1 — full beacon config found
        2 — product string identifies it but no config
        0 — not found
    """
    for item in data:
        if 'cobalt_strike_beacon' in item:
            return 1
        try:
            if item.get('product') == 'Cobalt Strike Beacon':
                return 2
        except Exception:
            pass
    return 0
