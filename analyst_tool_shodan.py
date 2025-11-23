# Python Standard Libary Imports


# 3rd Party Imports
from configparser import ConfigParser
from shodan import Shodan

# Custom Imports
from analyst_tool_utilities import *


def get_shodan_from_config():
    """ Creates a dictionary called shodan_headers that contains the formatted header needed to submit an query to shodan
    for an atomic indicator.
    
    Requires an Shodan API Key to use. 
    
    Reads in the Shodan API Key from the config.ini file.
    
    Note:  You are not required to use this module.  If you do not wish to use it then you can leave the config file as is 
    with shodan_api_key = None
    
    Returns the Shodan API Headers in the form of:
        Shodan_headers = {"api-key": "YOUR_API_KEY_HERE"}
    """

    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
    except:
        print("Error with config.ini.")
    else:
        shodan_headers = config_object["SHODAN"]

        if shodan_headers['shodan_api_key']:
            shodan_api_token = shodan_headers['shodan_api_key']
            shodan_headers = {"api-key": shodan_api_token}
            print("Shodan Configured.")
        else:
            print("Shodan not configured.")
            print("Please add your Shodan API Key to the config.ini file if you want to use this module.")
            shodan_headers = ''

        return shodan_headers
       
def get_print_shodan_ip_results(shodan_headers, suspect_ip):
    shodan_api_key = shodan_headers['api-key']
    api = Shodan(shodan_api_key)
    results = api.host(suspect_ip)
    print(color.UNDERLINE + '\nShodan IP Results for:' + color.END + f" {suspect_ip}")
    # Print Last Seen by Shodan
    print('\n\t{:<25} {}'.format('Last Seen:',results['last_update']))
    # Print open ports if any
    if type(results['ports']) == list:
        if len(results['ports']) == 0:
            print('\n\t{:<25} {}'.format('Open Ports:','None'))
        else:
            print('\tOpen Ports:')
            for port in results['ports']:
                print('\t{:<25} {}'.format('',port))
    else:
        print('\t{:<25} {}'.format('','None'))
    # Print Domains if Any    
    if type(results['domains']) == list:
        if len(results['domains']) == 0:
            print('\n\t{:<25} {}'.format('Domains:','None'))
        else:
            print('\n\tDomains:')
            for domain in results['domains']:
                print('\t{:<25} {}'.format('',domain.replace('.','[.]')))
    else:
        print('\t{:<25} {}'.format('','None'))
    # Print Hostnames if any    
    if type(results['hostnames']) == list:
        if len(results['hostnames']) == 0:
            print('\n\t{:<25} {}'.format('Hostnames:','None'))
        else:
            print('\n\tHostnames:')
            for host in results['hostnames']:
                print('\t{:<25} {}'.format('',host.replace('.','[.]')))
    else:
        print('\t{:<25} {}'.format('','None'))
    cs = is_cobalt_strike_beacon(results['data'])
    
    if cs == 1:
        if any('cobalt_strike_beacon' in item for item in results['data']):
            for item in results['data']:
                try:
                    cs_beacon = item['cobalt_strike_beacon']
                    print("\t{:<34} {}".format(color.GREEN + 'Cobalt Strike Beacon:' + color.END, "Yes"))
                    print('\t    {:<21} {}'.format('Port:',(cs_beacon['x86']['port'])))
                    print('\t    {:<21} {}'.format('Beacon Type:',cs_beacon['x86']['beacon_type']))
                    print('\t    {:<21} {}'.format('Spawn To x86:',cs_beacon['x86']['post-ex.spawnto_x86']))
                    print('\t    {:<21} {}'.format('Sleep Time:',cs_beacon['x86']['sleeptime']))
                    print('\t    {:<21} {}'.format('Spawn To x64:',(cs_beacon['x86']['post-ex.spawnto_x64'])))
                    print('\t    {:<21} {}'.format('Get URI:', cs_beacon['x86']['http-get.uri']))
                    print('\t    {:<21} {}'.format('Watermark:',cs_beacon['x86']['watermark']))
                    print('\t    {:<21} {}'.format('File Hash:',f"https://www.virustotal.com/gui/file/{cs_beacon['x86']['process-inject.stub']}"))
                except:
                    pass
        else:
            pass
    elif cs == 2:
        for item in results['data']:
            try:
                if item['product'] == 'Cobalt Strike Beacon':
                    print("\t{:<34} {}".format(color.GREEN + 'Cobalt Strike Beacon:' + color.END, "Yes, but no config info."))
                else:
                    pass
            except:
                pass        
    else:
         print('\n\t{:<25} {}'.format('Cobalt Strike Beacon:','No'))     
    
    print(f"\n\thttps://www.shodan.io/host/{suspect_ip}")

def is_cobalt_strike_beacon(results):
    """
    The expected argument ins results['data'] where results = api.host(suspect_ip).  
    Should be a list of dictionaries
    """
    cs = 0
    for item in results:
        try:
            item['cobalt_strike_beacon']
            cs = 1
            return cs
            break
        except:
            try:
                if item['product'] == 'Cobalt Strike Beacon':
                    cs = 2
                    return cs
                    break
            except:
                pass
        else:
            pass
