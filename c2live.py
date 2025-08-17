from configparser import ConfigParser
from elasticsearch import Elasticsearch

def get_c2live_config():
    """ Creates a dictionary called c2live_headers that contains the formatted header needed to submit an query to your local c2live instance.


    Note:  You are not required to use this module.  If you do not wish to use it then you can leave the config file as is with key = None

    Returns the Abuse IP DB API headers in the format of:
         c2_live_headers = {
            'URL': c2_headers['accept'],
            'Database': c2_headers['key']
    """
    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
    except:
        print("Error with config.ini.")
    else:
        c2live_headers = config_object["C2LIVE"]

        if c2live_headers['c2_live_url']:
        #    c2_live_headers = {
        #    'URL': c2live_headers['c2_live_url'],
        #    'Database': c2live_headers['c2_live_index']
        #}
            print("C2Live Configured.")
            return c2live_headers
        else:
            print("C2Live not configured.")
            print("Please configure C2Live in the config.ini file if you want to use this module.")
            c2live_headers = ''

def query_c2live(ip, c2live_headers):
    # Declatre constants
    es_url = c2live_headers['c2_live_url']
    index = c2live_headers['c2_live_index']
    search_ip = ip
    # Connect to Elasticsearch
    es = Elasticsearch(es_url)
    # List to hold all frameworks associated with an IP
    frameworks = []
    # List to hold ...........
    all_frameworks = []

    # Define the elasticsearch query
    query = {
        "query": {
            "match": {
                "ip": search_ip
            }
        }
    }

    # Executes the search for the IP in Elasticsearch
    response = es.search(index=index, body=query)

    for hit in response['hits']['hits']:
        if hit['_source']['framework'] in frameworks:
            pass
        else:
            frameworks.append(hit['_source']['framework'])

    for fw in frameworks:
        # List to hold C2 Timestamps
        c2_timestamps = []
        # Dictionary with list to hold the C2 framework and associated timestamps
        c2 = {"framework":"", "timestamps":c2_timestamps}
        for hit in response['hits']['hits']:
            if fw == hit['_source']['framework']:
                if hit['_source']['framework'] in c2['framework']:
                    # Slices the string to get just the date
                    ts = hit['_source']['@timestamp'][0:10]
                    c2_timestamps.append(ts)
                else:
                    c2['framework'] = hit['_source']['framework']
                    # Slices the string to get just the date
                    ts = hit['_source']['@timestamp'][0:10]
                    c2_timestamps.append(ts)
            else:
                pass
        # Sort the timestamps from oldest to newest
        c2_timestamps.sort()
        # Append C2 Dict to a list
        all_frameworks.append(c2)

    # Print the formatted results
    print("\nC2 Live results:")# for {}:".format(search_ip))
    if response ['hits']['hits']:
        for item in all_frameworks:
            print("\t" + item['framework'])
            print("\t\tFirst Seen:\t{}".format(item['timestamps'][0]))
            print("\t\tLast Seen:\t{}".format(item['timestamps'][-1]))
    else:
        print("\tIP not found in tracked C2's.")
