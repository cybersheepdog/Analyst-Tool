# Python Standard Library Imports
# None

# 3rd Party Imports
from configparser import ConfigParser
from elasticsearch import Elasticsearch

# Custom Imports
from analyst_tool_utilities import *

# Module-level Elasticsearch client cache: { url: Elasticsearch }
_es_client_cache: dict = {}


def _get_es_client(url: str) -> Elasticsearch:
    """Return a cached Elasticsearch client for the given URL.

    Creating an Elasticsearch() object establishes a connection pool.
    Reusing it across calls avoids repeated TCP handshakes and auth overhead.
    """
    if url not in _es_client_cache:
        _es_client_cache[url] = Elasticsearch(url)
    return _es_client_cache[url]


def get_c2live_config():
    """Read C2Live connection settings from config.ini and return them.

    Returns the config section object if configured, or None if not.

    Sample config.ini section:
        [C2LIVE]
        c2_live_url   = http://localhost:9200
        c2_live_index = c2live-*
    """
    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
    except Exception:
        print("Error with config.ini.")
        return None

    c2live_headers = config_object["C2LIVE"]
    if c2live_headers.get('c2_live_url'):
        print("C2Live Configured.")
        return c2live_headers
    else:
        print("C2Live not configured.")
        print("Please configure C2Live in the config.ini file if you want to use this module.")
        return None


def query_c2live(ip: str, c2live_headers) -> None:
    """Query a local C2Live Elasticsearch instance for a suspect IP and print results.

    Uses a cached Elasticsearch client (avoids reconnecting on every lookup)
    and a single-pass aggregation (avoids the original double-loop over hits).

    Sample output:
        C2 Live results:
            CobaltStrike
                First Seen: 2023-01-15
                Last Seen:  2023-06-22
            Metasploit
                First Seen: 2023-03-01
                Last Seen:  2023-03-01
    """
    if not c2live_headers:
        return

    es_url = c2live_headers['c2_live_url']
    index  = c2live_headers['c2_live_index']

    es = _get_es_client(es_url)

    query = {
        "query": {
            "match": {
                "ip": ip
            }
        }
    }

    try:
        response = es.search(index=index, body=query)
    except Exception as e:
        print(f"\tC2Live query failed: {e}")
        return

    hits = response['hits']['hits']

    print("\nC2 Live results:")

    if not hits:
        print("\tIP not found in tracked C2's.")
        return

    # Single-pass aggregation: { framework: [timestamps] }
    # Original used a set for dedup then a nested loop — O(frameworks * hits).
    # This dict approach is a single O(hits) pass.
    fw_timestamps: dict = {}
    for hit in hits:
        src = hit['_source']
        fw  = src.get('framework', 'Unknown')
        ts  = src.get('@timestamp', '')[:10]   # slice to date only
        if fw not in fw_timestamps:
            fw_timestamps[fw] = []
        fw_timestamps[fw].append(ts)

    for fw, timestamps in fw_timestamps.items():
        timestamps.sort()
        print(f"\t{fw}")
        print(f"\t\tFirst Seen:\t{timestamps[0]}")
        print(f"\t\tLast Seen:\t{timestamps[-1]}")
