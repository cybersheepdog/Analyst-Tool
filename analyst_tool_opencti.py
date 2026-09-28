# Python Standard Library Imports
import re
import threading
import time

# 3rd Party Imports
from configparser import ConfigParser

# Custom Imports
from analyst_tool_utilities import *
from analyst_tool_shared_config import load_config

# PERFORMANCE MODIFICATION:
# The original code called OpenCTIApiClient(url, token) on every single query,
# which re-establishes the GraphQL connection and re-authenticates each time.
# We cache the client in a module-level dict keyed by (url, token) so the
# connection is reused across lookups within the same session.
#
# pycti also health-checks the server when the client is CONSTRUCTED, so a
# failed construction (OpenCTI down) used to be retried — with its full
# connection timeout — on every single lookup. A failure is now remembered
# for _CLIENT_RETRY_SECONDS and reported as a ServiceError instead.

_opencti_client_cache = {}
_opencti_cache_lock = threading.Lock()
_opencti_client_failed_at = {}     # (url, token) -> (epoch, message)
_CLIENT_RETRY_SECONDS = 60


def _get_opencti_client(url, token):
    """Return a cached OpenCTIApiClient, creating one if needed.

    Raises ServiceError when the client cannot be built (server unreachable,
    bad token) and keeps raising, without re-trying the connection, for
    _CLIENT_RETRY_SECONDS.
    """
    key = (url, token)
    client = _opencti_client_cache.get(key)
    if client is not None:
        return client
    with _opencti_cache_lock:
        client = _opencti_client_cache.get(key)
        if client is not None:
            return client
        failed = _opencti_client_failed_at.get(key)
        if failed and time.time() - failed[0] < _CLIENT_RETRY_SECONDS:
            raise ServiceError("OpenCTI", None, failed[1])
        # Imported here, not at module load: pycti is heavy and only needed
        # when OpenCTI is actually configured.
        from pycti import OpenCTIApiClient
        verify = get_ssl_verify_from_config()
        try:
            try:
                client = OpenCTIApiClient(url, token, ssl_verify=verify)
            except TypeError:
                # Older pycti without ssl_verify kwarg — preserve original call.
                client = OpenCTIApiClient(url, token)
        except Exception as exc:
            msg = "cannot connect: %s" % str(exc).splitlines()[0][:120]
            _opencti_client_failed_at[key] = (time.time(), msg)
            raise ServiceError("OpenCTI", None, msg)
        _opencti_client_failed_at.pop(key, None)
        _opencti_client_cache[key] = client
        return client


def get_opencti_from_config():
    """Read OpenCTI settings from config.ini and return a combined header
    string "api_url,token,base_url" (base_url may be empty), or None."""
    try:
        config_object = load_config()
        cti_headers = config_object["OPEN_CTI"]
    except Exception:
        print("Error with config.ini.")
        return None

    if cti_headers['opencti_api_token']:
        base_url = ""
        try:
            base_url = (cti_headers.get('opencti_base_url') or "").strip()
        except Exception:
            pass
        opencti_headers = (cti_headers['opencti_api_url'] + "," +
                           cti_headers['opencti_api_token'] + "," + base_url)
        print("OpenCTI Configured.")
        return opencti_headers
    else:
        print("OpenCTI not configured.")
        print("Please add your OpenCTI API Key to the config.ini file if you want to use this module.")
        return None


def _split_headers(opencti_headers):
    """(api_url, token, base_url) from the combined header string."""
    parts = (opencti_headers or "").split(",")
    api_url = parts[0].strip() if parts else ""
    token = parts[1].strip() if len(parts) > 1 else ""
    base_url = parts[2].strip() if len(parts) > 2 else ""
    return api_url, token, base_url


def _dashboard_base(opencti_headers):
    """The web UI base URL: [OPEN_CTI] opencti_base_url when set, otherwise
    the API URL with a trailing /graphql removed. (The old code sliced off
    the last 8 characters unconditionally, which mangled any API URL that
    didn't end in exactly '/graphql'.)"""
    api_url, _token, base_url = _split_headers(opencti_headers)
    if base_url:
        return base_url.rstrip('/')
    return re.sub(r'/graphql/?$', '', api_url).rstrip('/')


def _same_value(a, b):
    return (a or "").strip().casefold() == (b or "").strip().casefold()


_HASH_RE = re.compile(r'[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}')


def _is_exact_hit(item, value):
    """True when an OpenCTI search hit is really about `value`.

    * its name is the value (most connectors name indicators this way), or
    * its STIX pattern compares against the quoted value
      ([ipv4-addr:value = '8.8.8.8'] — some feeds give indicators other names), or
    * for a hash, the hash appears anywhere in the pattern: a YARA-rule
      indicator that carries the hash in its meta is a real hit, and the old
      code showed its rule text. Hashes are long unique tokens, so a substring
      match is still exact; for IPs/domains it would bring back the
      8.8.8.8-matches-18.8.8.80 problem, so they need the quotes.
    """
    v = (value or "").strip().casefold()
    if not v:
        return False
    if _same_value(item.get('name'), v):
        return True
    pattern = (item.get('pattern') or "").casefold()
    if ("'" + v + "'") in pattern:
        return True
    return bool(_HASH_RE.fullmatch(v)) and v in pattern


def _score(item):
    try:
        return int(item.get('x_opencti_score') or 0)
    except (TypeError, ValueError):
        return 0


def query_opencti(opencti_headers, suspect_indicator):
    """Return the OpenCTI indicators whose name is exactly `suspect_indicator`,
    best first (highest score, then most recently modified).

    indicator.list(search=...) is a full-text search — a search for 8.8.8.8
    can return 18.8.8.80's indicator — so results are filtered to an exact
    (case-insensitive) name match. Callers see an empty list for "no exact
    match" whatever the search returned. Failures raise ServiceError so the
    cache never stores them.
    """
    cti_api_url, cti_api_token, _base = _split_headers(opencti_headers)

    client = _get_opencti_client(cti_api_url, cti_api_token)
    try:
        results = client.indicator.list(search=suspect_indicator, first=25)
    except ServiceError:
        raise
    except Exception as exc:
        raise ServiceError("OpenCTI", None, str(exc).splitlines()[0][:160])
    exact = [item for item in (results or [])
             if _is_exact_hit(item, suspect_indicator)]
    exact.sort(key=lambda i: (_score(i), str(i.get('modified') or '')), reverse=True)
    return exact


def _print_tlp(tlp):
    if tlp == "RED":
        print('\t{:<34} {}'.format(color.RED    + 'TLP:' + color.END, 'Red'))
    elif tlp.startswith("AMBER"):
        print('\t{:<34} {}'.format(color.ORANGE + 'TLP:' + color.END,
                                   'Amber+Strict' if 'STRICT' in tlp else 'Amber'))
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
    score = int(score or 0)
    if score >= 75:
        print('\t{:<34} {}'.format(color.RED    + 'Malicious:' + color.END, score))
    elif score >= 50:
        print('\t{:<34} {}'.format(color.ORANGE + 'Malicious:' + color.END, score))
    else:
        print('\t{:<25} {}'.format('Malicious:', score))


def _print_confidence(confidence):
    c = int(confidence or 0)
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


def _fmt_dt(value):
    """Trim an ISO timestamp to 'YYYY-MM-DD HH:MM:SS', or 'N/A' if empty."""
    if not value:
        return 'N/A'
    return str(value)[:19].replace('T', ' ')


# Most restrictive marking wins when several indicators share a value.
_TLP_RANK = {'RED': 4, 'AMBER+STRICT': 3, 'AMBER': 2, 'GREEN': 1, 'CLEAR': 0, 'WHITE': 0}


def _tlp_of(marking):
    d = str(marking.get('definition') or '').upper()
    d = d.replace('TLP:', '').strip()
    return d if d in _TLP_RANK else 'CLEAR'


def _extract_common_fields(results, opencti_headers):
    """Extract fields shared across all indicator types.

    `results` is the exact-match list from query_opencti(), best first: the
    scalar fields (score, confidence, dates, source) come from that first
    item; TLP is the most restrictive across all matches; tags are the union.
    """
    item = results[0]
    item_id       = item['id']
    link_url      = _dashboard_base(opencti_headers) + "/dashboard/observations/indicators/" + item_id
    created_by    = item.get('createdBy') or {}
    source        = created_by.get('name', 'Unknown') if isinstance(created_by, dict) else 'Unknown'
    active        = item.get('revoked')
    confidence    = item.get('confidence') or 0
    malicious_score = _score(item)

    # First/last seen — STIX validity window, falling back to created/modified.
    first_seen = _fmt_dt(item.get('valid_from') or item.get('created'))
    last_seen  = _fmt_dt(item.get('valid_until') or item.get('modified'))

    tlp = 'CLEAR'
    keywords = []
    for r in results:
        for marking in r.get('objectMarking') or []:
            t = _tlp_of(marking)
            if _TLP_RANK[t] > _TLP_RANK[tlp]:
                tlp = t
        for label in r.get('objectLabel') or []:
            value = label.get('value') if isinstance(label, dict) else None
            if value and value not in keywords:
                keywords.append(value)

    return (link_url, source, active, confidence, malicious_score, tlp,
            keywords, first_seen, last_seen)


def _print_match_count(results):
    """When several OpenCTI indicators share the value, say so and list the
    others in one line each, so the analyst knows there is more than the one
    block shown (which is the highest-scoring)."""
    if len(results) <= 1:
        return
    print('\t{:<25} {}'.format('Matches:', '%d indicators (highest score shown)' % len(results)))
    for other in results[1:]:
        created_by = other.get('createdBy') or {}
        src = created_by.get('name', 'Unknown') if isinstance(created_by, dict) else 'Unknown'
        print('\t{:<25} score {}, by {}, modified {}'.format(
            '', _score(other), src, _fmt_dt(other.get('modified'))))


def _print_common(results, opencti_headers, extra=None):
    link_url, source, active, confidence, malicious_score, tlp, keywords, first_seen, last_seen = \
        _extract_common_fields(results, opencti_headers)
    _print_active(active)
    _print_malicious(malicious_score)
    _print_confidence(confidence)
    print('\t{:<25} {}'.format('Source:', source))
    print('\t{:<25} {}'.format('First Seen:', first_seen))
    print('\t{:<25} {}'.format('Last Seen:', last_seen))
    _print_match_count(results)
    _print_tags(keywords)
    _print_tlp(tlp)
    if extra:
        extra()
    print('\t{:<25}'.format(link_url))


def print_opencti_ip_results(opencti_ip_results, suspect_indicator, countries, opencti_headers):
    print(color.UNDERLINE + '\nOpenCTI Info:' + color.END + " " + suspect_indicator)
    _print_common(opencti_ip_results, opencti_headers)


def print_opencti_domain_results(opencti_domain_results, opencti_headers, suspect_indicator=None):
    label = suspect_indicator or ''
    sanitized = label.replace(".", "[.]")
    print(color.UNDERLINE + '\nOpenCTI Info:' + color.END + (" " + sanitized if sanitized else ""))
    _print_common(opencti_domain_results, opencti_headers)


def print_opencti_hash_results(opencti_hash_results, suspect_indicator, opencti_headers):
    # Determine if pattern is a YARA rule or just a hash pattern
    pattern = opencti_hash_results[0].get('pattern') or ''
    if "file:hashes" in pattern or not pattern:
        rule = "No yara rule in OpenCTI"
    else:
        rule = pattern.replace("\n", "\n\t\t\t\t")

    print(color.UNDERLINE + '\nOpenCTI Info:' + color.END + " " + suspect_indicator)
    _print_common(opencti_hash_results, opencti_headers,
                  extra=lambda: print('\t{:<25} {}'.format('Rule:', rule)))


def print_opencti_url_results(opencti_url_results, suspect_indicator, opencti_headers=None):
    sanitized_url = sanitize_url(suspect_indicator)
    print(color.UNDERLINE + '\nOpenCTI Info:' + color.END + " " + sanitized_url)

    # query_opencti() already filters to exact matches; keep the filter for
    # callers that pass a raw search result.
    url_results = [item for item in opencti_url_results
                   if _is_exact_hit(item, suspect_indicator)]

    if not url_results:
        print('\n\tURL not found in OpenCTI')
        return

    if opencti_headers is None:
        # Cannot build the dashboard link without the headers; print what we can.
        opencti_headers = ","
    _print_common(url_results, opencti_headers)
