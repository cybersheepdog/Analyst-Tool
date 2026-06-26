# Analyst Tool — DNS resolution + Certificate Transparency (crt.sh)
#
# For a domain this adds quick pivot data:
#   - Resolved A / AAAA addresses (and a reverse PTR for each).
#   - MX / NS records, if the optional `dnspython` package is installed.
#   - Subdomains observed in Certificate Transparency logs via crt.sh.
#
# Uses only the standard library for A/AAAA/PTR (socket); MX/NS are best-effort
# and skipped cleanly when dnspython isn't available. crt.sh is queried over
# HTTP (no key) and is allowed to fail without affecting the rest of the report.

import socket

from analyst_tool_utilities import color, session_get

import requests

_crt_session = requests.Session()

# Optional: richer DNS (MX/NS) if dnspython is present.
try:
    import dns.resolver as _dnsresolver
except Exception:
    _dnsresolver = None


# ─────────────────────────────────────────────────────────────────────────────
# Resolution helpers
# ─────────────────────────────────────────────────────────────────────────────

def resolve_addresses(domain):
    """Return a sorted list of unique A/AAAA addresses for a domain (stdlib)."""
    try:
        infos = socket.getaddrinfo(domain, None)
    except Exception:
        return []
    addrs = {info[4][0] for info in infos}
    return sorted(addrs)


def reverse_ptr(ip):
    """Return the PTR hostname for an IP, or None."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _dns_records(domain, rtype):
    """Return a list of records of a given type via dnspython, or [] if unavailable."""
    if _dnsresolver is None:
        return []
    try:
        answers = _dnsresolver.resolve(domain, rtype, lifetime=8)
        return [r.to_text() for r in answers]
    except Exception:
        return []


def get_crt_subdomains(domain, limit=15):
    """Return (unique_subdomains, total_count) from crt.sh certificate logs.

    crt.sh can be slow or unavailable; this fails closed (returns ([], 0)).
    """
    url = "https://crt.sh/?q=%25." + domain + "&output=json"
    try:
        resp = session_get(_crt_session, url, timeout=20)
        if resp.status_code != 200 or not resp.text.strip():
            return [], 0
        data = resp.json()
    except Exception:
        return [], 0

    names = set()
    for entry in data:
        value = entry.get("name_value", "")
        for name in value.splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith(domain) and name != domain:
                names.add(name)
    ordered = sorted(names)
    return ordered[:limit], len(ordered)


# ─────────────────────────────────────────────────────────────────────────────
# Display
# ─────────────────────────────────────────────────────────────────────────────

def print_dns_and_crt(domain):
    """Print DNS resolution, MX/NS (if available), and crt.sh subdomains."""
    print(color.UNDERLINE + '\nDNS & Certificate Transparency:' + color.END)

    addrs = resolve_addresses(domain)
    if addrs:
        print('\tResolved Addresses:')
        for ip in addrs:
            ptr = reverse_ptr(ip)
            if ptr:
                print('\t{:<25} {}'.format('', ip + '  (' + ptr + ')'))
            else:
                print('\t{:<25} {}'.format('', ip))
    else:
        print('\t{:<25} {}'.format('Resolved Addresses:', 'None / did not resolve'))

    mx = _dns_records(domain, 'MX')
    ns = _dns_records(domain, 'NS')
    if _dnsresolver is not None:
        if mx:
            print('\tMX Records:')
            for r in mx[:5]:
                print('\t{:<25} {}'.format('', r))
        if ns:
            print('\tNS Records:')
            for r in ns[:5]:
                print('\t{:<25} {}'.format('', r))
    # If dnspython is missing we simply omit MX/NS rather than erroring.

    subs, total = get_crt_subdomains(domain)
    if total:
        print('\t{:<25} {}'.format('Subdomains (crt.sh):',
                                   '%d found%s' % (total, '' if total <= len(subs)
                                                   else ', showing %d' % len(subs))))
        for name in subs:
            print('\t{:<25} {}'.format('', name.replace('.', '[.]')))
    else:
        print('\t{:<25} {}'.format('Subdomains (crt.sh):', 'None found / unavailable'))
