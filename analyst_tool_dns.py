# Analyst Tool — DNS resolution + Certificate Transparency (crt.sh)
#
# [DNS] active_resolution (default false) decides how resolution is done:
#   * false (passive, default): NO query leaves the workstation for the
#     domain. Passive DNS history comes from AlienVault OTX (one cached call);
#     crt.sh is always used (it never touches the target).
#   * true (active): the live lookups below, as before.
#
# In active mode, for a domain this adds quick pivot data:
#   - Resolved A / AAAA addresses (and a reverse PTR for each).
#   - MX / NS records, if the optional `dnspython` package is installed.
#   - Subdomains observed in Certificate Transparency logs via crt.sh.
#
# Uses only the standard library for A/AAAA/PTR (socket); MX/NS are best-effort
# and skipped cleanly when dnspython isn't available. crt.sh is queried over
# HTTP (no key) and is allowed to fail without affecting the rest of the report.

import socket

from analyst_tool_utilities import (color, session_get, resolve_ptr,
                                    dns_active_resolution, IndicatorNotFound)

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
    """Return the PTR hostname for an IP, or None. Bounded (3 s): a resolver
    with no PTR for the address can otherwise block for its full retry cycle."""
    try:
        return resolve_ptr(ip, timeout=3.0)
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
            # '.' + domain: notevil.com is not a subdomain of evil.com
            if name.endswith('.' + domain) and name != domain:
                names.add(name)
    ordered = sorted(names)
    return ordered[:limit], len(ordered)


# ─────────────────────────────────────────────────────────────────────────────
# Display
# ─────────────────────────────────────────────────────────────────────────────

def _print_passive_dns(domain, otx, limit=5):
    """Print OTX passive DNS for a domain: most recent records first.
    Raises IndicatorNotFound (cacheable) when OTX has none."""
    from OTXv2 import IndicatorTypes
    from analyst_tool_otx import _otx_section
    data = _otx_section(otx, IndicatorTypes.DOMAIN, domain, 'passive_dns') or {}
    records = data.get('passive_dns') or []
    if not records:
        print('\t{:<25} {}'.format('Passive DNS (OTX):', 'none recorded'))
        raise IndicatorNotFound("AlienVault OTX")
    records = sorted(records, key=lambda r: str(r.get('last') or ''), reverse=True)
    print('\t{:<25} {}'.format('Passive DNS (OTX):', '%d records%s' % (
        len(records), '' if len(records) <= limit else ', newest %d' % limit)))
    for r in records[:limit]:
        addr = r.get('address') or '?'
        rtype = r.get('record_type') or ''
        host = r.get('hostname') or domain
        label = addr + ('  (' + rtype + ')' if rtype else '')
        if host.lower() != domain.lower():
            label += '  via ' + host.replace('.', '[.]')
        print('\t{:<25} {}'.format('', label))
        print('\t{:<25} first {}  last {}'.format(
            '', str(r.get('first') or '?')[:10], str(r.get('last') or '?')[:10]))


def print_dns_and_crt(domain, otx=None, cache=None, force_refresh=False):
    """Print DNS for a domain — passive (OTX) or live, per [DNS]
    active_resolution — and crt.sh subdomains."""
    print(color.UNDERLINE + '\nDNS & Certificate Transparency:' + color.END)

    if not dns_active_resolution():
        print('\t{:<25} {}'.format('Live resolution:',
                                   'off (passive mode — [DNS] active_resolution)'))
        if otx is None:
            print('\t{:<25} {}'.format('Passive DNS (OTX):', 'OTX not configured'))
        else:
            def _live():
                _print_passive_dns(domain, otx)
            try:
                if cache is not None:
                    cache.cached_call(domain, 'domain', 'otx_pdns', _live, force_refresh)
                else:
                    _live()
            except IndicatorNotFound:
                pass
            except Exception as exc:
                print('\t[AlienVault OTX] passive DNS unavailable: %s' % exc)
        _print_crt(domain)
        return

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

    _print_crt(domain)


def _print_crt(domain):
    """crt.sh subdomains (passive in both modes)."""
    subs, total = get_crt_subdomains(domain)
    if total:
        print('\t{:<25} {}'.format('Subdomains (crt.sh):',
                                   '%d found%s' % (total, '' if total <= len(subs)
                                                   else ', showing %d' % len(subs))))
        for name in subs:
            print('\t{:<25} {}'.format('', name.replace('.', '[.]')))
    else:
        print('\t{:<25} {}'.format('Subdomains (crt.sh):', 'None found / unavailable'))
