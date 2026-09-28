# Analyst Tool — one indicator classifier
#
# Every place that used to decide "what is this clipboard value?" — the main
# loop's if/elif chain, _indicator_type() for >>note targeting,
# _is_recognized_indicator() for the banner, and annotate.py's _guess_type() —
# now calls classify(). They had drifted apart (IPv6 accepted in one, not
# another; different detection orders), and the chain silently dropped the
# shapes analysts copy most from logs: 1.2.3.4:443, evil.com/login,
# evil.com., 8.8.8.8/32.
#
# classify() also normalises before detecting:
#   * trailing dot stripped                 evil.com.        → evil.com
#   * host:port → host (port noted)         1.2.3.4:443      → 1.2.3.4
#   * [ipv6]:port → ipv6                    [2001:db8::1]:80 → 2001:db8::1
#   * ip/cidr → ip (prefix noted)           8.8.8.8/32       → 8.8.8.8
#   * host/path (no scheme) → URL           evil.com/login   → http://evil.com/login
#   * domains lowercased, MITRE IDs uppercased
# and gates domains on a real TLD (validators' consider_tld when available)
# plus a file-extension deny-list, so report.docx / kernel32.dll / first.last
# no longer cost a VirusTotal + OTX + OpenCTI + crt.sh round.

import ipaddress
import re
from collections import namedtuple
from urllib.parse import urlsplit

import validators

# ── Regexes (shared with analyst.py, which re-exports them) ──────────────────
epoch_regex            = r'^[0-9]{10,16}(\.[0-9]{0,6})?$'
otx_pulse_regex        = r'^[0-9a-fA-F]{24}$'
hash_validation_regex  = r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
port_wid_validation_regex = r'^[0-9]{1,5}$'
mitre_regex            = r'^TA[0-9]{4}$|^T[0-9]{4}(\.[0-9]{3})?$'
cve_regex              = r'^CVE-\d{4}-\d{4,7}$'   # same as analyst_tool_cve

# Values with these final "extensions" are files, not domains, even where the
# extension happens to be a real TLD (.md is Moldova, .py is Paraguay). Kept
# short and obvious: things that turn up in logs and reports as bare file
# names. .zip and .mov are deliberately NOT here — they are live phishing
# TLDs, and an extra lookup beats a missed one. The '!' force prefix runs a
# lookup on anything regardless.
FILE_EXTENSION_DENYLIST = frozenset("""
    exe dll sys ocx cpl scr drv msi msp jar
    doc docx docm xls xlsx xlsm ppt pptx pptm pdf rtf odt ods txt csv tsv
    json xml yaml yml ini cfg conf log md
    html htm css js ts py pyc ps1 psm1 psd1 bat cmd vbs vbe wsf hta
    iso img vhd vhdx 7z rar gz tgz tar bz2 cab
    png jpg jpeg gif bmp svg ico webp mp4 avi mkv wav mp3
    lnk reg dat tmp bak db sqlite pcap pcapng evtx etl dmp bin
""".split())

_HAS_CONSIDER_TLD = None


def _validators_has_consider_tld():
    """True if the installed validators supports domain(consider_tld=...)."""
    global _HAS_CONSIDER_TLD
    if _HAS_CONSIDER_TLD is None:
        try:
            import inspect
            _HAS_CONSIDER_TLD = 'consider_tld' in inspect.signature(validators.domain).parameters
        except Exception:
            _HAS_CONSIDER_TLD = False
    return _HAS_CONSIDER_TLD


def parse_ip(value):
    """Return an ipaddress object for a bare IPv4/IPv6 literal, else None."""
    try:
        return ipaddress.ip_address((value or "").strip())
    except (ValueError, TypeError):
        return None


def looks_like_domain(value):
    """A syntactically valid domain whose last label is a real TLD (when the
    installed validators can check that) and is not a known file extension."""
    v = (value or "").strip().lower().rstrip('.')
    if not v or '.' not in v or '/' in v or ':' in v or '@' in v:
        return False
    if v.rsplit('.', 1)[-1] in FILE_EXTENSION_DENYLIST:
        return False
    try:
        if _validators_has_consider_tld():
            return validators.domain(v, consider_tld=True) is True
        return validators.domain(v) is True
    except Exception:
        return False


def looks_like_url(value):
    try:
        return validators.url(value) is True
    except Exception:
        return False


# kind: one of the strings below, or None when nothing matched.
#   'hash' 'port' 'lolbas' 'loldriver' 'cve' 'domain' 'url' 'mitre' 'epoch'
#   'pulse' 'ip' 'ip_private'
# value: the normalised value to look up (e.g. port stripped, scheme added).
# note:  one line explaining a normalisation the analyst should know about,
#        or None.
Classified = namedtuple('Classified', 'kind value note')

# Indicator kinds that team notes / tags can be attached to.
ANNOTATABLE = {'hash', 'ip', 'ip_private', 'domain', 'url', 'cve'}

_HOST_PORT = re.compile(r'^(?P<host>[^\s/:\[\]]+):(?P<port>\d{1,5})$')
_V6_BRACKET = re.compile(r'^\[(?P<host>[0-9a-fA-F:.]+)\](?::(?P<port>\d{1,5}))?$')
_CIDR = re.compile(r'^(?P<host>[0-9a-fA-F:.]+)/(?P<prefix>\d{1,3})$')
_HOST_PATH = re.compile(r'^(?P<host>[^\s/:@]+)(?P<path>/[^\s]*)$')


def normalize(value):
    """Apply the shape normalisations. Returns (value, note)."""
    v = (value or "").strip()
    note = None
    if not v:
        return v, None

    # Trailing dot on an FQDN (evil.com.) — never meaningful for a lookup.
    if v.endswith('.') and len(v) > 1 and '.' in v[:-1] and not v[:-1].endswith('.'):
        v = v[:-1]

    # [ipv6] or [ipv6]:port
    m = _V6_BRACKET.match(v)
    if m and parse_ip(m.group('host')) is not None:
        if m.group('port'):
            note = "port %s ignored — looking up the address" % m.group('port')
        return m.group('host'), note

    # ip/prefix
    m = _CIDR.match(v)
    if m and parse_ip(m.group('host')) is not None:
        prefix = int(m.group('prefix'))
        ip = parse_ip(m.group('host'))
        maxp = 32 if ip.version == 4 else 128
        if prefix <= maxp:
            if prefix < maxp:
                note = "network /%d — looking up the address %s" % (prefix, ip)
            return str(ip), note

    # host:port — the host may be an IPv4 or a domain (a bare IPv6 literal
    # also matches host:port, so check the whole thing is not an address).
    m = _HOST_PORT.match(v)
    if m and parse_ip(v) is None:
        host = m.group('host')
        if parse_ip(host) is not None or looks_like_domain(host):
            return host, "port %s ignored — looking up the host" % m.group('port')

    # host/path without a scheme → a URL, so VirusTotal's path-specific
    # report is what runs.
    m = _HOST_PATH.match(v)
    if m and '://' not in v:
        host = m.group('host')
        if looks_like_domain(host) or (parse_ip(host) is not None and parse_ip(host).version == 4):
            return 'http://' + v, "no scheme — treated as http://"

    return v, note


_CGNAT = ipaddress.ip_network('100.64.0.0/10')


def _non_routable_kind(ip):
    """A short label when `ip` should not be sent to external services, else None."""
    if ip.is_loopback:
        return 'loopback address'
    if ip.is_link_local:
        return 'link-local address'
    if ip.is_multicast:
        return 'multicast address'
    if ip.is_unspecified:
        return 'unspecified address'
    if ip.version == 4 and ip in _CGNAT:
        return 'shared address space (CGNAT, RFC 6598)'
    if ip.is_reserved:
        return 'reserved address'
    if ip.is_private:
        return 'private (RFC1918) address' if ip.version == 4 else 'private (ULA / documentation) address'
    if not ip.is_global:
        return 'non-routable address'
    return None


def classify(value, is_lolbas=None, is_loldriver=None):
    """Classify a clipboard value. See the module docstring.

    `is_lolbas` / `is_loldriver` are optional predicates (the catalogues live
    in analyst_tool_lols; annotate.py doesn't load them and passes None).
    """
    v, note = normalize(value)
    if not v:
        return Classified(None, v, None)

    if re.match(hash_validation_regex, v):
        return Classified('hash', v.lower(), note)
    if re.match(port_wid_validation_regex, v):
        return Classified('port', v, note)
    # A URL is never a LOLBAS / LOLDriver name, even when its path ends in
    # .exe or .sys — http://evil.com/payload.exe must get the URL report.
    if '://' not in v:
        if is_lolbas is not None and is_lolbas(v):
            return Classified('lolbas', v, note)
        if is_loldriver is not None and is_loldriver(v):
            return Classified('loldriver', v, note)
    if re.match(cve_regex, v, re.IGNORECASE):
        return Classified('cve', v.upper(), note)

    ip = parse_ip(v)
    if ip is not None:
        what = _non_routable_kind(ip)
        if what:
            # Private, loopback, link-local, CGNAT, multicast, reserved…: not
            # worth an API call, and the old "RFC1918" label was wrong for
            # most of them — the note says what it actually is (a stripped
            # port is irrelevant here: nothing is looked up).
            return Classified('ip_private', str(ip), what)
        return Classified('ip', str(ip), note)

    if looks_like_domain(v):
        return Classified('domain', v.lower().rstrip('.'), note)
    if looks_like_url(v):
        return Classified('url', v, note)
    if re.match(mitre_regex, v.upper()):
        return Classified('mitre', v.upper(), note)
    if re.match(epoch_regex, v):
        return Classified('epoch', v, note)
    if re.match(otx_pulse_regex, v):
        return Classified('pulse', v, note)
    return Classified(None, v, note)


def note_target_type(value):
    """Indicator type for >>note / annotate.py targeting, or None when the
    value is not something notes can attach to."""
    c = classify(value)
    if c.kind in ANNOTATABLE:
        return 'ip' if c.kind == 'ip_private' else c.kind
    return None


def url_host(value):
    """Lowercase host of a URL, or '' — used by the exclusion check."""
    try:
        return (urlsplit(value).hostname or '').lower()
    except ValueError:
        return ''


# ── Several indicators in one paste ──────────────────────────────────────────

# Kinds a pasted block is triaged for. Private/non-routable IPs, ports, epochs,
# MITRE IDs, CVEs and file names are left out: they're either not worth an API
# call or are everywhere in alert bodies.
BATCH_KINDS = ('hash', 'ip', 'domain', 'url')

_TOKEN_SPLIT = re.compile(r'[\s,;|<>"\'`]+')


def extract_indicators(text, kinds=BATCH_KINDS):
    """Indicators found in free text (an alert body, a list, a report
    paragraph), normalised and de-duplicated, in the order they appear.
    Text should already be re-fanged."""
    found, seen = [], set()
    for raw in _TOKEN_SPLIT.split(text or ''):
        tok = raw.strip('()[]{}!?')
        if '=' in tok and '://' not in tok:        # key=value from log lines
            tok = tok.rsplit('=', 1)[-1]
        tok = tok.rstrip('.:')                      # sentence punctuation
        if len(tok) < 4:
            continue
        c = classify(tok)
        if c.kind not in kinds:
            continue
        key = (c.kind, c.value if c.kind == 'url' else c.value.lower())
        if key in seen:
            continue
        seen.add(key)
        found.append(c)
    return found
