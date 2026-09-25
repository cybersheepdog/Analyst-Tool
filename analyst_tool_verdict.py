# Analyst Tool — one-line verdict
#
# Builds a single summary line for the top of a report by scanning the report's
# own (already-rendered) text for the key signals. This keeps it decoupled: it
# needs no changes to the individual service modules, and if a signal isn't
# present (service not configured, etc.) it's simply skipped.

import re

from analyst_tool_utilities import color

_ANSI = re.compile(r'\x1b\[[0-9;]*m')


def strip_ansi(text):
    return _ANSI.sub('', text or '')


# Every service section starts with one of these header fragments. A number is
# only ever read from inside its own service's block — from the anchor to the
# next header — so OpenCTI's "Malicious: 40" (a 0-100 score) can never be
# mistaken for VirusTotal's "Malicious: 40" (an engine count), whatever order
# the sections finished in.
_SECTION_HEADERS = (
    'VirusTotal Detections:', 'VirusToal Detections:',      # IP (old typo kept for cached rows)
    'VirusTotal Hash Report for', 'File Reputation:',
    'Domain Reputation for', 'Last Analysis Stats:',
    'VirusTotal URL Report for:',
    'OpenCTI Info:',
    'Abuse IP DB:',
    'AlienVault OTX',
    'Shodan IP Results for:', ' Shodan:',
    'IP Information:',
    'DNS & Certificate Transparency:', 'C2 Live', '*** TEAM NOTES', '*** MULTI-USER NOTICE',
)


def _block(text, anchor):
    """Return the text from `anchor` up to the next service header, or None
    when the anchor is absent. Never falls back to the whole report."""
    i = text.find(anchor)
    if i < 0:
        return None
    start = i + len(anchor)
    end = len(text)
    for h in _SECTION_HEADERS:
        j = text.find(h, start)
        if 0 <= j < end:
            end = j
    return text[i:end]


def _int_after(text, anchor, label):
    """Return the first integer after `label` inside `anchor`'s own block.
    None when the anchor is missing, the block says the indicator was not
    found, or the label does not occur in that block."""
    block = _block(text, anchor)
    if block is None:
        return None
    if 'not found in virustotal' in block.lower():
        return None
    m = re.search(re.escape(label) + r'\s*(\d+)', block)
    return int(m.group(1)) if m else None


def _opencti_score(text):
    """Return OpenCTI's malicious score (0-100) for a real hit, else None.

    Bounded to the OpenCTI block (its header to the next section header or
    its dashboard link) so VirusTotal's malicious *count* is never picked up.
    'Not found' / 'not configured' OpenCTI sections yield None.
    """
    block = _block(text, 'OpenCTI Info:')
    if block is None:
        return None
    end = block.find('/dashboard/observations/indicators/')
    if end >= 0:
        block = block[:end]
    low = block.lower()
    if 'not found in opencti' in low or 'not configured' in low:
        return None
    m = re.search(r'Malicious:\s*(\d+)', block)
    return int(m.group(1)) if m else None


# Services whose absence makes a "no signals" verdict unreliable.
_REPUTATION_SERVICES = ('VirusTotal', 'AbuseIPDB', 'AlienVault OTX', 'OpenCTI', 'C2Live')


def build_verdict(indicator_type, raw_text, unavailable=None):
    """Return a one-line, colour-coded verdict string for a report.

    Severity: 2 = likely malicious (red), 1 = suspicious (orange),
    0 = no strong reputation signals (plain).

    `unavailable` lists services that failed or timed out, as
    "Service (reason)" strings; they are appended to the line, and a
    severity-0 verdict is marked "(incomplete)" when a reputation source is
    among them, so silence is never read as "clean".
    """
    text = strip_ansi(raw_text)
    unavailable = list(unavailable or [])
    reasons = []     # drive severity
    context = []     # descriptive flags (VPN/Tor/datacenter/pulses)
    severity = 0

    def bump(level):
        nonlocal severity
        if level > severity:
            severity = level

    if indicator_type == 'ip':
        vt = _int_after(text, 'Detections:', 'Malicious:')
        if vt:
            reasons.append("VirusTotal %d malicious" % vt)
            bump(2 if vt >= 5 else 1)

        m = re.search(r'Abuse Confidence Score:\s*(\d+)%', text)
        if m:
            score = int(m.group(1))
            if score >= 40:
                reasons.append("AbuseIPDB %d%%" % score)
                bump(2 if score >= 70 else 1)

        if re.search(r'Cobalt Strike Beacon:\s*Yes', text):
            reasons.append("Cobalt Strike beacon")
            bump(2)

        if re.search(r'TOR Exit Node:\s*Yes', text):
            context.append("Tor exit node")
        if re.search(r'VPN Provider:\s*Yes', text):
            context.append("VPN egress")
        if re.search(r'Datacenter/Hosting:\s*Yes', text):
            context.append("datacenter-hosted")

    elif indicator_type in ('domain', 'url'):
        anchor = 'Last Analysis Stats:' if indicator_type == 'domain' else 'URL Report for:'
        vt = _int_after(text, anchor, 'Malicious:')
        if vt:
            reasons.append("VirusTotal %d malicious" % vt)
            bump(2 if vt >= 5 else 1)
        m = re.search(r'Related Pulses:\s*(\d+)', text)
        if m and int(m.group(1)) > 0:
            context.append("OTX %s pulses" % m.group(1))

    elif indicator_type == 'hash':
        vt = _int_after(text, 'File Reputation:', 'Malicious:')
        sus = _int_after(text, 'File Reputation:', 'Suspicious:')
        if vt:
            reasons.append("VirusTotal %d malicious" % vt)
            bump(2 if vt >= 5 else 1)
        elif sus:
            reasons.append("VirusTotal %d suspicious" % sus)
            bump(1)

    # OpenCTI — your org's own intel (applies to every indicator type). Its
    # malicious score is 0-100; thresholds mirror the OpenCTI module's colouring.
    octi = _opencti_score(text)
    if octi is not None and octi >= 50:
        reasons.append("OpenCTI %d/100" % octi)
        bump(2 if octi >= 75 else 1)

    if severity == 2:
        label, c = "Likely malicious", color.RED
    elif severity == 1:
        label, c = "Suspicious", color.ORANGE
    else:
        label, c = "No strong reputation signals", None
        if any(u.startswith(svc) for u in unavailable for svc in _REPUTATION_SERVICES):
            label += " (incomplete)"

    parts = reasons + context
    if unavailable:
        parts.append("signals unavailable: " + ", ".join(unavailable))
    detail = (" — " + "; ".join(parts)) if parts else ""
    line = "VERDICT: " + label + detail
    if c:
        return c + color.BOLD + line + color.END
    return color.BOLD + line + color.END
