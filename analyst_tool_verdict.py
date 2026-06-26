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


def _int_after(text, anchor, label):
    """Return the first integer after `label` that appears at/after `anchor`."""
    i = text.find(anchor)
    segment = text[i:] if i >= 0 else text
    m = re.search(re.escape(label) + r'\s*(\d+)', segment)
    return int(m.group(1)) if m else None


def build_verdict(indicator_type, raw_text):
    """Return a one-line, colour-coded verdict string for a report.

    Severity: 2 = likely malicious (red), 1 = suspicious (orange),
    0 = no strong reputation signals (plain).
    """
    text = strip_ansi(raw_text)
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

    if severity == 2:
        label, c = "Likely malicious", color.RED
    elif severity == 1:
        label, c = "Suspicious", color.ORANGE
    else:
        label, c = "No strong reputation signals", None

    parts = reasons + context
    detail = (" — " + "; ".join(parts)) if parts else ""
    line = "VERDICT: " + label + detail
    if c:
        return c + color.BOLD + line + color.END
    return color.BOLD + line + color.END
