import analyst_tool_verdict as V


def _plain(itype, txt):
    return V.strip_ansi(V.build_verdict(itype, txt))


def test_ip_malicious():
    txt = ("VirusToal Detections:\n\tMalicious: 12\n"
           "Abuse Confidence Score: 97%\n"
           "VPN Provider: Yes\nDatacenter/Hosting: Yes\n")
    v = _plain("ip", txt)
    assert "Likely malicious" in v
    assert "VirusTotal 12 malicious" in v
    assert "AbuseIPDB 97%" in v
    assert "VPN egress" in v and "datacenter-hosted" in v


def test_ip_suspicious_then_clean():
    sus = _plain("ip", "VirusToal Detections:\n\tMalicious: 2\n")
    assert "Suspicious" in sus
    clean = _plain("ip", "VirusToal Detections:\n\tMalicious: 0\nTOR Exit Node: No\n")
    assert "No strong reputation signals" in clean


def test_ip_cobalt_strike():
    v = _plain("ip", "Cobalt Strike Beacon: Yes\n")
    assert "Likely malicious" in v and "Cobalt Strike beacon" in v


def test_hash_and_domain():
    h = _plain("hash", "File Reputation:\n\tMalicious: 2\n\tSuspicious: 0\n")
    assert "VirusTotal 2 malicious" in h and "Suspicious" in h
    d = _plain("domain", "Last Analysis Stats:\n\tMalicious: 8\nRelated Pulses: 5\n")
    assert "Likely malicious" in d and "OTX 5 pulses" in d
