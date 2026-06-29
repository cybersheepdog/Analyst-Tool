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


def test_opencti_drives_verdict():
    link = "\thttps://octi/dashboard/observations/indicators/abc\n"
    # OpenCTI high score -> malicious even when VT is clean
    r = _plain("ip", "OpenCTI Info: X\n\tMalicious: 90\n" + link +
               "VirusToal Detections:\n\tMalicious: 0\n")
    assert "Likely malicious" in r and "OpenCTI 90/100" in r

    # OpenCTI block is bounded -> does NOT mistake VT's count (14) for the score
    r2 = _plain("ip", "OpenCTI Info: X\n\tMalicious: 60\n" + link +
                "VirusToal Detections:\n\tMalicious: 14\n")
    assert "OpenCTI 60/100" in r2 and "VirusTotal 14 malicious" in r2

    # 'Not found' / low score do not contribute
    r3 = _plain("ip", "OpenCTI Info: X\nX Not found in OpenCTI\n"
                "VirusToal Detections:\n\tMalicious: 14\n")
    assert "OpenCTI" not in r3 and "VirusTotal 14 malicious" in r3
    r4 = _plain("ip", "VirusToal Detections:\n\tMalicious: 0\n"
                "OpenCTI Info: X\n\tMalicious: 20\n" + link)
    assert "No strong reputation signals" in r4
