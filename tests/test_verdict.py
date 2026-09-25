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


# ── bounded scrape: each service's numbers come only from its own block ─────

def test_hash_not_found_in_vt_does_not_borrow_opencti_score():
    link = "\thttps://octi/dashboard/observations/indicators/abc\n"
    txt = ("VirusTotal Hash Report for abc:\nFile Reputation:\n"
           "\tFile hash not found in VirusTotal\n"
           "OpenCTI Info:\n\tMalicious:    40\n\tConfidence:   70\n" + link)
    v = _plain("hash", txt)
    assert "VirusTotal" not in v                      # was "VirusTotal 40 malicious"
    assert "No strong reputation signals" in v         # 40 < OpenCTI's own threshold

    txt2 = txt.replace("Malicious:    40", "Malicious:    85")
    v2 = _plain("hash", txt2)
    assert "OpenCTI 85/100" in v2 and "VirusTotal" not in v2


def test_missing_vt_anchor_never_scans_whole_report():
    link = "\thttps://octi/dashboard/observations/indicators/abc\n"
    # No VT section at all (task errored) — the only "Malicious:" is OpenCTI's
    txt = "OpenCTI Info:\n\tMalicious: 30\n" + link + "Abuse IP DB:\n\tTotal Reports: 3\n"
    v = _plain("domain", txt)
    assert "VirusTotal" not in v and "No strong reputation signals" in v


def test_vt_block_is_bounded_by_next_section_header():
    # VT section first, then OpenCTI: VT's count must be read, not OpenCTI's
    link = "\thttps://octi/dashboard/observations/indicators/abc\n"
    txt = ("VirusTotal Detections:\n\tMalicious: 0\n\tClean: 70\n"
           "OpenCTI Info:\n\tMalicious: 90\n" + link)
    v = _plain("ip", txt)
    assert "VirusTotal" not in v                      # 0 → no VT reason
    assert "OpenCTI 90/100" in v and "Likely malicious" in v


def test_unavailable_signals_are_reported():
    txt = "VirusTotal Detections:\n\tMalicious: 0\n"
    v = V.strip_ansi(V.build_verdict("ip", txt,
                                     unavailable=["AbuseIPDB (timed out)"]))
    assert "No strong reputation signals (incomplete)" in v
    assert "signals unavailable: AbuseIPDB (timed out)" in v
    # A non-reputation service missing does not mark the verdict incomplete
    v2 = V.strip_ansi(V.build_verdict("ip", txt, unavailable=["WhoIs/Tor/VPN (timed out)"]))
    assert "(incomplete)" not in v2 and "signals unavailable" in v2
    # A real detection is still a real detection
    v3 = V.strip_ansi(V.build_verdict("ip", "VirusTotal Detections:\n\tMalicious: 9\n",
                                      unavailable=["AbuseIPDB (HTTP 429)"]))
    assert "Likely malicious" in v3 and "(incomplete)" not in v3
