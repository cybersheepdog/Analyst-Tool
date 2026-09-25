"""Deadline, IPv6 classification and service-status plumbing in analyst.py.

analyst.py imports every service SDK, so these tests are skipped where the
full dependency stack isn't installed (the pure-logic suites still run).
"""
import time
import pytest

import analyst_tool_utilities as U

try:
    import analyst as A
except Exception as exc:                     # pragma: no cover
    A = None
    _why = str(exc)


def _need_analyst():
    if A is None:
        pytest.skip("analyst.py not importable here: " + _why)


# ── IPv6 ──────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("value,version", [
    ("2001:db8::1", 6), ("::1", 6), ("fe80::1", 6),
    ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 6),
    ("8.8.8.8", 4), (" 1.1.1.1 ", 4),
])
def test_parse_ip_accepts_real_addresses(value, version):
    ip = U.parse_ip(value)
    assert ip is not None and ip.version == version


@pytest.mark.parametrize("value", ["1:2:3:4:5:6:7", "evil.com", "8.8.8.8:443", "", None, "abc"])
def test_parse_ip_rejects_non_addresses(value):
    assert U.parse_ip(value) is None


def test_hostname_of_handles_ipv6_and_junk():
    assert U._hostname_of("2001:db8::1") == "2001:db8::1"     # was '2001'
    assert U._hostname_of("8.8.8.8") == "8.8.8.8"
    assert U._hostname_of("[abc") == ""                         # was ValueError
    assert U._hostname_of("https://Evil.com/x") == "evil.com"


def test_indicator_type_and_recognition_accept_ipv6():
    _need_analyst()
    assert A._indicator_type("2001:db8::1") == "ip"
    assert A._indicator_type("8.8.8.8") == "ip"
    assert A._is_recognized_indicator("2001:db8::1", {}, {}) is True
    assert A._is_recognized_indicator("fe80::1", {}, {}) is True


# ── deadline ──────────────────────────────────────────────────────────────────

def test_capture_stops_waiting_at_deadline(monkeypatch):
    _need_analyst()
    monkeypatch.setattr(A, "_deadline", lambda: 0.5)

    def _vt():
        print("VT-FAST")

    def _otx():
        time.sleep(3)
        print("OTX-LATE")

    t0 = time.time()
    texts, unavailable = A._run_parallel_capture([_vt, _otx])
    elapsed = time.time() - t0
    assert elapsed < 2.5                                   # did not wait for the sleeper
    assert "VT-FAST" in texts[0]
    assert "timed out" in texts[1] and "OTX-LATE" not in texts[1]
    assert unavailable == ["AlienVault OTX (timed out)"]


def test_service_error_and_not_found_status(monkeypatch):
    _need_analyst()
    monkeypatch.setattr(A, "_deadline", lambda: 5)

    def _vt():
        raise U.ServiceError("VirusTotal", 429, "Quota exceeded")

    def _shodan():
        print("\tNot found in Shodan")
        raise U.IndicatorNotFound("Shodan")

    def _abuseipdb():
        raise RuntimeError("boom")

    texts, unavailable = A._run_parallel_capture([_vt, _shodan, _abuseipdb])
    assert "[VirusTotal] unavailable: HTTP 429 — Quota exceeded" in texts[0]
    assert "Not found in Shodan" in texts[1]                # a not-found is a normal answer
    assert "[error in _abuseipdb]: boom" in texts[2]
    assert unavailable == ["VirusTotal (HTTP 429 — Quota exceeded)", "AbuseIPDB (error)"]


def test_run_with_verdict_reports_unavailable_and_does_not_rerun(monkeypatch, capsys):
    _need_analyst()
    monkeypatch.setattr(A, "_deadline", lambda: 5)
    calls = {"n": 0}

    def _vt():
        calls["n"] += 1
        print("VirusTotal Detections:\n\tMalicious: 0\n")

    def _abuseipdb():
        raise U.ServiceError("AbuseIPDB", 429, "rate limited")

    A._run_with_verdict("ip", [_vt, _abuseipdb], indicator="8.8.8.8")
    out = capsys.readouterr().out
    assert calls["n"] == 1                                  # never re-run
    assert "No strong reputation signals (incomplete)" in out
    assert "signals unavailable: AbuseIPDB (HTTP 429 — rate limited)" in out
