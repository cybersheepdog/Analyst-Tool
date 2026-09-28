"""VirusTotal detection counts come from last_analysis_stats (categories),
not from counting result strings that happen to equal 'malicious'."""
import io
import sys

import analyst_tool_virus_total as VT
from analyst_tool_verdict import build_verdict, strip_ansi


def _resp(results, stats=None):
    attrs = {"last_analysis_results": results}
    if stats is not None:
        attrs["last_analysis_stats"] = stats
    return {"data": {"attributes": attrs}}


EIGHT_MALWARE = {("E%d" % i): {"engine_name": "Engine%d" % i, "category": "malicious",
                               "result": "malware"} for i in range(8)}
EIGHT_MALWARE["Clean1"] = {"engine_name": "Clean1", "category": "harmless", "result": "clean"}


def _out(fn, *a):
    buf = io.StringIO(); real = sys.stdout; sys.stdout = buf
    try:
        fn(*a)
    finally:
        sys.stdout = real
    return strip_ansi(buf.getvalue())


def test_malware_results_count_as_malicious():
    stats = {"malicious": 8, "suspicious": 0, "harmless": 1, "undetected": 70, "timeout": 0}
    out = _out(VT.print_ip_detections, _resp(EIGHT_MALWARE, stats))
    assert "Malicious:" in out and " 8" in out.split("Malicious:")[1].splitlines()[0]
    assert "Malware:" in out and "8" in out.split("Malware:")[1].splitlines()[0]
    assert "Undetected:               70" in out
    assert "Flagged by:" in out and "Engine0: malware" in out and "(+3 more)" in out
    # and the verdict now sees it (it was "No strong reputation signals" before)
    v = strip_ansi(build_verdict("ip", "VirusTotal Detections:\n" + out))
    assert "Likely malicious" in v and "VirusTotal 8 malicious" in v


def test_falls_back_to_categories_without_stats():
    out = _out(VT.print_domain_detections, _resp(EIGHT_MALWARE))
    assert "8" in out.split("Malicious:")[1].splitlines()[0]
    assert "1" in out.split("Clean:")[1].splitlines()[0]


def test_clean_address_has_no_flagged_line():
    clean = {"A": {"engine_name": "A", "category": "harmless", "result": "clean"}}
    out = _out(VT.print_ip_detections, _resp(clean, {"malicious": 0, "harmless": 1}))
    assert "Flagged by" not in out
    assert "0" in out.split("Malicious:")[1].splitlines()[0]
