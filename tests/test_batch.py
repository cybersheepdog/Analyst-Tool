"""Several indicators in one paste: extraction and the triage table."""
import importlib
import sys

import pytest

import analyst_tool_classify as C


@pytest.fixture(autouse=True)
def _real_validators(monkeypatch):
    stub = sys.modules.pop("validators", None)
    try:
        real = importlib.import_module("validators")
    finally:
        if stub is not None:
            sys.modules["validators"] = stub
    monkeypatch.setattr(C, "validators", real)
    monkeypatch.setattr(C, "_HAS_CONSIDER_TLD", None)


ALERT = """Alert 4471: Outbound beacon
src_ip=10.0.0.5 dst_ip=45.145.66.165 dst_port=443
Host: evil.com (also seen: evil.com., cdn.evil.com)
Payload hash 44D88612FEA8A8F36DE82E1278ABB02F dropped as report.docx
Callback: https://evil.com/gate.php?id=7, see T1071 and CVE-2024-3400
"""


def test_extract_indicators_from_an_alert():
    found = C.extract_indicators(ALERT)
    got = [(c.kind, c.value) for c in found]
    assert got == [
        ("ip", "45.145.66.165"),
        ("domain", "evil.com"),
        ("domain", "cdn.evil.com"),
        ("hash", "44d88612fea8a8f36de82e1278abb02f"),
        ("url", "https://evil.com/gate.php?id=7"),
    ]
    # left out: private IP, port, file name, MITRE ID, CVE, duplicate evil.com.


def test_extract_list_of_ips_dedupes():
    found = C.extract_indicators("8.8.8.8\n1.1.1.1\n8.8.8.8\n9.9.9.9")
    assert [c.value for c in found] == ["8.8.8.8", "1.1.1.1", "9.9.9.9"]


def test_run_batch_prints_one_line_each_and_keeps_full_reports(monkeypatch, capsys):
    A = pytest.importorskip("analyst")
    seen = []

    def fake_lookup(kind, value, cache, force_refresh=False):
        seen.append(value)
        print("\x1b[31m\x1b[1mVERDICT: Likely malicious — VirusTotal 9 malicious\x1b[0m")
        print("FULL REPORT FOR " + value)

    monkeypatch.setattr(A, "_lookup_one", fake_lookup)
    monkeypatch.setattr(A, "get_batch_max_from_config", lambda: 2)

    class _Cache:
        def get_exclusions(self):
            return ["cdn.evil.com"]
    monkeypatch.setitem(A._SERVICES, "excluded_domains", [])

    found = C.extract_indicators(ALERT)
    last = A._run_batch(found, _Cache())
    out = capsys.readouterr().out
    assert seen == ["45.145.66.165", "evil.com"]                 # capped at 2
    assert "BATCH: 2 indicators (of 4 found)" in out            # cdn.evil.com excluded
    assert "FULL REPORT" not in out                              # captured, not printed
    assert "  1  ip" in out and "Likely malicious" in out
    assert "2 more — >>batch next" in out
    assert last == ("evil.com", "domain")

    # >>full 2 prints the stored report; >>batch next continues numbering
    assert A._handle_command("full 2", _Cache(), None) == ("evil.com", "domain")
    assert "FULL REPORT FOR evil.com" in capsys.readouterr().out
    A._handle_command("batch next", _Cache(), None)
    out = capsys.readouterr().out
    assert "  3  hash" in out and "  4  url" in out
    assert seen[2:] == ["44d88612fea8a8f36de82e1278abb02f", "https://evil.com/gate.php?id=7"]
    A._handle_command("full 9", _Cache(), None)
    assert "No batch row 9" in capsys.readouterr().out
