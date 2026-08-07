"""Tests for the >>report export (analyst_tool_report)."""
import io
import os
import re
import sys
import tempfile

import analyst_tool_report as R


def _buf(**over):
    cfg = {"dir": tempfile.mkdtemp(), "format": "markdown",
           "defang": True, "max_kept": 20}
    cfg.update(over)
    return R.ReportBuffer(cfg)


def _grab(fn, *args, **kwargs):
    old = sys.stdout
    sys.stdout = io.StringIO()
    try:
        result = fn(*args, **kwargs)
        out = sys.stdout.getvalue()
    finally:
        sys.stdout = old
    return result, re.sub(r'\x1b\[[0-9;]*m', '', out)


SAMPLE_IP = ("VERDICT: Likely malicious — VirusTotal 12 malicious\n"
             "\nVirusTotal:\n\tMalicious: 12\n"
             "\thttps://www.virustotal.com/gui/ip-address/45.145.66.165\n")


# ── defang helpers ───────────────────────────────────────────────────────────

def test_defang_indicator():
    assert R.defang_indicator("45.145.66.165") == "45[.]145[.]66[.]165"
    assert R.defang_indicator("evil.com") == "evil[.]com"
    assert R.defang_indicator("https://evil.com/x") == "hxxps://evil[.]com/x"
    assert R.defang_indicator("HTTP://evil.com") == "HxxP://evil[.]com" or \
        "xx" in R.defang_indicator("HTTP://evil.com")


def test_defang_text_only_touches_indicators():
    text = "score 8.8 on 2026-07-10 for 45.145.66.165 (e.g. bad)"
    out = R.defang_text(text, ["45.145.66.165"])
    assert "45[.]145[.]66[.]165" in out
    assert "score 8.8" in out            # unrelated dots untouched
    assert "2026-07-10" in out
    assert "e.g." in out


def test_defang_text_neutralizes_schemes():
    out = R.defang_text("see https://other.example/path", [])
    assert out.startswith("see hxxps://")


def test_safe_filename():
    assert R._safe_filename("45.145.66.165") == "45.145.66.165"
    frag = R._safe_filename("https://evil.com/a?b=c")
    assert "/" not in frag and "?" not in frag and not frag.startswith("http")
    assert len(R._safe_filename("x" * 200)) <= 60


# ── record / export ──────────────────────────────────────────────────────────

def test_export_writes_markdown_file():
    b = _buf()
    b.record("45.145.66.165", "ip", SAMPLE_IP)
    path, out = _grab(b.export, "", username="alice")
    assert path and os.path.exists(path)
    assert "[+] Report (1 lookup) saved" in out
    doc = open(path, encoding="utf-8").read()
    assert doc.startswith("# Analyst Tool Report")
    assert "Analyst: alice" in doc
    assert "## 45[.]145[.]66[.]165 (ip)" in doc
    assert "```text" in doc
    assert "VERDICT: Likely malicious" in doc
    assert "45.145.66.165" not in doc          # everything defanged
    assert "hxxps://www.virustotal.com" in doc  # scheme neutralized
    assert path.endswith(".md")


def test_export_plain_text_no_defang():
    b = _buf(format="text", defang=False)
    b.record("45.145.66.165", "ip", SAMPLE_IP)
    path, _ = _grab(b.export, "", username="bob")
    doc = open(path, encoding="utf-8").read()
    assert doc.startswith("ANALYST TOOL REPORT")
    assert "45.145.66.165" in doc and "45[.]145" not in doc
    assert "```" not in doc
    assert path.endswith(".txt")


def test_export_last_n_oldest_first():
    b = _buf()
    b.record("1.1.1.1", "ip", "VERDICT: a\nreport one\n")
    b.record("evil.com", "domain", "VERDICT: b\nreport two\n")
    b.record("2.2.2.2", "ip", "VERDICT: c\nreport three\n")
    path, out = _grab(b.export, "2", username="alice")
    assert "(2 lookups)" in out
    doc = open(path, encoding="utf-8").read()
    assert "1.1.1.1" not in doc and "1[.]1[.]1[.]1" not in doc
    assert doc.index("evil[.]com") < doc.index("2[.]2[.]2[.]2")  # oldest first
    assert "_2.2.2.2" in os.path.basename(path)  # named after newest


def test_export_empty_buffer():
    b = _buf()
    path, out = _grab(b.export, "", username="alice")
    assert path is None
    assert "Nothing to export yet" in out


def test_buffer_bounded_and_ansi_stripped():
    b = _buf(max_kept=3)
    for i in range(5):
        b.record("10.0.0.%d" % i, "ip", "\x1b[31mreport %d\x1b[0m\n" % i)
    assert len(b) == 3
    path, _ = _grab(b.export, "3", username="a")
    doc = open(path, encoding="utf-8").read()
    assert "\x1b[" not in doc
    assert "report 2" in doc and "report 1" not in doc


def test_record_report_hook_never_raises():
    R.record_report(None, "ip", None)      # bad input is a no-op
    R.record_report("", "ip", "")


def test_config_defaults(tmp_path=None):
    cfg = R.get_report_config_from_config("nonexistent.ini")
    assert cfg["dir"] == "reports"
    assert cfg["format"] == "markdown"
    assert cfg["defang"] is True
    assert cfg["max_kept"] == 20
