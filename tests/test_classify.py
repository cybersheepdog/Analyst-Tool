"""classify() — the one indicator classifier (analyst_tool_classify)."""
import importlib
import sys

import pytest

import analyst_tool_classify as C
from analyst_tool_classify import classify, normalize, looks_like_domain, note_target_type


@pytest.fixture(autouse=True)
def _real_validators(monkeypatch):
    """conftest stubs `validators` (domain/url always False) so the other
    suites run without it; the classifier's tests need the real package."""
    stub = sys.modules.pop("validators", None)
    try:
        real = importlib.import_module("validators")
    except ImportError:
        real = None
    finally:
        if stub is not None:
            sys.modules["validators"] = stub
    if real is None or not hasattr(real, "ValidationError"):
        pytest.skip("validators package not installed")
    monkeypatch.setattr(C, "validators", real)
    monkeypatch.setattr(C, "_HAS_CONSIDER_TLD", None)


def _k(value, **kw):
    return classify(value, **kw).kind


# ── shapes analysts copy from logs ───────────────────────────────────────────

@pytest.mark.parametrize("value,kind,norm,note_has", [
    ("8.8.8.8:443",        "ip",     "8.8.8.8",              "port 443"),
    ("evil.com:8080",      "domain", "evil.com",             "port 8080"),
    ("evil.com.",          "domain", "evil.com",             None),
    ("EVIL.COM",           "domain", "evil.com",             None),
    ("8.8.8.8/32",         "ip",     "8.8.8.8",              None),
    ("45.145.66.0/23",     "ip",     "45.145.66.0",          "network /23"),
    ("evil.com/login",     "url",    "http://evil.com/login", "no scheme"),
    ("1.2.3.4/admin.php",  "url",    "http://1.2.3.4/admin.php", "no scheme"),
    ("https://evil.com/x", "url",    "https://evil.com/x",   None),
    ("[2001:db8::1]:443",  "ip_private", "2001:db8::1",      "documentation"),
    ("2606:4700::1111",    "ip",     "2606:4700::1111",      None),
    ("2606:4700:0000:0000:0000:0000:0000:1111", "ip", "2606:4700::1111", None),
    ("cve-2021-44228",     "cve",    "CVE-2021-44228",       None),
    ("t1059",              "mitre",  "T1059",                None),
    ("T1059.001",          "mitre",  "T1059.001",            None),
    ("44D88612FEA8A8F36DE82E1278ABB02F", "hash", "44d88612fea8a8f36de82e1278abb02f", None),
    ("1700000000",         "epoch",  "1700000000",           None),
    ("443",                "port",   "443",                  None),
])
def test_classify_and_normalise(value, kind, norm, note_has):
    c = classify(value)
    assert c.kind == kind
    assert c.value == norm
    if note_has:
        assert c.note and note_has in c.note
    else:
        assert c.note is None


# ── non-routable IPs get the right label, not "RFC1918" for everything ──────

@pytest.mark.parametrize("value,label", [
    ("10.0.0.5", "RFC1918"), ("127.0.0.1", "loopback"), ("169.254.1.1", "link-local"),
    ("100.64.1.1", "CGNAT"), ("224.0.0.1", "multicast"), ("0.0.0.0", "unspecified"),
    ("255.255.255.255", "reserved"), ("fe80::1", "link-local"), ("::1", "loopback"),
])
def test_non_routable_ips(value, label):
    c = classify(value)
    assert c.kind == "ip_private" and label in c.note


# ── file names are not domains ───────────────────────────────────────────────

@pytest.mark.parametrize("value", [
    "report.docx", "kernel32.dll", "readme.md", "script.py", "config.ini",
    "Invoice.pdf", "first.last", "Microsoft.Windows.ShellExperienceHost",
])
def test_filenames_and_dotted_words_are_not_domains(value):
    assert _k(value) is None


@pytest.mark.parametrize("value", ["evil.com", "www.google.com", "update.zip", "evil.sh", "sub.domain.co.uk"])
def test_real_domains_still_pass(value):
    assert _k(value) == "domain"


def test_lolbas_predicate_runs_before_domain_and_is_case_insensitive():
    seen = []
    pred = lambda v: seen.append(v) or v.lower() == "certutil.exe"
    assert _k("certutil.exe", is_lolbas=pred) == "lolbas"
    assert _k("Certutil.exe", is_lolbas=pred) == "lolbas"
    assert _k("evil.com", is_lolbas=pred) == "domain"


# ── note targeting ────────────────────────────────────────────────────────────

def test_note_target_type():
    assert note_target_type("8.8.8.8") == "ip"
    assert note_target_type("10.0.0.5") == "ip"
    assert note_target_type("2001:db8::1") == "ip"
    assert note_target_type("evil.com") == "domain"
    assert note_target_type("CVE-2024-3400") == "cve"
    assert note_target_type("44d88612fea8a8f36de82e1278abb02f") == "hash"
    assert note_target_type("T1059") is None
    assert note_target_type("443") is None
    assert note_target_type("still works") is None


def test_junk_and_empty():
    assert classify("").kind is None
    assert classify(None).kind is None
    assert classify("[abc").kind is None
    assert classify("not an indicator").kind is None
    assert normalize("  ") == ("", None)
