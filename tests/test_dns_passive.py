"""[DNS] active_resolution: passive by default — no live queries."""
import io
import sys

import pytest

import analyst_tool_dns as D
import analyst_tool_utilities as U


def _out(fn, *a, **k):
    buf = io.StringIO(); real = sys.stdout; sys.stdout = buf
    try:
        fn(*a, **k)
    finally:
        sys.stdout = real
    return U.color and __import__("analyst_tool_verdict").strip_ansi(buf.getvalue())


@pytest.fixture
def passive(monkeypatch):
    monkeypatch.setattr(U, "_dns_active_cache", False)
    monkeypatch.setattr(D, "dns_active_resolution", lambda: False)
    monkeypatch.setattr(D, "get_crt_subdomains", lambda d: ([], 0))
    calls = []
    for name in ("resolve_addresses", "reverse_ptr", "_dns_records"):
        monkeypatch.setattr(D, name, lambda *a, _n=name: calls.append(_n) or [])
    return calls


def test_default_is_passive(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.ini").write_text("[GENERAL]\nssl_verify = true\n")
    monkeypatch.setattr(U, "_dns_active_cache", None)
    assert U.dns_active_resolution() is False
    (tmp_path / "config.ini").write_text("[DNS]\nactive_resolution = true\n")
    monkeypatch.setattr(U, "_dns_active_cache", None)
    assert U.dns_active_resolution() is True


def test_passive_mode_makes_no_live_queries_and_uses_otx(passive, monkeypatch):
    import analyst_tool_otx as O
    monkeypatch.setattr(O, "_otx_section", lambda otx, t, v, s: {"passive_dns": [
        {"address": "1.2.3.4", "record_type": "A", "hostname": "evil.com",
         "first": "2026-01-01T00:00:00", "last": "2026-09-01T00:00:00"},
        {"address": "5.6.7.8", "record_type": "A", "hostname": "www.evil.com",
         "first": "2025-01-01T00:00:00", "last": "2025-02-01T00:00:00"}]})
    out = _out(D.print_dns_and_crt, "evil.com", otx=object())
    assert passive == []                                   # nothing live
    assert "Live resolution:" in out and "off (passive mode" in out
    assert "Passive DNS (OTX):" in out and "2 records" in out
    assert out.index("1.2.3.4") < out.index("5.6.7.8")      # newest first
    assert "via www[.]evil[.]com" in out
    assert "DNS & Certificate Transparency:" in out         # verdict boundary kept


def test_passive_without_otx(passive):
    out = _out(D.print_dns_and_crt, "evil.com")
    assert "OTX not configured" in out and passive == []


def test_passive_none_recorded(passive, monkeypatch):
    import analyst_tool_otx as O
    monkeypatch.setattr(O, "_otx_section", lambda *a: {"passive_dns": []})
    out = _out(D.print_dns_and_crt, "evil.com", otx=object())
    assert "none recorded" in out


def test_active_mode_still_resolves(monkeypatch):
    monkeypatch.setattr(D, "dns_active_resolution", lambda: True)
    monkeypatch.setattr(D, "get_crt_subdomains", lambda d: ([], 0))
    monkeypatch.setattr(D, "resolve_addresses", lambda d: ["9.9.9.9"])
    monkeypatch.setattr(D, "reverse_ptr", lambda ip: "dns9.quad9.net")
    out = _out(D.print_dns_and_crt, "evil.com")
    assert "9.9.9.9  (dns9.quad9.net)" in out and "passive" not in out


def test_vpn_check_skips_ptr_in_passive_mode(monkeypatch):
    called = []
    monkeypatch.setattr(U, "resolve_ptr", lambda *a, **k: called.append(a) or None)
    monkeypatch.setattr(U, "is_vpn_ip", lambda ip: False)
    monkeypatch.setattr(U, "_dns_active_cache", False)
    _out(U.check_vpn, "8.8.8.8")
    assert called == []
    monkeypatch.setattr(U, "_dns_active_cache", True)
    _out(U.check_vpn, "8.8.8.8")
    assert len(called) == 1
