import analyst_tool_utilities as u


def test_refang_scheme():
    assert u.refang("hxxps://evil[.]com") == "https://evil.com"
    assert u.refang("hxxp://e[.]com") == "http://e.com"


def test_refang_dots():
    assert u.refang("8[.]8[.]8[.]8") == "8.8.8.8"
    assert u.refang("bad(dot)domain(dot)com") == "bad.domain.com"
    assert u.refang("evil dot com") == "evil.com"


def test_refang_at():
    assert u.refang("user[at]evil[.]com") == "user@evil.com"
    assert u.refang("user[@]evil[.]com") == "user@evil.com"


def test_refang_passthrough():
    assert u.refang("8.8.8.8") == "8.8.8.8"
    assert u.refang("example.com") == "example.com"
    assert u.refang("https://good.com/path") == "https://good.com/path"
    assert u.refang("") == ""
    assert u.refang(None) is None


# ── 2026-09-26: scheme-only hxxp; spelled-out dots need a real TLD ──────────

def test_refang_hxxp_only_as_scheme():
    assert u.refang("HXXPS://evil[.]com") == "https://evil.com"
    assert u.refang("hxxp[:]//evil[.]com") == "http://evil.com"
    assert u.refang("https://x.com/shxxpell") == "https://x.com/shxxpell"


def test_refang_spelled_dots_need_a_tld(monkeypatch):
    import importlib, sys
    import analyst_tool_classify as C
    stub = sys.modules.pop("validators", None)
    try:
        real = importlib.import_module("validators")
    finally:
        if stub is not None:
            sys.modules["validators"] = stub
    monkeypatch.setattr(C, "validators", real)
    monkeypatch.setattr(C, "_HAS_CONSIDER_TLD", None)
    assert u.refang("evil dot com") == "evil.com"
    assert u.refang("mail dot evil dot co dot uk") == "mail.evil.co.uk"
    assert u.refang("contact alice dot smith today") == "contact alice dot smith today"
