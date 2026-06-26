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
