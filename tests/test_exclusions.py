import analyst_tool_utilities as u


def test_hostname_of():
    assert u._hostname_of("https://a.b.com/x?y=1") == "a.b.com"
    assert u._hostname_of("a.b.com") == "a.b.com"
    assert u._hostname_of("HTTP://A.COM/Path") == "a.com"
    assert u._hostname_of("") == ""


def test_is_excluded_domain():
    ex = ["ultimatewindowssecurity.com", "speedguide.net"]
    # exact + subdomain + full URL all match
    assert u.is_excluded_domain("ultimatewindowssecurity.com", ex)
    assert u.is_excluded_domain("www.ultimatewindowssecurity.com", ex)
    assert u.is_excluded_domain(
        "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4625", ex)
    assert u.is_excluded_domain("https://speedguide.net/port.php?port=4444", ex)
    # non-matches
    assert not u.is_excluded_domain("example.com", ex)
    assert not u.is_excluded_domain("notultimatewindowssecurity.com", ex)   # not a subdomain
    assert not u.is_excluded_domain("ultimatewindowssecurity.com.evil.com", ex)  # suffix trick
    assert not u.is_excluded_domain("anything", [])


def test_config_parse(tmp_path):
    cfg = tmp_path / "config.ini"
    cfg.write_text("[EXCLUSIONS]\ndomains = A.com , .b.net,, c.org\n")
    got = u.get_excluded_domains_from_config(str(cfg))
    assert got == ["a.com", "b.net", "c.org"]
