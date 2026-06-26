import requests
import analyst_tool_utilities as u


class FakeSession:
    def __init__(self, fail_ssl=False):
        self.calls = []
        self.fail_ssl = fail_ssl

    def get(self, url, **kwargs):
        self.calls.append(kwargs.get("verify", "DEFAULT"))
        if self.fail_ssl and kwargs.get("verify") is True:
            raise requests.exceptions.SSLError("handshake failed")
        return "OK"


def test_verify_default_unchanged():
    u._ssl_verify_cache = True
    s = FakeSession()
    assert u.session_get(s, "http://x", headers={"a": "b"}) == "OK"
    assert s.calls == ["DEFAULT"]


def test_insecure_fallback_on_sslerror():
    u._ssl_verify_cache = False
    s = FakeSession(fail_ssl=True)
    assert u.session_get(s, "http://x") == "OK"
    assert s.calls == [True, False]   # tried verified, then retried insecure


def test_insecure_success_no_retry():
    u._ssl_verify_cache = False
    s = FakeSession(fail_ssl=False)
    assert u.session_get(s, "http://x") == "OK"
    assert s.calls == [True]


def test_explicit_verify_respected():
    u._ssl_verify_cache = False
    s = FakeSession()
    u.session_get(s, "http://x", verify=True)
    assert s.calls == [True]
