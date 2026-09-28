"""OpenCTI: exact-match filtering, best-hit selection, dashboard link, null
scores, TLP precedence, client failure cool-down (analyst_tool_opencti)."""
import io
import sys
import time
import pytest

import analyst_tool_opencti as O
from analyst_tool_utilities import ServiceError, IndicatorNotFound


class _FakeIndicatorApi:
    def __init__(self, results, fail=None):
        self.results, self.fail, self.calls = results, fail, []

    def list(self, **kw):
        self.calls.append(kw)
        if self.fail:
            raise self.fail
        return self.results


class _FakeClient:
    def __init__(self, results, fail=None):
        self.indicator = _FakeIndicatorApi(results, fail)


def _use_client(monkeypatch, results, fail=None):
    client = _FakeClient(results, fail)
    monkeypatch.setattr(O, "_get_opencti_client", lambda url, token: client)
    return client


def _ind(name, score, modified="2026-01-01T00:00:00Z", created_by="MISP",
         tlp=None, labels=(), id_="abc"):
    return {"id": id_, "name": name, "x_opencti_score": score, "confidence": 60,
            "revoked": False, "modified": modified, "created": modified,
            "createdBy": {"name": created_by},
            "objectMarking": [{"definition": tlp}] if tlp else [],
            "objectLabel": [{"value": l} for l in labels],
            "pattern": "[ipv4-addr:value = '%s']" % name}


HEADERS = "https://cti.example.com/graphql,token,"


def test_fuzzy_hits_are_dropped_and_best_exact_hit_first(monkeypatch):
    client = _use_client(monkeypatch, [
        _ind("18.8.8.80", 95, id_="wrong"),        # full-text neighbour
        _ind("8.8.8.8", 40, created_by="MISP", id_="low"),
        _ind("8.8.8.8", 80, created_by="Analyst", id_="high"),
    ])
    hits = O.query_opencti(HEADERS, "8.8.8.8")
    assert [h["id"] for h in hits] == ["high", "low"]
    assert client.indicator.calls[0]["first"] == 25


def test_no_exact_match_is_empty_even_when_search_returned_neighbours(monkeypatch):
    _use_client(monkeypatch, [_ind("notevil.com", 90)])
    assert O.query_opencti(HEADERS, "evil.com") == []


def test_exact_match_is_case_insensitive(monkeypatch):
    _use_client(monkeypatch, [_ind("44D88612FEA8A8F36DE82E1278ABB02F", 70)])
    assert len(O.query_opencti(HEADERS, "44d88612fea8a8f36de82e1278abb02f")) == 1


def test_query_failure_is_a_service_error(monkeypatch):
    _use_client(monkeypatch, [], fail=RuntimeError("connection refused"))
    with pytest.raises(ServiceError) as ei:
        O.query_opencti(HEADERS, "8.8.8.8")
    assert ei.value.service == "OpenCTI" and "connection refused" in str(ei.value)


def test_dashboard_base_url():
    assert O._dashboard_base("https://cti.corp/graphql,t,") == "https://cti.corp"
    assert O._dashboard_base("https://cti.corp/graphql/,t,") == "https://cti.corp"
    assert O._dashboard_base("https://cti.corp,t,") == "https://cti.corp"      # was 'https://c'
    assert O._dashboard_base("https://api.corp/graphql,t,https://ui.corp/") == "https://ui.corp"
    assert O._dashboard_base("https://cti.corp/graphql,t") == "https://cti.corp"  # old 2-part form


def test_common_fields_null_score_tlp_precedence_and_tag_union():
    results = [
        _ind("8.8.8.8", None, tlp="TLP:GREEN", labels=["c2"]),
        _ind("8.8.8.8", 20, tlp="TLP:AMBER+STRICT", labels=["c2", "phishing"]),
        _ind("8.8.8.8", 10, tlp="TLP:CLEAR"),
    ]
    link, source, active, confidence, score, tlp, tags, first, last = \
        O._extract_common_fields(results, HEADERS)
    assert score == 0                                     # None → 0, not TypeError
    assert tlp == "AMBER+STRICT"                          # most restrictive, not last
    assert tags == ["c2", "phishing"]                     # union, deduplicated
    assert link == "https://cti.example.com/dashboard/observations/indicators/abc"


def test_print_ip_results_shows_match_count(capsys):
    results = [_ind("8.8.8.8", 80, created_by="Analyst"),
               _ind("8.8.8.8", 40, created_by="MISP")]
    O.print_opencti_ip_results(results, "8.8.8.8", None, HEADERS)
    out = capsys.readouterr().out
    assert "Malicious:" in out and "80" in out
    assert "2 indicators (highest score shown)" in out
    assert "score 40, by MISP" in out


def test_print_url_results_with_headers_prints_details(capsys):
    results = [_ind("http://evil.com/x", 90)]
    O.print_opencti_url_results(results, "http://evil.com/x", HEADERS)
    out = capsys.readouterr().out
    assert "Malicious:" in out and "/dashboard/observations/indicators/abc" in out
    O.print_opencti_url_results([], "http://evil.com/x", HEADERS)
    assert "URL not found in OpenCTI" in capsys.readouterr().out


def test_client_failure_is_remembered_for_cooldown(monkeypatch):
    attempts = {"n": 0}

    class _Boom:
        def __init__(self, *a, **k):
            attempts["n"] += 1
            raise RuntimeError("cannot reach server")

    import types
    monkeypatch.setitem(sys.modules, "pycti", types.SimpleNamespace(OpenCTIApiClient=_Boom))
    monkeypatch.setattr(O, "_opencti_client_cache", {})
    monkeypatch.setattr(O, "_opencti_client_failed_at", {})
    monkeypatch.setattr(O, "_CLIENT_RETRY_SECONDS", 60)
    for _ in range(3):
        with pytest.raises(ServiceError):
            O._get_opencti_client("https://x/graphql", "t")
    assert attempts["n"] == 1                              # not re-tried inside the window


def test_exact_hit_rules():
    ip = "8.8.8.8"
    assert O._is_exact_hit({"name": "8.8.8.8"}, ip)
    assert O._is_exact_hit({"name": "Google DNS", "pattern": "[ipv4-addr:value = '8.8.8.8']"}, ip)
    assert not O._is_exact_hit({"name": "x", "pattern": "[ipv4-addr:value = '18.8.8.80']"}, ip)
    assert not O._is_exact_hit({"name": "18.8.8.80"}, ip)
    h = "44d88612fea8a8f36de82e1278abb02f"
    yara = {"name": "EICAR_rule", "pattern": 'rule EICAR { meta: hash = "%s" condition: true }' % h.upper()}
    assert O._is_exact_hit(yara, h)                     # YARA hit kept, as before
    assert not O._is_exact_hit({"name": "x", "pattern": "rule y { }"}, h)
    assert not O._is_exact_hit({"name": "8.8.8.8"}, "")
