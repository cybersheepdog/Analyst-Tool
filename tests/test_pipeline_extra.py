"""Circuit breaker inside the cache, LOLBAS case handling, shared-config
negative cache, log module."""
import os
import tempfile
import time
import pytest

import analyst_tool_cache as C
import analyst_tool_lols as L
from analyst_tool_breaker import BREAKER, ServiceBreaker
from analyst_tool_utilities import ServiceError, IndicatorNotFound


def _backend():
    return C.SQLiteBackend(os.path.join(tempfile.mkdtemp(), "t.db"))


@pytest.fixture(autouse=True)
def _clean_breaker():
    BREAKER.reset()
    yield
    BREAKER.reset()


# ── breaker + cache ──────────────────────────────────────────────────────────

def test_quota_error_trips_breaker_and_later_lookups_are_skipped():
    be = _backend()
    mgr = C.CacheManager(be, freshness_days=7, username="bob")
    out = []
    mgr._emit = lambda t: out.append(t)
    calls = {"n": 0}

    def quota():
        calls["n"] += 1
        raise ServiceError("VirusTotal", 429, "Quota exceeded")

    with pytest.raises(ServiceError):
        mgr.cached_call("a", "hash", "virustotal", quota)
    assert calls["n"] == 1 and BREAKER.check("VirusTotal")

    # Different indicator, same service → skipped without a live call
    with pytest.raises(ServiceError) as ei:
        mgr.cached_call("b", "hash", "virustotal", quota)
    assert calls["n"] == 1
    assert "skipped: quota exceeded" in str(ei.value)

    # '!' force prefix bypasses the breaker
    with pytest.raises(ServiceError):
        mgr.cached_call("b", "hash", "virustotal", quota, force_refresh=True)
    assert calls["n"] == 2

    # A fresh cached row is still served while the breaker is open
    be.store_miss("c", "hash", "virustotal", "cached text")
    mgr.cached_call("c", "hash", "virustotal", quota)
    assert calls["n"] == 2 and "cached text" in out[-1]

    # A stale row is served via stale-while-error when skipped
    be.store_miss("d", "hash", "virustotal", "old text")
    be._conn().execute("UPDATE indicator_cache SET updated_at=updated_at-30*86400 WHERE indicator='d'")
    be._conn().commit()
    mgr.cached_call("d", "hash", "virustotal", quota)
    assert calls["n"] == 2 and "old text" in out[-1] and "stale" in out[-1]


def test_not_found_and_timeouts_do_not_trip():
    be = _backend()
    mgr = C.CacheManager(be, freshness_days=7, username="bob")
    mgr._emit = lambda t: None

    def nf():
        print("not found")
        raise IndicatorNotFound("Shodan")

    mgr.cached_call("a", "ip", "shodan", nf)
    assert BREAKER.check("Shodan") is None

    def outage():
        raise ServiceError("AlienVault OTX", 503, "bad gateway")

    with pytest.raises(ServiceError):
        mgr.cached_call("a", "ip", "otx", outage)
    assert BREAKER.check("AlienVault OTX") is None


def test_breaker_applies_with_cache_disabled():
    mgr = C.CacheManager(None)
    calls = {"n": 0}

    def quota():
        calls["n"] += 1
        raise ServiceError("AbuseIPDB", 429, "rate limited")

    with pytest.raises(ServiceError):
        mgr.cached_call("a", "ip", "abuseipdb", quota)
    with pytest.raises(ServiceError) as ei:
        mgr.cached_call("b", "ip", "abuseipdb", quota)
    assert calls["n"] == 1 and "skipped" in str(ei.value)


def test_opencti_has_its_own_freshness_and_not_found_never_outlives_it():
    be = _backend()
    mgr = C.CacheManager(be, freshness_days=7, username="bob",
                         not_found_hours=24, opencti_freshness_hours=6)
    mgr._emit = lambda t: None
    assert mgr.freshness_for("opencti") == 6 * 3600
    assert mgr.freshness_for("virustotal") == 7 * 86400
    calls = {"n": 0}

    def nf():
        calls["n"] += 1
        print("Not found in OpenCTI")
        raise IndicatorNotFound("OpenCTI")

    mgr.cached_call("8.8.8.8", "ip", "opencti", nf)
    mgr.cached_call("8.8.8.8", "ip", "opencti", nf)
    assert calls["n"] == 1
    be._conn().execute("UPDATE indicator_cache SET updated_at=updated_at-7*3600")   # 7 h old
    be._conn().commit()
    mgr.cached_call("8.8.8.8", "ip", "opencti", nf)
    assert calls["n"] == 2                          # expired at 6 h, not 24 h


# ── LOLBAS case / path handling ─────────────────────────────────────────────

def test_lolbas_lookup_is_case_insensitive_and_accepts_paths(capsys):
    data = [{"Name": "Certutil.exe", "Description": "d", "Full_Path": "x",
             "Commands": "c", "Detection": [], "url": "u"}]
    L._build_lolbas_indexes(data)
    for form in ("certutil.exe", "CERTUTIL.EXE", r"C:\Windows\System32\certutil.exe",
                 '"C:\\Windows\\System32\\certutil.exe"', "/usr/bin/certutil.exe"):
        assert L.get_lolbas_file_endings(None, form) is True, form
        L.lookup_lolbas(None, form)
        assert "Certutil.exe" in capsys.readouterr().out, form
    assert L.get_lolbas_file_endings(None, "evil.com") is False
    assert L.get_lolbas_file_endings(None, "someexe") is False   # needs the dot


def test_loldriver_lookup_is_case_insensitive():
    data = [{"Tags": ["RTCore64.sys"], "Commands": {"Description": "d", "Command": "c",
             "OperatingSystem": "w", "Privileges": "p", "Usecase": "u"},
             "MitreID": "T1068", "Resources": [], "Id": "1"}]
    L._build_loldriver_indexes(data)
    assert L.get_loldriver_file_endings(None, "rtcore64.sys") is True
    assert L._loldriver_by_tag.get(L._lookup_key("RTCORE64.SYS")) is not None


# ── shared config: unreachable remote is remembered ─────────────────────────

def test_remote_failure_is_cached_for_a_minute(monkeypatch, tmp_path, capsys):
    import analyst_tool_shared_config as S
    S.clear_cache()
    cfg = tmp_path / "config.ini"
    cfg.write_text("[CACHE]\nenabled = true\nbackend = remote\nhost = db\ndbname = x\n"
                   "db_user = u\npassword = p\n")
    attempts = {"n": 0}

    def _fail(cfg):
        attempts["n"] += 1
        return None
    monkeypatch.setattr(S, "_fetch_remote_shared_config", _fail)
    for _ in range(5):
        S.load_config(str(cfg))
    assert attempts["n"] == 1
    assert capsys.readouterr().out.count("database unreachable") == 1
    S.clear_cache()
    S.load_config(str(cfg))
    assert attempts["n"] == 2                       # clear_cache resets the window
    S.clear_cache()


# ── log module ───────────────────────────────────────────────────────────────

def test_log_module_writes_file_and_console_line(tmp_path, capsys, monkeypatch):
    import logging
    import analyst_tool_log as LG
    monkeypatch.setattr(LG, "_configured", False)
    logger = logging.getLogger(LG.LOGGER_NAME)
    for h in list(logger.handlers):
        logger.removeHandler(h)
    path = tmp_path / "t.log"
    LG.setup_logging(str(path))
    try:
        raise KeyError("data")
    except KeyError as exc:
        LG.report_error("unit", exc)
    for h in logger.handlers:
        h.flush()
    text = path.read_text()
    assert "unit: KeyError: 'data'" in text and "Traceback" in text
    assert "[error] KeyError: 'data'" in capsys.readouterr().out
    assert logging.getLogger("urllib3").level == logging.CRITICAL
