import os
import tempfile
import time
import analyst_tool_cache as C


def _backend():
    return C.SQLiteBackend(os.path.join(tempfile.mkdtemp(), "t.db"))


def test_miss_then_hit_and_counters():
    be = _backend()
    mgr = C.CacheManager(be, freshness_days=7, username="bob")
    calls = {"n": 0}

    def live():
        calls["n"] += 1
        print("THE-REPORT")

    mgr.cached_call("8.8.8.8", "ip", "virustotal", live)   # miss -> live
    mgr.cached_call("8.8.8.8", "ip", "virustotal", live)   # hit  -> cached
    assert calls["n"] == 1

    row = be.get_fresh_row("8.8.8.8", "virustotal", 7 * 86400)
    assert row and "THE-REPORT" in row["payload"]
    # lookup_count=2, cache_hits=1, api_calls=1
    cur = be._conn().execute(
        "SELECT lookup_count, cache_hits, api_calls FROM indicator_cache "
        "WHERE indicator=? AND service=?", ("8.8.8.8", "virustotal"))
    assert tuple(cur.fetchone()) == (2, 1, 1)


def test_force_refresh_and_freshness():
    be = _backend()
    mgr = C.CacheManager(be, freshness_days=7, username="bob")
    calls = {"n": 0}

    def live():
        calls["n"] += 1
        print("R")

    mgr.cached_call("1.1.1.1", "ip", "virustotal", live)                       # miss
    mgr.cached_call("1.1.1.1", "ip", "virustotal", live, force_refresh=True)   # forced miss
    assert calls["n"] == 2
    # age it beyond freshness -> miss again
    be._conn().execute("UPDATE indicator_cache SET updated_at=? WHERE indicator=?",
                       (time.time() - 8 * 86400, "1.1.1.1"))
    be._conn().commit()
    assert be.get_fresh_row("1.1.1.1", "virustotal", 7 * 86400) is None


def test_check_dedup_and_stats():
    be = _backend()
    assert be.record_check("1.1.1.1", "ip", "bob", 3600) is True
    assert be.record_check("1.1.1.1", "ip", "bob", 3600) is False    # within dedup window
    assert be.record_check("1.1.1.1", "ip", "alice", 3600) is True   # different user
    distinct, total = be.check_stats("1.1.1.1", 7 * 86400)
    assert (distinct, total) == (2, 2)


def test_quota_stripped():
    text = "a\nYou have reached 75% of your 500 daily VT API Queries\nb\n"
    assert "API Queries" not in C.CacheManager._strip_quota(text)


def test_normalization():
    assert C.CacheManager._norm("EXAMPLE.com", "domain") == "example.com"
    assert C.CacheManager._norm(" 8.8.8.8 ", "ip") == "8.8.8.8"


def test_disabled_manager_runs_live():
    mgr = C.CacheManager(None)
    calls = {"n": 0}
    mgr.cached_call("x", "ip", "vt", lambda: calls.__setitem__("n", calls["n"] + 1))
    mgr.cached_call("x", "ip", "vt", lambda: calls.__setitem__("n", calls["n"] + 1))
    assert calls["n"] == 2
    assert mgr.record_check_and_alert("x", "ip") is None  # no-op when disabled
