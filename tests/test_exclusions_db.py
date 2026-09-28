import os
import tempfile
import analyst_tool_cache as C


def _backend():
    return C.SQLiteBackend(os.path.join(tempfile.mkdtemp(), "e.db"))


def test_add_dedup_list_delete():
    be = _backend()
    assert be.add_exclusion("a.com", "bob") is True
    assert be.add_exclusion("a.com", "alice") is False     # dedup
    assert be.add_exclusion("b.net", "bob") is True
    assert {r["domain"] for r in be.list_exclusions()} == {"a.com", "b.net"}
    assert be.delete_exclusion("a.com") == 1               # anyone may remove
    assert {r["domain"] for r in be.list_exclusions()} == {"b.net"}


def test_manager_exclusions_and_ttl():
    be = _backend()
    m = C.CacheManager(be, username="bob", exclusion_refresh_minutes=999)
    m.add_exclusion("evil.com")
    assert "evil.com" in m.get_exclusions()
    be.add_exclusion("x.com", "z")                         # direct, manager unaware
    assert "x.com" not in m.get_exclusions()               # TTL not expired -> stale (expected)
    m.remove_exclusion("nope.com")                         # invalidates the manager cache
    assert "x.com" in m.get_exclusions()                   # now refreshed


def test_disabled_manager_exclusions():
    m = C.CacheManager(None)
    assert m.get_exclusions() == set()
    m.add_exclusion("a.com")        # must not raise
    m.remove_exclusion("a.com")
    m.print_exclusions()


def test_duplicate_exclusions_collapsed_and_prevented(tmp_path):
    import analyst_tool_cache as C
    p = str(tmp_path / "x.db")
    be = C.SQLiteBackend(p)
    # simulate duplicates written by an older version (no unique index yet)
    conn = be._conn()
    conn.execute("DROP INDEX IF EXISTS ux_excl_domain")
    for who in ("alice", "bob"):
        conn.execute("INSERT INTO exclusions (domain, added_by, created_at) VALUES (?,?,?)",
                     ("dup.example.com", who, 1.0))
    conn.commit()
    be2 = C.SQLiteBackend(p)                      # schema pass collapses them
    rows = [r for r in be2.list_exclusions() if r["domain"] == "dup.example.com"]
    assert len(rows) == 1 and rows[0]["added_by"] == "alice"
    assert be2.add_exclusion("dup.example.com", "carol") is False
    assert be2.add_exclusion("new.example.com", "carol") is True
    assert be2.add_exclusion("new.example.com", "dave") is False
