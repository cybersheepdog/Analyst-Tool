"""Tests for the >>history and >>find commands (lookup history & note search)."""
import io
import os
import sys
import tempfile
import time

import analyst_tool_cache as C


def _backend():
    return C.SQLiteBackend(os.path.join(tempfile.mkdtemp(), "a.db"))


def _grab(fn, *args, **kwargs):
    """Run fn while capturing what it emits/prints; return the plain text."""
    old = sys.stdout
    sys.stdout = io.StringIO()
    try:
        fn(*args, **kwargs)
        out = sys.stdout.getvalue()
    finally:
        sys.stdout = old
    return C.re.sub(r'\x1b\[[0-9;]*m', '', out)


# ── backend.list_history ────────────────────────────────────────────────────

def test_list_history_orders_and_filters():
    be = _backend()
    be.record_check("1.1.1.1", "ip", "alice", 0)
    time.sleep(0.01)
    be.record_check("evil.com", "domain", "bob", 0)
    time.sleep(0.01)
    be.record_check("2.2.2.2", "ip", "alice", 0)

    rows = be.list_history(None, 20)
    assert [r["indicator"] for r in rows] == ["2.2.2.2", "evil.com", "1.1.1.1"]

    mine = be.list_history("alice", 20)
    assert [r["indicator"] for r in mine] == ["2.2.2.2", "1.1.1.1"]
    assert all(r["username"] == "alice" for r in mine)

    assert len(be.list_history(None, 2)) == 2  # limit respected


def test_history_respects_dedup():
    """Rapid re-checks by the same user within the dedup window log once."""
    be = _backend()
    be.record_check("1.1.1.1", "ip", "alice", 3600)
    be.record_check("1.1.1.1", "ip", "alice", 3600)
    assert len(be.list_history("alice", 20)) == 1


# ── backend.search_notes ────────────────────────────────────────────────────

def test_search_notes_text_and_tags():
    be = _backend()
    be.add_note("8.8.8.8", "ip", "alice", "benign resolver", "fp benign")
    time.sleep(0.01)
    be.add_note("45.145.66.165", "ip", "bob", "confirmed phishing C2", "phishing c2")
    time.sleep(0.01)
    be.add_note("evil.com", "domain", "bob", "C2 domain, case 42", "c2")

    # whole-tag match: #c2 matches the tag, not the note word "C2"
    rows = be.search_notes(tags=["c2"])
    assert {r["indicator"] for r in rows} == {"45.145.66.165", "evil.com"}
    assert rows[0]["indicator"] == "evil.com"  # newest first

    # text terms are case-insensitive substrings over note/indicator/tags
    rows = be.search_notes(terms=["PHISHING"])
    assert {r["indicator"] for r in rows} == {"45.145.66.165"}
    rows = be.search_notes(terms=["45.145"])
    assert {r["indicator"] for r in rows} == {"45.145.66.165"}

    # AND semantics across terms and tags
    rows = be.search_notes(terms=["case"], tags=["c2"])
    assert {r["indicator"] for r in rows} == {"evil.com"}

    # a tag term must match a WHOLE tag ("fp" must not match "phishing")
    rows = be.search_notes(tags=["fp"])
    assert {r["indicator"] for r in rows} == {"8.8.8.8"}

    assert be.search_notes(terms=["nomatch"]) == []


# ── CacheManager.print_history ──────────────────────────────────────────────

def test_print_history_own_vs_team():
    be = _backend()
    alice = C.CacheManager(be, username="alice")
    be.record_check("1.1.1.1", "ip", "alice", 0)
    be.record_check("evil.com", "domain", "bob", 0)

    out = _grab(alice.print_history, "")
    assert "YOUR HISTORY (alice)" in out
    assert "1.1.1.1" in out and "evil.com" not in out

    out = _grab(alice.print_history, "team")
    assert "TEAM HISTORY" in out
    assert "evil.com" in out and "bob" in out  # team view shows the user

    out = _grab(alice.print_history, "team 1")  # limit parsed from either order
    assert out.count("\t20") <= 1  # sanity: prints at most 1 row (+header)
    assert "evil.com" in out and "1.1.1.1" not in out


def test_print_history_empty_and_disabled():
    be = _backend()
    mgr = C.CacheManager(be, username="alice")
    out = _grab(mgr.print_history, "")
    assert "(no lookups recorded yet)" in out

    disabled = C.CacheManager(None)
    out = _grab(disabled.print_history, "")
    assert "Needs the cache enabled" in out


# ── CacheManager.find_annotations ───────────────────────────────────────────

def test_find_annotations_output():
    be = _backend()
    mgr = C.CacheManager(be, username="alice")
    mgr.add_note("45.145.66.165", "ip", "confirmed phishing C2 #phishing #c2")
    mgr.add_note("8.8.8.8", "ip", "benign resolver #fp")

    out = _grab(mgr.find_annotations, "#c2")
    assert "FIND '#c2'" in out
    assert "45.145.66.165" in out and "8.8.8.8" not in out
    assert "confirmed phishing C2" in out
    assert "[phishing]" in out  # tag pills rendered

    out = _grab(mgr.find_annotations, "resolver")
    assert "8.8.8.8" in out and "45.145.66.165" not in out

    out = _grab(mgr.find_annotations, "nomatch")
    assert "(no matches)" in out

    out = _grab(mgr.find_annotations, "")  # no terms → usage, not a crash
    assert "usage" in out


def test_find_disabled():
    disabled = C.CacheManager(None)
    out = _grab(disabled.find_annotations, "#c2")
    assert "Needs the cache enabled" in out
