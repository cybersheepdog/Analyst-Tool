import io
import os
import sys
import tempfile
import time
import analyst_tool_cache as C


def _backend():
    return C.SQLiteBackend(os.path.join(tempfile.mkdtemp(), "a.db"))


def test_extract_tags_ignores_case_numbers():
    clean, tags = C.CacheManager._extract_tags(
        "confirmed phishing C2, case #1487 #phishing #c2")
    assert tags == ["phishing", "c2"]          # letter-led only
    assert "case #1487" in clean               # #1487 kept (it's a case ref)
    assert "#phishing" not in clean


def test_add_list_delete():
    be = _backend()
    alice = C.CacheManager(be, username="alice")
    bob = C.CacheManager(be, username="bob")
    alice.add_note("8.8.8.8", "ip", "confirmed phishing #phishing #c2")
    time.sleep(0.01)
    bob.add_note("8.8.8.8", "ip", "blocked at fw #blocked")

    notes, total = be.list_notes("8.8.8.8", 5)
    assert total == 2
    assert notes[0]["username"] == "bob"       # newest first
    assert "phishing" in dict((n["username"], n["tags"]) for n in notes)["alice"]

    assert be.delete_notes("8.8.8.8", "alice") == 1   # only removes alice's
    notes, total = be.list_notes("8.8.8.8", 5)
    assert total == 1 and notes[0]["username"] == "bob"


def test_notes_indicator_normalized():
    be = _backend()
    m = C.CacheManager(be, username="x")
    m.add_note("EXAMPLE.com", "domain", "looks fine #fp")
    notes, total = be.list_notes("example.com", 5)   # lowercased key
    assert total == 1 and "fp" in notes[0]["tags"]


def test_print_team_notes_output():
    be = _backend()
    m = C.CacheManager(be, username="alice")
    m.add_note("9.9.9.9", "ip", "confirmed phishing #phishing")
    buf = io.StringIO(); real = sys.stdout; sys.stdout = buf
    try:
        m.print_team_notes("9.9.9.9", "ip")
    finally:
        sys.stdout = real
    out = buf.getvalue()
    assert "TEAM NOTES (1)" in out
    assert "confirmed phishing" in out
    assert "phishing" in out


def test_disabled_manager_note_is_noop():
    m = C.CacheManager(None)
    m.add_note("8.8.8.8", "ip", "x")        # must not raise
    m.print_team_notes("8.8.8.8", "ip")     # must not raise
    m.remove_my_notes("8.8.8.8", "ip")
