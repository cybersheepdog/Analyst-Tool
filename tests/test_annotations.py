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


# ── duplicate guard + dedupe ────────────────────────────────────────────────

def test_duplicate_note_within_window_is_skipped():
    be = _backend()
    m = C.CacheManager(be, username="alice")
    m.add_note("8.8.4.4", "ip", "beaconing to c2 #c2")
    m.add_note("8.8.4.4", "ip", "beaconing to c2 #c2")      # re-fired command
    _notes, total = be.list_notes("8.8.4.4", 5)
    assert total == 1


def test_duplicate_guard_is_per_user_and_per_text():
    be = _backend()
    alice = C.CacheManager(be, username="alice")
    bob = C.CacheManager(be, username="bob")
    alice.add_note("1.1.1.1", "ip", "same text")
    bob.add_note("1.1.1.1", "ip", "same text")              # different analyst
    alice.add_note("1.1.1.1", "ip", "different text")       # different note
    alice.add_note("1.1.1.2", "ip", "same text")            # different target
    _notes, total = be.list_notes("1.1.1.1", 5)
    assert total == 3
    assert be.list_notes("1.1.1.2", 5)[1] == 1


def test_duplicate_guard_window_expiry_and_disable():
    be = _backend()
    m = C.CacheManager(be, username="alice", note_dedup_seconds=0)
    m.add_note("2.2.2.2", "ip", "twice on purpose")
    m.add_note("2.2.2.2", "ip", "twice on purpose")         # guard disabled
    assert be.list_notes("2.2.2.2", 5)[1] == 2

    narrow = C.CacheManager(be, username="alice", note_dedup_seconds=0.01)
    narrow.add_note("3.3.3.3", "ip", "later repeat")
    time.sleep(0.05)
    narrow.add_note("3.3.3.3", "ip", "later repeat")        # outside window
    assert be.list_notes("3.3.3.3", 5)[1] == 2


def test_dedupe_keeps_oldest_and_only_your_own():
    be = _backend()
    now = time.time()
    # Duplicates as the old double-entry bug produced them: identical rows,
    # seconds apart. Written straight to the backend to bypass the new guard.
    be.add_note("5.5.5.5", "ip", "alice", "confirmed c2", "c2")
    be.add_note("5.5.5.5", "ip", "alice", "confirmed c2", "c2")
    be.add_note("5.5.5.5", "ip", "alice", "confirmed c2", "c2")
    be.add_note("5.5.5.5", "ip", "bob", "same text", "")
    be.add_note("5.5.5.5", "ip", "bob", "same text", "")     # bob's, untouched

    alice = C.CacheManager(be, username="alice")
    assert alice.dedupe_notes(dry_run=True) == 2             # reports only
    assert be.list_notes("5.5.5.5", 10)[1] == 5

    assert alice.dedupe_notes() == 2
    rows = be.list_note_rows("5.5.5.5")
    assert len(rows) == 3
    assert [r["username"] for r in rows].count("alice") == 1  # oldest kept
    assert [r["username"] for r in rows].count("bob") == 2
    assert rows[0]["created_at"] <= rows[1]["created_at"]
    assert alice.dedupe_notes() == 0                         # idempotent
    assert now > 0


def test_dedupe_scoped_to_one_indicator():
    be = _backend()
    for _ in range(2):
        be.add_note("6.6.6.6", "ip", "alice", "dup here", "")
        be.add_note("7.7.7.7", "ip", "alice", "dup there", "")
    alice = C.CacheManager(be, username="alice")
    assert alice.dedupe_notes("6.6.6.6", "ip") == 1
    assert be.list_notes("6.6.6.6", 10)[1] == 1
    assert be.list_notes("7.7.7.7", 10)[1] == 2   # other indicator untouched


def test_dedupe_normalizes_indicator_case():
    be = _backend()
    m = C.CacheManager(be, username="alice")
    be.add_note("evil.com", "domain", "alice", "phish kit", "")
    be.add_note("evil.com", "domain", "alice", "phish kit", "")
    assert m.dedupe_notes("EVIL.com", "domain") == 1
    assert be.list_notes("evil.com", 10)[1] == 1


def test_delete_notes_by_ids_is_precise():
    be = _backend()
    be.add_note("4.4.4.4", "ip", "alice", "one", "")
    be.add_note("4.4.4.4", "ip", "alice", "two", "")
    rows = be.list_note_rows("4.4.4.4", "alice")
    assert be.delete_notes_by_ids([rows[1]["id"]]) == 1
    left = be.list_note_rows("4.4.4.4", "alice")
    assert len(left) == 1 and left[0]["note"] == "one"
    assert be.delete_notes_by_ids([]) == 0


def test_delete_notes_by_ids_owner_guard():
    be = _backend()
    be.add_note("4.4.4.5", "ip", "alice", "mine", "")
    be.add_note("4.4.4.5", "ip", "bob", "theirs", "")
    rows = be.list_note_rows("4.4.4.5")
    bob_id = [r["id"] for r in rows if r["username"] == "bob"][0]
    assert be.delete_notes_by_ids([bob_id], "alice") == 0   # not alice's row
    assert be.list_notes("4.4.4.5", 10)[1] == 2
    assert be.delete_notes_by_ids([bob_id], "bob") == 1
