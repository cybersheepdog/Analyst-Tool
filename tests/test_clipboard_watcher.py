"""ClipboardWatcher: every copy queued in order; re-copy re-runs with a
sequence counter; failed/blank reads never become events."""
import queue

import pytest

from analyst_tool_clipboard import ClipboardWatcher


class FakeClipboard:
    def __init__(self, text="startup"):
        self.text, self.seq, self.fail = text, 1, False

    def copy(self, text):
        self.text = text
        self.seq += 1

    def read(self):
        if self.fail:
            return None
        return self.text


def _drain(w):
    out = []
    while True:
        try:
            out.append(w.get(timeout=0.01))
        except queue.Empty:
            return out


def test_startup_content_is_baseline_not_an_event():
    cb = FakeClipboard()
    w = ClipboardWatcher(cb.read, seq_fn=lambda: cb.seq)
    assert w.poll_once() is False and _drain(w) == []


def test_every_copy_is_queued_in_order():
    cb = FakeClipboard()
    w = ClipboardWatcher(cb.read, seq_fn=lambda: cb.seq)
    for v in ("8.8.8.8", "evil.com", "44d88612fea8a8f36de82e1278abb02f"):
        cb.copy(v)
        w.poll_once()
    assert _drain(w) == ["8.8.8.8", "evil.com", "44d88612fea8a8f36de82e1278abb02f"]


def test_recopy_of_same_text_reruns_with_sequence_counter():
    cb = FakeClipboard()
    w = ClipboardWatcher(cb.read, seq_fn=lambda: cb.seq)
    cb.copy("8.8.8.8"); w.poll_once()
    cb.copy("8.8.8.8"); w.poll_once()
    assert _drain(w) == ["8.8.8.8", "8.8.8.8"]


def test_text_compare_fallback_ignores_recopy():
    cb = FakeClipboard()
    w = ClipboardWatcher(cb.read, seq_fn=None)
    cb.copy("8.8.8.8"); w.poll_once()
    cb.copy("8.8.8.8"); w.poll_once()
    assert _drain(w) == ["8.8.8.8"]


def test_failed_or_blank_read_is_retried_not_queued():
    """The old double-note bug: a transient failed read must not make the
    unchanged clipboard look new afterwards."""
    for seq in (True, False):
        cb = FakeClipboard()
        w = ClipboardWatcher(cb.read, seq_fn=(lambda: cb.seq) if seq else None)
        cb.copy(">>note 1.2.3.4 c2")
        w.poll_once()
        cb.fail = True
        w.poll_once()                 # read fails
        cb.fail = False
        w.poll_once(); w.poll_once()  # clipboard unchanged
        assert _drain(w) == [">>note 1.2.3.4 c2"], seq
    # with the counter, a change whose read fails is picked up on a later poll
    cb = FakeClipboard()
    w = ClipboardWatcher(cb.read, seq_fn=lambda: cb.seq)
    cb.copy("evil.com"); cb.fail = True
    assert w.poll_once() is False
    cb.fail = False
    assert w.poll_once() is True and _drain(w) == ["evil.com"]


def test_queue_limit_counts_drops():
    cb = FakeClipboard()
    w = ClipboardWatcher(cb.read, seq_fn=lambda: cb.seq, max_queue=2)
    for i in range(4):
        cb.copy("host%d.evil.com" % i); w.poll_once()
    assert _drain(w) == ["host0.evil.com", "host1.evil.com"] and w.dropped == 2


def test_resync_drops_the_tools_own_clipboard_write():
    cb = FakeClipboard()
    w = ClipboardWatcher(cb.read, seq_fn=lambda: cb.seq)
    cb.copy("8.8.8.8"); w.poll_once()
    cb.copy("REPORT TEXT 1.2.3.4 evil.com"); w.poll_once()   # >>report clip wrote this
    w.resync()
    w.poll_once()
    assert _drain(w) == ["8.8.8.8"]


def test_background_thread_picks_up_copies():
    import time
    cb = FakeClipboard()
    w = ClipboardWatcher(cb.read, seq_fn=lambda: cb.seq, interval=0.01).start()
    try:
        cb.copy("evil.com")
        assert w.get(timeout=2.0) == "evil.com"
    finally:
        w.stop()
