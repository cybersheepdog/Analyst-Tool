# Analyst Tool — clipboard watcher
#
# Before: the main loop polled the clipboard itself, one value at a time, and
# ran each lookup on the same thread. Two consequences:
#   * anything copied while a report was running (8-20 s) was lost — only the
#     latest clipboard value was ever seen;
#   * copying the same value again did nothing (it compared text).
#
# Now a watcher thread notices every copy and queues it; the main loop takes
# copies off the queue in order. On Windows it uses the clipboard's change
# counter (GetClipboardSequenceNumber), which:
#   * counts a re-copy of identical text as a new copy, so it re-runs;
#   * costs nothing to poll — the clipboard is only opened when something was
#     actually copied, instead of every second (fewer lock clashes with RDP
#     clipboard sync and password managers);
#   * never mistakes a failed or momentarily empty read for a new value (the
#     cause of the old ">>note saved twice" bug): the read is simply retried.
# Elsewhere it falls back to comparing text, as before.

import queue
import sys
import threading
import time


def _windows_sequence_fn():
    """GetClipboardSequenceNumber on Windows, else None."""
    if not sys.platform.startswith("win"):
        return None
    try:
        import ctypes
        fn = ctypes.windll.user32.GetClipboardSequenceNumber
        fn.restype = ctypes.c_uint32
        fn()
        return fn
    except Exception:
        return None


class ClipboardWatcher:
    """Queue every clipboard copy (text only) for the main loop.

    read_fn   — returns the clipboard text, or None/'' when unreadable/empty.
    seq_fn    — 'auto' (Windows change counter when available), None (compare
                text), or a callable returning a changing counter.
    max_queue — copies waiting beyond this are dropped (and counted).
    """

    def __init__(self, read_fn, max_queue=10, interval=0.5, seq_fn='auto'):
        self._read = read_fn
        self._seq = _windows_sequence_fn() if seq_fn == 'auto' else seq_fn
        self.max_queue = max(1, int(max_queue))
        self.interval = interval
        self.dropped = 0
        self._q = queue.Queue()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        # Whatever is on the clipboard at startup is the baseline, not a copy
        # to act on (same as before).
        self._last_seq = self._safe(self._seq) if self._seq else None
        self._last_text = self._safe(self._read)

    @staticmethod
    def _safe(fn):
        try:
            return fn()
        except Exception:
            return None

    @property
    def uses_sequence_number(self):
        return self._seq is not None

    # -- thread ---------------------------------------------------------------

    def start(self):
        threading.Thread(target=self._run, name="clipboard", daemon=True).start()
        return self

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:
                pass
            self._stop.wait(self.interval)

    def poll_once(self):
        """Check the clipboard once; queue it if it is a new copy."""
        with self._lock:
            if self._seq is not None:
                seq = self._safe(self._seq)
                if seq is None or seq == self._last_seq:
                    return False
                text = self._safe(self._read)
                if not text:
                    # Locked by another process, mid-copy, or not text (an
                    # image): don't record this change — try again next poll.
                    return False
                self._last_seq = seq
            else:
                text = self._safe(self._read)
                if not text or text == self._last_text:
                    return False
            self._last_text = text
            if self._q.qsize() >= self.max_queue:
                self.dropped += 1
                return False
            self._q.put(text)
            return True

    # -- consumer side --------------------------------------------------------

    def get(self, timeout=1.0):
        """Next queued copy (raises queue.Empty after `timeout`)."""
        return self._q.get(timeout=timeout)

    def pending(self):
        return self._q.qsize()

    def resync(self):
        """The tool just wrote to the clipboard itself (>>report clip): make
        that the baseline and drop it from the queue, so the tool's own output
        is never looked up as if the analyst had copied it."""
        with self._lock:
            current = self._safe(self._read)
            if self._seq is not None:
                self._last_seq = self._safe(self._seq)
            if current:
                self._last_text = current
            kept = []
            while True:
                try:
                    item = self._q.get_nowait()
                except queue.Empty:
                    break
                if item != current:
                    kept.append(item)
            for item in kept:
                self._q.put(item)
