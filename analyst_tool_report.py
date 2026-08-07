# Analyst Tool — ticket-ready report export (>>report)
# Author: Jeremy Wiedner (@JeremyWiedner)
# License: BSD 3-Clause
#
# Purpose:
#   Every multi-service lookup (IP / domain / URL / hash) already renders its
#   full report as one text block (that's how the verdict line is built). This
#   module keeps the most recent of those blocks in a small in-memory buffer so
#   `>>report` can export the last lookup(s) to a markdown/plain-text file — or
#   straight back onto the clipboard — ready to paste into a SIEM ticket or
#   case notes.
#
# Design notes:
#   * Recording is passive: a lookup's already-captured text is appended to a
#     bounded deque. No service or printing code changes, no extra API calls.
#   * Exports strip ANSI colour codes and (by default) DEFANG the indicators
#     (8[.]8[.]8[.]8, hxxp://) so the file is safe to paste anywhere. Only the
#     reported indicators are defanged — not every dot in the text — so scores,
#     dates and prose are untouched.
#   * Everything is fail-safe: any problem recording or exporting prints a
#     message (or is skipped) and never interrupts the lookup loop.

import os
import re
import threading
import time
from collections import deque
from configparser import ConfigParser

_ANSI = re.compile(r'\x1b\[[0-9;]*m')


def strip_ansi(text):
    return _ANSI.sub('', text or '')


# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

def get_report_config_from_config(path="config.ini"):
    """Read the [REPORT] section from config.ini, with safe defaults."""
    cfg = {
        "dir": "reports",
        "format": "markdown",   # markdown | text
        "defang": True,
        "max_kept": 20,
    }
    parser = ConfigParser()
    try:
        parser.read(path)
    except Exception:
        return cfg
    if not parser.has_section("REPORT"):
        return cfg

    def _get(key, default):
        try:
            val = parser.get("REPORT", key)
            return val if val != "" else default
        except Exception:
            return default

    cfg["dir"] = _get("dir", "reports")
    fmt = str(_get("format", "markdown")).strip().lower()
    cfg["format"] = fmt if fmt in ("markdown", "text") else "markdown"
    try:
        cfg["defang"] = str(parser.get("REPORT", "defang")).strip().lower() \
            not in ("false", "0", "no", "off")
    except Exception:
        pass
    try:
        cfg["max_kept"] = max(1, min(int(parser.get("REPORT", "max_kept")), 100))
    except Exception:
        pass
    return cfg


# ─────────────────────────────────────────────────────────────────────────────
# Defang — applied only to the reported indicator(s), never text-wide, so
# scores (8.8), dates and prose survive intact.
# ─────────────────────────────────────────────────────────────────────────────

def defang_indicator(indicator):
    """Return the defanged form of one indicator (dots bracketed, hxxp)."""
    d = indicator or ""
    d = re.sub(r'^(h)tt(ps?://)', r'\1xx\2', d, flags=re.IGNORECASE)
    return d.replace('.', '[.]')


def defang_text(text, indicators):
    """Defang every occurrence of the given indicators inside `text`.

    Longer indicators are replaced first so a URL is defanged as a whole
    before its bare domain would match. http(s):// schemes are always
    neutralized to hxxp(s):// as a safety net.
    """
    out = text or ""
    for ind in sorted({i for i in (indicators or []) if i}, key=len, reverse=True):
        out = out.replace(ind, defang_indicator(ind))
    out = re.sub(r'\bhttps://', 'hxxps://', out)
    out = re.sub(r'\bhttp://', 'hxxp://', out)
    return out


def _safe_filename(indicator):
    """Reduce an indicator to a filesystem-safe fragment."""
    frag = (indicator or "report").strip()
    frag = re.sub(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', '', frag)   # drop URL scheme
    frag = re.sub(r'[^A-Za-z0-9._-]+', '_', frag).strip('._-')
    return (frag or "report")[:60]


# ─────────────────────────────────────────────────────────────────────────────
# Report buffer
# ─────────────────────────────────────────────────────────────────────────────

class ReportBuffer:
    """Bounded, thread-safe store of the most recent rendered reports."""

    _GREEN, _BOLD, _END = "\033[92m", "\033[1m", "\033[0m"

    def __init__(self, cfg=None):
        cfg = cfg or get_report_config_from_config()
        self.dir = cfg["dir"]
        self.format = cfg["format"]
        self.defang = cfg["defang"]
        self._reports = deque(maxlen=cfg["max_kept"])
        self._lock = threading.Lock()

    def record(self, indicator, indicator_type, text):
        """Store one finished report. Called after a lookup renders."""
        if not indicator or not text:
            return
        with self._lock:
            self._reports.append({
                "indicator": indicator,
                "type": indicator_type,
                "time": time.time(),
                "text": text,
            })

    def __len__(self):
        return len(self._reports)

    # -- document building ----------------------------------------------------

    def _build(self, reports, username, markdown):
        """Render `reports` (oldest first) into one exportable document."""
        stamp = time.strftime('%Y-%m-%d %H:%M')
        indicators = [r["indicator"] for r in reports]
        lines = []
        if markdown:
            lines.append("# Analyst Tool Report — %s" % stamp)
            lines.append("")
            lines.append("Analyst: %s" % username)
        else:
            lines.append("ANALYST TOOL REPORT — %s" % stamp)
            lines.append("Analyst: %s" % username)
            lines.append("=" * 60)
        for r in reports:
            ind = defang_indicator(r["indicator"]) if self.defang else r["indicator"]
            when = time.strftime('%Y-%m-%d %H:%M', time.localtime(r["time"]))
            body = strip_ansi(r["text"]).strip("\n")
            if self.defang:
                body = defang_text(body, indicators)
            lines.append("")
            if markdown:
                lines.append("## %s (%s) — looked up %s" % (ind, r["type"], when))
                lines.append("")
                lines.append("```text")
                lines.append(body)
                lines.append("```")
            else:
                lines.append("-" * 60)
                lines.append("%s (%s) — looked up %s" % (ind, r["type"], when))
                lines.append("-" * 60)
                lines.append(body)
        return "\n".join(lines) + "\n"

    # -- export ---------------------------------------------------------------

    def export(self, arg="", username="unknown"):
        """Handle `>>report [N] [clip]` — tokens in any order.

        N       how many recent lookups to include (default 1, newest last)
        clip    copy to the clipboard instead of writing a file
        """
        count, to_clip = 1, False
        for tok in (arg or "").split():
            tl = tok.lower()
            if tl in ("clip", "clipboard", "copy"):
                to_clip = True
            elif tl.isdigit():
                count = max(1, min(int(tl), self._reports.maxlen))
        with self._lock:
            reports = list(self._reports)[-count:]
        if not reports:
            print("\t[report] Nothing to export yet — look something up first. "
                  "(IP / domain / URL / hash reports are exportable.)")
            return None

        markdown = self.format == "markdown"
        doc = self._build(reports, username, markdown)

        if to_clip:
            try:
                import pyperclip
                pyperclip.copy(doc)
            except Exception as exc:
                print("\t[report] Could not copy to clipboard: %s" % exc)
                return None
            print(self._GREEN + self._BOLD +
                  "[+] Report (%d lookup%s) copied to clipboard — "
                  "ready to paste into your ticket."
                  % (len(reports), "s" if len(reports) != 1 else "") + self._END)
            return None

        ext = ".md" if markdown else ".txt"
        name = time.strftime('%Y-%m-%d_%H%M%S') + "_" + \
            _safe_filename(reports[-1]["indicator"]) + ext
        try:
            os.makedirs(self.dir, exist_ok=True)
            path = os.path.join(self.dir, name)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(doc)
        except Exception as exc:
            print("\t[report] Could not write the file: %s" % exc)
            return None
        print(self._GREEN + self._BOLD +
              "[+] Report (%d lookup%s) saved to %s"
              % (len(reports), "s" if len(reports) != 1 else "", path) + self._END)
        return path


# ─────────────────────────────────────────────────────────────────────────────
# Module-level buffer — one per process, created lazily so config.ini is read
# from the working directory the tool actually runs in.
# ─────────────────────────────────────────────────────────────────────────────

_buffer = None
_buffer_lock = threading.Lock()


def get_report_buffer():
    global _buffer
    if _buffer is None:
        with _buffer_lock:
            if _buffer is None:
                _buffer = ReportBuffer()
    return _buffer


def record_report(indicator, indicator_type, text):
    """Fail-safe hook for the lookup path: never raises."""
    try:
        get_report_buffer().record(indicator, indicator_type, text)
    except Exception:
        pass
