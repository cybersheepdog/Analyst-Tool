# Analyst Tool — Port & Windows Event ID enrichment
#
# A copied number could be either a TCP/UDP port or a Windows Event ID, so this
# prints BOTH interpretations with real, looked-up detail (not just links):
#
#   - Ports: the IANA Service Name and Port Number registry is downloaded once
#     and cached locally (like the Tor / MITRE lists), then looked up offline.
#     socket.getservbyport() is a stdlib fallback, and a small bundled
#     notable_ports.json adds malware/C2/tooling context IANA doesn't carry.
#   - Event IDs: a curated, bundled windows_event_ids.json (Security + Sysmon),
#     optionally refreshed from a JSON feed URL ([WINDOWS_EVENTS] feed_url).
#
# The SpeedGuide / Ultimate Windows Security links are kept as "for more detail"
# pointers — those sites have no data feed, so we don't scrape them.

import csv
import io
import json
import os
import socket
import threading
import time
from configparser import ConfigParser

import requests

from analyst_tool_utilities import color, session_get

# ── Sources / cache files ────────────────────────────────────────────────────
_IANA_URL = ("https://www.iana.org/assignments/service-names-port-numbers/"
             "service-names-port-numbers.csv")
iana_ports_filename     = "iana_ports.csv"
_IANA_MAX_AGE_SECONDS   = 30 * 86400          # IANA registry changes slowly

notable_ports_filename  = "notable_ports.json"      # bundled in repo
windows_events_filename = "windows_event_ids.json"  # bundled in repo
_EVENTS_MAX_AGE_SECONDS = 30 * 86400

_session = requests.Session()
_lock = threading.Lock()

# In-memory caches (loaded lazily, once)
_iana = None        # {(port:int, proto:str): "service — description"}
_notable = None     # {int: {"use":..., "malicious":bool, "note":...}}
_events = None       # {str: {"name":..., "log":..., "category":..., "notable":...}}


# ── Config ───────────────────────────────────────────────────────────────────

def _events_feed_url(path="config.ini"):
    cfg = ConfigParser()
    try:
        cfg.read(path)
        return cfg.get("WINDOWS_EVENTS", "feed_url", fallback="").strip() or None
    except Exception:
        return None


# ── IANA port registry (downloaded feed, cached) ─────────────────────────────

def _parse_iana_csv(text):
    """Parse the IANA registry CSV into {(port, proto): 'service — description'}."""
    out = {}
    try:
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            num = (row.get("Port Number") or "").strip()
            if not num or "-" in num:          # skip blanks and port ranges
                continue
            try:
                port = int(num)
            except ValueError:
                continue
            proto = (row.get("Transport Protocol") or "").strip().lower()
            service = (row.get("Service Name") or "").strip()
            desc = (row.get("Description") or "").strip()
            label = service
            if desc and desc.lower() != service.lower():
                label = (service + " — " + desc) if service else desc
            if label:
                out[(port, proto)] = label
    except Exception:
        pass
    return out


def _load_iana():
    """Load the IANA registry, downloading/refreshing the cache if stale."""
    global _iana
    if _iana is not None:
        return _iana
    with _lock:
        if _iana is not None:
            return _iana
        text = None
        fresh = (os.path.isfile(iana_ports_filename) and
                 (time.time() - os.path.getmtime(iana_ports_filename)) < _IANA_MAX_AGE_SECONDS)
        if fresh:
            try:
                with open(iana_ports_filename, encoding="utf-8") as f:
                    text = f.read()
            except OSError:
                text = None
        if text is None:
            try:
                resp = session_get(_session, _IANA_URL, timeout=20)
                if resp.status_code == 200:
                    text = resp.text
                    with open(iana_ports_filename, "w", encoding="utf-8") as f:
                        f.write(text)
            except Exception:
                text = None
        if text is None and os.path.isfile(iana_ports_filename):
            try:
                with open(iana_ports_filename, encoding="utf-8") as f:
                    text = f.read()
            except OSError:
                text = None
        _iana = _parse_iana_csv(text) if text else {}
        return _iana


# ── Bundled data: notable ports + event catalog ──────────────────────────────

def _load_json(filename):
    try:
        with open(filename, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _load_notable():
    global _notable
    if _notable is None:
        raw = _load_json(notable_ports_filename)
        # keys come in as strings from JSON; index by int
        _notable = {}
        for k, v in raw.items():
            try:
                _notable[int(k)] = v
            except (ValueError, TypeError):
                continue
    return _notable


def _load_events():
    global _events
    if _events is not None:
        return _events
    with _lock:
        if _events is not None:
            return _events
        # Optional refresh from a configured feed.
        feed = _events_feed_url()
        if feed:
            stale = not (os.path.isfile(windows_events_filename) and
                         (time.time() - os.path.getmtime(windows_events_filename))
                         < _EVENTS_MAX_AGE_SECONDS)
            if stale:
                try:
                    resp = session_get(_session, feed, timeout=20)
                    if resp.status_code == 200 and resp.text.strip():
                        json.loads(resp.text)  # validate
                        with open(windows_events_filename, "w", encoding="utf-8") as f:
                            f.write(resp.text)
                except Exception:
                    pass
        _events = {str(k): v for k, v in _load_json(windows_events_filename).items()}
        return _events


# ── Lookups ──────────────────────────────────────────────────────────────────

def _servbyport(port):
    """Stdlib offline service name (tcp then udp), or None."""
    for proto in ("tcp", "udp"):
        try:
            return socket.getservbyport(port, proto)
        except Exception:
            continue
    return None


def lookup_port(port):
    """Return a dict of what's known about a port, or {} if nothing."""
    info = {}
    iana = _load_iana()
    label = iana.get((port, "tcp")) or iana.get((port, "udp"))
    if not label:
        name = _servbyport(port)
        if name:
            label = name
    if label:
        info["service"] = label
    notable = _load_notable().get(port)
    if notable:
        info["notable"] = notable
    return info


def lookup_event(eid):
    """Return the event catalog entry for an id (string/int), or None."""
    return _load_events().get(str(eid).strip())


# ── Display ──────────────────────────────────────────────────────────────────

def _port_link(port):
    return "https://www.speedguide.net/port.php?port=%s" % port


def _wevid_link(eid):
    return ("https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/"
            "event.aspx?eventid=%s" % eid)


def print_port_info(pwid):
    print(color.UNDERLINE + "\nPort " + str(pwid) + ":" + color.END)
    try:
        port = int(pwid)
    except ValueError:
        port = -1

    if not (0 <= port <= 65535):
        print("\t{:<25} {}".format("Service:", "not a valid port number (0-65535)"))
        return

    info = lookup_port(port)
    if info.get("service"):
        print("\t{:<25} {}".format("Service:", info["service"]))
    else:
        print("\t{:<25} {}".format("Service:", "no well-known service"))

    notable = info.get("notable")
    if notable:
        use = notable.get("use", "")
        if notable.get("malicious"):
            print("\t{:<34} {}".format(color.RED + "Notable:" + color.END,
                                       color.RED + use + " (commonly malicious)" + color.END))
        else:
            print("\t{:<25} {}".format("Notable:", use))
        if notable.get("note"):
            print("\t{:<25} {}".format("", notable["note"]))

    print("\t" + _port_link(port))


def print_wevid_info(pwid):
    print(color.UNDERLINE + "\nWindows Event ID " + str(pwid) + ":" + color.END)
    entry = lookup_event(pwid)
    if not entry:
        print("\t{:<25} {}".format("Name:", "not a commonly logged security event"))
        print("\t" + _wevid_link(pwid))
        return

    name = entry.get("name", "")
    log = entry.get("log", "")
    category = entry.get("category", "")
    context = " [%s%s]" % (log, " · " + category if category else "") if log else ""
    print("\t{:<25} {}{}".format("Name:", name, context))
    if entry.get("notable"):
        print("\t{:<34} {}".format(color.ORANGE + "Analyst note:" + color.END,
                                   entry["notable"]))
    print("\t" + _wevid_link(pwid))


def print_port_and_wevid(pwid):
    """Print enriched info for a number as BOTH a port and a Windows Event ID."""
    print("\n\n\n" + color.BOLD + "Port / Windows Event ID lookup: " + str(pwid) + color.END)
    print_port_info(pwid)
    print_wevid_info(pwid)
