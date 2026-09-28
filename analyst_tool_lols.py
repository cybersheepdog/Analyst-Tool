# Python Standard Library Imports
import json
import os
import textwrap
import threading
import time
import requests

# Custom Imports
# session_get honours the [GENERAL] ssl_verify flag (verify=True by default,
# with an opt-in verify=False retry on SSLError). No circular import: the
# utilities module does not import this one.
from analyst_tool_utilities import session_get

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

lolbas_url    = "https://lolbas-project.github.io/api/lolbas.json"
loldriver_url = "https://www.loldrivers.io/api/drivers.json"
filename      = "lolbas.json"
filename2     = "drivers.json"

file_age       = 14                          # days before refresh
current_time   = time.time()
threshold_time = current_time - (file_age * 86400)

_session = requests.Session()               # reused for all downloads

# When a catalogue can't be loaded at startup (no network and no usable
# cached copy), lookups start disabled and a daemon thread retries the
# download this often until it succeeds.
_RETRY_SECONDS = 600
_retry_started: set = set()                 # labels with a retry thread running
_retry_lock = threading.Lock()

# ─────────────────────────────────────────────────────────────────────────────
# Module-level caches — populated by get_lolbas_json / get_loldriver_json
# ─────────────────────────────────────────────────────────────────────────────

_lolbas_json:      list  = []
_loldriver_json:   list  = []

# O(1) lookup dicts
_lolbas_by_name:   dict  = {}   # { "cmd.exe": <entry dict> }
_loldriver_by_tag: dict  = {}   # { "evil.sys": <entry dict> }

# Extension sets for fast endswith() checks
_lolbas_extensions:    set = set()
_loldriver_extensions: set = set()


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_or_fetch(url: str, fname: str, threshold: float) -> str:
    """Return the content of fname, fetching a fresh copy from url if stale.

    Replaces the duplicated try/except/if/else blocks in the original
    get_lolbas_json and get_loldriver_json functions.
    Uses a module-level requests.Session with a 15s timeout instead of
    urlretrieve (which has no timeout and no connection reuse).
    """
    def _read() -> str:
        with open(fname, encoding="utf-8") as f:
            return f.read()

    def _fetch_and_save() -> str:
        return _fetch_and_save_file(url, fname)

    try:
        mod_time = os.path.getmtime(fname)
        if mod_time > threshold:
            return _read()          # file is fresh — use it
        else:
            try:
                return _fetch_and_save()
            except Exception:
                return _read()      # fetch failed — fall back to stale file
    except OSError:
        # file doesn't exist yet
        return _fetch_and_save()


def _fetch_and_save_file(url: str, fname: str) -> str:
    """Download url, save it to fname, return the text (raises on failure)."""
    resp = session_get(_session, url, timeout=15)
    resp.raise_for_status()
    with open(fname, "w", encoding="utf-8") as f:
        f.write(resp.text)
    return resp.text


def _parse_catalogue(raw: str) -> list:
    """Parse a catalogue download; raises ValueError on anything but a list
    (an HTML error page or a truncated file must not become 'loaded')."""
    data = json.loads(raw)
    if not isinstance(data, list):
        raise ValueError("unexpected JSON (not a list)")
    return data


def _short(exc) -> str:
    """A readable reason for the one-line console message (the full
    exception goes to analyst_tool.log)."""
    if isinstance(exc, requests.exceptions.Timeout):
        return "download timed out"
    if isinstance(exc, (requests.exceptions.ProxyError, requests.exceptions.ConnectionError)):
        return "no network"
    if isinstance(exc, requests.exceptions.HTTPError) and exc.response is not None:
        return "HTTP %s" % exc.response.status_code
    if isinstance(exc, ValueError):
        return "bad or corrupt data"
    text = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
    return text if len(text) <= 90 else text[:87] + "..."


def _log(level, msg, *args):
    try:
        from analyst_tool_log import get_logger
        getattr(get_logger(), level)(msg, *args)
    except Exception:
        pass


def _start_retry(label: str, url: str, fname: str, on_loaded) -> None:
    """Retry the download on a daemon thread every _RETRY_SECONDS until it
    succeeds, then hand the parsed list to on_loaded(). One thread per label."""
    with _retry_lock:
        if label in _retry_started:
            return
        _retry_started.add(label)

    def _loop():
        while True:
            time.sleep(_RETRY_SECONDS)
            try:
                data = _parse_catalogue(_fetch_and_save_file(url, fname))
                on_loaded(data)
            except Exception as exc:
                # Never let the thread die: a failure here would leave the
                # catalogue off for the rest of the session with no retry.
                _log("info", "%s retry failed: %s", label, _short(exc))
                continue
            with _retry_lock:
                _retry_started.discard(label)
            print("\n%s loaded (%d entries) — lookups enabled." % (label, len(data)))
            _log("info", "%s loaded by background retry (%d entries)", label, len(data))
            return

    threading.Thread(target=_loop, name="%s-retry" % label, daemon=True).start()


def _load_catalogue(label: str, url: str, fname: str, threshold: float, on_loaded) -> str:
    """Load a catalogue for startup. Returns the raw JSON text, or "" when it is
    unavailable — no network and no usable cached copy (missing or corrupt).

    Before, that case raised straight out of analyst() and the tool would not
    start at all. Now lookups for this catalogue are simply off, and a
    background retry turns them on once a download succeeds.
    """
    try:
        raw = _load_or_fetch(url, fname, threshold)
        data = _parse_catalogue(raw)
    except Exception as exc:
        print("%s unavailable (%s) — lookups off, retrying every %d min."
              % (label, _short(exc), max(1, _RETRY_SECONDS // 60)))
        _log("warning", "%s unavailable at startup: %s: %s", label, type(exc).__name__, exc)
        _start_retry(label, url, fname, on_loaded)
        return ""
    on_loaded(data)
    return raw


def _lookup_key(value) -> str:
    """Normalise a copied binary name for catalogue lookup: the file name
    only (a full path like C:\\Windows\\System32\\certutil.exe is what logs
    give you), lowercased (the catalogues capitalise: Certutil.exe)."""
    v = (value or "").strip().strip('"\'')
    v = v.replace('\\', '/').rsplit('/', 1)[-1]
    return v.lower()


def _build_lolbas_indexes(data: list) -> None:
    """Populate the module-level LOLBAS caches from a parsed list."""
    global _lolbas_by_name, _lolbas_extensions
    _lolbas_by_name = {_lookup_key(entry['Name']): entry for entry in data}
    _lolbas_extensions = {
        entry['Name'].rsplit('.', 1)[-1].strip().lower()
        for entry in data
        if '.' in entry['Name']
    }


def _build_loldriver_indexes(data: list) -> None:
    """Populate the module-level LOLDriver caches from a parsed list."""
    global _loldriver_by_tag, _loldriver_extensions
    _loldriver_by_tag = {}
    _loldriver_extensions = set()
    for entry in data:
        tags = entry.get('Tags') or []
        for tag in tags:
            _loldriver_by_tag[_lookup_key(tag)] = entry
            parts = tag.split('.')
            if len(parts) > 1:
                _loldriver_extensions.add(parts[-1].strip().lower())


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def get_lolbas_json(lolbas_url, filename, file_age, current_time, threshold_time) -> str:
    """Load (or refresh) the LOLBAS JSON, build indexes, and return the raw text.

    Indexes are built once here so that get_lolbas_file_endings() and
    lookup_lolbas() never re-parse the JSON.
    """
    def _loaded(data):
        global _lolbas_json
        _lolbas_json = data
        _build_lolbas_indexes(data)

    # "" when unavailable: the fallback re-parse in the lookup helpers is
    # skipped for a falsy value, so it can't race the background retry.
    raw = _load_catalogue("LolBas", lolbas_url, filename, threshold_time, _loaded)
    if raw:
        print("LolBas configured.")
    return raw


def get_loldriver_json(loldriver_url, filename2, file_age, current_time, threshold_time) -> str:
    """Load (or refresh) the LOLDriver JSON, build indexes, and return the raw text.

    Indexes are built once here so that get_loldriver_file_endings() and
    lookup_loldriver() never re-parse the JSON.
    """
    def _loaded(data):
        global _loldriver_json
        _loldriver_json = data
        _build_loldriver_indexes(data)

    raw = _load_catalogue("LolDriver", loldriver_url, filename2, threshold_time, _loaded)
    if raw:
        print("LolDriver configured")
    return raw


def get_lolbas_file_endings(lolbas, clipboard_contents) -> bool:
    """Return True if clipboard_contents ends with a known LOLBAS file extension.

    Uses the pre-built _lolbas_extensions set (O(n_extensions) at most,
    but extensions are few) rather than re-parsing the JSON on every call.
    The `lolbas` parameter is kept for API compatibility but is not used
    when indexes are already populated.
    """
    if not _lolbas_extensions and lolbas:
        # Fallback: indexes not built yet (e.g. called before get_lolbas_json)
        data = json.loads(lolbas)
        _build_lolbas_indexes(data)

    key = _lookup_key(clipboard_contents)
    for ext in _lolbas_extensions:
        if key.endswith('.' + ext):
            return True
    return False


def get_loldriver_file_endings(driver, clipboard_contents) -> bool:
    """Return True if clipboard_contents ends with a known LOLDriver file extension.

    Uses the pre-built _loldriver_extensions set rather than re-parsing JSON.
    """
    if not _loldriver_extensions and driver:
        data = json.loads(driver)
        _build_loldriver_indexes(data)

    key = _lookup_key(clipboard_contents)
    for ext in _loldriver_extensions:
        if key.endswith('.' + ext):
            return True
    return False


def lookup_lolbas(lolbas, clipboard_contents) -> None:
    """Print LOLBAS details for clipboard_contents.

    Uses the pre-built _lolbas_by_name dict for O(1) lookup instead of
    iterating the full list.
    """
    if not _lolbas_by_name and lolbas:
        data = json.loads(lolbas)
        _build_lolbas_indexes(data)

    entry = _lolbas_by_name.get(_lookup_key(clipboard_contents))

    if entry is None:
        print(f"\n\t{clipboard_contents} is not a known LolBin.")
        return

    print(f"\nName:\t\t\t{entry['Name']}")
    print("Description:")
    print(textwrap.indent(textwrap.fill(entry['Description'], width=102), "\t\t\t"))

    if isinstance(entry['Full_Path'], list):
        print("Full Path:")
        for path in entry['Full_Path']:
            print(f"\t\t\t{path['Path']}")
    else:
        print(f"Full Path:\t{entry['Full_Path']}")

    if isinstance(entry['Commands'], list):
        print("Commands:")
        for command in entry['Commands']:
            print(f"\tCommand:\t{command['Command']}")
            print(f"\tDescription:\t{command['Description']}")
            print(f"\tUse Case:\t{command['Usecase']}")
            print(f"\tPrivilege:\t{command['Privileges']}")
            print(f"\tMITRE:\t\t{command['MitreID']}")
            print("\n")
    else:
        print(f"Commands:\t{entry['Commands']}")

    if isinstance(entry['Detection'], list):
        print("IOC's:")
        for ioc in entry['Detection']:
            try:
                print(f"\tIOC:\t\t{ioc['IOC']}")
            except KeyError:
                pass

    print(f"URL:\t{entry['url']}")


def lookup_loldriver(driver, clipboard_contents) -> None:
    """Print LOLDriver details for clipboard_contents.

    Uses the pre-built _loldriver_by_tag dict for O(1) lookup instead of
    iterating the full list.
    """
    if not _loldriver_by_tag and driver:
        data = json.loads(driver)
        _build_loldriver_indexes(data)

    entry = _loldriver_by_tag.get(_lookup_key(clipboard_contents))

    if entry is None:
        print(f"\n\t{clipboard_contents} is not a known LolDriver.")
        return

    print(f"\nName:\t\t\t{entry['Tags'][0]}")
    print("Description:")
    print(textwrap.indent(textwrap.fill(entry['Commands']['Description'], width=102), "\t\t\t"))
    print(f"MITRE:\t\t\t{entry['MitreID']}\n")

    if isinstance(entry['Commands'], list):
        print("List")
    else:
        print(f"Command:\t\t{entry['Commands']['Command']}\n")
        print(f"Operating System:\t{entry['Commands']['OperatingSystem']}")
        print(f"Privileges:\t\t{entry['Commands']['Privileges']}")
        print(f"Use Case:\t\t{entry['Commands']['Usecase']}")

    print("Resources:")
    resources = entry.get('Resources', [])
    if isinstance(resources, list):
        for ref in resources:
            print(f"\t\t\t{ref}")
    else:
        print(f"\t\t\t{resources}")

    print(f"URL:\t\t\thttps://www.loldrivers.io/drivers/{entry['Id']}/")
