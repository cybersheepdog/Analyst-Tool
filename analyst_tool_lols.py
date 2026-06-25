# Python Standard Library Imports
import json
import os
import textwrap
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
        resp = session_get(_session, url, timeout=15)
        resp.raise_for_status()
        with open(fname, "w", encoding="utf-8") as f:
            f.write(resp.text)
        return resp.text

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


def _build_lolbas_indexes(data: list) -> None:
    """Populate the module-level LOLBAS caches from a parsed list."""
    global _lolbas_by_name, _lolbas_extensions
    _lolbas_by_name = {entry['Name']: entry for entry in data}
    _lolbas_extensions = {
        entry['Name'].rsplit('.', 1)[-1].strip()
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
            _loldriver_by_tag[tag] = entry
            parts = tag.split('.')
            if len(parts) > 1:
                _loldriver_extensions.add(parts[-1].strip())


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def get_lolbas_json(lolbas_url, filename, file_age, current_time, threshold_time) -> str:
    """Load (or refresh) the LOLBAS JSON, build indexes, and return the raw text.

    Indexes are built once here so that get_lolbas_file_endings() and
    lookup_lolbas() never re-parse the JSON.
    """
    global _lolbas_json
    raw = _load_or_fetch(lolbas_url, filename, threshold_time)
    _lolbas_json = json.loads(raw)
    _build_lolbas_indexes(_lolbas_json)
    print("LolBas configured.")
    return raw


def get_loldriver_json(loldriver_url, filename2, file_age, current_time, threshold_time) -> str:
    """Load (or refresh) the LOLDriver JSON, build indexes, and return the raw text.

    Indexes are built once here so that get_loldriver_file_endings() and
    lookup_loldriver() never re-parse the JSON.
    """
    global _loldriver_json
    raw = _load_or_fetch(loldriver_url, filename2, threshold_time)
    _loldriver_json = json.loads(raw)
    _build_loldriver_indexes(_loldriver_json)
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

    for ext in _lolbas_extensions:
        if clipboard_contents.endswith(ext):
            return True
    return False


def get_loldriver_file_endings(driver, clipboard_contents) -> bool:
    """Return True if clipboard_contents ends with a known LOLDriver file extension.

    Uses the pre-built _loldriver_extensions set rather than re-parsing JSON.
    """
    if not _loldriver_extensions and driver:
        data = json.loads(driver)
        _build_loldriver_indexes(data)

    for ext in _loldriver_extensions:
        if clipboard_contents.endswith(ext):
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

    entry = _lolbas_by_name.get(clipboard_contents)

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

    entry = _loldriver_by_tag.get(clipboard_contents)

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
