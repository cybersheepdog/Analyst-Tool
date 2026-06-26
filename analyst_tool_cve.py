# Analyst Tool — CVE / CISA KEV lookup
#
# Copy a CVE id (e.g. CVE-2021-44228) to get:
#   - NVD 2.0 details: description, CVSS base score/severity, published date,
#     and a few references.
#   - CISA Known Exploited Vulnerabilities (KEV) status: whether the CVE is in
#     the catalog of vulnerabilities known to be exploited in the wild, with the
#     date added, required action, due date, and known-ransomware-use flag.
#
# The KEV catalog is a single JSON file, cached on disk like the other lists.
# NVD works without a key at low volume; an optional key (config.ini [CVE]
# nvd_api_key) raises the rate limit.

import json
import os
import time
import requests

from configparser import ConfigParser

from analyst_tool_utilities import color, session_get

# CVE id: CVE-YYYY-NNNN (4 to 7 digit sequence). Case-insensitive in use.
cve_regex = r'^CVE-\d{4}-\d{4,7}$'

_NVD_URL              = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_KEV_URL              = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
kev_filename          = "cisa_kev.json"
_KEV_MAX_AGE_SECONDS  = 24 * 60 * 60   # refresh daily

_kev_session = requests.Session()
_nvd_session = requests.Session()


# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

def get_nvd_key_from_config(path="config.ini"):
    """Return an optional NVD API key from config.ini [CVE] nvd_api_key, or None."""
    config_object = ConfigParser()
    try:
        config_object.read(path)
        key = config_object.get("CVE", "nvd_api_key", fallback="").strip()
        return key or None
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# CISA KEV catalog (cached)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_kev(text):
    """Parse the KEV JSON text into { 'CVE-XXent': entry_dict }."""
    try:
        data = json.loads(text)
    except Exception:
        return {}
    out = {}
    for entry in data.get("vulnerabilities", []):
        cid = entry.get("cveID")
        if cid:
            out[cid.upper()] = entry
    return out


def get_cisa_kev(path=kev_filename):
    """Return the KEV catalog as a dict, using a 24h on-disk cache.

    Fetches a fresh copy when the cache is missing/stale, falling back to the
    stale file (or an empty dict) if the download fails.
    """
    now = time.time()
    if os.path.isfile(path) and (now - os.path.getmtime(path)) < _KEV_MAX_AGE_SECONDS:
        try:
            with open(path, encoding="utf-8") as f:
                return _parse_kev(f.read())
        except OSError:
            pass

    try:
        resp = session_get(_kev_session, _KEV_URL, timeout=20)
        if resp.status_code == 200:
            with open(path, "w", encoding="utf-8") as f:
                f.write(resp.text)
            return _parse_kev(resp.text)
    except Exception:
        pass

    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                return _parse_kev(f.read())
        except OSError:
            pass
    return {}


# ─────────────────────────────────────────────────────────────────────────────
# NVD lookup + parsing
# ─────────────────────────────────────────────────────────────────────────────

def _fetch_nvd(cve_id, nvd_key=None):
    """Return the parsed NVD JSON for a CVE, or None on error."""
    headers = {"apiKey": nvd_key} if nvd_key else {}
    try:
        resp = session_get(_nvd_session, _NVD_URL,
                           params={"cveId": cve_id}, headers=headers, timeout=20)
        if resp.status_code != 200:
            return None
        return json.loads(resp.text)
    except Exception:
        return None


def parse_nvd(nvd_json):
    """Extract the fields we display from an NVD 2.0 response.

    Returns a dict (description, cvss, severity, vector, published, references)
    or None if the CVE wasn't found in the response.
    """
    if not nvd_json:
        return None
    vulns = nvd_json.get("vulnerabilities") or []
    if not vulns:
        return None
    cve = vulns[0].get("cve", {})

    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    cvss = severity = vector = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            cvss = data.get("baseScore")
            severity = (data.get("baseSeverity")
                        or metrics[key][0].get("baseSeverity"))
            vector = data.get("vectorString")
            break

    return {
        "description": description,
        "cvss": cvss,
        "severity": severity,
        "vector": vector,
        "published": cve.get("published", ""),
        "references": [r.get("url") for r in cve.get("references", []) if r.get("url")],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Display
# ─────────────────────────────────────────────────────────────────────────────

def _severity_color(severity):
    s = (severity or "").upper()
    if s in ("CRITICAL", "HIGH"):
        return color.RED
    if s == "MEDIUM":
        return color.ORANGE
    return None


def print_cve_info(cve_id, kev=None, nvd_key=None):
    """Print an NVD + CISA KEV report for a CVE id."""
    cve_id = cve_id.upper().strip()
    print("\n\n\n" + color.BOLD + "CVE Report for " + cve_id + ":" + color.END)

    # ── CISA KEV (the highest-signal field — show it first) ───────────────────
    kev = kev if kev is not None else get_cisa_kev()
    entry = kev.get(cve_id)
    print(color.UNDERLINE + '\nCISA Known Exploited Vulnerabilities:' + color.END)
    if entry:
        print("\t{:<34} {}".format(color.RED + 'On CISA KEV:' + color.END,
                                   color.RED + 'YES — known exploited' + color.END))
        print('\t{:<25} {}'.format('Date Added:',   entry.get('dateAdded', 'N/A')))
        print('\t{:<25} {}'.format('Vulnerability:', entry.get('vulnerabilityName', 'N/A')))
        print('\t{:<25} {}'.format('Required Action:', entry.get('requiredAction', 'N/A')))
        print('\t{:<25} {}'.format('Due Date:',     entry.get('dueDate', 'N/A')))
        ransom = entry.get('knownRansomwareCampaignUse', 'Unknown')
        if str(ransom).lower() == 'known':
            print("\t{:<34} {}".format(color.RED + 'Ransomware Use:' + color.END,
                                       color.RED + 'Known' + color.END))
        else:
            print('\t{:<25} {}'.format('Ransomware Use:', ransom))
    else:
        print('\t{:<25} {}'.format('On CISA KEV:', 'No'))

    # ── NVD details ───────────────────────────────────────────────────────────
    nvd = parse_nvd(_fetch_nvd(cve_id, nvd_key))
    print(color.UNDERLINE + '\nNVD Details:' + color.END)
    if not nvd:
        print('\tNo NVD record found (or NVD unreachable).')
        print("\thttps://nvd.nist.gov/vuln/detail/" + cve_id)
        return

    if nvd["cvss"] is not None:
        c = _severity_color(nvd["severity"])
        label = '%s (%s)' % (nvd["cvss"], nvd["severity"] or 'N/A')
        if c:
            print('\t{:<34} {}'.format(c + 'CVSS Base Score:' + color.END, c + label + color.END))
        else:
            print('\t{:<25} {}'.format('CVSS Base Score:', label))
        if nvd["vector"]:
            print('\t{:<25} {}'.format('Vector:', nvd["vector"]))
    else:
        print('\t{:<25} {}'.format('CVSS Base Score:', 'Not scored yet'))

    print('\t{:<25} {}'.format('Published:', (nvd["published"] or 'N/A')[:10]))

    print(color.UNDERLINE + '\nDescription:' + color.END)
    print('\t' + (nvd["description"] or 'No description available.'))

    if nvd["references"]:
        print(color.UNDERLINE + '\nReferences:' + color.END)
        for ref in nvd["references"][:5]:
            print('\t' + ref)

    print("\nhttps://nvd.nist.gov/vuln/detail/" + cve_id)
