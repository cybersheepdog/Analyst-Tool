# Analyst Tool — Code Review (2026-09-25)

Scope: every `.py` module, `config.ini`, `requirements.txt`, and the user docs.
Items marked **verified** were reproduced against the code on this machine
(with the installed `validators`, `stix2`, `elasticsearch`, `OTXv2`, `shodan`).
Effort: S = under an hour, M = an afternoon, L = a few days. Line numbers are
approximate.

## Status

Implemented 2026-09-25 (see git history): **A1** bounded verdict scrape +
"signals unavailable" / "(incomplete)"; **A2** not-found vs error split for
VirusTotal, AbuseIPDB, OTX and Shodan with `not_found_hours`; **A3** OTX/Shodan/
whois/PTR timeouts, one shared pool, `lookup_deadline_seconds`; **A4** IPv6 via
`ipaddress` through the full IP report; plus from A15 the "re-run every task on
verdict failure" fallback, the `_hostname_of` IPv6/`[abc` cases, and the
`vt_api_count` abort. Everything else below is still open.

## Top 10 by value ÷ effort

| # | Item | Effort |
|---|------|--------|
| 1 | Verdict attributes OpenCTI's score to VirusTotal (A1) | S now / M properly |
| 2 | VT error responses cached as "not found" for 7 days (A2) | S |
| 3 | No timeout on OTX / Shodan; report waits for the slowest service (A3, B1) | M |
| 4 | IPv6 detection matches no real IPv6 address (A4) | S |
| 5 | `IP:port`, `host/path`, trailing-dot FQDNs, filenames — silent or wrong (A5, A6) | M |
| 6 | Main loop swallows every exception silently (A7) | S |
| 7 | C2Live result excluded from verdict and `>>report` (A8) | S |
| 8 | Startup stalls: MITRE client, remote-config retries, serial feed downloads (B2–B4) | S each |
| 9 | Batch IOC extraction from free text on the clipboard (C1) | M |
| 10 | One indicator classifier with a test table (D1) | M |

---

## A. Correctness

### A1. Verdict misattributes OpenCTI's score to VirusTotal — **verified**
`analyst_tool_verdict.py` `_int_after()` searches forward from the VT anchor to
the *end of the report* for the next `Malicious:` line, and falls back to the
whole report when the anchor is missing. OpenCTI prints its own `Malicious:`
(0–100 score). Reproduced: a hash VT has never seen + OpenCTI score 40 (below
OpenCTI's own 50 threshold) → `VERDICT: Likely malicious — VirusTotal 40
malicious`. Triggers on every hash VT lacks, on domain/URL VT 404s, and on any
VT task error.
**Fix (S):** bound each scrape to its own block (slice from the VT header to the
next service header) and return `None` when the anchor is absent.
**Fix (M, right answer):** each `_*_live` returns a small signals dict alongside
its printed text; cache both; build the verdict from the dicts, not from
ANSI-coloured console output. This also un-breaks the verdict whenever a column
width or header wording changes.

### A2. VT error responses are printed as "not found" and cached — **verified by reading**
`analyst_tool_virus_total.py` hash/domain paths `json.loads(response.text)`
without a status check, then `try: resp['data'] except: print('not found')`.
429 (quota), 401, 403 and 5xx bodies all lack `data`. Because `cached_call`
stores whatever the live function printed unless it *raises*, the "not found"
is served for `freshness_days`. Scenario: quota exhausted at 4pm → every hash
copied for the rest of the week reads "not found". The URL path has the inverse
problem: a real 404 raises `KeyError: 'data'`, prints `[error in _vt]: 'data'`,
and is re-queried (and re-billed) on every copy.
**Fix (S):** check `status_code` first: 404 → cacheable "not found"; anything
else non-200 → raise with VT's `error.message` so it stays out of the cache.
Same pattern for AbuseIPDB (`abuse_ip_report['data']`), OTX (`NotFound` raises
with an empty message → `[error in _otx]: `), and Shodan (`APIError('No
information available')` treated as an error instead of a cacheable miss).

### A3. OTX and Shodan calls have no timeout — **verified in SDK source**
`OTXv2.get()` and `shodan.Shodan._request()` call `session.get()` with no
`timeout`; OTXv2 also mounts `Retry(total=5, backoff_factor=1)` (~31 s of
retries on 429/5xx). `ipwhois` (`retry_count=3` + referrals) and
`socket.gethostbyaddr` in `check_vpn` / `reverse_ptr` are likewise unbounded.
`_run_parallel_capture` joins *all* futures with no deadline and `with
ThreadPoolExecutor` blocks on exit, so one black-holed connection freezes the
clipboard loop with no message. The `analyst()` docstring's "all network calls
carry a 10 s timeout" is not true for these.
**Fix (M):** wrap the OTX/Shodan sessions' `request` with
`functools.partial(..., timeout=10)` after construction; one process-wide
executor; `as_completed(futures, timeout=BUDGET)` and print `[timed out]
<service>` for stragglers (see B1 for printing early).

### A4. IPv6 regex matches no real IPv6 address — **verified**
`analyst.py` `ipv6_regex = '^([0-9a-fA-F]{0,4}:){6}[0-9a-fA-F]{0,4}$'` requires
exactly seven groups. `2001:db8::1`, `::1`, `fe80::1` and the full 8-group form
all fail; `1:2:3:4:5:6:7` (invalid) passes. Everything falls through to
`IPv4Address()` which raises into the silent handler (A7). README advertises
IPv6.
**Fix (S):** `ipaddress.ip_address(v)` and branch on `.version`; route v6
through `get_ip_analysis_results` (VT, AbuseIPDB, OTX accept v6; skip the
v4-only X4BNet lists).

### A5. `host:port`, `host/path`, `ip/cidr`, trailing-dot FQDNs are dropped silently — **verified**
`8.8.8.8:443`, `evil.com:8080`, `example.com/path`, `8.8.8.8/32`, `evil.com.`
match no branch; the final `IPv4Address()` raises and A7 eats it. These are the
most common shapes copied from firewall / proxy / Zeek logs. The `[EXCLUSIONS]`
comment implies `192.168.1.42:8080` is understood.
**Fix (M):** normalise before classifying: strip trailing `.`, split off
`:port` and `/path`, run the host through the IP/domain pipeline, and when a
path is present also run the URL pipeline with `http://` prefixed.

### A6. Filenames and dotted identifiers trigger full domain lookups — **verified**
`validators.domain()` returns `True` for `report.docx`, `kernel32.dll`,
`first.last`, `Invoice.pdf`, `readme.md`. Each false positive spends a VT
call, an OTX call, an OpenCTI query, live DNS from the workstation, and up to
20 s on crt.sh. Only LOLBAS/LOLDrivers extensions are caught first, and those
lookups are case-sensitive (`certutil.exe` vs the catalogue's `Certutil.exe`)
and match extensions without the dot.
**Fix (S):** gate domains on a cached IANA TLD list (same pattern as
`iana_ports.csv`); lowercase LOLBAS keys and use `os.path.basename()`; keep `!`
as the override.

### A7. Main loop swallows every exception — **verified by reading**
`analyst.py` `except Exception: sleep_time = 1` around the whole dispatch. A
crash in `print_cve_info`, `mitre.lookup`, `print_converted_epoch_timestamp`,
`is_excluded_domain` (raises `ValueError` on text with an unbalanced `[`), or
`ip_whois` (below) prints a SCAN banner and then nothing. Combined with
`logging.disable(sys.maxsize)` at import, the tool is undebuggable in the field.
**Fix (S):** print `[error] <Type>: <msg>` and log a traceback to a rotating
`analyst_tool.log`; silence noisy libraries by name instead of globally.

### A8. C2Live excluded from the verdict and from `>>report`
`query_c2live()` runs *after* `get_ip_analysis_results()` returns, outside the
capture. A C2 framework hit — the strongest IP signal the tool has — never
changes the verdict line and never reaches the export. Same for the IP heading,
TEAM NOTES and MULTI-USER NOTICE (emitted before capture starts).
Also: `es.search(index=…, body=query)` — `body=` was removed in
elasticsearch-py 9 (**9.5.0 is installed here**), so every C2Live query
currently fails with "unexpected keyword"; and First/Last Seen are computed
from the default 10 hits, not the full history.
**Fix (S):** make `_c2live` a task in the IP list; `es.search(query=…,
size=0, aggs=…)` for min/max per framework; teach `build_verdict` about a
`Framework:` line.

### A9. `>>note` after a CVE / MITRE / IPv6 / pulse lookup attaches to the *previous* indicator
`last_indicator` is only set in the hash / domain / URL / public-IP branches.
Analyst looks up `CVE-2024-3400`, types `>>note exploited on VPN-01`, and the
note lands on the last IP with a green "[+] Note saved for 45.145.66.165" that
is easy to miss. Shared-intel integrity bug.
**Fix (S):** set `last_indicator = (cve.upper(), 'cve')` in the CVE branch and
`last_indicator = None` for non-annotatable types so `>>note` refuses rather
than misfiles.

### A10. MITRE tactics refresh can never succeed — **verified**
`analyst_tool_mitre.py` serialises techniques via `json.loads(t.serialize())`
but `json.dump`s the tactics directly. stix2 objects are `Mapping`s, not
`dict`s → `TypeError: Object of type … is not JSON serializable` → caught →
falls back to the stale file or `[]`. On a fresh install `TA0001` prints
nothing.
**Fix (S):** `[json.loads(t.serialize()) for t in get_enterprise_tactics()]`.

### A11. OpenCTI: fuzzy first-hit, missing headers, base-URL slicing, `None` scores
- `indicator.list(search=…)` is full-text; `_extract_common_fields` takes
  `results[0]`. `8.8.8.8` can return `18.8.8.80`'s indicator. Only the URL path
  filters on exact `name`.
- `print_opencti_url_results` is called from `analyst.py` **without**
  `opencti_headers`, and returns early when it is `None` → a found URL prints
  only the header.
- `base_url = url[:-8]` assumes the API URL ends in `/graphql`; the
  `opencti_base_url` config key is documented but never read.
- `int(score)` / `int(confidence)` raise on `null` → whole block lost.
- TLP loop keeps the *last* marking, not the most restrictive.
**Fix (S each):** exact-name filter; pass the headers; `re.sub(r'/graphql/?$',
'', url)` or read `opencti_base_url`; `int(x or 0)`; max TLP.

### A12. `ip_whois` org regex aborts the whole IP Information section — **verified**
`re.match('([a-zA-Z0-9 .,_")(-]+)\n?', desc).group(1)` → `AttributeError` when
the description starts with `'`, `[`, `&` or a non-ASCII letter; `AT&T
Services` prints as `AT`, `Société Générale` as `Soci`. `ip_network(cidr)`
raises on multi-CIDR strings. All swallowed by `_whois_tor`'s `except: pass`,
so Organization, CIDR, Range, Country and abuse contacts vanish silently.
**Fix (S):** `desc.splitlines()[0]`; prefer `lookup_rdap(depth=0)`; always
print ASN (today only when no org was found).

### A13. VT IP/domain "Malicious" undercounts
`print_ip_detections` / `print_domain_detections` count engines whose `result
== 'malicious'`; VT engines flagging IPs/domains usually return `malware` or
`phishing` with `category == malicious`. An IP with eight "malware" verdicts
prints `Malicious: 0`. VT already supplies `last_analysis_stats` (the hash
path uses it). The `'time out'` key never matches VT's `timeout`.
**Fix (S):** use `last_analysis_stats`; list the top 5 `engine: result`.

### A14. PostgreSQL pool poisoned by a dropped connection
`PostgresBackend._cursor()`: after a server restart / VPN blip the dead
connection is `putconn`'d back; every `cached_call` then swallows the error and
goes live (quota burns silently) and `>>note` prints "server closed the
connection" forever. The pool is built without `connect_timeout` (unlike
`_connect()` in `shared_config`).
**Fix (S):** on `OperationalError`/`InterfaceError` → `putconn(conn,
close=True)`, re-raise, print one "cache backend lost, reconnecting" line;
`connect_timeout=5`.

### A15. Smaller items (S each)
- `_run_with_verdict` on *any* exception after capture re-runs every task via
  `_run_parallel` → double API spend and double cache writes. Print `combined`
  instead.
- `CacheManager._norm` lowercases whole URLs → `http://x/A` and `http://x/a`
  share one cache row though VT treats them differently. Lowercase scheme+host
  only.
- `_hostname_of('2001:db8::1')` → `'2001'`; `_hostname_of('[abc')` raises.
- Private-IP branch labels `127.0.0.1`, `169.254.x`, `0.0.0.0` as "RFC1918";
  CGNAT `100.64/10` and multicast `224/4` go to every paid API. Use
  `is_global` and print the real reason.
- `refang`: `" dot "` is rewritten anywhere (`alice dot smith` → `alice.smith`);
  `hxxp` replaced mid-word (`shxxpell` → `shttpell`); `evil (dot) com`,
  `evil\.com`, `fxp://` unhandled. `sanitize_url`: `HTTPS://x` → `hxxp:HTTPS://x`.
- Postgres `add_exclusion` is SELECT-then-INSERT with no unique index →
  concurrent `>>exclude` inserts duplicates. `UNIQUE(domain)` + `ON CONFLICT`.
- OTX URL link uses `/indicator/domain/` (should be `/url/`); passive-DNS
  entries print only when count ≤ 5 — for 6+ nothing is shown.
- crt.sh subdomain filter `name.endswith(domain)` counts `notevil.com` as a
  subdomain of `evil.com`.
- `mitre_tactic_regex` has an unanchored middle alternative and a literal `,`
  in a class. `^TA\d{4}$`.
- Blank `enabled =` in `[CACHE]` disables caching (`""` is in the false tuple)
  though the docs say the default is on.
- `vt_api_count` is a serial extra HTTP call per lookup, counted against the
  quota it checks, and a 404/429 on it aborts the VT hash report.
- Feeds loaded at startup (KEV, LOLBAS, LOLDrivers, MITRE, Windows events)
  never refresh in a long-running session; only Tor/VPN/datacenter re-check age.
- `[error in …]: {exc}` puts raw exception text into the captured report that
  `>>report` exports. Redact `key=`/`token=` patterns as cheap insurance.
  `shared_config` `set` takes the API key on argv (shell history) — `getpass`
  when omitted.

---

## B. Speed

### B1. The report waits for the slowest service (M)
`_run_parallel_capture` joins everything before printing the verdict. crt.sh
(20 s timeout, routinely slow or 502), OTX retries, Shodan, and OS-resolver PTR
timeouts each gate VT/AbuseIPDB results that finished in under a second.
**Fix:** two-phase print — wait on the reputation tasks (VT, AbuseIPDB, OTX,
OpenCTI, C2Live) with a ~12 s budget, print verdict + those sections, then
append the slow sections as they land with a `(late)` marker and list "signals
unavailable: OTX (timeout)" in the verdict so silence isn't read as clean.
Cache DNS/crt.sh through `cached_call` with a 1-day freshness.

### B2. Startup: MITRE client built even when the JSON cache is fresh (S)
`AsyncAnalystToolMitre.__init__` calls `attack_client()` *before* `_load_data()`
checks the 90-day file cache, and imports `attackcti` (+ stix2, taxii2client,
pydantic) eagerly. Build the client lazily inside the refresh branch.

### B3. Startup: unreachable remote DB → ~35–40 s stall (S)
`shared_config.load_config()` caches only on success; each of the ~8
`create_*_from_config()` calls at startup redoes `psycopg2.connect(
connect_timeout=5)`. Cache the negative result for the process and print one
"shared config unavailable, using local keys" line.

### B4. First IP lookup downloads three feeds serially inside the report (S)
`_whois_tor` → `check_tor` (10 s) → `check_vpn` (PTR + 15 s) →
`check_datacenter` (20 s, multi-MB + `collapse_addresses` over tens of
thousands of CIDRs), all under the first IP's fan-out while the verdict waits.
KEV / LOLBAS / LOLDrivers / IANA downloads are serial at startup too.
**Fix:** one daemon prefetch thread right after "Analyst Tool Initialized."
(the loaders are already lock-protected); split tor/vpn/datacenter into their
own task so whois latency doesn't gate them.

### B5. Serial work inside services (S each)
- OTX IP: three serial calls (`general`, `reputation`, `passive_dns`);
  `general` already contains `reputation`.
- DNS: N serial PTRs (CDN domains have 8+ A records) → MX (8 s) → NS (8 s) →
  crt.sh. Pool of 4; cap PTRs at 5.
- OpenCTI `indicator.list` defaults to `first=500` with the full attribute
  set. `first=10` + `customAttributes` for the ~12 fields printed; back-off when
  client construction fails (pycti health-checks on construct, so an OpenCTI
  outage costs a retry per lookup).
- MITRE `lookup` is `async` for a synchronous dict scan; `_run_coro` spawns a
  thread + event loop per lookup, and the scan is O(techniques × refs). Index
  by `external_id` once at load.
- A new `ThreadPoolExecutor` per lookup; each new thread opens a fresh
  thread-local sqlite connection. One process-wide executor.

### B6. DB round trips on the critical path (S)
`print_team_notes` + `record_check_and_alert` = 3 queries serially on the main
thread before the fan-out; each cached service does `get_fresh_row` +
`record_hit`. `list_notes` fetches every row for an indicator and slices in
Python; `list_history` sorts an unindexed, never-purged `indicator_checks`.
**Fix:** `UPDATE … RETURNING` for hit+count; `LIMIT` in `list_notes`; index
`indicator_checks(username, checked_at DESC)`; purge checks older than
`check_window_days` in `startup()`; `PRAGMA journal_mode=WAL` on SQLite.

### B7. Heavy imports for unconfigured services (S)
`IPython`, `attackcti`, `pycti`, `elasticsearch`, `shodan`, `OTXv2` are
imported eagerly via `from … import *` regardless of config. Lazy-import inside
each `create_*_from_config` success path. `python -X importtime analyst.py`
will show the cost.

### B8. Clipboard events lost while a lookup runs (M)
The lookup runs on the polling thread; copies made during an 8–20 s report are
never seen (only the latest clipboard value is), and re-copying the same value
is a no-op. On Windows, `GetClipboardSequenceNumber()` is a µs call that
detects a re-copy of identical text as a new event and avoids opening the
clipboard every second (the contention the poll-loop fix works around).
**Fix:** poll thread pushes distinct values onto a `queue.Queue`; a worker
thread runs lookups; use the sequence number on Windows.

---

## C. Analyst usefulness

### C1. Batch / free-text IOC extraction (M) — biggest workflow win
Today the clipboard must hold exactly one clean indicator; a pasted alert
body, email header block, or a list of 20 IPs from a report yields nothing.
If the clipboard contains whitespace/newlines, run refang + the regex set over
it, dedupe, print a numbered triage table (`# type indicator cached? notes?`)
with a one-line verdict each, and `>>full 3` to expand one. Cap at N with a
prompt to avoid quota surprises.

### C2. Verdict should use all the signals it already has, and team tags should override (M)
C2Live ignored (A8); OTX pulse count is context only for IPs; Tor/VPN/
datacenter never affect severity; KEV/CVSS not surfaced for CVEs (there is no
CVE verdict at all); AbuseIPDB < 40 % ignored even with hundreds of reports;
Shodan `tags`/`vulns` unused. **Team notes tagged `#fp`/`#benign` don't
downgrade and `#c2`/`#malware` don't upgrade** — a red verdict prints directly
under a green `[fp]` pill. "No strong reputation signals" reads as *clean* to a
tired analyst; distinguish "Unknown / new" (recent first-seen, datacenter, no
VT history). Show which signals were unavailable.

### C3. Active DNS vs the "passive only" claim (S)
README/USER_GUIDE promise passive lookups, but `resolve_addresses`
(`getaddrinfo`), MX/NS via dnspython, and the PTRs in `check_vpn` /
`reverse_ptr` send live queries from the analyst's workstation that reach the
attacker's authoritative nameserver. For a SOC tool this is an OPSEC issue.
`[DNS] active_resolution = false` by default; when off, use OTX `passive_dns`
and VT `resolutions` (both already one call away) and label the section
"Passive DNS".

### C4. Ticket-ready summary block on the console (S)
End each report with six copy-paste lines: defanged indicator, verdict, VT
x/y + top 3 engine names, AbuseIPDB % / reports, ASN · org · country,
first/last seen, links. `>>report` exists, but the console is where people
copy from.

### C5. Pivoting without retyping (S/M)
Reports print related artefacts (Shodan hostnames, OTX passive DNS, crt.sh
subdomains, VT contacted IPs/domains) defanged, so copying one is fiddly.
Number pivotable artefacts (`[1] 45.145.66.0/23  [2] tor-exit0.dfri.se`) and
support `>>pivot 2`; add a "Related" section per report; add the verdict to
`>>history` rows so a shift summary is one command. Add `>>refresh` (re-run
last indicator live) and show cache age in the verdict line (`VT cached 3d`).

### C6. `>>report` omissions (S)
Missing: TEAM NOTES, MULTI-USER NOTICE, C2Live, the IP heading, and all
CVE/port/MITRE lookups (`record_report` is wired for four types). `defang_text`
also rewrites the tool's own reference links, so the ticket's pivot links are
dead. Keep hosts on the reference-domain list intact; add `>>report json`
(structured signals from A1) for SOAR ingestion.

### C7. Consistency: defanging, timestamps, section layout (S–M)
- Shodan, DNS and OpenCTI-domain bracket dots; VT, OTX and OpenCTI-IP print
  raw; OpenCTI-URL uses `hXXP`. One `defang()` helper + a `[GENERAL]` flag.
- VT epochs render as naive local time; AbuseIPDB/OTX/OpenCTI print ISO UTC.
  Print UTC everywhere (`…Z`), and for the epoch converter print UTC + local +
  ISO on one line; accept Windows FILETIME (18 digits) and LDAP timestamps.
- Four header styles, a "VirusToal" typo, column widths hand-tuned around
  ANSI codes. Two helpers — `section(title, indicator)` and `kv(label, value,
  level)` padding on visible length — fix all of it and make A1's parser
  trivial. The `>=10 red / >=5 orange` block is copy-pasted ~12 times.
- Windows consoles: ANSI escapes render as `←[31m` in legacy cmd/PowerShell 5.
  `colorama.just_fix_windows_console()` or `SetConsoleMode(…, 0x7)` at startup;
  respect `NO_COLOR`.

### C8. Per-service enrichment already in the responses you fetch (M total)
- **VT hash:** `meaningful_name`, all three hashes (pivot from an MD5),
  `type_tag`, `tags`, `popular_threat_classification.suggested_threat_label`
  (the single best label), `sandbox_verdicts`, crowdsourced YARA/IDS rule names,
  `total_votes`, `pe_info.imphash`; `?relationships=contacted_domains,
  contacted_ips,execution_parents` in the same call.
- **VT IP:** `as_owner`, `asn`, `network`, `reputation`, `last_https_certificate`
  CN/SAN, `?relationships=resolutions,communicating_files`.
- **VT domain:** `categories` (fastest "is this ads/CDN/SaaS" triage),
  `popularity_ranks` (instant benign signal), `registrar`, `last_dns_records`.
- **VT URL:** `final_url`, `title`, `last_http_response_code`, `redirection_chain`.
  Lowercase scheme+host before base64-encoding (VT ids derive from the canonical
  URL, so mixed-case hosts 404 on URLs VT knows).
- **AbuseIPDB:** `verbose` → per-report categories (histogram the top 3: SSH
  brute force, port scan, web-app attack…), 2 most recent comments, `isTor`,
  `isWhitelisted`, `isp`, `hostnames`; use `X-RateLimit-Limit` instead of the
  hard-coded 1000; surface `errors[0].detail` instead of "Issue with Abuse IP DB
  API."
- **Shodan:** `vulns` cross-referenced against the local KEV dict ("2 KEV CVEs
  exposed" is free), `tags` (`vpn`, `proxy`, `tor`, `c2`, `honeypot`,
  `self-signed`), `os`, per-service `port product version`, `http.title`,
  `ssl.cert.subject.CN`, `ssl.jarm`. Generalise the C2 check to any product in a
  C2 list (Cobalt Strike, Sliver, Havoc, Mythic, Brute Ratel…) or the `c2` tag.
- **OTX:** 5 most recent pulses overall (name, author, `adversary`,
  `malware_families`, `attack_ids`) — today only configured providers are
  detailed; `general.validation[]` (whitelist reasons like "Alexa top 1M" — the
  best FP guard OTX offers); hash `analysis.plugins.*.results.detection` (free
  multi-AV); URL `url_list` (Safe Browsing verdict).
- **OpenCTI:** match count, `pattern`, `description`, `killChainPhases`,
  `externalReferences`, related reports, highest TLP.
- **CVE:** EPSS score + percentile (`api.first.org`, no key), CWE ids,
  `vulnStatus`, top affected CPEs, and NVD `references[].tags` — show `Exploit`
  / `Patch` / `Vendor Advisory` refs first (the data is already in the response
  and currently dropped). Prefer the `Primary` CVSS metric over `[0]`.
  Distinguish NVD 403/503 from "not found".
- **MITRE:** technique URL on the parent path, all `kill_chain_phases`,
  platforms, data sources, list of sub-techniques, skip `revoked`/deprecated.
- **LOLDrivers:** build a hash index from `KnownVulnerableSamples[]` at load and
  check it in the **hash** branch — an offline "known BYOVD driver" hit is
  instant and free, before VT. Print `Category` and `LoadsDespiteHVCI`.

### C9. Startup status table and `>>status` (S)
One screen at startup: service → configured / key source (local | shared) /
last error. Today it is ~15 scattered lines including "No VT User. Please
add…" on every launch.

---

## D. Maintainability

### D1. One indicator classifier, with a test table (M)
Four divergent classifiers: the main `if/elif` chain, `_indicator_type`
(different order, no port/epoch), `_is_recognized_indicator`, and
`annotate._guess_type` (accepts IPv6, defaults unknowns to `domain`).
Consequence: `annotate.py add 2001:db8::1 …` stores type `ip`, but
`>>note 2001:db8::1 …` treats the address as note *text* on the last indicator.
`classify(value) -> (type, normalized)` in utilities, table-driven, with a
pytest table of every edge case in section A. This is the fix that carries
A4, A5, A6, A9 and A15's IP cases.

### D2. One HTTP helper (M)
Three copies of `_get_session` (the `analyst.py` one is unused) plus eight
module-level `requests.Session`s shared across worker threads. One
`api_get(service, url, *, headers, params, timeout=10, not_found=(404,))`:
per-thread session, `Retry(total=2, backoff_factor=0.5,
status_forcelist=[429,500,502,503,504], respect_retry_after_header=True)`,
the existing SSL policy, always a timeout, raises `NotFound` (cacheable) vs
`ServiceError(service, status, message)` (not cached, stale-while-error).
Fixes A2, A3's requests-based half, and the inconsistent error strings in one
place.

### D3. Structured results instead of scraping printed text (L, incremental)
Each service: `fetch(ioc) -> dict` (injectable session), `render(dict) ->
str`. Verdict, `>>report json`, and the cache work on data. Start with VT and
AbuseIPDB — the verdict's main inputs — and A1 disappears.

### D4. Logging (S)
`logging.disable(sys.maxsize)` at import; five bare `except Exception:
pass/return` in `cached_call` alone. `logging.getLogger('analyst')` → rotating
`analyst_tool.log`; silence `taxii2client`, `urllib3`, `elasticsearch` by name;
stdout stays for the report.

### D5. Paths relative to CWD (S)
`config.ini`, `analyst_cache.db`, `reports/`, every feed file and JSON cache
are bare relative names. Launching from a shortcut with a different "Start in"
yields "Error with config.ini.", an empty new cache, and a full re-download of
every feed. Anchor on `os.path.dirname(os.path.abspath(__file__))` (or
`ANALYST_TOOL_HOME`) in one `paths.py`.

### D6. Config validation (S)
Every parse error silently falls back (`freshness_days = seven` → 7.0;
`backend = postgres` → local; `port = abc` → 5432); unknown keys are ignored,
so a typo'd `[VIRUS_TOTAL]` key just means "not configured". A
`validate_config()` that warns on unparsable values and unknown keys, and
errors on `backend = remote` without host/dbname. Route the five ad-hoc
`ConfigParser` readers (`get_ssl_verify_from_config`, exclusions, events feed,
passphrase, NVD key) through `load_config()`.

### D7. `requirements.txt` (S)
`pandas` and `aiohttp` are imported nowhere; `configparser` is a py2 backport
that can shadow the stdlib; `IPython`, `psycopg2-binary`, `cryptography`,
`dnspython`, `elasticsearch`, `pycti`, `shodan`, `OTXv2` are optional per config
yet mandatory to install; nothing is pinned (VT/OTX/pycti/elasticsearch break
between majors — see A8). Core + `requirements-optional.txt`, `~=` pins.

### D8. Schema evolution (M)
`_ensure_schema` runs DDL on every start (a read-only DB role disables the
whole cache) and there is no version/migration path — needed for a real `id`
primary key on `indicator_annotations` (drops the rowid/ctid dedupe), the
unique exclusion index, and B6's indexes. A `schema_version` table + ordered
migrations; tolerate "permission denied" on DDL when the tables exist.

### D9. Dead code and star imports (S)
`analyst.py` star-imports nine modules and gets `requests` transitively;
`virus_total.py` redefines `class color`. Dead: `_get_session`/`_thread_local`
in `analyst.py`, `creation_date_regex`, utilities `is_ip_address`,
`is_port_or_weivd`, `open_*_page`, the OTX MITRE helpers (which pull
attackcti/IPython into the OTX import chain). `ruff --select
F401,F403,F405,F811` enumerates them.

### D10. Testability (M)
`analyst()` is a 250-line function mixing config load, I/O, classification,
dispatch and sleep. Split into `load_services()`, `classify()`,
`dispatch(indicator, services)`, `run_loop(clipboard_source, dispatch)` with an
injectable clipboard source so the loop can be driven by a list in tests. Keep
real API JSON fixtures per service.

### D11. Windows / pyperclip specifics (S)
`pyperclip.copy()` in `>>report clip` can fail on lock contention like `paste()`
— retry briefly. `input()` for `>>note` raises `EOFError` under pythonw / a
shortcut without a console and the note is silently dropped — print a message.
The `ssl_verify = false` retry sets `simplefilter("ignore",
InsecureRequestWarning)` globally — restrict to the tool's sessions.

---

## Suggested order

1. **A2 + A3 + D2** together — status handling, not-found vs error, timeouts,
   retries. One change fixes the cache poisoning, the blank OTX errors, and the
   hang risk.
2. **A1 + A13** — verdict correctness. Small, high trust impact.
3. **D1** carrying **A4, A5, A6, A9, A15-IP** — detection, with tests.
4. **A8, A10, A11, A12** — each is a silent data-loss bug.
5. **B1–B4, B7** — the visible speed win (seconds per lookup, tens of seconds
   per launch).
6. **C2, C4, C7** — verdict coverage, summary block, defang/UTC policy.
7. **C1** — batch extraction; **B8** — queue + clipboard sequence number.
8. Per-service enrichment (C8) as time allows.

## Fixed during this review

- `delete_notes_by_ids` (PostgreSQL) deleted by `ctid` alone although its
  docstring claimed an owner re-check. A ctid is a physical slot that can be
  reused after delete + VACUUM, so a stale id could in principle reach another
  analyst's note. Both backends now take the owner and delete only that user's
  rows; `dedupe_notes` passes it; regression test added.
