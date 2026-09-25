# Analyst Tool
# Author: Jeremy Wiedner (@JeremyWiedner)
# License: BSD 3-Clause
# Purpose: To help automate some of an analyst workflow as much as possible. Simply copy a Domain, Hash, IP Address, Port # or Windows Event ID and the main script will pull the
#coding: utf-8

# Python Standard Library Imports
import asyncio
import ipaddress
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeoutError
import threading

# 3rd Party Imports
import validators
from ipwhois import IPWhois
from pyperclip import paste

# Custom Imports
from analyst_tool_abuseip import *
from analyst_tool_cache import build_cache_manager
from analyst_tool_c2live import get_c2live_config, query_c2live
from analyst_tool_cve import cve_regex, print_cve_info, get_cisa_kev, get_nvd_key_from_config
from analyst_tool_dns import print_dns_and_crt
from analyst_tool_portwevid import print_port_and_wevid
from analyst_tool_report import get_report_buffer, record_report
from analyst_tool_lols import *
from analyst_tool_mitre import *
from analyst_tool_opencti import *
from analyst_tool_otx import *
from analyst_tool_utilities import *
# `import *` skips underscore-prefixed names, so import the host helper explicitly
# (used by the >>exclude command handler).
from analyst_tool_utilities import _hostname_of
from analyst_tool_virus_total import *
from analyst_tool_shodan import *

# disables python info printout to jupyter notebook
logging.disable(sys.maxsize)

# Regex to be used in the main loop of the Jupyter Notebook
epoch_regex = '^[0-9]{10,16}(\.[0-9]{0,6})?$'
otx_pulse_regex = '^[0-9a-fA-F]{24}$'
hash_validation_regex = '^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
port_wid_validation_regex = '^[0-9]{1,5}$'
# IPv6 is detected with ipaddress.ip_address() (see parse_ip in utilities);
# the old 7-group regex matched no real IPv6 address. Kept for compatibility.
ipv6_regex = r'^(?=.*:)[0-9a-fA-F:.]+$'
# Gate regex for MITRE ATT&CK IDs: tactic (TA####), technique (T####) or
# sub-technique (T####.###). The AsyncAnalystToolMitre.lookup() method then
# does its own finer-grained matching to pick the correct handler.
mitre_regex = r'^TA[0-9]{4}$|^T[0-9]{4}(\.[0-9]{3})?$'

# Other Regex
# Regex to pull the created date out of whois info for a domain
creation_date_regex = 'created: ([0-9T:-]+)'

# Thread-local storage so each thread gets its own requests.Session (HTTP keep-alive)
_thread_local = threading.local()

def _get_session():
    """Return a per-thread requests.Session with a default 10s timeout."""
    if not hasattr(_thread_local, 'session'):
        _thread_local.session = requests.Session()
    return _thread_local.session


def _run_coro(coro):
    """Run an async coroutine to completion in any context.

    asyncio.run() raises RuntimeError when an event loop is already running,
    which is the case inside a Jupyter notebook kernel. When that happens we
    execute the coroutine in a short-lived worker thread (which has no running
    loop) so the same call works on a plain terminal and in Jupyter alike.
    """
    try:
        running_loop = asyncio.get_running_loop()
    except RuntimeError:
        running_loop = None

    if running_loop is not None and running_loop.is_running():
        with ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(lambda: asyncio.run(coro)).result()
    return asyncio.run(coro)


def analyst(terminal=0):
    """ The main function of the program.  Runs an infinite loop and checks the contents of
    the clipboard every 1-3 seconds (adaptive) to see if it has changed.  If so it then runs
    a series of checks to determine if it is one of the following:

        Hash (md5, sha1 or sha256)
        Port # or Windows EventID (requires user interaction to choose between the 2 or neither)
        Domain (lots of false positives here. will trigger on things like first.last)
        Mitre Tactics, Techniques & SubTechniques
        Private IP address
        Public IP address
        None of the above

    Optional Parameter:
        terminal:
            Default 0 - allows markdown to be displayed in jupyter notebook output for Mitre ATT&CK functions
            Changing to 1 (or anything else) disables markdown and allows to print to terminal screen)

    PERFORMANCE NOTES:
        - API calls for each indicator are dispatched concurrently (ThreadPoolExecutor).
        - Sleep is adaptive: 1s when idle, 3s after a lookup fires, to improve responsiveness.
        - MITRE data is only re-initialized via attack_client() when the on-disk JSON cache is stale.
        - Every network call carries a per-request timeout, and a whole report waits at most
          [GENERAL] lookup_deadline_seconds (default 20) for its slowest service; a service
          that misses the deadline is reported as "timed out" and the verdict says so.
    """

    abuse_ip_db_headers = create_abuse_ip_db_headers_from_config()
    opencti_headers     = get_opencti_from_config()
    otx                 = create_av_otx_headers_from_config()
    otx_intel_list      = get_otx_intel_list_from_config()
    virus_total_headers = create_virus_total_headers_from_config()
    vt_user             = get_vt_user_from_config()
    c2live_headers      = get_c2live_config()
    shodan_headers      = get_shodan_from_config()

    lolbas = get_lolbas_json(lolbas_url, filename, file_age, current_time, threshold_time)
    driver = get_loldriver_json(loldriver_url, filename2, file_age, current_time, threshold_time)

    # CVE / CISA KEV: load the KEV catalog (cached) and any optional NVD key.
    cve_kev = get_cisa_kev()
    nvd_key = get_nvd_key_from_config()

    # Domains to skip for domain/URL lookups (e.g. the tool's own reference links).
    excluded_domains = get_excluded_domains_from_config()

    # --- MITRE loading ---
    # AsyncAnalystToolMitre handles its own cache check internally.
    # It reads from the on-disk JSON if fresh (90-day window), or calls
    # attack_client() only when the cache is stale. No wrapper needed here.
    mitre = AsyncAnalystToolMitre(terminal=terminal)
    mitre_tactics    = mitre.mitre_tactics
    mitre_techniques = mitre.mitre_techniques

    # --- Result cache ---
    # Serves VirusTotal/AbuseIPDB/Shodan/OTX results from a local SQLite (or
    # shared PostgreSQL) DB when they're younger than freshness_days, to save
    # API calls. Disabled/misconfigured caches degrade to live lookups.
    cache = build_cache_manager()
    cache.startup()

    print("Analyst Tool Initialized.")

    last_seen = get_clipboard_contents()
    last_indicator = None  # (value, type) of the most recent lookup, for >>note
    last_command = (None, 0.0)  # (command text, when it ran) — duplicate guard
    sleep_time = 1  # adaptive: 1s idle, 3s after a lookup

    try:
        while True:
            try:
                check = get_clipboard_contents()
            except TypeError as e:
                print('\n\n\n' + str(e))
                time.sleep(sleep_time)
                continue

            # ── Unreadable / empty clipboard is NOT a change ──────────────────
            # On Windows a poll can land while another process holds the
            # clipboard lock, or in the brief gap between EmptyClipboard() and
            # SetClipboardData() during someone else's copy. paste() then
            # raises (get_clipboard_contents() returns None) or hands back ''.
            # Recording that blank as `last_seen` would make the *unchanged*
            # clipboard look new on the next poll, so the same line gets
            # processed twice — e.g. a >>note saved twice. Skip the poll
            # instead and leave `last_seen` pointing at the real content.
            if not check:
                time.sleep(sleep_time)
                continue

            try:
                if check != last_seen:
                    last_seen = check

                    # ── Clipboard command (>> notes/tags/exclusions) ──────────
                    # Detected regardless of cache state so the user gets feedback
                    # (e.g. "needs the cache enabled") instead of silence. Errors
                    # are surfaced rather than swallowed.
                    if (cache.command_prefix and check
                            and check.startswith(cache.command_prefix)):
                        # Belt-and-braces against a command running twice: the
                        # loop sleeps 3s after every command, so an identical
                        # command re-appearing inside that window can only be a
                        # repeat of the same copy, never a deliberate re-entry.
                        if (check == last_command[0]
                                and time.time() - last_command[1] < 3):
                            time.sleep(sleep_time)
                            continue
                        last_command = (check, time.time())
                        try:
                            last_indicator = _handle_command(
                                check[len(cache.command_prefix):].strip(),
                                cache, last_indicator)
                        except Exception as _cmd_err:
                            print('\t[command error] ' + str(_cmd_err))
                        # A command can change the clipboard itself
                        # (>>report clip). Re-sync so its output isn't picked
                        # up as a brand-new indicator on the next poll.
                        _after = get_clipboard_contents()
                        if _after:
                            last_seen = _after
                        time.sleep(3)
                        continue

                    matched = True  # track whether a lookup fired

                    # Force-refresh: an indicator copied with the configured
                    # prefix (default "!") bypasses the cache for that lookup.
                    force_refresh = False
                    clipboard_contents = check
                    if (cache.enabled and clipboard_contents
                            and cache.force_prefix
                            and clipboard_contents.startswith(cache.force_prefix)):
                        force_refresh = True
                        clipboard_contents = clipboard_contents[
                            len(cache.force_prefix):].strip()

                    # Re-fang defanged IOCs (hxxp, [.], (dot), [at]) so the
                    # detection below matches indicators copied from reports.
                    clipboard_contents = refang(clipboard_contents)

                    # ── Excluded host? ────────────────────────────────────────
                    # Skip anything whose host is on the exclusion list, in ANY
                    # form: bare IP/domain, IP:port, host/path, or a full URL
                    # (e.g. excluding 192.168.1.42 also skips 192.168.1.42:8080
                    # and 192.168.1.42/tool). Local config list + shared DB list.
                    if is_excluded_domain(clipboard_contents,
                                          excluded_domains + list(cache.get_exclusions())):
                        print('\n(Skipped — ' + clipboard_contents
                              + ' is in the exclusion list.)')
                        time.sleep(3)
                        continue

                    # Clear separator banner before a recognized indicator's report.
                    if _is_recognized_indicator(clipboard_contents, lolbas, driver):
                        print_scan_header(clipboard_contents)

                    # ── Hash ──────────────────────────────────────────────────────────────
                    if re.match(hash_validation_regex, clipboard_contents):
                        suspect_hash = clipboard_contents
                        last_indicator = (suspect_hash, 'hash')
                        _lookup_hash_parallel(
                            suspect_hash, virus_total_headers, vt_user,
                            opencti_headers, otx, otx_intel_list,
                            cache=cache, force_refresh=force_refresh
                        )

                    # ── Port / Windows Event ID ───────────────────────────────────────────
                    elif re.match(port_wid_validation_regex, clipboard_contents):
                        print_port_and_wevid(clipboard_contents)

                    # ── LOLBas ────────────────────────────────────────────────────────────
                    elif get_lolbas_file_endings(lolbas, clipboard_contents):
                        lookup_lolbas(lolbas, clipboard_contents)

                    # ── LOLDriver ─────────────────────────────────────────────────────────
                    elif get_loldriver_file_endings(driver, clipboard_contents):
                        lookup_loldriver(driver, clipboard_contents)

                    # ── CVE / CISA KEV ────────────────────────────────────────────────────
                    elif re.match(cve_regex, clipboard_contents, re.IGNORECASE):
                        print_cve_info(clipboard_contents, cve_kev, nvd_key)

                    # ── Domain ────────────────────────────────────────────────────────────
                    elif validators.domain(clipboard_contents) == True:
                        suspect_domain = clipboard_contents
                        last_indicator = (suspect_domain, 'domain')
                        _lookup_domain_parallel(
                            suspect_domain, virus_total_headers, vt_user,
                            opencti_headers, otx, otx_intel_list,
                            cache=cache, force_refresh=force_refresh
                        )

                    # ── URL ───────────────────────────────────────────────────────────────
                    elif validators.url(clipboard_contents) == True:
                        suspect_url = clipboard_contents
                        last_indicator = (suspect_url, 'url')
                        _lookup_url_parallel(
                            suspect_url, virus_total_headers,
                            opencti_headers, otx, otx_intel_list,
                            cache=cache, force_refresh=force_refresh
                        )

                    # ── MITRE ─────────────────────────────────────────────────────────────
                    elif re.match(mitre_regex, clipboard_contents):
                        _run_coro(mitre.lookup(clipboard_contents.strip()))

                    # ── Epoch timestamp ───────────────────────────────────────────────────
                    elif re.match(epoch_regex, clipboard_contents):
                        print_converted_epoch_timestamp(clipboard_contents)

                    # ── OTX Pulse ID ──────────────────────────────────────────────────────
                    elif re.match(otx_pulse_regex, clipboard_contents):
                        suspect_pulse = clipboard_contents
                        print_otx_pulse_info(suspect_pulse, otx, otx_intel_list)

                    # ── IP address (IPv4 or IPv6) ─────────────────────────────────────────
                    # Both versions go through the same report: VirusTotal,
                    # AbuseIPDB, Shodan, OTX and whois all accept IPv6. The
                    # v4-only Tor/VPN/datacenter lists simply answer "No".
                    elif parse_ip(clipboard_contents) is not None:
                        addr = parse_ip(clipboard_contents)
                        if addr.is_private:
                            print('\n\n\nThis is a private (RFC1918 / ULA / link-local) IP Address'
                                  + '\n\n\n')
                        else:
                            suspect_ip = str(addr)   # canonical form (compressed IPv6)
                            last_indicator = (suspect_ip, 'ip')
                            get_ip_analysis_results(
                                suspect_ip, virus_total_headers, abuse_ip_db_headers,
                                otx, otx_intel_list, vt_user, opencti_headers, shodan_headers,
                                cache=cache, force_refresh=force_refresh
                            )
                            query_c2live(suspect_ip, c2live_headers)

                    else:
                        matched = False

                    sleep_time = 3 if matched else 1
                else:
                    sleep_time = 1

            except Exception:
                sleep_time = 1

            time.sleep(sleep_time)
    finally:
        cache.shutdown()


# ─────────────────────────────────────────────────────────────────────────────
# Parallel lookup helpers
# Each helper fans out the API calls for one indicator type concurrently.
# Print order is non-deterministic (first-to-finish prints first).
# ─────────────────────────────────────────────────────────────────────────────

# One process-wide pool. Creating a pool per lookup meant `with ThreadPoolExecutor`
# blocked on exit until every task returned — so a single hung service froze the
# clipboard loop. With a shared pool a lookup can stop waiting at its deadline
# and let the straggler finish (and be discarded) in the background. Sized so
# one lookup's stragglers can never starve the next one: max 6 tasks per report.
_LOOKUP_POOL = ThreadPoolExecutor(max_workers=16, thread_name_prefix='lookup')

# Friendly names for the nested task functions, used in timeout / error lines
# and in the verdict's "signals unavailable" note.
_TASK_LABELS = {
    '_vt': 'VirusTotal', '_otx': 'AlienVault OTX', '_shodan': 'Shodan',
    '_abuseipdb': 'AbuseIPDB', '_opencti': 'OpenCTI', '_whois_tor': 'WhoIs/Tor/VPN',
    '_dns': 'DNS/crt.sh', '_c2live': 'C2Live',
}


def _task_label(task):
    name = getattr(task, '__name__', repr(task))
    return _TASK_LABELS.get(name, name)


def _deadline():
    """Seconds to wait for a report's slowest service; None = no limit."""
    try:
        d = get_lookup_deadline_from_config()
    except Exception:
        d = 20.0
    return d if d and d > 0 else None


def _run_task(task):
    """Run one service task, printing a one-line reason on failure.

    Returns None on success, or a short reason string ('HTTP 429 — ...',
    'timed out', ...) that the verdict reports as an unavailable signal.
    An IndicatorNotFound that escapes (cache disabled) is a normal answer.
    """
    label = _task_label(task)
    try:
        task()
        return None
    except IndicatorNotFound:
        return None
    except ServiceError as exc:
        reason = (("HTTP %s" % exc.status) if exc.status is not None else "unavailable")
        if exc.message:
            reason += " — " + str(exc.message)
        print("\t[%s] unavailable: %s" % (label, reason))
        return reason
    except Exception as exc:
        print("\t[error in %s]: %s" % (getattr(task, '__name__', repr(task)), exc))
        return "error"


def _run_parallel(tasks, max_workers=None):
    """Execute a list of zero-argument callables concurrently (streaming: each
    task prints straight to the console as it finishes). Exceptions inside
    individual tasks are caught and printed so one misbehaving service never
    blocks the others. Stops waiting at the lookup deadline."""
    futures = {_LOOKUP_POOL.submit(_run_task, t): t for t in tasks}
    try:
        for future in as_completed(futures, timeout=_deadline()):
            future.result()
    except FuturesTimeoutError:
        for future, task in futures.items():
            if not future.done():
                future.cancel()
                print("\t[%s] timed out after %.0fs" % (_task_label(task), _deadline()))


def _run_parallel_capture(tasks, max_workers=None):
    """Run tasks concurrently but capture each one's printed output, returning
    (texts, unavailable) — the captured strings in submission order, and a
    list of "Service (reason)" strings for tasks that failed or timed out.

    Used to build a verdict at the top of a report: we gather all the service
    output first (into per-task buffers via the cache's thread-local capture),
    then the caller prints the verdict followed by the captured detail.

    A task that misses the deadline is left running on the pool; its output
    goes to its own thread-local buffer and is discarded, so nothing prints
    late into the next report.
    """
    from analyst_tool_cache import _capture, install_capture
    install_capture()  # ensure the stdout tee is present even if caching is off

    results = [""] * len(tasks)
    reasons = [None] * len(tasks)    # per task, in submission order

    def _wrap(i, task):
        with _capture() as buf:
            reason = _run_task(task)
        return i, buf.getvalue(), reason

    futures = {_LOOKUP_POOL.submit(_wrap, i, t): (i, t) for i, t in enumerate(tasks)}
    try:
        for future in as_completed(futures, timeout=_deadline()):
            i, text, reason = future.result()
            results[i] = text
            reasons[i] = reason
    except FuturesTimeoutError:
        deadline = _deadline()
        for future, (i, task) in futures.items():
            if not future.done():
                future.cancel()
                results[i] = "\t[%s] timed out after %.0fs\n" % (_task_label(task), deadline)
                reasons[i] = "timed out"
    unavailable = ["%s (%s)" % (_task_label(tasks[i]), r)
                   for i, r in enumerate(reasons) if r]
    return results, unavailable


def _run_with_verdict(indicator_type, tasks, max_workers=None, indicator=None):
    """Run the report tasks, print a one-line verdict, then the detail.

    If the capture machinery itself fails, fall back to the streaming
    behaviour so a report is never lost. A failure *after* the tasks have run
    (verdict or report buffer) prints what was captured rather than re-running
    the tasks, which would spend every API call a second time. When
    `indicator` is given, the finished report (verdict + detail) is also kept
    in the in-memory report buffer so `>>report` can export it later.
    """
    try:
        texts, unavailable = _run_parallel_capture(tasks, max_workers)
    except Exception:
        _run_parallel(tasks, max_workers)
        return
    combined = "".join(texts)
    try:
        from analyst_tool_verdict import build_verdict
        verdict = build_verdict(indicator_type, combined, unavailable=unavailable)
    except Exception:
        verdict = None
    if verdict:
        print(verdict)
    print(combined, end="")
    if indicator:
        try:
            record_report(indicator, indicator_type,
                          ((verdict + "\n") if verdict else "") + combined)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Clipboard commands (notes / tags) — distinguished by the configured prefix
# (default ">>"), so they're never mistaken for an indicator. See NOTE_COMMANDS.md.
# ─────────────────────────────────────────────────────────────────────────────

def _indicator_type(token):
    """Best-effort classification of a token for note targeting."""
    if not token:
        return None
    t = token.strip()
    if re.match(hash_validation_regex, t):
        return 'hash'
    if re.match(cve_regex, t, re.IGNORECASE):
        return 'cve'
    if parse_ip(t) is not None:
        return 'ip'
    try:
        if validators.url(t) is True:
            return 'url'
    except Exception:
        pass
    try:
        if validators.domain(t) is True:
            return 'domain'
    except Exception:
        pass
    return None


def _split_target(rest, last_indicator):
    """Decide whether `rest` starts with an explicit indicator or should attach
    to the last lookup. Returns (indicator, indicator_type, remaining_text)."""
    parts = rest.split(None, 1)
    if parts and _indicator_type(parts[0]):
        target = parts[0]
        text = parts[1].strip() if len(parts) > 1 else ""
        return target, _indicator_type(target), text
    if last_indicator:
        return last_indicator[0], last_indicator[1], rest
    return None, None, rest


def _handle_command(body, cache, last_indicator):
    """Parse and run a >> command (note / tag / note-rm)."""
    parts = body.split(None, 1)
    if not parts:
        print("\t[cmd] usage: >>note <indicator?> <text>  |  "
              ">>tag <indicator> <tags>  |  >>note-rm <indicator>  |  "
              ">>note-dedupe [indicator] [dry]  |  "
              ">>find <text/#tags>  |  >>history [N] [team]  |  "
              ">>report [N] [clip]")
        return last_indicator
    verb = parts[0].lower()
    rest = parts[1].strip() if len(parts) > 1 else ""

    if verb == 'note':
        target, itype, text = _split_target(rest, last_indicator)
        if target is None:
            print("\t[note] No indicator given and no recent lookup to attach to.")
            return last_indicator
        if not text:
            try:
                text = input("Note (#tags inline) > ").strip()
            except Exception:
                text = ""
        if text:
            cache.add_note(target, itype, text)
    elif verb == 'tag':
        target, itype, text = _split_target(rest, last_indicator)
        if target and text:
            cache.add_note(target, itype, "", extra_tags=text.split())
        else:
            print("\t[tag] usage: >>tag <indicator> <tag1> <tag2> ...")
    elif verb in ('note-dedupe', 'notededupe', 'dedupe', 'note-dedup'):
        # >>note-dedupe [indicator] [dry] — collapse YOUR identical notes to
        # the oldest copy. No indicator = sweep all of your notes. Add 'dry'
        # (or 'preview') to see what would go without deleting anything.
        words = rest.split()
        dry = bool(words) and words[-1].lower() in ('dry', 'dry-run', 'preview')
        if dry:
            words = words[:-1]
        target = words[0] if words else None
        cache.dedupe_notes(target,
                           _indicator_type(target) if target else None,
                           dry_run=dry)
    elif verb in ('note-rm', 'noterm', 'unnote'):
        target = rest.strip()
        if not target and last_indicator:
            target, itype = last_indicator
        else:
            itype = _indicator_type(target)
        if target:
            cache.remove_my_notes(target, itype)
        else:
            print("\t[note-rm] usage: >>note-rm <indicator>")
    elif verb in ('exclude', 'excl'):
        # Add a domain (or the host of the last domain/URL looked up) to the
        # shared exclusion list. Normalize URLs/domains to a bare host.
        raw = rest.strip() or (last_indicator[0] if last_indicator else "")
        host = _hostname_of(raw)
        if host:
            cache.add_exclusion(host)
        else:
            print("\t[exclude] usage: >>exclude <domain>  "
                  "(or copy a domain/URL, then >>exclude)")
    elif verb in ('exclude-rm', 'unexclude', 'excl-rm'):
        host = _hostname_of(rest.strip())
        if host:
            cache.remove_exclusion(host)
        else:
            print("\t[exclude-rm] usage: >>exclude-rm <domain>")
    elif verb in ('exclude-list', 'exclusions', 'excl-list'):
        cache.print_exclusions()
    elif verb in ('history', 'hist'):
        # >>history [N] [team] — your (or everyone's) recent lookups.
        cache.print_history(rest)
    elif verb in ('report', 'rpt'):
        # >>report [N] [clip] — export the last N lookups to a ticket-ready
        # file (or the clipboard with 'clip').
        get_report_buffer().export(rest, username=cache.username)
    elif verb in ('find', 'search'):
        # >>find <text and/or #tags> — search the shared notes/tags.
        cache.find_annotations(rest)
    else:
        print("\t[cmd] Unknown command '%s'. Try note / tag / note-rm / "
              "note-dedupe / find / history / report / exclude." % verb)
    return last_indicator


def _is_recognized_indicator(value, lolbas, driver):
    """True if `value` would be handled by a lookup branch below. Used to print
    the separator banner only for real indicators, not arbitrary copied text."""
    try:
        if re.match(hash_validation_regex, value):
            return True
        if re.match(port_wid_validation_regex, value):
            return True
        if get_lolbas_file_endings(lolbas, value):
            return True
        if get_loldriver_file_endings(driver, value):
            return True
        if re.match(cve_regex, value, re.IGNORECASE):
            return True
        if validators.domain(value) == True:
            return True
        if validators.url(value) == True:
            return True
        if re.match(mitre_regex, value):
            return True
        if re.match(epoch_regex, value):
            return True
        if re.match(otx_pulse_regex, value):
            return True
        return parse_ip(value) is not None
    except Exception:
        return False


def _lookup_hash_parallel(suspect_hash, virus_total_headers, vt_user,
                           opencti_headers, otx, otx_intel_list,
                           cache=None, force_refresh=False):
    """Fire VT, OpenCTI, and OTX hash lookups concurrently.

    VT and OTX results are served from the cache when fresh (OpenCTI is not
    cached). Lookups for unconfigured services run live (and uncached).
    """
    if cache is not None:
        cache.print_team_notes(suspect_hash, 'hash')
        cache.record_check_and_alert(suspect_hash, 'hash')

    def _cc(service, fn):
        if cache is None:
            fn()
        else:
            cache.cached_call(suspect_hash, 'hash', service, fn, force_refresh)

    def _vt_live():
        if virus_total_headers:
            print_virus_total_hash_results(suspect_hash, virus_total_headers, vt_user)
        else:
            print(color.UNDERLINE + '\nVirusTotal:' + color.END)
            print('\tVirusTotal not configured.')

    def _vt():
        if virus_total_headers:
            _cc('virustotal', _vt_live)
        else:
            _vt_live()

    def _opencti():
        if opencti_headers:
            results = query_opencti(opencti_headers, suspect_hash)
            if len(results) == 0:
                print(color.UNDERLINE + '\nOpenCTI Info:' + color.END)
                print("\n" + suspect_hash + " Not found in OpenCTI")
            else:
                print_opencti_hash_results(results, suspect_hash, opencti_headers)

    def _otx_live():
        if otx:
            print_alien_vault_hash_results(otx, suspect_hash, otx_intel_list)

    def _otx():
        if otx:
            _cc('otx', _otx_live)
        else:
            _otx_live()

    _run_with_verdict('hash', [_vt, _opencti, _otx], indicator=suspect_hash)


def _lookup_domain_parallel(suspect_domain, virus_total_headers, vt_user,
                             opencti_headers, otx, otx_intel_list,
                             cache=None, force_refresh=False):
    """Fire VT, OpenCTI, and OTX domain lookups concurrently.

    VT and OTX results are served from the cache when fresh (OpenCTI is not
    cached). Lookups for unconfigured services run live (and uncached).
    """
    if cache is not None:
        cache.print_team_notes(suspect_domain, 'domain')
        cache.record_check_and_alert(suspect_domain, 'domain')

    def _cc(service, fn):
        if cache is None:
            fn()
        else:
            cache.cached_call(suspect_domain, 'domain', service, fn, force_refresh)

    def _vt_live():
        print_vt_domain_report(suspect_domain, virus_total_headers, vt_user)

    def _vt():
        if virus_total_headers:
            _cc('virustotal', _vt_live)
        else:
            _vt_live()

    def _opencti():
        if opencti_headers:
            results = query_opencti(opencti_headers, suspect_domain)
            if len(results) == 0:
                print(color.UNDERLINE + '\nOpenCTI Info:' + color.END)
                print("\nNot found in OpenCTI")
            else:
                print_opencti_domain_results(results, opencti_headers)

    def _otx_live():
        if otx:
            print_alien_vault_domain_results(otx, suspect_domain, otx_intel_list)

    def _otx():
        if otx:
            _cc('otx', _otx_live)
        else:
            _otx_live()

    def _dns():
        # DNS resolution + crt.sh — live (not an API-keyed/rate-limited service).
        print_dns_and_crt(suspect_domain)

    _run_with_verdict('domain', [_vt, _opencti, _otx, _dns],
                      indicator=suspect_domain)


def _lookup_url_parallel(suspect_url, virus_total_headers,
                          opencti_headers, otx, otx_intel_list,
                          cache=None, force_refresh=False):
    """Fire VT, OpenCTI, and OTX URL lookups concurrently.

    VT and OTX results are served from the cache when fresh (OpenCTI is not
    cached). Lookups for unconfigured services run live (and uncached).
    """
    if cache is not None:
        cache.print_team_notes(suspect_url, 'url')
        cache.record_check_and_alert(suspect_url, 'url')

    def _cc(service, fn):
        if cache is None:
            fn()
        else:
            cache.cached_call(suspect_url, 'url', service, fn, force_refresh)

    def _vt_live():
        print_virus_total_url_report(virus_total_headers, suspect_url)

    def _vt():
        if virus_total_headers:
            _cc('virustotal', _vt_live)
        else:
            _vt_live()

    def _opencti():
        if opencti_headers:
            results = query_opencti(opencti_headers, suspect_url)
            print_opencti_url_results(results, suspect_url)

    def _otx_live():
        if otx:
            print_alien_vault_url_results(otx, suspect_url, otx_intel_list)

    def _otx():
        if otx:
            _cc('otx', _otx_live)
        else:
            _otx_live()

    _run_with_verdict('url', [_vt, _opencti, _otx], indicator=suspect_url)


# ─────────────────────────────────────────────────────────────────────────────
# IP analysis
# ─────────────────────────────────────────────────────────────────────────────

def get_ip_analysis_results(suspect_ip, virus_total_headers, abuse_ip_db_headers,
                             otx, otx_intel_list, vt_user, opencti_headers, shodan_headers,
                             cache=None, force_refresh=False):
    """ A function to call the various IP modules concurrently and display them.

    All enabled services (VirusTotal, Shodan, WhoIs, Tor check, AbuseIPDB,
    AlienVault OTX, OpenCTI) are queried at the same time via a thread pool,
    so total wall-clock time equals the slowest single service rather than
    the sum of all services.

    This function requires the following parameters:
        IP address              - Obtained automatically from the main loop.
        virus_total_headers     - From create_virus_total_headers_from_config().
        abuse_ip_db_headers     - From create_abuse_ip_db_headers_from_config().
        otx                     - From create_av_otx_headers_from_config().
        otx_intel_list          - From get_otx_intel_list_from_config().
        vt_user                 - From get_vt_user_from_config().
        opencti_headers         - From get_opencti_from_config().
        shodan_headers          - From get_shodan_from_config().
    """
    heading = "\n\n\nIP Analysis Report for " + suspect_ip + ":"
    print(color.BOLD + heading + color.END)

    if cache is not None:
        cache.print_team_notes(suspect_ip, 'ip')
        cache.record_check_and_alert(suspect_ip, 'ip')

    def _cc(service, fn):
        if cache is None:
            fn()
        else:
            cache.cached_call(suspect_ip, 'ip', service, fn, force_refresh)

    def _opencti():
        if opencti_headers is None:
            print(color.UNDERLINE + '\nOpenCTI Info:' + color.END)
            print('\tOpenCTI not configured.')
        else:
            results = query_opencti(opencti_headers, suspect_ip)
            if len(results) == 0:
                print(color.UNDERLINE + '\nOpenCTI Info:' + color.END)
                print("\n" + suspect_ip + " Not found in OpenCTI")
            else:
                print_opencti_ip_results(results, suspect_ip, countries, opencti_headers)

    def _vt_live():
        if virus_total_headers is None:
            print(color.UNDERLINE + '\nVirusTotal Detections:' + color.END)
            print('\tVirus Total not configured.')
        else:
            get_vt_ip_results(suspect_ip, virus_total_headers, vt_user)

    def _vt():
        if virus_total_headers is None:
            _vt_live()
        else:
            _cc('virustotal', _vt_live)

    def _shodan_live():
        if shodan_headers is None:
            print(color.UNDERLINE + '\n Shodan:' + color.END)
            print('\tShodan not configured.')
        else:
            get_print_shodan_ip_results(shodan_headers, suspect_ip)

    def _shodan():
        if shodan_headers is None:
            _shodan_live()
        else:
            _cc('shodan', _shodan_live)

    def _whois_tor():
        print(color.UNDERLINE + '\nIP Information:' + color.END)
        org_text = None
        try:
            org_text = ip_whois(suspect_ip)   # returns WhoIs org/ASN text
        except Exception:
            pass
        check_tor(suspect_ip)
        check_vpn(suspect_ip, org_text)        # list match OR known-VPN org name
        check_datacenter(suspect_ip)

    def _abuseipdb_live():
        if abuse_ip_db_headers is None:
            print(color.UNDERLINE + '\nAbuse IP DB:' + color.END)
            print('\tAbuse IP DB not configured.')
        else:
            # Let errors propagate so a failed call is NOT cached; the wrapper
            # below prints the friendly message and stale-while-error applies.
            check_abuse_ip_db(suspect_ip, abuse_ip_db_headers)

    def _abuseipdb():
        if abuse_ip_db_headers is None:
            _abuseipdb_live()
        else:
            # Errors propagate to _run_task, which prints
            # "[AbuseIPDB] unavailable: HTTP 429 — ..." and tells the verdict.
            _cc('abuseipdb', _abuseipdb_live)

    def _otx_live():
        if otx is None:
            print(color.UNDERLINE + '\nAlienVault OTX:' + color.END)
            print('\tAlienVault not configured.')
        else:
            print_alien_vault_ip_results(otx, suspect_ip, otx_intel_list)

    def _otx():
        if otx is None:
            _otx_live()
        else:
            _cc('otx', _otx_live)

    _run_with_verdict('ip', [_opencti, _vt, _shodan, _whois_tor, _abuseipdb, _otx],
                      max_workers=6, indicator=suspect_ip)


# ─────────────────────────────────────────────────────────────────────────────
# ip_whois
# ─────────────────────────────────────────────────────────────────────────────

def ip_whois(suspect_ip):
    """ A function to query WhoIs for an IP address and print out information from the response.

    This function requires the following parameter:
        IP address: Obtained automatically from the main script.

    Sample Output:
        IP Information:
            Organization:             RU-ITRESHENIYA
            CIDR:                     45.145.66.0/23
            Range:                    45.145.66.0 - 45.145.67.255
            Country:                  Russian Federation (the)
            Associated Email:
                Email:                abuse@hostway.ru
    """
    org_match = '([a-zA-Z0-9 .,_")(-]+)\n?'
    obj = IPWhois(suspect_ip, timeout=8)   # per-connection timeout (RIR whois, port 43)
    res = obj.lookup_whois()
    company_count = 0
    whois_orgs = []   # collected org/ASN text, returned for VPN-provider matching

    for line in res['nets']:
        if line['description'] is not None:
            m = re.match(org_match, line['description'])
            org = m.group(1)
            company_count += 1
            whois_orgs.append(line['description'])
            print('\t{:<33} {}'.format(color.BOLD + 'Organization:' + color.END, org))
        elif line['name'] is not None:
            m = re.match(org_match, line['name'])
            org = m.group(1)
            company_count += 1
            whois_orgs.append(line['name'])
            print('\t{:<33} {}'.format(color.BOLD + 'Organization:' + color.END, org))
        else:
            print('\t{:<33} {}'.format(color.BOLD + 'Organization:' + color.END,
                                       'Org is blank in whois data.'))

        print('\t{:<25} {}'.format('CIDR:', line['cidr']))
        if line['range']:
            print('\t{:<25} {}'.format('Range:', line['range']))
        else:
            ip_range = ipaddress.ip_network(line['cidr'])
            ip_range = str(ip_range[0]) + ' - ' + str(ip_range[-1])
            print('\t{:<25} {}'.format('Range:', ip_range))

        country_code = line['country']
        print_country(country_code, countries)

        print('\tAssociated Email:')
        if line['emails'] is None:
            print('\t\t{:<17} {}'.format('Email:', 'No associated emails.'))
        else:
            for email in line['emails']:
                print('\t\t{:<17} {}'.format('Email:', email))

    if company_count == 0:
        print('\t{:<25} {}'.format('ASN Description:', res['asn_description']))

    if res.get('asn_description'):
        whois_orgs.append(res['asn_description'])
    return ' '.join(w for w in whois_orgs if w)

# End of analyst.py
