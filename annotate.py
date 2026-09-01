#!/usr/bin/env python3
"""Companion CLI for Analyst Tool shared annotations.

Add, list, or remove notes/tags on an indicator without using the clipboard.
Writes to the same cache database (local SQLite or shared PostgreSQL) the main
tool uses, so notes appear automatically on everyone's next lookup.

Examples:
    python annotate.py add 45.145.66.165 "confirmed phishing C2, case #1487" --tags phishing,c2
    python annotate.py list 45.145.66.165
    python annotate.py rm 45.145.66.165
    python annotate.py dedupe 45.145.66.165 --dry-run
    python annotate.py find "#c2"
    python annotate.py history --team -n 50

The author is the [CACHE] user from config.ini, or your OS login name if unset.
See NOTE_COMMANDS.md for the full reference.
"""
import argparse
import ipaddress
import re
import sys
from urllib.parse import urlparse

from analyst_tool_cache import build_cache_manager


def _host(value):
    """Normalize a domain or URL to a bare lowercase hostname."""
    v = (value or "").strip()
    if not v:
        return ""
    parsed = urlparse(v if "://" in v else "//" + v)
    return (parsed.hostname or "").lower().rstrip(".")


def _guess_type(token):
    """Light indicator classifier (avoids importing the heavy main module)."""
    t = (token or "").strip()
    if re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', t):
        return 'hash'
    if re.match(r'^CVE-\d{4}-\d{4,7}$', t, re.IGNORECASE):
        return 'cve'
    try:
        ipaddress.ip_address(t)
        return 'ip'
    except ValueError:
        pass
    try:
        import validators
        if validators.url(t) is True:
            return 'url'
        if validators.domain(t) is True:
            return 'domain'
    except Exception:
        pass
    if '/' in t or '://' in t:
        return 'url'
    return 'domain'


def main():
    parser = argparse.ArgumentParser(
        description="Add, list, or remove shared indicator annotations.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_add = sub.add_parser("add", help="add a note (and optional tags)")
    p_add.add_argument("indicator")
    p_add.add_argument("note")
    p_add.add_argument("--tags", default="",
                       help="comma- or space-separated tags, e.g. --tags phishing,c2")

    p_list = sub.add_parser("list", help="show notes for an indicator")
    p_list.add_argument("indicator")

    p_rm = sub.add_parser("rm", help="remove YOUR notes for an indicator")
    p_rm.add_argument("indicator")

    p_dedupe = sub.add_parser(
        "dedupe", help="remove YOUR duplicate notes, keeping the oldest copy")
    p_dedupe.add_argument("indicator", nargs="?",
                          help="limit to one indicator (default: all yours)")
    p_dedupe.add_argument("--dry-run", action="store_true",
                          help="report what would be removed, delete nothing")

    p_find = sub.add_parser("find", help="search notes/tags, e.g. find '#c2' or find phishing")
    p_find.add_argument("query", nargs="+",
                        help="words match note text/indicator/tags; #tag matches a whole tag")

    p_hist = sub.add_parser("history", help="show recent lookups (yours by default)")
    p_hist.add_argument("--team", action="store_true",
                        help="show everyone's lookups, not just yours")
    p_hist.add_argument("-n", "--limit", type=int, default=20,
                        help="how many rows to show (default 20)")

    p_excl = sub.add_parser("exclude", help="manage the shared domain exclusion list")
    esub = p_excl.add_subparsers(dest="ecmd", required=True)
    esub.add_parser("list", help="show the shared exclusion list")
    e_add = esub.add_parser("add", help="add a domain/URL to skip")
    e_add.add_argument("domain")
    e_rm = esub.add_parser("rm", help="remove a domain (anyone may remove)")
    e_rm.add_argument("domain")

    args = parser.parse_args()

    cache = build_cache_manager()
    if not cache.enabled:
        print("This needs the cache enabled. Set [CACHE] enabled = true (and a "
              "backend) in config.ini.", file=sys.stderr)
        sys.exit(1)

    if args.cmd == "add":
        tags = [t for t in re.split(r"[,\s]+", args.tags) if t]
        cache.add_note(args.indicator, _guess_type(args.indicator), args.note, extra_tags=tags)
    elif args.cmd == "list":
        cache.print_team_notes(args.indicator, _guess_type(args.indicator))
    elif args.cmd == "rm":
        cache.remove_my_notes(args.indicator, _guess_type(args.indicator))
    elif args.cmd == "dedupe":
        cache.dedupe_notes(
            args.indicator,
            _guess_type(args.indicator) if args.indicator else None,
            dry_run=args.dry_run)
    elif args.cmd == "find":
        cache.find_annotations(" ".join(args.query))
    elif args.cmd == "history":
        cache.print_history(("team " if args.team else "") + str(args.limit))
    elif args.cmd == "exclude":
        if args.ecmd == "add":
            cache.add_exclusion(_host(args.domain))
        elif args.ecmd == "list":
            cache.print_exclusions()
        elif args.ecmd == "rm":
            cache.remove_exclusion(_host(args.domain))


if __name__ == "__main__":
    main()
