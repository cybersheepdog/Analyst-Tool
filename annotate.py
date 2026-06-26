#!/usr/bin/env python3
"""Companion CLI for Analyst Tool shared annotations.

Add, list, or remove notes/tags on an indicator without using the clipboard.
Writes to the same cache database (local SQLite or shared PostgreSQL) the main
tool uses, so notes appear automatically on everyone's next lookup.

Examples:
    python annotate.py add 45.145.66.165 "confirmed phishing C2, case #1487" --tags phishing,c2
    python annotate.py list 45.145.66.165
    python annotate.py rm 45.145.66.165

The author is the [CACHE] user from config.ini, or your OS login name if unset.
See NOTE_COMMANDS.md for the full reference.
"""
import argparse
import ipaddress
import re
import sys

from analyst_tool_cache import build_cache_manager


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

    args = parser.parse_args()

    cache = build_cache_manager()
    if not cache.enabled:
        print("Notes need the cache enabled. Set [CACHE] enabled = true (and a "
              "backend) in config.ini.", file=sys.stderr)
        sys.exit(1)

    itype = _guess_type(args.indicator)

    if args.cmd == "add":
        tags = [t for t in re.split(r"[,\s]+", args.tags) if t]
        cache.add_note(args.indicator, itype, args.note, extra_tags=tags)
    elif args.cmd == "list":
        cache.print_team_notes(args.indicator, itype)
    elif args.cmd == "rm":
        cache.remove_my_notes(args.indicator, itype)


if __name__ == "__main__":
    main()
