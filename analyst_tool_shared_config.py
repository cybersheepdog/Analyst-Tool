# Analyst Tool — Shared (remote) configuration loader
# Author: Jeremy Wiedner (@JeremyWiedner)
# License: BSD 3-Clause
#
# Purpose:
#   Let a team keep API keys in ONE place — the shared PostgreSQL database the
#   tool already uses for the remote cache — instead of pasting the same keys
#   into every analyst's local config.ini.
#
#   load_config() returns a ConfigParser that is "remote-first, local-fallback":
#     1. The local config.ini is read as the base (so personal settings such as
#        the analyst identity, report directory, etc. always stay local).
#     2. If, and only if, the [CACHE] backend is 'remote' and a host/dbname are
#        configured, the shared_config table is read and its values are OVERLAID
#        on top — but only for a fixed whitelist of API-key options (see
#        SHARED_KEY_OPTIONS). A shared value wins over the local one; a missing
#        or blank shared value leaves the local one untouched.
#     3. On ANY problem (remote backend not selected, driver missing, server
#        unreachable, table absent, timeout) the function silently falls back to
#        the local config.ini. Nothing about the existing single-user behaviour
#        changes when no remote is configured.
#
#   Access control is the database login itself: only analysts who already hold
#   the shared-cache DB credentials can read the shared keys.
#
# Design notes:
#   * Fail-safe and non-breaking, exactly like the cache layer: a down or
#     misconfigured server never stops a lookup — you just get your local keys.
#   * The merged parser is cached per config path, so the DB is queried at most
#     once per run even though many modules ask for their keys independently.
#   * Only whitelisted API-credential options are ever taken from the remote,
#     so a shared row can never silently change local paths, identities, TLS
#     policy, or any other behaviour.

import os
import time
from configparser import ConfigParser

from analyst_tool_cache import get_cache_config_from_config


# ─────────────────────────────────────────────────────────────────────────────
# Whitelist: which [SECTION] option names are shared API credentials.
#   Only these are ever pulled from the remote database. Everything else in
#   config.ini (identities, file paths, freshness windows, TLS policy, ...)
#   remains strictly local and per-analyst.
# ─────────────────────────────────────────────────────────────────────────────
SHARED_KEY_OPTIONS = {
    "ABUSE_IP_DB":     {"key"},
    "VIRUS_TOTAL":     {"x-apikey"},
    "ALIEN_VAULT_OTX": {"otx_api_key"},
    "OPEN_CTI":        {"opencti_api_url", "opencti_api_token", "opencti_base_url"},
    "C2LIVE":          {"c2_live_url", "c2_live_index"},
    "SHODAN":          {"shodan_api_key"},
    "CVE":             {"nvd_api_key"},
}

# How long to wait for the shared-config DB before giving up and using local
# keys. Kept short so a slow/unreachable server can't stall tool startup.
_CONNECT_TIMEOUT_SECONDS = 5

# Cache of merged ConfigParser objects, keyed by the config path.
_merged_cache = {}

# ─────────────────────────────────────────────────────────────────────────────
# Optional envelope encryption
#   When a passphrase is available, API-key VALUES are encrypted client-side
#   (Fernet / AES-128-CBC + HMAC) before they are stored, and decrypted after
#   they are read — so the database, its backups, and anyone with only a DB
#   login never see plaintext keys. The passphrase itself is NEVER stored in the
#   database; it is read locally from an environment variable or a local file.
#
#   Everything is backward-compatible: with no passphrase set, values are stored
#   and read as plaintext exactly as before. Encrypted values carry the ENC_PREFIX
#   marker, so plaintext and encrypted rows can coexist during a migration.
# ─────────────────────────────────────────────────────────────────────────────

# Environment variable that holds the shared passphrase (highest priority).
PASSPHRASE_ENV = "ANALYST_SHARED_KEY"
# Marker prefixing an encrypted value in the database.
ENC_PREFIX = "enc:v1:"
# Reserved row holding the per-deployment KDF salt (non-secret). It lives in the
# same table but is never treated as a config value (its section isn't whitelisted).
META_SECTION = "_meta"
SALT_OPTION = "kdf_salt"
_KDF_ITERATIONS = 200_000

_warned_encrypted = False


def _get_passphrase(path="config.ini"):
    """Return the local shared passphrase, or None.

    Sources, in priority order: the ANALYST_SHARED_KEY environment variable,
    then a local key file named in [SHARED_CONFIG] key_file. Never read from the
    database.
    """
    val = os.environ.get(PASSPHRASE_ENV)
    if val and val.strip():
        return val.strip()
    try:
        parser = ConfigParser()
        parser.read(path)
        key_file = parser.get("SHARED_CONFIG", "key_file", fallback="").strip()
        if key_file and os.path.exists(key_file):
            with open(key_file, "r") as fh:
                content = fh.read().strip()
                return content or None
    except Exception:
        pass
    return None


def _derive_fernet(passphrase, salt):
    """Derive a Fernet cipher from a passphrase + salt (PBKDF2-HMAC-SHA256)."""
    import base64
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=_KDF_ITERATIONS)
    return Fernet(base64.urlsafe_b64encode(kdf.derive(passphrase.encode())))


def _build_fernet_for_read(remote, path):
    """Build the decryption cipher from the passphrase + the DB-stored salt.

    Returns None when no passphrase is set or no salt row exists (i.e. nothing
    is encrypted). Never raises.
    """
    passphrase = _get_passphrase(path)
    if not passphrase:
        return None
    salt_b64 = remote.get((META_SECTION, SALT_OPTION))
    if not salt_b64:
        return None
    try:
        import base64
        return _derive_fernet(passphrase, base64.b64decode(salt_b64))
    except Exception:
        return None


def _maybe_decrypt(value, fernet):
    """Decrypt an ENC_PREFIX value; pass plaintext through unchanged.

    Returns None if an encrypted value cannot be decrypted (no/there wrong
    passphrase, corrupt token, or cryptography missing), signalling the caller
    to skip it and fall back to the local value.
    """
    if value is None:
        return None
    text = str(value)
    if not text.startswith(ENC_PREFIX):
        return text  # legacy plaintext
    if fernet is None:
        return None
    try:
        token = text[len(ENC_PREFIX):].encode()
        return fernet.decrypt(token).decode()
    except Exception:
        return None


def _warn_encrypted_unavailable():
    global _warned_encrypted
    if _warned_encrypted:
        return
    _warned_encrypted = True
    import sys
    sys.stderr.write(
        "Note: shared API keys are encrypted but no valid passphrase is set "
        "(%s); using local keys where available.\n" % PASSPHRASE_ENV)


def _create_shared_config_table_sql():
    return (
        "CREATE TABLE IF NOT EXISTS shared_config ("
        " section TEXT NOT NULL,"
        " option TEXT NOT NULL,"
        " value TEXT,"
        " updated_at DOUBLE PRECISION,"
        " updated_by TEXT,"
        " PRIMARY KEY (section, option))"
    )


def _connect(cfg):
    """Open a short-timeout psycopg2 connection using the [CACHE] credentials.

    Raises if psycopg2 is missing or the server can't be reached; callers treat
    any exception as "no remote available" and fall back to local config.
    """
    import psycopg2  # optional dependency, only needed for the remote backend
    return psycopg2.connect(
        host=cfg["host"], port=cfg["port"], dbname=cfg["dbname"],
        user=cfg["db_user"], password=cfg["password"], sslmode=cfg["sslmode"],
        connect_timeout=_CONNECT_TIMEOUT_SECONDS)


def _remote_enabled(cfg):
    """True only when a shared remote database is actually configured."""
    return (str(cfg.get("backend", "")).strip().lower() == "remote"
            and bool(cfg.get("host")) and bool(cfg.get("dbname")))


def _fetch_remote_shared_config(cfg):
    """Return {(section, option): value} from the shared_config table.

    Best-effort: creates the table if it doesn't exist, then reads every row.
    Returns None (never raises) on any failure so the caller falls back to
    local configuration.
    """
    conn = None
    try:
        conn = _connect(cfg)
        cur = conn.cursor()
        try:
            cur.execute(_create_shared_config_table_sql())
            conn.commit()
        except Exception:
            # Read-only role, or table already owned by someone else — fine, we
            # only need SELECT below.
            conn.rollback()
        cur.execute("SELECT section, option, value FROM shared_config")
        rows = cur.fetchall()
        cur.close()
        return {(r[0], r[1]): r[2] for r in rows}
    except Exception:
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _overlay_remote(parser, remote, fernet=None):
    """Overlay whitelisted, non-blank remote values onto `parser` in place.

    Values are decrypted first when they carry the ENC_PREFIX marker. An
    encrypted value that can't be decrypted is skipped (local value is kept)
    and a one-time note is emitted.
    """
    for (section, option), value in remote.items():
        allowed = SHARED_KEY_OPTIONS.get(section)
        if not allowed or option not in allowed:
            continue
        plain = _maybe_decrypt(value, fernet)
        if plain is None or str(plain).strip() == "":
            if value is not None and str(value).startswith(ENC_PREFIX):
                _warn_encrypted_unavailable()
            continue
        if not parser.has_section(section):
            parser.add_section(section)
        parser.set(section, option, str(plain))


def load_config(path="config.ini", force_reload=False):
    """Return a ConfigParser with shared API keys overlaid on the local config.

    Remote-first, local-fallback: whitelisted API-key options come from the
    shared database when available, everything else (and everything, if no
    remote is configured or reachable) comes from the local config.ini.

    Always returns a ConfigParser and never raises. When a remote overlay is
    applied, the merged result is cached per `path` so the database is queried
    at most once per run; pass force_reload=True to re-query. Local-only reads
    are NOT cached, preserving the original per-call read of config.ini.
    """
    if not force_reload and path in _merged_cache:
        return _merged_cache[path]

    parser = ConfigParser()
    try:
        parser.read(path)
    except Exception:
        parser = ConfigParser()  # unreadable local file → start empty, still safe

    try:
        cfg = get_cache_config_from_config(path)
        if _remote_enabled(cfg):
            remote = _fetch_remote_shared_config(cfg)
            if remote:
                fernet = _build_fernet_for_read(remote, path)
                _overlay_remote(parser, remote, fernet)
                # Only cache when we actually talked to the remote — this is the
                # expensive path. Local-only reads stay uncached so a mid-session
                # edit to config.ini is still picked up, exactly as before.
                _merged_cache[path] = parser
    except Exception:
        # Any unexpected problem: keep the local-only parser.
        pass

    return parser


def clear_cache():
    """Forget any cached merged config (used by tests and the admin CLI)."""
    _merged_cache.clear()


# ─────────────────────────────────────────────────────────────────────────────
# Admin CLI — seed and manage the shared keys.
#   Run on any machine that can reach the database using the same [CACHE]
#   credentials from config.ini:
#
#     python analyst_tool_shared_config.py list
#     python analyst_tool_shared_config.py set VIRUS_TOTAL x-apikey <APIKEY>
#     python analyst_tool_shared_config.py delete SHODAN shodan_api_key
#     python analyst_tool_shared_config.py import-local   # push local keys up
# ─────────────────────────────────────────────────────────────────────────────

def _require_remote(cfg):
    if not _remote_enabled(cfg):
        raise SystemExit(
            "Remote backend is not configured. Set [CACHE] backend = remote and "
            "host/dbname in config.ini before managing shared keys.")


def _get_or_create_salt(cur):
    """Return the deployment KDF salt (bytes), creating+storing one if absent.

    The salt is not secret; it lives in the shared_config _meta row so every
    analyst derives the same key from the shared passphrase.
    """
    import base64
    cur.execute("SELECT value FROM shared_config WHERE section=%s AND option=%s",
                (META_SECTION, SALT_OPTION))
    row = cur.fetchone()
    if row and row[0]:
        try:
            return base64.b64decode(row[0])
        except Exception:
            pass
    salt = os.urandom(16)
    cur.execute(
        "INSERT INTO shared_config (section, option, value, updated_at, updated_by) "
        "VALUES (%s,%s,%s,%s,%s) "
        "ON CONFLICT (section, option) DO UPDATE SET value=excluded.value",
        (META_SECTION, SALT_OPTION, base64.b64encode(salt).decode(),
         time.time(), "system"))
    return salt


def _admin_set(cfg, section, option, value, updated_by="admin"):
    allowed = SHARED_KEY_OPTIONS.get(section)
    if not allowed or option not in allowed:
        raise SystemExit(
            "Refusing to set %s/%s — not a recognised shared API-key option.\n"
            "Allowed options: %s" % (section, option, _format_whitelist()))
    passphrase = _get_passphrase("config.ini")
    conn = _connect(cfg)
    try:
        cur = conn.cursor()
        cur.execute(_create_shared_config_table_sql())
        if passphrase:
            try:
                salt = _get_or_create_salt(cur)
                fernet = _derive_fernet(passphrase, salt)
                stored = ENC_PREFIX + fernet.encrypt(value.encode()).decode()
            except ImportError:
                raise SystemExit(
                    "A passphrase is set but the 'cryptography' package is not "
                    "installed. Run: pip install cryptography")
        else:
            stored = value  # plaintext (backward-compatible)
        cur.execute(
            "INSERT INTO shared_config (section, option, value, updated_at, updated_by) "
            "VALUES (%s,%s,%s,%s,%s) "
            "ON CONFLICT (section, option) DO UPDATE SET "
            " value=excluded.value, updated_at=excluded.updated_at, "
            " updated_by=excluded.updated_by",
            (section, option, stored, time.time(), updated_by))
        conn.commit()
        cur.close()
        return "encrypted" if passphrase else "plaintext"
    finally:
        conn.close()


def _admin_delete(cfg, section, option):
    conn = _connect(cfg)
    try:
        cur = conn.cursor()
        cur.execute(_create_shared_config_table_sql())
        cur.execute("DELETE FROM shared_config WHERE section=%s AND option=%s",
                    (section, option))
        removed = cur.rowcount
        conn.commit()
        cur.close()
        return removed
    finally:
        conn.close()


def _admin_list(cfg):
    remote = _fetch_remote_shared_config(cfg)
    if remote is None:
        raise SystemExit("Could not read shared_config from the database.")
    return remote


def _format_whitelist():
    parts = []
    for section in sorted(SHARED_KEY_OPTIONS):
        for option in sorted(SHARED_KEY_OPTIONS[section]):
            parts.append("%s/%s" % (section, option))
    return ", ".join(parts)


def _mask(value):
    if not value:
        return "(blank)"
    v = str(value)
    if len(v) <= 8:
        return v[0] + "***"
    return v[:4] + "…" + v[-4:]


def _main(argv):
    import getpass

    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__ if False else (
            "Manage shared API keys stored in the remote database.\n\n"
            "Usage:\n"
            "  python analyst_tool_shared_config.py list\n"
            "  python analyst_tool_shared_config.py set SECTION OPTION VALUE\n"
            "  python analyst_tool_shared_config.py delete SECTION OPTION\n"
            "  python analyst_tool_shared_config.py import-local\n\n"
            "Encryption (optional but recommended): set the passphrase in the\n"
            "%s environment variable (or a local file named in [SHARED_CONFIG]\n"
            "key_file). When set, values are encrypted before storage and\n"
            "decrypted on read; the passphrase is never stored in the database.\n\n"
            "Shared options: " % PASSPHRASE_ENV + _format_whitelist()))
        return 0

    cfg = get_cache_config_from_config("config.ini")
    _require_remote(cfg)

    try:
        who = getpass.getuser()
    except Exception:
        who = "admin"

    cmd = argv[0]
    if cmd == "list":
        rows = _admin_list(cfg)
        keys = {k: v for k, v in rows.items() if k[0] != META_SECTION}
        if not keys:
            print("(no shared keys set)")
            return 0
        encrypted_any = False
        for (section, option) in sorted(keys):
            value = keys[(section, option)]
            enc = str(value or "").startswith(ENC_PREFIX)
            encrypted_any = encrypted_any or enc
            state = "encrypted" if enc else "PLAINTEXT"
            shown = "" if enc else "  " + _mask(value)
            print("%-16s %-18s %-9s%s" % (section, option, state, shown))
        if encrypted_any and not _get_passphrase("config.ini"):
            print("\n(values are encrypted; set %s to decrypt/manage them)"
                  % PASSPHRASE_ENV)
        return 0

    if cmd == "set":
        if len(argv) < 4:
            raise SystemExit("usage: set SECTION OPTION VALUE")
        how = _admin_set(cfg, argv[1], argv[2], argv[3], updated_by=who)
        print("Set %s/%s (%s)." % (argv[1], argv[2], how))
        return 0

    if cmd == "delete":
        if len(argv) < 3:
            raise SystemExit("usage: delete SECTION OPTION")
        removed = _admin_delete(cfg, argv[1], argv[2])
        print("Deleted %d row(s) for %s/%s." % (removed, argv[1], argv[2]))
        return 0

    if cmd == "import-local":
        local = ConfigParser()
        local.read("config.ini")
        pushed = 0
        for section in sorted(SHARED_KEY_OPTIONS):
            if not local.has_section(section):
                continue
            for option in sorted(SHARED_KEY_OPTIONS[section]):
                try:
                    value = local.get(section, option, fallback="").strip()
                except Exception:
                    value = ""
                if value:
                    how = _admin_set(cfg, section, option, value, updated_by=who)
                    pushed += 1
                    print("  pushed %s/%s (%s)" % (section, option, how))
        note = "" if _get_passphrase("config.ini") else \
            "  (stored in PLAINTEXT — set %s to encrypt)" % PASSPHRASE_ENV
        print("Imported %d shared key(s) from local config.ini.%s" % (pushed, note))
        return 0

    raise SystemExit("Unknown command '%s'. Try --help." % cmd)


if __name__ == "__main__":
    import sys
    sys.exit(_main(sys.argv[1:]))
