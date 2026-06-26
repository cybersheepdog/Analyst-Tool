# Analyst Tool — Caching layer
# Author: Jeremy Wiedner (@JeremyWiedner)
# License: BSD 3-Clause
#
# Purpose:
#   Cache the result of each external, rate-limited service (VirusTotal,
#   AbuseIPDB, Shodan, AlienVault OTX) per indicator. When an indicator is
#   looked up again and a cached result is younger than the freshness window
#   (default 7 days), the stored result is replayed instead of spending an API
#   call. Usage counters track how many calls were saved.
#
#   Two interchangeable backends are supported, chosen in config.ini:
#     - local : a zero-setup SQLite file (single user)
#     - remote: a shared PostgreSQL database (a team saves calls together)
#
# Design notes:
#   * The cache stores each service's RENDERED output text (exactly what it
#     prints, ANSI colors included) so a replayed result is identical to a live
#     one. This means NO existing service/printing code had to change.
#   * To capture that output while the tool's lookups run concurrently, a
#     thread-aware stdout proxy is installed: writes go to a per-thread buffer
#     while capturing, otherwise straight to the screen.
#   * Everything is opt-in and fail-safe: if the cache is disabled or the DB
#     can't be reached, lookups run live exactly as before — the loop never
#     breaks.

import getpass
import io
import os
import sys
import threading
import time
from configparser import ConfigParser
from contextlib import contextmanager

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

def get_cache_config_from_config(path="config.ini"):
    """Read the [CACHE] section from config.ini and return a settings dict.

    Returns a dict with sensible defaults. If the file or section is missing,
    caching still defaults to ON with the local SQLite backend (the shipped
    default), so a single user gets call-saving out of the box.
    """
    cfg = {
        "enabled": True,
        "backend": "local",
        "freshness_days": 7.0,
        "db_path": "analyst_cache.db",
        "force_prefix": "!",
        "purge_days": 0.0,
        # per-user check logging / multi-user notice
        "user": "",
        "check_window_days": 7.0,
        "check_dedup_minutes": 60.0,
        # remote (PostgreSQL)
        "host": "",
        "port": 5432,
        "dbname": "",
        "db_user": "",
        "password": "",
        "sslmode": "prefer",
    }

    parser = ConfigParser()
    try:
        parser.read(path)
    except Exception:
        return cfg

    if not parser.has_section("CACHE"):
        return cfg

    def _get(key, default):
        try:
            val = parser.get("CACHE", key)
            return val if val != "" else default
        except Exception:
            return default

    def _bool(key, default):
        try:
            return str(parser.get("CACHE", key)).strip().lower() not in (
                "false", "0", "no", "off", "")
        except Exception:
            return default

    def _float(key, default):
        try:
            return float(parser.get("CACHE", key))
        except Exception:
            return default

    def _int(key, default):
        try:
            return int(parser.get("CACHE", key))
        except Exception:
            return default

    cfg["enabled"] = _bool("enabled", True)
    cfg["backend"] = str(_get("backend", "local")).strip().lower()
    cfg["freshness_days"] = _float("freshness_days", 7.0)
    cfg["db_path"] = _get("db_path", "analyst_cache.db")
    cfg["force_prefix"] = _get("force_prefix", "!")
    cfg["purge_days"] = _float("purge_days", 0.0)
    cfg["user"] = _get("user", "")
    cfg["check_window_days"] = _float("check_window_days", 7.0)
    cfg["check_dedup_minutes"] = _float("check_dedup_minutes", 60.0)
    cfg["host"] = _get("host", "")
    cfg["port"] = _int("port", 5432)
    cfg["dbname"] = _get("dbname", "")
    cfg["db_user"] = _get("db_user", "")
    cfg["password"] = _get("password", "")
    cfg["sslmode"] = _get("sslmode", "prefer")
    return cfg


# ─────────────────────────────────────────────────────────────────────────────
# Backends
#   Both expose the same interface:
#     get_fresh_row(indicator, service, fresh_secs) -> dict | None
#     get_any_row(indicator, service)               -> dict | None
#     record_hit(indicator, service)                -> None
#     store_miss(indicator, itype, service, payload)-> None
#     stats()                                       -> (hits, api_calls, rows)
#     purge(older_secs)                             -> int
# Rows are dicts: {payload, updated_at(epoch), lookup_count}
# ─────────────────────────────────────────────────────────────────────────────

_CREATE_TABLE = (
    "CREATE TABLE IF NOT EXISTS indicator_cache ("
    " indicator TEXT NOT NULL,"
    " indicator_type TEXT,"
    " service TEXT NOT NULL,"
    " payload TEXT,"
    " created_at DOUBLE PRECISION,"
    " updated_at DOUBLE PRECISION,"
    " lookup_count INTEGER DEFAULT 0,"
    " cache_hits INTEGER DEFAULT 0,"
    " api_calls INTEGER DEFAULT 0,"
    " PRIMARY KEY (indicator, service))"
)

# Per-user check log: one row per qualifying check of an indicator by a user.
# Used to detect when more than one analyst (or the same analyst in separate
# sessions >dedup apart) has looked at an indicator within the window.
_CREATE_CHECKS = (
    "CREATE TABLE IF NOT EXISTS indicator_checks ("
    " indicator TEXT NOT NULL,"
    " indicator_type TEXT,"
    " username TEXT,"
    " checked_at DOUBLE PRECISION)"
)


class SQLiteBackend:
    """Local single-file cache using the stdlib sqlite3 module."""

    def __init__(self, db_path):
        import sqlite3  # stdlib, always available
        self._sqlite3 = sqlite3
        self._path = db_path
        self._local = threading.local()
        self._write_lock = threading.Lock()
        self._ensure_schema()

    def _conn(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._sqlite3.connect(self._path, timeout=10)
            conn.row_factory = self._sqlite3.Row
            self._local.conn = conn
        return conn

    def _ensure_schema(self):
        with self._write_lock:
            conn = self._conn()
            # SQLite accepts "DOUBLE PRECISION" as a REAL affinity.
            conn.execute(_CREATE_TABLE)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_indicator "
                "ON indicator_cache(indicator)")
            conn.execute(_CREATE_CHECKS)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_checks_ind "
                "ON indicator_checks(indicator)")
            conn.commit()

    def get_fresh_row(self, indicator, service, fresh_secs):
        cur = self._conn().execute(
            "SELECT payload, updated_at, lookup_count FROM indicator_cache "
            "WHERE indicator=? AND service=?", (indicator, service))
        row = cur.fetchone()
        if row is None or row["updated_at"] is None:
            return None
        if (time.time() - row["updated_at"]) < fresh_secs:
            return {"payload": row["payload"],
                    "updated_at": row["updated_at"],
                    "lookup_count": row["lookup_count"]}
        return None

    def get_any_row(self, indicator, service):
        cur = self._conn().execute(
            "SELECT payload, updated_at, lookup_count FROM indicator_cache "
            "WHERE indicator=? AND service=?", (indicator, service))
        row = cur.fetchone()
        if row is None:
            return None
        return {"payload": row["payload"],
                "updated_at": row["updated_at"],
                "lookup_count": row["lookup_count"]}

    def record_hit(self, indicator, service):
        with self._write_lock:
            conn = self._conn()
            conn.execute(
                "UPDATE indicator_cache SET lookup_count=lookup_count+1, "
                "cache_hits=cache_hits+1 WHERE indicator=? AND service=?",
                (indicator, service))
            conn.commit()

    def store_miss(self, indicator, itype, service, payload):
        now = time.time()
        with self._write_lock:
            conn = self._conn()
            conn.execute(
                "INSERT INTO indicator_cache "
                "(indicator, indicator_type, service, payload, created_at, "
                " updated_at, lookup_count, cache_hits, api_calls) "
                "VALUES (?,?,?,?,?,?,1,0,1) "
                "ON CONFLICT(indicator, service) DO UPDATE SET "
                " payload=excluded.payload, "
                " indicator_type=excluded.indicator_type, "
                " updated_at=excluded.updated_at, "
                " lookup_count=indicator_cache.lookup_count+1, "
                " api_calls=indicator_cache.api_calls+1",
                (indicator, itype, service, payload, now, now))
            conn.commit()

    def stats(self):
        cur = self._conn().execute(
            "SELECT COALESCE(SUM(cache_hits),0), COALESCE(SUM(api_calls),0), "
            "COUNT(*) FROM indicator_cache")
        hits, api_calls, rows = cur.fetchone()
        return int(hits), int(api_calls), int(rows)

    def purge(self, older_secs):
        cutoff = time.time() - older_secs
        with self._write_lock:
            conn = self._conn()
            cur = conn.execute(
                "DELETE FROM indicator_cache WHERE updated_at < ?", (cutoff,))
            conn.commit()
            return cur.rowcount

    def record_check(self, indicator, itype, username, dedup_secs):
        """Log a check by username, skipping a same-user check within dedup_secs.

        Returns True if a new check row was inserted, False if deduplicated.
        """
        now = time.time()
        with self._write_lock:
            conn = self._conn()
            cur = conn.execute(
                "SELECT MAX(checked_at) FROM indicator_checks "
                "WHERE indicator=? AND username=?", (indicator, username))
            last = cur.fetchone()[0]
            if last is None or (now - last) > dedup_secs:
                conn.execute(
                    "INSERT INTO indicator_checks "
                    "(indicator, indicator_type, username, checked_at) "
                    "VALUES (?,?,?,?)", (indicator, itype, username, now))
                conn.commit()
                return True
            return False

    def check_stats(self, indicator, window_secs):
        """Return (distinct_users, total_checks) within the window."""
        cutoff = time.time() - window_secs
        cur = self._conn().execute(
            "SELECT COUNT(DISTINCT username), COUNT(*) FROM indicator_checks "
            "WHERE indicator=? AND checked_at>=?", (indicator, cutoff))
        distinct, total = cur.fetchone()
        return int(distinct), int(total)


class PostgresBackend:
    """Shared remote cache using PostgreSQL (psycopg2).

    A small threaded connection pool is used so concurrent lookups don't block
    each other. Raises on construction if psycopg2 is missing or the server is
    unreachable; the factory catches that and falls back to live lookups.
    """

    def __init__(self, cfg):
        import psycopg2  # optional dependency, only needed for remote
        from psycopg2.pool import ThreadedConnectionPool
        self._psycopg2 = psycopg2
        self._pool = ThreadedConnectionPool(
            1, 8,
            host=cfg["host"], port=cfg["port"], dbname=cfg["dbname"],
            user=cfg["db_user"], password=cfg["password"], sslmode=cfg["sslmode"])
        self._ensure_schema()

    @contextmanager
    def _cursor(self):
        conn = self._pool.getconn()
        try:
            cur = conn.cursor()
            yield cur
            conn.commit()
            cur.close()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.putconn(conn)

    def _ensure_schema(self):
        with self._cursor() as cur:
            cur.execute(_CREATE_TABLE)
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_indicator "
                "ON indicator_cache(indicator)")
            cur.execute(_CREATE_CHECKS)
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_checks_ind "
                "ON indicator_checks(indicator)")

    def get_fresh_row(self, indicator, service, fresh_secs):
        with self._cursor() as cur:
            cur.execute(
                "SELECT payload, updated_at, lookup_count FROM indicator_cache "
                "WHERE indicator=%s AND service=%s", (indicator, service))
            row = cur.fetchone()
        if row is None or row[1] is None:
            return None
        if (time.time() - float(row[1])) < fresh_secs:
            return {"payload": row[0], "updated_at": float(row[1]),
                    "lookup_count": row[2]}
        return None

    def get_any_row(self, indicator, service):
        with self._cursor() as cur:
            cur.execute(
                "SELECT payload, updated_at, lookup_count FROM indicator_cache "
                "WHERE indicator=%s AND service=%s", (indicator, service))
            row = cur.fetchone()
        if row is None:
            return None
        return {"payload": row[0],
                "updated_at": float(row[1]) if row[1] is not None else None,
                "lookup_count": row[2]}

    def record_hit(self, indicator, service):
        with self._cursor() as cur:
            cur.execute(
                "UPDATE indicator_cache SET lookup_count=lookup_count+1, "
                "cache_hits=cache_hits+1 WHERE indicator=%s AND service=%s",
                (indicator, service))

    def store_miss(self, indicator, itype, service, payload):
        now = time.time()
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO indicator_cache "
                "(indicator, indicator_type, service, payload, created_at, "
                " updated_at, lookup_count, cache_hits, api_calls) "
                "VALUES (%s,%s,%s,%s,%s,%s,1,0,1) "
                "ON CONFLICT (indicator, service) DO UPDATE SET "
                " payload=excluded.payload, "
                " indicator_type=excluded.indicator_type, "
                " updated_at=excluded.updated_at, "
                " lookup_count=indicator_cache.lookup_count+1, "
                " api_calls=indicator_cache.api_calls+1",
                (indicator, itype, service, payload, now, now))

    def stats(self):
        with self._cursor() as cur:
            cur.execute(
                "SELECT COALESCE(SUM(cache_hits),0), "
                "COALESCE(SUM(api_calls),0), COUNT(*) FROM indicator_cache")
            hits, api_calls, rows = cur.fetchone()
        return int(hits), int(api_calls), int(rows)

    def purge(self, older_secs):
        cutoff = time.time() - older_secs
        with self._cursor() as cur:
            cur.execute(
                "DELETE FROM indicator_cache WHERE updated_at < %s", (cutoff,))
            return cur.rowcount

    def record_check(self, indicator, itype, username, dedup_secs):
        now = time.time()
        with self._cursor() as cur:
            cur.execute(
                "SELECT MAX(checked_at) FROM indicator_checks "
                "WHERE indicator=%s AND username=%s", (indicator, username))
            row = cur.fetchone()
            last = row[0] if row else None
            if last is None or (now - float(last)) > dedup_secs:
                cur.execute(
                    "INSERT INTO indicator_checks "
                    "(indicator, indicator_type, username, checked_at) "
                    "VALUES (%s,%s,%s,%s)", (indicator, itype, username, now))
                return True
            return False

    def check_stats(self, indicator, window_secs):
        cutoff = time.time() - window_secs
        with self._cursor() as cur:
            cur.execute(
                "SELECT COUNT(DISTINCT username), COUNT(*) FROM indicator_checks "
                "WHERE indicator=%s AND checked_at>=%s", (indicator, cutoff))
            distinct, total = cur.fetchone()
        return int(distinct), int(total)


# ─────────────────────────────────────────────────────────────────────────────
# Thread-aware stdout capture
#   Installed once while analyst() runs. While a thread has an active capture
#   buffer, that thread's writes go to the buffer; all other writes pass through
#   to the real stdout. This lets us capture one service's output without
#   disturbing the others running concurrently.
# ─────────────────────────────────────────────────────────────────────────────

_capture_local = threading.local()


class _CaptureTee:
    def __init__(self, original):
        self._original = original

    def write(self, s):
        buf = getattr(_capture_local, "buffer", None)
        if buf is not None:
            buf.write(s)
        else:
            self._original.write(s)

    def flush(self):
        try:
            self._original.flush()
        except Exception:
            pass

    def __getattr__(self, name):
        # Delegate everything else (encoding, isatty, fileno, ...) to the real stream.
        return getattr(self._original, name)


def install_capture():
    if not isinstance(sys.stdout, _CaptureTee):
        sys.stdout = _CaptureTee(sys.stdout)


def restore_capture():
    if isinstance(sys.stdout, _CaptureTee):
        sys.stdout = sys.stdout._original


@contextmanager
def _capture():
    prev = getattr(_capture_local, "buffer", None)
    buf = io.StringIO()
    _capture_local.buffer = buf
    try:
        yield buf
    finally:
        _capture_local.buffer = prev


# ─────────────────────────────────────────────────────────────────────────────
# Cache manager
# ─────────────────────────────────────────────────────────────────────────────

class CacheManager:
    """Coordinates freshness, counters, capture/replay and resilience.

    A manager with backend=None is the disabled form: cached_call simply runs
    the live function, so callers never need to special-case it.
    """

    def __init__(self, backend, freshness_days=7.0, force_prefix="!",
                 purge_days=0.0, username="unknown", check_window_days=7.0,
                 check_dedup_minutes=60.0):
        self.backend = backend
        self.enabled = backend is not None
        self.freshness_seconds = max(0.0, float(freshness_days)) * 86400.0
        self.force_prefix = force_prefix or ""
        self.purge_days = max(0.0, float(purge_days))
        self.username = username or "unknown"
        self.check_window_seconds = max(0.0, float(check_window_days)) * 86400.0
        self.dedup_seconds = max(0.0, float(check_dedup_minutes)) * 60.0
        self._print_lock = threading.Lock()

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _norm(indicator, itype):
        value = (indicator or "").strip()
        if itype in ("hash", "domain", "url"):
            return value.lower()
        return value

    @staticmethod
    def _strip_quota(text):
        """Drop live API-quota warning lines so they aren't replayed stale.

        Both the VirusTotal and AbuseIPDB quota messages contain the phrase
        'API Queries'. Those reflect live usage and must not be served from a
        cached entry (no API call happens on a hit).
        """
        return "".join(
            line for line in text.splitlines(keepends=True)
            if "API Queries" not in line)

    def _emit(self, text):
        """Write a finished block to the real screen, atomically."""
        if not text:
            return
        out = sys.stdout
        if isinstance(out, _CaptureTee):
            out = out._original
        with self._print_lock:
            out.write(text if text.endswith("\n") else text + "\n")
            try:
                out.flush()
            except Exception:
                pass

    @staticmethod
    def _cached_marker(age_seconds, lookups):
        days = age_seconds / 86400.0
        if days < 1:
            age = "less than a day"
        elif days < 2:
            age = "1 day"
        else:
            age = "%d days" % int(days)
        return "\t(cached result — %s old, %d lookups)\n" % (age, lookups)

    # -- main entry point ----------------------------------------------------

    def cached_call(self, indicator, indicator_type, service, live_fn,
                    force_refresh=False):
        """Serve `service` for `indicator` from cache when fresh, else live.

        live_fn is the existing zero-argument function that prints the report.
        On a cache miss its printed output is captured, shown, and stored.
        """
        if not self.enabled:
            live_fn()
            return

        key = self._norm(indicator, indicator_type)

        # 1) Fresh cache hit (unless the user forced a refresh)
        if not force_refresh:
            try:
                row = self.backend.get_fresh_row(
                    key, service, self.freshness_seconds)
            except Exception:
                row = None
            if row is not None:
                try:
                    self.backend.record_hit(key, service)
                except Exception:
                    pass
                age = time.time() - (row["updated_at"] or time.time())
                self._emit(self._cached_marker(age, (row["lookup_count"] or 0) + 1)
                           + (row["payload"] or ""))
                return

        # 2) Miss → run live, capturing its printed output
        try:
            with _capture() as buf:
                live_fn()
            text = buf.getvalue()
        except Exception:
            # 3) Stale-while-error: live call failed — fall back to any cached
            #    copy, even if older than the freshness window.
            try:
                stale = self.backend.get_any_row(key, service)
            except Exception:
                stale = None
            if stale is not None and stale.get("payload"):
                try:
                    self.backend.record_hit(key, service)
                except Exception:
                    pass
                self._emit("\t(stale cached result — live lookup failed)\n"
                           + stale["payload"])
                return
            raise

        # Store the result (without live-only quota lines), then show the live output.
        try:
            self.backend.store_miss(
                key, indicator_type, service, self._strip_quota(text))
        except Exception:
            pass
        self._emit(text)

    # -- multi-user check logging -------------------------------------------

    _TYPE_LABELS = {"ip": "IP", "hash": "hash", "domain": "domain", "url": "URL"}

    def record_check_and_alert(self, indicator, indicator_type):
        """Log that the current user looked up `indicator`, and if more than one
        qualifying check exists within the window, print a heads-up notice.

        A "qualifying check" = a different user, or the same user more than
        `check_dedup_minutes` after their previous check (so rapid re-copies by
        one analyst don't inflate the count).
        """
        if not self.enabled:
            return
        key = self._norm(indicator, indicator_type)
        try:
            self.backend.record_check(
                key, indicator_type, self.username, self.dedup_seconds)
            distinct_users, total_checks = self.backend.check_stats(
                key, self.check_window_seconds)
        except Exception:
            return

        if total_checks <= 1:
            return

        label = self._TYPE_LABELS.get(indicator_type, indicator_type)
        days = self.check_window_seconds / 86400.0
        days_s = "%d" % int(days) if days == int(days) else "%.1f" % days

        if distinct_users > 1:
            msg = ("%d users have checked this %s in the last %s days "
                   "(%d checks total)." % (distinct_users, label, days_s, total_checks))
        else:
            msg = ("This %s has been checked %d times in the last %s days."
                   % (label, total_checks, days_s))
        self._emit_alert(msg)

    def _emit_alert(self, msg):
        bold, yellow, end = "\033[1m", "\033[93m", "\033[0m"
        self._emit("%s%s*** MULTI-USER NOTICE: %s%s" % (bold, yellow, msg, end))

    # -- lifecycle -----------------------------------------------------------

    def startup(self):
        """Install capture, optionally purge, and print a one-line summary."""
        if not self.enabled:
            return
        install_capture()
        if self.purge_days > 0:
            try:
                removed = self.backend.purge(self.purge_days * 86400.0)
                if removed:
                    print("Cache: purged %d entries older than %g days."
                          % (removed, self.purge_days))
            except Exception:
                pass
        try:
            hits, api_calls, rows = self.backend.stats()
            print("Cache enabled as user '%s' (%d entries). "
                  "API calls saved so far: %d." % (self.username, rows, hits))
        except Exception:
            print("Cache enabled as user '%s'." % self.username)

    def shutdown(self):
        restore_capture()


# ─────────────────────────────────────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────────────────────────────────────

def build_cache_manager(path="config.ini"):
    """Build a CacheManager from config.ini. Always returns a manager.

    On any problem (disabled, missing driver, unreachable DB) it returns a
    disabled manager so callers run live lookups with no special handling.
    """
    cfg = get_cache_config_from_config(path)

    if not cfg["enabled"]:
        print("Cache disabled in config.")
        return CacheManager(None)

    backend = None
    try:
        if cfg["backend"] == "remote":
            if not cfg["host"] or not cfg["dbname"]:
                print("Cache: remote backend selected but host/dbname not set. "
                      "Caching disabled.")
            else:
                backend = PostgresBackend(cfg)
        else:
            backend = SQLiteBackend(cfg["db_path"])
    except Exception as exc:
        print("Cache: could not initialize %s backend (%s). Caching disabled."
              % (cfg["backend"], exc))
        backend = None

    # Identity recorded in the check log: explicit config value, else OS user.
    username = (cfg["user"] or "").strip()
    if not username:
        try:
            username = getpass.getuser()
        except Exception:
            username = "unknown"

    manager = CacheManager(
        backend,
        freshness_days=cfg["freshness_days"],
        force_prefix=cfg["force_prefix"],
        purge_days=cfg["purge_days"],
        username=username,
        check_window_days=cfg["check_window_days"],
        check_dedup_minutes=cfg["check_dedup_minutes"])
    return manager
