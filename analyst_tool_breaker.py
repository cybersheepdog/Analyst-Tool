# Analyst Tool — per-service circuit breaker
#
# When a service answers "quota exceeded" (HTTP 429) or "bad credentials"
# (401/403), every further lookup would spend a timeout and print the same
# error line until the quota resets. The breaker remembers the failure and
# skips that service's LIVE call for a while, printing one line instead:
#
#     [VirusTotal] skipped: quota exceeded — retrying after 14:32
#
# Cached results are unaffected (the check happens at the point of the live
# call, inside CacheManager.cached_call), stale-while-error still serves an
# older copy, and the '!' force prefix bypasses the breaker for one lookup.
#
#   429            → skip for [GENERAL] quota_backoff_minutes (default 15)
#   401 / 403      → skip until the tool restarts (a bad key won't fix itself)
#   timeouts / 5xx → never trip (usually transient; retried every lookup)

import threading
import time
from configparser import ConfigParser

from analyst_tool_utilities import ServiceError

_QUOTA_CODES = (429,)
_AUTH_CODES = (401, 403)


def _backoff_minutes_from_config(path="config.ini"):
    try:
        cfg = ConfigParser()
        cfg.read(path)
        return max(0.0, float(cfg.get("GENERAL", "quota_backoff_minutes", fallback="15")))
    except Exception:
        return 15.0


class ServiceBreaker:
    def __init__(self, quota_backoff_minutes=None):
        self._lock = threading.Lock()
        self._open = {}      # service -> (until_epoch or None for "until restart", reason)
        self._minutes = quota_backoff_minutes

    def _minutes_(self):
        if self._minutes is None:
            self._minutes = _backoff_minutes_from_config()
        return self._minutes

    def trip(self, service, status):
        """Open the breaker for `service` based on an HTTP status. Returns True
        if it tripped."""
        if status in _QUOTA_CODES:
            minutes = self._minutes_()
            if minutes <= 0:
                return False
            until = time.time() + minutes * 60.0
            reason = "quota exceeded — retrying after %s" % time.strftime("%H:%M", time.localtime(until))
        elif status in _AUTH_CODES:
            until, reason = None, "invalid or unauthorised API key — fix config.ini and restart"
        else:
            return False
        with self._lock:
            self._open[service] = (until, reason)
        return True

    def check(self, service):
        """Return the skip reason if `service` is currently open, else None."""
        with self._lock:
            entry = self._open.get(service)
            if entry is None:
                return None
            until, reason = entry
            if until is not None and time.time() >= until:
                del self._open[service]
                return None
            return reason

    def reset(self, service=None):
        with self._lock:
            if service is None:
                self._open.clear()
            else:
                self._open.pop(service, None)

    def status(self):
        """[(service, reason)] for every open breaker (for >>status)."""
        with self._lock:
            now = time.time()
            return [(s, r) for s, (u, r) in self._open.items() if u is None or now < u]

    def guard(self, service, force=False):
        """Raise ServiceError if `service` is open (unless `force`)."""
        if force:
            return
        reason = self.check(service)
        if reason:
            raise ServiceError(service, None, "skipped: " + reason)

    def observe(self, exc):
        """Trip on a ServiceError with a quota/auth status. Returns True if tripped."""
        if isinstance(exc, ServiceError):
            return self.trip(exc.service, exc.status)
        return False


BREAKER = ServiceBreaker()
