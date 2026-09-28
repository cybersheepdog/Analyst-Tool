"""Per-service circuit breaker (analyst_tool_breaker)."""
import time
import pytest

from analyst_tool_breaker import ServiceBreaker
from analyst_tool_utilities import ServiceError


def test_quota_trips_for_backoff_window_then_clears():
    b = ServiceBreaker(quota_backoff_minutes=0.001)   # 60 ms
    assert b.trip("VirusTotal", 429) is True
    assert "quota exceeded" in b.check("VirusTotal")
    with pytest.raises(ServiceError) as ei:
        b.guard("VirusTotal")
    assert "skipped: quota exceeded" in str(ei.value)
    b.guard("VirusTotal", force=True)               # '!' prefix bypasses
    time.sleep(0.1)
    assert b.check("VirusTotal") is None             # window elapsed
    b.guard("VirusTotal")                            # no raise


def test_auth_trips_until_restart():
    b = ServiceBreaker(quota_backoff_minutes=15)
    assert b.trip("Shodan", 401) is True
    assert "API key" in b.check("Shodan")
    assert b.status() == [("Shodan", b.check("Shodan"))]
    b.reset("Shodan")
    assert b.check("Shodan") is None


def test_timeouts_and_5xx_never_trip():
    b = ServiceBreaker(quota_backoff_minutes=15)
    assert b.trip("OTX", 503) is False
    assert b.trip("OTX", None) is False
    assert b.check("OTX") is None
    assert b.observe(ServiceError("OTX", None, "timed out")) is False
    assert b.observe(RuntimeError("x")) is False


def test_observe_trips_from_service_error():
    b = ServiceBreaker(quota_backoff_minutes=15)
    assert b.observe(ServiceError("AbuseIPDB", 429, "rate limited")) is True
    assert b.check("AbuseIPDB")
    assert b.check("VirusTotal") is None             # independent per service


def test_zero_backoff_disables_quota_breaker():
    b = ServiceBreaker(quota_backoff_minutes=0)
    assert b.trip("VirusTotal", 429) is False
    assert b.trip("VirusTotal", 403) is True          # auth still trips
