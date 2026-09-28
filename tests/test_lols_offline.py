"""LOLBAS / LOLDrivers startup without network (analyst_tool_lols)."""
import json
import os
import time

import pytest

import analyst_tool_lols as L

CATALOGUE = [{"Name": "Certutil.exe", "Description": "d", "Full_Path": "x",
              "Commands": "c", "Detection": [], "url": "u"}]


@pytest.fixture(autouse=True)
def _fresh_state(monkeypatch):
    monkeypatch.setattr(L, "_retry_started", set())
    monkeypatch.setattr(L, "_RETRY_SECONDS", 0.05)
    L._build_lolbas_indexes([])
    yield
    L._build_lolbas_indexes([])


def _wait_for(pred, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.02)
    return False


def test_offline_no_cache_starts_disabled_then_background_retry_enables(tmp_path, monkeypatch, capsys):
    fname = str(tmp_path / "lolbas.json")
    attempts = {"n": 0}

    def fetch(url, path):
        attempts["n"] += 1
        if attempts["n"] < 3:                       # startup + first retry fail
            raise OSError("Tunnel connection failed: 403 Forbidden")
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps(CATALOGUE))
        return json.dumps(CATALOGUE)

    monkeypatch.setattr(L, "_fetch_and_save_file", fetch)
    raw = L.get_lolbas_json(L.lolbas_url, fname, 14, time.time(), time.time() - 14 * 86400)

    assert raw == ""                                         # no crash, disabled
    out = capsys.readouterr().out
    assert "LolBas unavailable (" in out and "retrying every" in out
    assert L.get_lolbas_file_endings(raw, "certutil.exe") is False

    assert _wait_for(lambda: L.get_lolbas_file_endings(raw, "certutil.exe"))
    assert attempts["n"] == 3
    assert os.path.exists(fname)                             # saved for next startup
    assert "LolBas loaded (1 entries)" in capsys.readouterr().out
    assert "LolBas" not in L._retry_started                  # thread finished


def test_corrupt_fresh_cache_is_treated_as_unavailable(tmp_path, monkeypatch, capsys):
    fname = tmp_path / "lolbas.json"
    fname.write_text("<html>502 Bad Gateway</html>")         # fresh mtime, bad content
    monkeypatch.setattr(L, "_fetch_and_save_file",
                        lambda url, path: json.dumps(CATALOGUE))
    raw = L.get_lolbas_json(L.lolbas_url, str(fname), 14, time.time(), time.time() - 14 * 86400)
    assert raw == ""
    assert "LolBas unavailable" in capsys.readouterr().out
    assert _wait_for(lambda: L.get_lolbas_file_endings(raw, "certutil.exe"))


def test_non_list_json_is_rejected(tmp_path, monkeypatch):
    fname = tmp_path / "lolbas.json"
    fname.write_text(json.dumps({"error": "rate limited"}))
    monkeypatch.setattr(L, "_RETRY_SECONDS", 3600)          # don't let the retry fire
    raw = L.get_lolbas_json(L.lolbas_url, str(fname), 14, time.time(), time.time() - 14 * 86400)
    assert raw == ""


def test_cached_copy_still_used_offline(tmp_path, monkeypatch, capsys):
    fname = tmp_path / "lolbas.json"
    fname.write_text(json.dumps(CATALOGUE))
    os.utime(fname, (time.time() - 30 * 86400,) * 2)         # stale → tries to refresh

    def fetch(url, path):
        raise OSError("offline")
    monkeypatch.setattr(L, "_fetch_and_save_file", fetch)
    raw = L.get_lolbas_json(L.lolbas_url, str(fname), 14, time.time(), time.time() - 14 * 86400)
    assert raw and "LolBas configured." in capsys.readouterr().out
    assert L.get_lolbas_file_endings(raw, "certutil.exe") is True
    assert "LolBas" not in L._retry_started                  # no retry needed


def test_loldriver_offline_does_not_crash(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(L, "_RETRY_SECONDS", 3600)
    monkeypatch.setattr(L, "_fetch_and_save_file",
                        lambda url, path: (_ for _ in ()).throw(OSError("offline")))
    raw = L.get_loldriver_json(L.loldriver_url, str(tmp_path / "drivers.json"), 14,
                               time.time(), time.time() - 14 * 86400)
    assert raw == "" and "LolDriver unavailable (offline)" in capsys.readouterr().out


def test_retry_survives_a_failing_loader(tmp_path, monkeypatch):
    """If building the catalogue throws once, the retry thread keeps going."""
    calls = {"fetch": 0, "load": 0}

    def fetch(url, path):
        calls["fetch"] += 1
        if calls["fetch"] == 1:
            raise OSError("offline")
        return json.dumps(CATALOGUE)
    monkeypatch.setattr(L, "_fetch_and_save_file", fetch)

    real_build = L._build_lolbas_indexes

    def flaky_build(data):
        calls["load"] += 1
        if data and calls["load"] == 2:            # first real load attempt blows up
            raise RuntimeError("boom")
        real_build(data)
    monkeypatch.setattr(L, "_build_lolbas_indexes", flaky_build)
    raw = L.get_lolbas_json(L.lolbas_url, str(tmp_path / "l.json"), 14, time.time(), 0)
    assert raw == ""
    assert _wait_for(lambda: L.get_lolbas_file_endings(raw, "certutil.exe"))


def test_short_reasons_are_readable():
    import requests
    assert L._short(requests.exceptions.ProxyError("HTTPSConnectionPool(...) Max retries")) == "no network"
    assert L._short(requests.exceptions.ConnectTimeout("x")) == "download timed out"
    assert L._short(ValueError("Expecting value: line 1")) == "bad or corrupt data"
