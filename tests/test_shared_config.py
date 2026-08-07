"""Tests for the shared (remote) config loader.

The remote database is never contacted: we monkeypatch the fetch/creds helpers
so the merge, whitelist and fallback logic can be exercised in isolation.
"""
import os
import tempfile

import analyst_tool_shared_config as SC


LOCAL_INI = """\
[VIRUS_TOTAL]
accept = application/json
x-apikey = LOCAL_VT
user = bob

[SHODAN]
shodan_api_key = LOCAL_SHODAN

[CVE]
nvd_api_key = LOCAL_NVD
"""


def _write_ini(text=LOCAL_INI):
    path = os.path.join(tempfile.mkdtemp(), "config.ini")
    with open(path, "w") as fh:
        fh.write(text)
    return path


def _setup(monkeypatch, remote_rows, backend="remote"):
    """Point the loader at fake creds + a fake remote result set."""
    SC.clear_cache()
    monkeypatch.setattr(SC, "get_cache_config_from_config",
                        lambda path="config.ini": {
                            "backend": backend, "host": "db", "dbname": "d",
                            "port": 5432, "db_user": "u", "password": "p",
                            "sslmode": "prefer"})
    monkeypatch.setattr(SC, "_fetch_remote_shared_config",
                        lambda cfg: remote_rows)


def test_remote_overrides_local(monkeypatch):
    path = _write_ini()
    _setup(monkeypatch, {("VIRUS_TOTAL", "x-apikey"): "REMOTE_VT"})
    cfg = SC.load_config(path, force_reload=True)
    assert cfg.get("VIRUS_TOTAL", "x-apikey") == "REMOTE_VT"     # remote wins
    assert cfg.get("VIRUS_TOTAL", "user") == "bob"              # local kept


def test_blank_remote_falls_back_to_local(monkeypatch):
    path = _write_ini()
    _setup(monkeypatch, {("SHODAN", "shodan_api_key"): "   "})
    cfg = SC.load_config(path, force_reload=True)
    assert cfg.get("SHODAN", "shodan_api_key") == "LOCAL_SHODAN"


def test_missing_remote_key_falls_back_to_local(monkeypatch):
    path = _write_ini()
    _setup(monkeypatch, {})                                     # nothing shared
    cfg = SC.load_config(path, force_reload=True)
    assert cfg.get("CVE", "nvd_api_key") == "LOCAL_NVD"


def test_non_whitelisted_option_is_ignored(monkeypatch):
    path = _write_ini()
    # 'user' is NOT a shared credential — a remote value must not override it.
    _setup(monkeypatch, {("VIRUS_TOTAL", "user"): "REMOTE_HIJACK"})
    cfg = SC.load_config(path, force_reload=True)
    assert cfg.get("VIRUS_TOTAL", "user") == "bob"


def test_unknown_section_is_ignored(monkeypatch):
    path = _write_ini()
    _setup(monkeypatch, {("SECRETS", "password"): "nope"})
    cfg = SC.load_config(path, force_reload=True)
    assert not cfg.has_section("SECRETS")


def test_local_backend_never_touches_remote(monkeypatch):
    path = _write_ini()
    calls = {"n": 0}

    def _boom(cfg):
        calls["n"] += 1
        raise AssertionError("remote must not be queried on local backend")

    SC.clear_cache()
    monkeypatch.setattr(SC, "get_cache_config_from_config",
                        lambda path="config.ini": {
                            "backend": "local", "host": "", "dbname": "",
                            "port": 5432, "db_user": "", "password": "",
                            "sslmode": "prefer"})
    monkeypatch.setattr(SC, "_fetch_remote_shared_config", _boom)
    cfg = SC.load_config(path, force_reload=True)
    assert cfg.get("SHODAN", "shodan_api_key") == "LOCAL_SHODAN"
    assert calls["n"] == 0


def test_remote_unreachable_falls_back(monkeypatch):
    path = _write_ini()
    # Fetch returns None (its documented "couldn't reach the DB" signal).
    _setup(monkeypatch, None)
    cfg = SC.load_config(path, force_reload=True)
    assert cfg.get("VIRUS_TOTAL", "x-apikey") == "LOCAL_VT"


def test_new_section_from_remote_added(monkeypatch):
    # A whitelisted key whose section isn't in the local file should be created.
    path = _write_ini("[VIRUS_TOTAL]\naccept = application/json\nx-apikey = L\n")
    _setup(monkeypatch, {("ABUSE_IP_DB", "key"): "REMOTE_ABUSE"})
    cfg = SC.load_config(path, force_reload=True)
    assert cfg.get("ABUSE_IP_DB", "key") == "REMOTE_ABUSE"


def test_missing_local_file_is_safe(monkeypatch):
    _setup(monkeypatch, {("SHODAN", "shodan_api_key"): "REMOTE_ONLY"})
    cfg = SC.load_config("/no/such/config.ini", force_reload=True)
    assert cfg.get("SHODAN", "shodan_api_key") == "REMOTE_ONLY"


# ── envelope encryption ──────────────────────────────────────────────────────

pytest = __import__("pytest")
cryptography = pytest.importorskip("cryptography")  # skip crypto tests if absent

import base64  # noqa: E402


def _encrypted_rows(passphrase, plaintext, section="VIRUS_TOTAL", option="x-apikey"):
    """Build a remote-rows dict with a salt row and one encrypted value."""
    salt = os.urandom(16)
    fernet = SC._derive_fernet(passphrase, salt)
    token = SC.ENC_PREFIX + fernet.encrypt(plaintext.encode()).decode()
    return {(SC.META_SECTION, SC.SALT_OPTION): base64.b64encode(salt).decode(),
            (section, option): token}


def test_encrypted_value_decrypted_with_passphrase(monkeypatch):
    monkeypatch.setenv(SC.PASSPHRASE_ENV, "team-passphrase")
    path = _write_ini()
    _setup(monkeypatch, _encrypted_rows("team-passphrase", "REMOTE_VT_SECRET"))
    cfg = SC.load_config(path, force_reload=True)
    assert cfg.get("VIRUS_TOTAL", "x-apikey") == "REMOTE_VT_SECRET"


def test_encrypted_value_without_passphrase_falls_back(monkeypatch):
    monkeypatch.delenv(SC.PASSPHRASE_ENV, raising=False)
    path = _write_ini()
    _setup(monkeypatch, _encrypted_rows("team-passphrase", "REMOTE_VT_SECRET"))
    cfg = SC.load_config(path, force_reload=True)
    assert cfg.get("VIRUS_TOTAL", "x-apikey") == "LOCAL_VT"   # local kept


def test_wrong_passphrase_falls_back(monkeypatch):
    rows = _encrypted_rows("the-right-one", "REMOTE_VT_SECRET")
    monkeypatch.setenv(SC.PASSPHRASE_ENV, "the-wrong-one")
    path = _write_ini()
    _setup(monkeypatch, rows)
    cfg = SC.load_config(path, force_reload=True)
    assert cfg.get("VIRUS_TOTAL", "x-apikey") == "LOCAL_VT"


def test_passphrase_from_key_file(monkeypatch, tmp_path):
    monkeypatch.delenv(SC.PASSPHRASE_ENV, raising=False)
    key_file = tmp_path / "shared.key"
    key_file.write_text("file-passphrase\n")
    ini = tmp_path / "config.ini"
    ini.write_text(LOCAL_INI + "\n[SHARED_CONFIG]\nkey_file = %s\n" % key_file)
    _setup(monkeypatch, _encrypted_rows("file-passphrase", "FROM_FILE"))
    cfg = SC.load_config(str(ini), force_reload=True)
    assert cfg.get("VIRUS_TOTAL", "x-apikey") == "FROM_FILE"


def test_roundtrip_plain_and_maybe_decrypt():
    salt = os.urandom(16)
    fernet = SC._derive_fernet("pp", salt)
    token = SC.ENC_PREFIX + fernet.encrypt(b"SECRET").decode()
    assert SC._maybe_decrypt(token, fernet) == "SECRET"        # good key
    assert SC._maybe_decrypt(token, None) is None              # no key -> skip
    assert SC._maybe_decrypt("LEGACY", fernet) == "LEGACY"     # plaintext passes
