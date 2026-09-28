"""ensure_tool_home(): find config.ini when launched from another folder."""
import os

import analyst_tool_utilities as U

TOOL_DIR = os.path.dirname(os.path.abspath(U.__file__))


def test_folder_with_config_is_left_alone(tmp_path, monkeypatch):
    (tmp_path / "config.ini").write_text("[GENERAL]\n")
    monkeypatch.chdir(tmp_path)
    assert U.ensure_tool_home(announce=False) is None
    assert os.getcwd() == str(tmp_path)


def test_switches_to_tool_folder_when_cwd_has_no_config(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ANALYST_TOOL_HOME", raising=False)
    home = U.ensure_tool_home()
    assert home == TOOL_DIR and os.getcwd() == TOOL_DIR
    assert "Using tool folder: " + TOOL_DIR in capsys.readouterr().out


def test_env_override(tmp_path, monkeypatch):
    target = tmp_path / "home"; target.mkdir()
    start = tmp_path / "elsewhere"; start.mkdir()
    monkeypatch.chdir(start)
    monkeypatch.setenv("ANALYST_TOOL_HOME", str(target))
    assert U.ensure_tool_home(announce=False) == str(target)
    assert os.getcwd() == str(target)


def test_nonexistent_env_home_is_ignored(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ANALYST_TOOL_HOME", str(tmp_path / "missing"))
    assert U.ensure_tool_home(announce=False) is None
    assert os.getcwd() == str(tmp_path)
