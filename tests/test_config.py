# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Configuration defaults, validation and the offline kill-switch."""

from __future__ import annotations

import os

import pytest
from damavik.config import Config, ConfigError, from_dict, load, validate

MINIMAL = """
host_id: test-host
retention_days: 3
dashboard:
  bind: 127.0.0.1
  port: 8787
"""


def test_defaults_are_local_only():
    cfg = Config()
    assert cfg.dashboard["bind"] == "127.0.0.1"
    # The only default-on provider is the *local* OSV mirror: it reads files.
    assert set(cfg.enabled_intel()) == {"osv_mirror"}
    assert cfg.retention_days == 7


def test_no_network_provider_is_on_by_default():
    cfg = Config()
    # These are the only network-capable providers that exist; see
    # intel.providers_for.  A provider that is not implemented is not listed.
    assert set(cfg.intel) == {"osv_mirror", "bazaar", "urlhaus"}
    for name in ("bazaar", "urlhaus"):
        assert cfg.intel[name]["enabled"] is False, name


def test_load_from_file(tmp_path):
    path = tmp_path / "damavik.yaml"
    path.write_text(MINIMAL, encoding="utf-8")
    cfg = load(str(path))
    assert cfg.host_id == "test-host"
    assert cfg.retention_days == 3
    assert cfg.source_path == str(path)


def test_unknown_key_is_a_hard_error():
    problems = validate({"offlnie": True})
    assert any("unknown configuration key" in p for p in problems)


def test_non_loopback_bind_is_refused():
    problems = validate({"dashboard": {"bind": "0.0.0.0", "port": 8787}})
    assert any("loopback" in p for p in problems)


def test_negative_retention_is_refused():
    assert any("retention_days" in p for p in validate({"retention_days": -1}))


def test_bad_port_is_refused():
    assert any("port" in p for p in validate({"dashboard": {"port": 99999}}))


def test_a_provider_that_does_not_exist_is_a_hard_error():
    """Configuring an unimplemented provider must fail, not be ignored.

    ``abuseipdb``/``otx``/``vt`` used to be accepted here and then never
    constructed, so enabling one looked like it worked.
    """
    for name in ("abuseipdb", "otx", "vt", "virustotal"):
        problems = validate({"intel": {name: {"enabled": True}}})
        assert any("unknown configuration key" in p for p in problems), name


def test_offline_disables_every_provider():
    cfg = from_dict(
        {
            "offline": True,
            "intel": {"bazaar": {"enabled": True}, "urlhaus": {"enabled": True}},
        }
    )
    assert cfg.enabled_intel() == {}


def test_enabled_keyless_providers_are_listed():
    cfg = from_dict({"intel": {"osv_mirror": {"enabled": False}, "bazaar": {"enabled": True}}})
    assert set(cfg.enabled_intel()) == {"bazaar"}


def test_deep_merge_keeps_unmentioned_defaults():
    cfg = from_dict({"sensor": {"flows": False}})
    assert cfg.sensor["flows"] is False
    assert cfg.sensor["dns"] is True  # untouched default survives


def test_paths_resolve_under_state_dir(tmp_path):
    cfg = from_dict({"state_dir": str(tmp_path)})
    assert cfg.db_path().endswith("damavik.db")
    assert cfg.journal_path().startswith(str(tmp_path))
    assert cfg.alerts_path().startswith(str(tmp_path))


def test_missing_explicit_config_raises():
    with pytest.raises(ConfigError):
        load("/nonexistent/damavik.yaml")


def test_example_config_in_repo_is_valid(repo_root):
    """The shipped example must load, or the docs are lying."""
    path = os.path.join(repo_root, "config", "damavik.example.yaml")
    assert os.path.exists(path), path
    cfg = load(path)
    assert cfg.dashboard["bind"] == "127.0.0.1"


# --- environment overrides ---------------------------------------------------
# The systemd units ship DAMAVIK_STATE_DIR / DAMAVIK_RULES_DIR.  A sandboxed
# brain cannot take the config file's ~/.local/state for an answer (ProtectHome
# and ProtectSystem=strict make it unwritable), so the units' Environment= lines
# have to reach the Config object.  Precedence: file < environment < command line.


def test_env_overrides_state_dir_and_rules_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("DAMAVIK_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("DAMAVIK_RULES_DIR", str(tmp_path / "rules"))
    cfg = load(None)
    assert cfg.state_dir == str(tmp_path / "state")
    assert cfg.rules["dir"] == str(tmp_path / "rules")


def test_env_overrides_win_over_the_config_file(monkeypatch, tmp_path):
    path = tmp_path / "damavik.yaml"
    path.write_text("state_dir: /from/file\n", encoding="utf-8")
    monkeypatch.setenv("DAMAVIK_STATE_DIR", "/from/env")
    assert load(str(path)).state_dir == "/from/env"


def test_command_line_wins_over_the_environment(monkeypatch, tmp_path):
    from damavik.cli import main

    monkeypatch.setenv("DAMAVIK_STATE_DIR", str(tmp_path / "from-env"))
    code = main(["--state-dir", str(tmp_path / "cli"), "--offline", "status", "--json"])
    assert code == 0
    assert os.path.isdir(tmp_path / "cli")
    assert not os.path.exists(tmp_path / "from-env")


def test_env_flags_and_numbers_are_parsed(monkeypatch):
    monkeypatch.setenv("DAMAVIK_OFFLINE", "yes")
    monkeypatch.setenv("DAMAVIK_RETENTION_DAYS", "3")
    monkeypatch.setenv("DAMAVIK_HOST_ID", "unit-host")
    cfg = load(None)
    assert cfg.offline is True
    assert cfg.retention_days == 3
    assert cfg.host_id == "unit-host"


def test_a_broken_env_value_is_a_config_error_not_a_traceback(monkeypatch):
    monkeypatch.setenv("DAMAVIK_RETENTION_DAYS", "soon")
    with pytest.raises(ConfigError):
        load(None)
    monkeypatch.delenv("DAMAVIK_RETENTION_DAYS")
    monkeypatch.setenv("DAMAVIK_RETENTION_DAYS", "-1")
    with pytest.raises(ConfigError):
        load(None)


def test_unrelated_environment_variables_are_ignored(monkeypatch):
    monkeypatch.setenv("DAMAVIK_SOMETHING_ELSE", "1")
    assert load(None).retention_days == 7
