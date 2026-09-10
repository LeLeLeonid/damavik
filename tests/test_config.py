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
    for name in ("bazaar", "urlhaus", "abuseipdb", "otx", "vt"):
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


def test_keyed_provider_without_key_is_refused(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_KEY", raising=False)
    problems = validate({"intel": {"abuseipdb": {"enabled": True, "key_env": "ABUSEIPDB_KEY"}}})
    assert any("ABUSEIPDB_KEY" in p for p in problems)


def test_keyed_provider_with_key_is_accepted(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_KEY", "test")
    assert validate({"intel": {"abuseipdb": {"enabled": True, "key_env": "ABUSEIPDB_KEY"}}}) == []


def test_offline_disables_every_provider():
    cfg = from_dict(
        {
            "offline": True,
            "intel": {"bazaar": {"enabled": True}, "urlhaus": {"enabled": True}},
        }
    )
    assert cfg.enabled_intel() == {}


def test_enabled_keyless_providers_are_listed():
    cfg = from_dict(
        {"intel": {"osv_mirror": {"enabled": False}, "bazaar": {"enabled": True}}}
    )
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
