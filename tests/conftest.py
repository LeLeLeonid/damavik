# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Shared pytest fixtures.  No third-party plugins, no network."""

from __future__ import annotations

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "brain"))

FIXTURES = os.path.join(ROOT, "tests", "fixtures")


@pytest.fixture(scope="session")
def repo_root() -> str:
    return ROOT


@pytest.fixture(scope="session")
def rules_dir() -> str:
    return os.path.join(ROOT, "rules")


@pytest.fixture(scope="session")
def attack_chain() -> str:
    return os.path.join(FIXTURES, "attack-chain.jsonl")


@pytest.fixture(scope="session")
def rule_cases() -> dict:
    with open(os.path.join(FIXTURES, "rule_cases.json"), encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture()
def config(tmp_path, rules_dir):  # noqa: ANN001
    """A fully offline config writing into a temporary state dir."""
    from damavik.config import Config

    return Config(
        state_dir=str(tmp_path),
        offline=True,
        rules={"dir": rules_dir},
        intel={"osv_mirror": {"enabled": True, "sync": "weekly",
                              "dir": os.path.join(FIXTURES, "osv")}},
        alerts={"path": "alerts.log", "notify": False, "cooldown_s": 0, "min_score": 45.0},
    )


@pytest.fixture()
def store(tmp_path):  # noqa: ANN001
    from damavik.store import Store

    handle = Store(str(tmp_path / "test.db"))
    yield handle
    handle.close()
