# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Packaging invariants for the shipped data.

The product promises "clone it and run it" *and* "install it and run it". Both
paths resolve the ruleset and the demo capture through ``cli.find_data``, which
falls back to a copy vendored inside the package (``damavik/data/``) because
``pip install`` leaves neither ``rules/`` nor ``tests/`` next to the working
directory. That copy is a duplicate, so it has to be checked: a vendored rule
that drifts from ``rules/`` means a pip-installed brain scores differently from
a checkout, silently.
"""

from __future__ import annotations

import os
import pathlib

import pytest
from damavik import __file__ as pkg_file
from damavik import cli

REPO = pathlib.Path(__file__).resolve().parent.parent
CANONICAL_RULES = REPO / "rules"
CANONICAL_FIXTURE = REPO / "tests" / "fixtures" / "attack-chain.jsonl"
VENDORED = pathlib.Path(pkg_file).resolve().parent / "data"


def test_vendored_rules_are_byte_identical_to_the_checkout():
    canonical = {p.name: p.read_bytes() for p in sorted(CANONICAL_RULES.glob("*.yml"))}
    vendored = {p.name: p.read_bytes() for p in sorted((VENDORED / "rules").glob("*.yml"))}
    assert len(canonical) == 20, "the shipped ruleset changed size; update the count here"
    assert set(vendored) == set(canonical), "vendored ruleset has different filenames"
    drifted = sorted(name for name, body in canonical.items() if vendored[name] != body)
    assert not drifted, f"vendored rules drifted from rules/: {drifted}"


def test_vendored_demo_capture_is_byte_identical_to_the_checkout_capture():
    vendored = VENDORED / "tests" / "fixtures" / "attack-chain.jsonl"
    assert vendored.read_bytes() == CANONICAL_FIXTURE.read_bytes()


def test_packaging_declares_the_vendored_data():
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert "data/rules/*.yml" in text, "the wheel would ship no ruleset"
    assert "data/tests/fixtures/*.jsonl" in text, "the wheel would ship no demo capture"


def test_lookup_order_is_cwd_then_checkout_then_package_then_usr_share(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    order = cli.data_candidates("rules")
    assert order[0] == os.path.join(str(tmp_path), "rules")
    assert order[1] == str(REPO / "rules")
    vendored = str(VENDORED / "rules")
    assert vendored in order
    assert order.index(vendored) < order.index("/usr/share/damavik/rules")


def test_vendored_ruleset_loads_and_is_a_complete_ruleset():
    from damavik.rules import load_rules_dir

    ruleset, errors = load_rules_dir(str(VENDORED / "rules"))
    assert errors == []
    assert len(ruleset.rules) == 20


@pytest.mark.parametrize("name", ["rules", os.path.join("tests", "fixtures", "attack-chain.jsonl")])
def test_every_shipped_path_resolves_to_an_existing_location(monkeypatch, tmp_path, name):
    """A fresh CWD plus no checkout means the vendored copy has to serve."""
    monkeypatch.chdir(tmp_path)
    resolved = cli.find_data(name)
    assert os.path.exists(resolved), resolved


# --- the installer ----------------------------------------------------------
# `packaging/install.sh` is the "no pip, no root, POSIX sh" path, and it failed
# in two ways at once: the launcher it wrote ran `cli.py` as a script (relative
# imports, instant ImportError) and the units it installed could not work.  The
# unit files are plain data, so their invariants are cheap to pin here; the
# installer also re-runs the *installed* command as its own gate, and CI runs
# the whole script into a throwaway prefix.


def test_launcher_runs_the_module_not_the_script():
    text = (REPO / "packaging" / "install.sh").read_text(encoding="utf-8")
    assert "python3 -m damavik.cli" in text
    assert 'exec python3 "$SHARE_DIR/damavik/cli.py"' not in text, (
        "running cli.py as a script cannot work: it uses relative imports"
    )
    assert "selftest" in text.split("--- verify what was just installed")[1]


def test_installed_units_reference_the_launcher_and_the_env_overrides():
    units = sorted((REPO / "packaging" / "systemd").glob("*.service"))
    assert [u.name for u in units] == ["damavik-dashboard.service", "damavik-sensor.service"]
    for unit in units:
        body = unit.read_text(encoding="utf-8")
        assert "/usr/local/bin/damavik" in body
        assert "DAMAVIK_STATE_DIR=" in body
        assert "ReadWritePaths=/var/lib/damavik" in body


def test_the_monitor_unit_is_self_contained():
    """One unit must be able to monitor the box on its own.

    The packaged install used to ship a `damavik run` unit with
    StandardInput=null - a service that reads EOF, exits 0 and is then simply
    inactive - while the sensor unit was BindsTo that inactive unit, so the
    three of them together monitored nothing.
    """
    sensor = (REPO / "packaging" / "systemd" / "damavik-sensor.service").read_text(encoding="utf-8")
    assert "ExecStart=/bin/sh -c '/usr/local/bin/damavik sensor" in sensor
    assert "/usr/local/bin/damavik run" in sensor
    assert "BindsTo=" not in sensor
    # WatchdogSec without an sd_notify ping kills a healthy service every
    # interval; systemd restarts it, forever.
    assert "WatchdogSec=" not in sensor or "sd_notify" in sensor
