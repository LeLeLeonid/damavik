# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Privacy invariants, enforced mechanically rather than by promise.

The README makes three claims about the network.  These tests fail when the
code stops matching them, which is the only reason the claims are worth making.
"""

from __future__ import annotations

import ast
import os

from damavik.config import Config, from_dict

BRAIN = os.path.join(os.path.dirname(__file__), "..", "brain", "damavik")

#: Modules allowed to make outbound requests.  Everything else must not.
NETWORK_MODULES = {os.path.join("intel", "base.py")}

#: Imports that imply an outbound connection.
OUTBOUND_IMPORTS = ("urllib.request", "http.client", "smtplib", "ftplib", "telnetlib")


def python_modules():
    for root, _dirs, files in os.walk(BRAIN):
        for name in files:
            if name.endswith(".py"):
                yield os.path.join(root, name)


def imported_names(path: str) -> set[str]:
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def test_only_intel_may_talk_to_the_network():
    offenders = []
    for path in python_modules():
        relative = os.path.relpath(path, BRAIN)
        if relative in NETWORK_MODULES:
            continue
        found = imported_names(path) & set(OUTBOUND_IMPORTS)
        if found:
            offenders.append(f"{relative}: {sorted(found)}")
    assert offenders == [], f"unexpected outbound imports: {offenders}"


def test_intel_base_is_the_only_https_caller():
    with open(os.path.join(BRAIN, "intel", "base.py"), encoding="utf-8") as handle:
        source = handle.read()
    assert "urlopen" in source
    assert 'startswith("https://")' in source, "the transport must refuse plain HTTP"


def test_no_provider_is_enabled_by_default():
    cfg = Config()
    for name, spec in cfg.intel.items():
        if name == "osv_mirror":
            continue  # local files, no network
        assert spec["enabled"] is False, name


def test_offline_flag_disables_everything():
    cfg = from_dict({"offline": True, "intel": {"bazaar": {"enabled": True}}})
    assert cfg.enabled_intel() == {}
    from damavik.intel import providers_for

    assert providers_for(cfg) == []


def test_dashboard_cannot_bind_off_loopback():
    cfg = Config()
    assert cfg.dashboard["bind"] in ("127.0.0.1", "::1", "localhost")
    from damavik.config import validate

    assert any("loopback" in problem for problem in validate({"dashboard": {"bind": "10.0.0.1"}}))


def test_alerts_have_no_outbound_transport():
    """No webhook, no HTTP client: an alert can only be written locally.

    ``alerts.webhook`` used to exist in the schema without any code behind it;
    asserting its absence keeps a future implementation from landing silently.
    """
    cfg = Config()
    assert "webhook" not in cfg.alerts
    assert cfg.alerts["path"] and not str(cfg.alerts["path"]).startswith("http")


def test_static_ui_has_no_external_references(repo_root):
    """No scheme, no CDN host, no remote <script>/<link>: the UI is vendored."""
    static = os.path.join(repo_root, "brain", "damavik", "dash", "static")
    for name in os.listdir(static):
        with open(os.path.join(static, name), encoding="utf-8") as handle:
            body = handle.read()
        assert "://" not in body, f"{name} references a remote URL"
        for host in ("unpkg", "jsdelivr", "cdnjs", "googleapis", "bootstrapcdn"):
            assert host not in body.lower(), f"{name} references {host}"
        for tag in ("<script src=", '<link rel="stylesheet" href="http'):
            if tag in body:
                assert 'src="/' in body or 'href="/' in body, f"{name} loads a remote asset"


def test_no_telemetry_or_update_checks_in_source():
    needles = ("telemetry", "phone_home", "check_for_update", "analytics")
    for path in python_modules():
        with open(path, encoding="utf-8") as handle:
            body = handle.read().lower()
        for needle in needles:
            assert needle not in body, f"{path} mentions {needle}"


def test_purge_removes_everything(config, tmp_path):
    from damavik.cli import main

    fixture = os.path.join(os.path.dirname(__file__), "fixtures", "attack-chain.jsonl")
    assert (
        main(
            [
                "--state-dir",
                str(tmp_path),
                "--rules-dir",
                config.rules["dir"],
                "run",
                "--file",
                fixture,
            ]
        )
        == 0
    )
    assert os.path.exists(tmp_path / "damavik.db")
    assert main(["--state-dir", str(tmp_path), "purge", "--yes"]) == 0
    assert not os.path.exists(tmp_path / "journal.jsonl")
    from damavik.store import Store

    store = Store(str(tmp_path / "damavik.db"))
    assert store.summary()["events"] == 0
    store.close()


def test_readme_states_the_network_guarantees(repo_root):
    """The only document in the repo must still make the claims the code keeps."""
    with open(os.path.join(repo_root, "README.md"), encoding="utf-8") as handle:
        body = handle.read().lower()
    for claim in ("127.0.0.1", "offline", "no telemetry", "alert-only"):
        assert claim in body, claim
