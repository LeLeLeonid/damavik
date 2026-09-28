# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""CLI: every subcommand is reachable, JSON-capable and exits honestly."""

from __future__ import annotations

import json
import os
import time

import pytest
from damavik.cli import main
from damavik.schema import iso_to_ms

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
CHAIN = os.path.join(FIXTURES, "attack-chain.jsonl")
DPKG = os.path.join(FIXTURES, "dpkg_status.txt")
OSV_DIR = os.path.join(FIXTURES, "osv")


@pytest.fixture()
def cli(tmp_path, repo_root, rules_dir):
    def run(*args, expect=0):
        argv = [
            "--state-dir",
            str(tmp_path),
            "--rules-dir",
            rules_dir,
            "--offline",
            *args,
        ]
        code = main(argv)
        assert code == expect, f"{args} exited {code}"
        return code

    return run


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "damavik" in capsys.readouterr().out


def test_no_command_is_an_error():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_run_then_status(cli, capsys):
    cli("run", "--file", CHAIN)
    capsys.readouterr()
    cli("status", "--json")
    summary = json.loads(capsys.readouterr().out)
    assert summary["events"] == 35
    assert summary["alerts"] > 0
    assert summary["offline"] is True
    assert summary["rules"] >= 15


def test_an_old_capture_is_still_stored_and_reported_as_stale(cli, capsys):
    """The shipped capture is dated in the past, by definition.

    Loading it must keep every event (it is the batch this run loaded) and say
    so, instead of ingesting 35 events and deleting 35 events in the same call.
    """
    cli("run", "--file", CHAIN, "--json")
    payload = json.loads(capsys.readouterr().out)
    assert payload["events"] == 35
    assert payload["retention_removed"]["events"] == 0
    assert payload["stale_capture_s"] > 86400
    cli("status", "--json")
    assert json.loads(capsys.readouterr().out)["events"] == 35


def test_rebase_replays_a_capture_on_the_current_clock(cli, capsys):
    cli("run", "--file", CHAIN, "--rebase", "--json")
    payload = json.loads(capsys.readouterr().out)
    assert payload["events"] == 35
    assert payload["stale_capture_s"] == 0
    cli("top-risks", "--limit", "1", "--json")
    row = json.loads(capsys.readouterr().out)[0]
    age_s = time.time() - iso_to_ms(row["ts"]) / 1000.0
    assert 0 <= age_s < 300, "a rebased capture must look live"


def test_a_later_run_prunes_the_history_it_inherited(cli, capsys):
    """Retention moved from "delete what I just loaded" to "delete what I
    inherited", which is the only version that leaves a replay intact."""
    cli("run", "--file", CHAIN, "--json")
    capsys.readouterr()
    cli("run", "--file", CHAIN, "--json")
    output = capsys.readouterr()
    assert "retention: pruned 35 events" in output.err
    assert json.loads(output.out)["events"] == 35


def test_selftest_proves_the_index_holds_the_evidence(cli, capsys):
    """selftest is the gate install.sh refuses to install without, so it has to
    look at what was stored, not at in-memory counters."""
    cli("selftest", "--json")
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True, report["failures"]
    assert report["stats"]["events"] == report["summary"]["events"] == 35
    assert report["alerts"] == report["stats"]["alerts"] > 0
    assert report["journal"]["ok"] is True


def test_status_human_readable(cli, capsys):
    cli("status")
    assert "events" in capsys.readouterr().out


def test_demo(cli, capsys):
    cli("demo", "--fixture", CHAIN, "--json")
    payload = json.loads(capsys.readouterr().out)
    assert payload["stats"]["events"] == 35
    assert payload["alerts"]


def test_demo_counts_are_not_the_display_limit(cli, capsys):
    cli("demo", "--fixture", CHAIN, "--limit", "3")
    out = capsys.readouterr().out
    assert "processed 35 events" in out
    assert "showing 3" in out


def test_alerts_json_and_human(cli, capsys):
    cli("run", "--file", CHAIN)
    capsys.readouterr()
    cli("alerts", "--limit", "5", "--json")
    alerts = json.loads(capsys.readouterr().out)
    assert len(alerts) == 5
    assert all(alert["explain"] for alert in alerts)
    cli("alerts", "--limit", "5", "-v")
    out = capsys.readouterr().out
    assert "why" in out
    assert "iocs" in out


def test_alerts_empty_state(cli, capsys):
    cli("alerts")
    assert "no alerts" in capsys.readouterr().out


def test_ps_tree(cli, capsys):
    cli("run", "--file", CHAIN)
    capsys.readouterr()
    cli("ps-tree")
    out = capsys.readouterr().out
    assert "soffice.bin" in out
    cli("ps-tree", "--json")
    roots = json.loads(capsys.readouterr().out)
    assert isinstance(roots, list) and roots


def test_ps_tree_empty(cli, capsys):
    cli("ps-tree")
    assert "no processes" in capsys.readouterr().out


def test_flows(cli, capsys):
    cli("run", "--file", CHAIN)
    capsys.readouterr()
    cli("flows", "--pid", "3000", "--json")
    rows = json.loads(capsys.readouterr().out)
    assert rows and all(row["pid"] == 3000 for row in rows)


def test_flows_empty(cli, capsys):
    cli("flows")
    assert "no flows" in capsys.readouterr().out


def test_top_risks(cli, capsys):
    cli("run", "--file", CHAIN)
    capsys.readouterr()
    cli("top-risks", "--limit", "5", "--json")
    rows = json.loads(capsys.readouterr().out)
    scores = [row["score"] for row in rows]
    assert scores == sorted(scores, reverse=True)


def test_tail_once(cli, capsys):
    cli("run", "--file", CHAIN)
    capsys.readouterr()
    cli("tail", "--once", "--json")
    lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
    assert lines
    assert all(json.loads(line)["ts"] for line in lines)


def test_tail_alerts_only(cli, capsys):
    cli("run", "--file", CHAIN)
    capsys.readouterr()
    cli("tail", "--once", "--alerts-only")
    out = capsys.readouterr().out
    assert "dns.query" in out or "proc.exec" in out


def test_verify_ok(cli, capsys):
    cli("run", "--file", CHAIN)
    capsys.readouterr()
    cli("verify", "--json")
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True
    assert report["entries"] > 0


def test_verify_detects_tampering(cli, capsys, tmp_path):
    cli("run", "--file", CHAIN)
    capsys.readouterr()
    journal = tmp_path / "journal.jsonl"
    lines = journal.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["rec"]["event"]["score"] = 99.0  # a real semantic change
    lines[0] = json.dumps(record, sort_keys=True)
    journal.write_text("\n".join(lines) + "\n", encoding="utf-8")
    cli("verify", "--json", expect=2)
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False
    assert report["first_bad_line"] == 1


def test_verify_says_nothing_was_ingested_instead_of_ok(cli, capsys):
    """A missing journal is only fine while there is nothing it should hold."""
    cli("verify", "--json")
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True
    assert report["entries"] == 0
    assert report["reason"] == "no journal yet"


def test_verify_notices_a_deleted_audit_trail(cli, capsys, tmp_path):
    """Events in the index + no journal = the trail was deleted, not never written."""
    cli("run", "--file", CHAIN)
    capsys.readouterr()
    os.remove(tmp_path / "journal.jsonl")
    cli("verify", "--json", expect=2)
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False
    assert report["reason"] == "journal missing"


def test_option_order_does_not_matter(cli, capsys, tmp_path, rules_dir):
    """The units ship `run --config …`: runtime options work after a subcommand."""
    code = main(
        [
            "--state-dir",
            str(tmp_path),
            "--rules-dir",
            rules_dir,
            "run",
            "--offline",
            "--file",
            CHAIN,
            "--json",
        ]
    )
    assert code == 0
    stats = json.loads(capsys.readouterr().out)
    assert stats["events"] == 35
    # --config is accepted after the subcommand, which is the form the systemd
    # units use; a global-only --config made every unit unstartable.
    assert main(["status", "--state-dir", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["events"] == 35


def test_reserialising_a_record_is_not_tampering(cli, capsys, tmp_path):
    """Canonical hashing means different JSON spacing still verifies."""
    cli("run", "--file", CHAIN)
    capsys.readouterr()
    journal = tmp_path / "journal.jsonl"
    lines = journal.read_text(encoding="utf-8").splitlines()
    respaced = [json.dumps(json.loads(line), sort_keys=True) for line in lines]
    assert respaced[0] != lines[0]  # genuinely different bytes
    journal.write_text("\n".join(respaced) + "\n", encoding="utf-8")
    cli("verify", "--json")
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_validate_fixture(cli, capsys):
    cli("validate", CHAIN)
    assert "validated 35 lines" in capsys.readouterr().out


def test_validate_reports_bad_events(cli, capsys, tmp_path):
    bad = tmp_path / "bad.jsonl"
    lines = [
        ('{"ts":"2026-09-10T10:00:00Z","type":"proc.exec","proc":{"pid":1,"sha256":"not-a-hash"}}'),
        ('{"ts":"2026-09-10T10:00:01Z","type":"net.flow","net":{"dst":"1.2.3.4","dport":99999}}'),
    ]
    bad.write_text("\n".join(lines) + "\n", encoding="utf-8")
    cli("validate", str(bad), expect=1)
    out = capsys.readouterr().out
    assert "2 invalid" in out
    assert "sha256" in out and "dport" in out


def test_validate_rejects_unparseable_lines(cli, capsys, tmp_path):
    bad = tmp_path / "junk.jsonl"
    bad.write_text("not json at all\n", encoding="utf-8")
    cli("validate", str(bad), expect=1)
    assert "bad-json" in capsys.readouterr().out


def test_validate_accepts_an_unknown_type_but_records_it(cli, capsys, tmp_path):
    """A newer sensor must not be rejected - just labelled."""
    odd = tmp_path / "odd.jsonl"
    odd.write_text('{"ts":"2026-09-10T10:00:00Z","type":"future.event"}\n', encoding="utf-8")
    cli("validate", str(odd))
    assert "validated 1 lines" in capsys.readouterr().out
    from damavik.normalize import iter_jsonl, read_lines

    event = next(iter(iter_jsonl(read_lines(str(odd)))))
    assert event["type"] == "sensor.meta"
    assert event["meta"]["original_type"] == "future.event"


def test_selftest(cli, capsys, repo_root, monkeypatch):
    monkeypatch.chdir(repo_root)
    cli("selftest", "--json")
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True, report["failures"]
    assert report["stats"]["alerts"] > 0
    assert report["journal"]["ok"] is True


def test_selftest_fails_when_the_fixture_is_missing(cli, capsys, tmp_path):
    cli("selftest", "--fixture", str(tmp_path / "nope.jsonl"), "--json", expect=1)
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False
    assert report["failures"]


def test_pkg_scan_and_list(cli, capsys):
    cli("osv-sync", "--dir", OSV_DIR, "--index", "--json")
    capsys.readouterr()
    cli("pkg-list", "--scan", "--dpkg-status", DPKG, "--osv-dir", OSV_DIR, "--json")
    payload = json.loads(capsys.readouterr().out)
    assert payload["scan"]["scanned"] == 3
    assert payload["scan"]["changes"] == 3
    cli("pkg-list", "--osv-dir", OSV_DIR, "--json")
    payload = json.loads(capsys.readouterr().out)
    names = {pkg["name"] for pkg in payload["packages"]}
    assert "libfoo" in names
    assert any(item["name"] == "libfoo" for item in payload["vulnerable"])


def test_pkg_scan_is_a_silent_baseline_then_emits_news(cli, capsys, tmp_path):
    """DMK-V-001/002 select on pkg.event fields that only the scanner produces.

    Nothing used to emit those rows, so on a live host the two package rules
    could never fire - only a hand-written capture could trigger them.  The
    first scan records the inventory silently (everything is "new" on a fresh
    install); a later scan turns a genuinely new package into an event, a score
    and an alert.
    """
    snapshot = tmp_path / "status"
    snapshot.write_text(
        "Package: libfoo\nStatus: install ok installed\nArchitecture: amd64\n"
        "Version: 1.2.3\nDescription: example library with a parser\n",
        encoding="utf-8",
    )
    cli("pkg-list", "--scan", "--dpkg-status", str(snapshot), "--osv-dir", OSV_DIR, "--json")
    first = json.loads(capsys.readouterr().out)["scan"]
    assert first["baseline"] is True
    assert first["events"] == 0, "a first scan must not alert on the pre-installed OS"

    snapshot.write_text(
        snapshot.read_text(encoding="utf-8")
        + "\nPackage: netcat-openbsd\nStatus: install ok installed\nArchitecture: amd64\n"
        "Version: 1.226-1\nDescription: TCP/IP swiss army knife\n",
        encoding="utf-8",
    )
    cli("pkg-list", "--scan", "--dpkg-status", str(snapshot), "--osv-dir", OSV_DIR, "--json")
    second = json.loads(capsys.readouterr().out)["scan"]
    assert second["baseline"] is False
    assert second["events"] == 1, second
    assert second["alerts"] >= 1, "a new network-capable package must alert"

    cli("alerts", "--json")
    alerts = json.loads(capsys.readouterr().out)
    assert any(alert["rule"] == "DMK-V-002" for alert in alerts), [a["rule"] for a in alerts]

    # A scan of an unchanged host stays quiet: no re-alerting on every poll.
    cli("pkg-list", "--scan", "--dpkg-status", str(snapshot), "--osv-dir", OSV_DIR, "--json")
    third = json.loads(capsys.readouterr().out)["scan"]
    assert third["events"] == 0, third


def test_pkg_scan_refuses_an_empty_inventory(cli, capsys, tmp_path):
    """A dpkg file that cannot be read is not a host that uninstalled everything.

    `read_dpkg_status` returns [] for a missing path, and "every stored package
    is absent from this snapshot" then means hundreds of removal events written
    into the audit trail - false history caused by a failed open.  The scan says
    so and exits non-zero instead.
    """
    snapshot = tmp_path / "status"
    snapshot.write_text(
        "Package: libfoo\nStatus: install ok installed\nVersion: 1.2.3\n", encoding="utf-8"
    )
    cli("pkg-list", "--scan", "--dpkg-status", str(snapshot), "--osv-dir", OSV_DIR, "--json")
    capsys.readouterr()

    missing = tmp_path / "unmounted" / "status"
    cli(
        "pkg-list",
        "--scan",
        "--dpkg-status",
        str(missing),
        "--osv-dir",
        OSV_DIR,
        "--json",
        expect=1,
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["scan"]["unavailable"] is True
    assert payload["scan"]["removed"] == 0 and payload["scan"]["events"] == 0
    assert payload["packages"], "the stored inventory must survive a failed read"
    assert all(pkg["removed"] == 0 for pkg in payload["packages"])


def test_pkg_scan_stores_and_journals_what_it_finds(cli, capsys, tmp_path):
    """The scanner writes through the pipeline: index, journal, alerts."""
    snapshot = tmp_path / "status"
    snapshot.write_text("Package: a\nStatus: install ok installed\nVersion: 1\n", encoding="utf-8")
    cli("pkg-list", "--scan", "--dpkg-status", str(snapshot), "--osv-dir", OSV_DIR, "--json")
    capsys.readouterr()
    snapshot.write_text(
        snapshot.read_text(encoding="utf-8")
        + "\nPackage: b\nStatus: install ok installed\nVersion: 1\n"
        "Description: a network tool\n",
        encoding="utf-8",
    )
    cli("pkg-list", "--scan", "--dpkg-status", str(snapshot), "--osv-dir", OSV_DIR, "--json")
    capsys.readouterr()
    cli("status", "--json")
    summary = json.loads(capsys.readouterr().out)
    assert summary["events"] == 1
    cli("verify", "--json")
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_osv_sync_reports_counts(cli, capsys):
    cli("osv-sync", "--dir", OSV_DIR, "--index", "--json")
    payload = json.loads(capsys.readouterr().out)
    assert payload["advisories"] >= 3
    assert payload["rows_indexed"] > 0


def test_osv_sync_without_a_directory_hints(cli, capsys, tmp_path):
    cli("osv-sync", "--dir", str(tmp_path / "empty"), "--json")
    payload = json.loads(capsys.readouterr().out)
    assert payload["advisories"] == 0


def test_purge_requires_confirmation(cli, capsys):
    cli("run", "--file", CHAIN)
    capsys.readouterr()
    cli("purge", expect=2)
    cli("purge", "--yes")
    capsys.readouterr()
    cli("status", "--json")
    assert json.loads(capsys.readouterr().out)["events"] == 0


def test_bench_reports_the_budgets(cli, capsys):
    cli("bench", "--events", "300", "--gate")
    report = json.loads(capsys.readouterr().out)
    assert report["events"] == 300
    assert report["within_budget"] is True
    assert report["us_per_event"] > 0


def test_sensor_once(cli, capsys):
    cli("sensor", "--once", "--interval", "1")
    out = capsys.readouterr().out.strip().splitlines()
    assert out
    from damavik.schema import validate_event

    for line in out:
        assert validate_event(json.loads(line)) == []


def test_sensor_can_write_to_a_file(cli, capsys, tmp_path):
    target = tmp_path / "sensor.jsonl"
    cli("sensor", "--once", "--out", str(target))
    assert target.read_text(encoding="utf-8").strip()


def test_bad_config_is_reported(tmp_path, rules_dir, capsys):
    config = tmp_path / "damavik.yaml"
    config.write_text("nonsense_key: 1\n", encoding="utf-8")
    code = main(["--config", str(config), "status"])
    assert code == 2
    assert "config error" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Path resolution. The documented invocation is `cd brain && python3 -m
# damavik.cli …`, and an installed copy has neither rules/ nor tests/ next to
# the working directory. Defaults must resolve from the checkout, not the CWD.
# ---------------------------------------------------------------------------


def test_defaults_resolve_from_the_checkout_not_the_cwd(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    code = main(["--state-dir", str(tmp_path / "state"), "--offline", "selftest", "--json"])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True, report["failures"]
    assert report["rules"] >= 15
    assert report["stats"]["alerts"] > 0


def test_bench_works_from_any_directory(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    code = main(
        [
            "--state-dir",
            str(tmp_path / "state"),
            "--offline",
            "bench",
            "--events",
            "120",
        ]
    )
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["events"] == 120


def test_find_data_honours_an_explicit_override(tmp_path):
    """An operator who names a path means it, even before it exists."""
    from damavik.cli import find_data

    target = tmp_path / "custom-rules"
    assert find_data("rules", str(target)) == str(target)
    target.mkdir()
    assert find_data("rules", str(target)) == str(target)


def test_find_data_returns_a_sensible_path_when_nothing_exists(monkeypatch, tmp_path):
    from damavik.cli import find_data

    monkeypatch.chdir(tmp_path)
    assert find_data("definitely-not-here") == str(tmp_path / "definitely-not-here")


def test_colour_is_off_when_piped(monkeypatch):
    """Output is piped into grep more often than it is read."""
    import io

    from damavik.cli import use_color

    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert use_color(io.StringIO()) is False


def test_force_and_no_colour_env(monkeypatch):
    import io

    from damavik.cli import use_color

    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert use_color(io.StringIO()) is True
    # an explicit opt-out wins over a forced opt-in
    monkeypatch.setenv("NO_COLOR", "1")
    assert use_color(io.StringIO()) is False
