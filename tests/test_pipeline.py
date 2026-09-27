# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""End-to-end: sensor JSONL -> normalize -> enrich -> score -> store -> alert."""

from __future__ import annotations

import json

import pytest
from damavik.journal import verify
from damavik.pipeline import Pipeline

EXPECTED_RULES = {
    "DMK-P-001",
    "DMK-P-002",
    "DMK-P-003",
    "DMK-P-004",
    "DMK-P-005",
    "DMK-F-001",
    "DMK-F-002",
    "DMK-F-003",
    "DMK-N-001",
    "DMK-N-002",
    "DMK-N-003",
    "DMK-N-004",
    "DMK-D-001",
    "DMK-D-002",
    "DMK-D-003",
    "DMK-R-001",
    "DMK-R-002",
    "DMK-S-001",
    "DMK-V-001",
    "DMK-V-002",
}


@pytest.fixture()
def run(config, attack_chain):
    pipeline = Pipeline(config)
    pipeline.run_file(attack_chain)
    yield pipeline
    pipeline.close()


def test_every_event_is_processed(run):
    assert run.stats.events == 35
    assert run.stats.scored == 35
    assert run.ingest_stats.rejected == 0


def test_the_whole_attack_chain_is_detected(run):
    fired = set(run.stats.rule_hits)
    missing = EXPECTED_RULES - fired
    assert not missing, f"rules that never fired: {sorted(missing)}"


def test_alerts_are_generated_and_ranked(run):
    alerts = run.store.alerts(limit=100)
    assert alerts
    levels = {alert["level"] for alert in alerts}
    assert "critical" in levels, "the YARA malware hit must reach critical"
    scores = [alert["score"] for alert in alerts]
    assert max(scores) >= 85.0


def test_every_alert_carries_its_evidence(run):
    for alert in run.store.alerts(limit=100):
        assert alert["explain"].strip(), alert["id"]
        assert alert["events"], alert["id"]
        assert alert["iocs"], alert["id"]
        assert alert["id"].startswith("a-")


def test_the_kill_chain_is_reconstructable(run):
    """office -> shell -> egress, in that order, all in the store."""
    events = run.store.events(limit=100)
    by_pid = {}
    for event in events:
        proc = event.get("proc") or {}
        if proc.get("pid") is not None:
            by_pid.setdefault(proc["pid"], event)
    shell = by_pid.get(2000)
    assert shell is not None
    assert shell["proc"].get("parent_exe", "").endswith("soffice.bin")
    flow = next(
        e for e in events if e["type"] == "net.flow" and (e.get("proc") or {}).get("pid") == 2000
    )
    assert flow["net"]["dport"] == 4444
    assert flow["meta"]["age_ms"] <= 2000


def test_allowlisted_init_scores_zero(run):
    init = next(
        e
        for e in run.store.events(limit=100)
        if (e.get("proc") or {}).get("exe", "").endswith("systemd")
    )
    assert init["score"] == 0.0
    assert "allowlisted" in init["tags"]


def test_supply_chain_shift_is_flagged(run):
    hits = [e for e in run.store.events(limit=100) if "supply_chain_shift" in (e.get("tags") or [])]
    assert hits, "a known path running a new hash must be flagged"
    assert hits[0]["meta"]["hash_changed"] is True


def test_dns_enrichment_is_present(run):
    dns = next(e for e in run.store.events(limit=100, etype="dns.query"))
    assert dns["dns"]["root"] == "exfil-tunnel.example"
    assert dns["meta"]["dns_entropy_ratio"] >= 0.9
    assert dns["meta"]["dns_label_len"] == 12


def test_journal_chain_verifies(run):
    report = verify(run.journal)
    assert report.ok, report.reason
    # the journal holds both events and the alerts they produced
    assert report.entries == run.stats.events + run.stats.alerts


def test_flow_aggregates_exist_for_the_beacon(run):
    rows = run.store.flow_aggregates(limit=50)
    beacon = [row for row in rows if row["dst"] == "45.155.205.233"]
    assert beacon
    assert max(row["conns"] for row in beacon) >= 6


def test_malformed_input_is_counted_not_fatal(config, tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text(
        "\n".join(
            [
                "not json at all",
                json.dumps(
                    {
                        "ts": "2026-09-10T10:00:00Z",
                        "type": "proc.exec",
                        "proc": {"pid": 1, "exe": "/bin/x"},
                    }
                ),
                json.dumps([1, 2, 3]),
                "x" * 200000,
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    with Pipeline(config) as pipeline:
        pipeline.run_file(str(path))
        assert pipeline.stats.events == 1
        assert pipeline.ingest_stats.rejected >= 2
        assert pipeline.ingest_stats.oversized == 1


def test_duplicate_lines_are_deduplicated(config, tmp_path):
    line = json.dumps(
        {
            "ts": "2026-09-10T10:00:00Z",
            "type": "proc.exec",
            "proc": {"pid": 1, "exe": "/bin/x"},
        }
    )
    path = tmp_path / "dupes.jsonl"
    path.write_text("\n".join([line] * 5) + "\n", encoding="utf-8")
    with Pipeline(config) as pipeline:
        pipeline.run_file(str(path))
        assert pipeline.ingest_stats.duplicates == 4
        assert pipeline.store.count_events() == 1


def test_cooldown_collapses_a_beacon(config, tmp_path):
    """Six beacons in a window must not become six alerts."""
    config.alerts["cooldown_s"] = 600
    lines = []
    for index in range(6):
        lines.append(
            json.dumps(
                {
                    "ts": f"2026-09-10T10:00:{index:02d}.000Z",
                    "type": "net.flow",
                    "proc": {"pid": 900 + index, "exe": "/bin/beacon"},
                    "net": {"proto": "tcp", "dst": "45.155.205.233", "dport": 443},
                }
            )
        )
    path = tmp_path / "beacon.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with Pipeline(config) as pipeline:
        pipeline.run_file(str(path))
        beacons = [a for a in pipeline.store.alerts(limit=50) if a["rule"] == "DMK-N-003"]
        assert len(beacons) == 1, [alert["ts"] for alert in beacons]


def test_local_traffic_is_not_egress(config, tmp_path):
    """Loopback and LAN traffic must not raise beacon alerts.

    Regression for a measured false positive: on an idle box the shipped sensor
    reported 36 connections to 127.0.0.1 and 26 to the host's own address, and
    DMK-N-003 ("repeated egress to one destination") fired twice on a machine
    nobody was touching.
    """
    lines = []
    for destination in ("127.0.0.1", "10.12.0.34", "fe80::1", "192.168.1.5"):
        for index in range(10):
            lines.append(
                json.dumps(
                    {
                        "ts": f"2026-09-10T10:00:{index:02d}.000Z",
                        "type": "net.flow",
                        "host": "t",
                        "proc": {"pid": 4242, "exe": "/usr/bin/chatty"},
                        "net": {
                            "proto": "tcp",
                            "src": "10.0.0.24",
                            "sport": 50000,
                            "dst": destination,
                            "dport": 443,
                            "bytes_in": 0,
                            "bytes_out": 0,
                        },
                    }
                )
            )
    path = tmp_path / "local.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with Pipeline(config) as pipeline:
        pipeline.run_file(str(path))
        fired = set(pipeline.stats.rule_hits)
        assert "DMK-N-003" not in fired
        # The traffic is still evidence: it is stored and scored, just not alerted.
        assert pipeline.store.count_events() == 40
        assert pipeline.store.flow_aggregates(limit=50)


def test_public_egress_still_beacons(config, tmp_path):
    """The other half of the previous test: do not silence the real thing."""
    lines = [
        json.dumps(
            {
                "ts": f"2026-09-10T10:00:{index:02d}.000Z",
                "type": "net.flow",
                "host": "t",
                "proc": {"pid": 4242, "exe": "/usr/bin/beacon"},
                "net": {
                    "proto": "tcp",
                    "src": "10.0.0.24",
                    "sport": 50000,
                    "dst": "185.220.101.45",
                    "dport": 443,
                    "bytes_in": 0,
                    "bytes_out": 0,
                },
            }
        )
        for index in range(10)
    ]
    path = tmp_path / "public.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with Pipeline(config) as pipeline:
        pipeline.run_file(str(path))
        assert "DMK-N-003" in pipeline.stats.rule_hits


def test_offline_config_instantiates_no_providers(config):
    with Pipeline(config) as pipeline:
        names = [type(enricher).__name__ for enricher in pipeline.enrichers]
        assert "IntelEnricher" not in names
        assert "ContextEnricher" in names


def test_finish_applies_retention(config, attack_chain):
    config.retention_days = 0  # 0 means "keep everything"
    with Pipeline(config) as pipeline:
        pipeline.run_file(attack_chain)
        pipeline.finish()
        assert pipeline.store.count_events() == 35
        assert pipeline.store.get_meta("last_run")


def test_retention_never_prunes_the_batch_the_run_just_loaded(config, attack_chain):
    """The regression that emptied the product.

    `run --file capture.jsonl` on a capture older than `retention_days` used to
    ingest every event and delete every event, in the same call, silently.
    """
    config.retention_days = 1  # the capture is far older
    with Pipeline(config) as pipeline:
        stats = pipeline.run_file(attack_chain)
        assert stats.events == 35
        assert pipeline.store.count_events() == 35
        assert pipeline.store.count_alerts() == stats.alerts > 0
        assert stats.retention_removed["events"] == 0
        # ... and the operator is told the capture is stale rather than left
        # staring at an empty 24-hour timeline.
        assert stats.stale_capture_s > 86400


def test_retention_prunes_inherited_history(config, attack_chain):
    """Retention still does its job - on the index a run *inherits*."""
    config.retention_days = 1
    with Pipeline(config) as first:
        first.run_file(attack_chain)
        assert first.store.count_events() == 35
    with Pipeline(config) as second:
        removed = second.apply_storage_policy()
        assert removed["events"] == 35 and removed["alerts"] > 0
        assert second.store.count_events() == 0


def test_stats_shape(run):
    stats = run.stats.as_dict()
    for key in ("events", "scored", "alerts", "rule_hits", "elapsed_s"):
        assert key in stats
