# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Performance budgets from the master plan, measured rather than asserted.

The gates here are deliberately loose (roughly 3x what this codebase measures
on a small CI box) so they catch a real regression - an accidental O(n) query
inside the hot loop, a rule set that stopped being indexed - without failing
on a slow runner.  `damavik bench` prints the real numbers.
"""

from __future__ import annotations

import os
import time

import pytest
from damavik.pipeline import Pipeline
from damavik.rules import RuleSet, load_rules_dir

EVENTS = 3000
BUDGET_US_PER_EVENT = 3000.0
BUDGET_RSS_MB = 150.0


def repeated(path: str, count: int) -> list[str]:
    """Distinct events - ingest dedupes identical ones by design."""
    from damavik.replay import expand

    with open(path, encoding="utf-8") as handle:
        base = [line for line in handle if line.strip()]
    return list(expand(base, count))


@pytest.fixture(scope="module")
def measurement(tmp_path_factory, repo_root, attack_chain):
    from damavik.config import Config

    config = Config(
        state_dir=str(tmp_path_factory.mktemp("bench")),
        offline=True,
        rules={"dir": os.path.join(repo_root, "rules")},
        alerts={
            "path": "alerts.log",
            "notify": False,
            "cooldown_s": 0,
            "min_score": 45.0,
        },
    )
    lines = repeated(attack_chain, EVENTS)
    started = time.perf_counter()
    pipeline = Pipeline(config)
    pipeline.run(lines)
    elapsed = time.perf_counter() - started
    events = pipeline.stats.events
    rules = len(pipeline.rules)
    summary = pipeline.store.summary()
    pipeline.close()
    return {
        "events": events,
        "rules": rules,
        "elapsed_s": elapsed,
        "us_per_event": elapsed / events * 1e6,
        "us_per_event_per_rule": elapsed / events * 1e6 / rules,
        "rss_mb": _rss_mb(),
        "db_bytes": summary["db_bytes"],
        "alerts": pipeline.stats.alerts,
    }


def _rss_mb() -> float:
    try:
        with open("/proc/self/status", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024.0
    except (OSError, ValueError, IndexError):
        pass
    return 0.0


def test_ingest_throughput_is_within_budget(measurement):
    assert measurement["events"] == EVENTS
    assert measurement["us_per_event"] < BUDGET_US_PER_EVENT, measurement


def test_rule_stage_cost_per_rule(measurement):
    # 20 rules must not each cost milliseconds; prefiltering is doing its job.
    assert measurement["us_per_event_per_rule"] < 200.0, measurement


def test_memory_is_within_budget(measurement):
    if measurement["rss_mb"] == 0.0:
        pytest.skip("VmRSS unavailable on this platform")
    assert measurement["rss_mb"] < BUDGET_RSS_MB, measurement


def test_database_stays_small_for_a_week_of_events(measurement):
    # 3000 events should not cost megabytes: the raw JSON is the only payload.
    assert measurement["db_bytes"] < 20 * 1024 * 1024


def test_rule_lookup_is_indexed_by_event_type(rules_dir):
    ruleset, _ = load_rules_dir(rules_dir)
    proc_rules = ruleset.candidates_for({"type": "proc.exec"})
    dns_rules = ruleset.candidates_for({"type": "dns.query"})
    assert 0 < len(proc_rules) < len(ruleset)
    assert 0 < len(dns_rules) < len(ruleset)
    # rules with category "any" are shared by design; the rest must not overlap
    shared = set(ruleset.universal)
    assert not (set(proc_rules) - shared) & (set(dns_rules) - shared)
    assert shared, "the autorun/listener rules must stay universal"


def test_rule_evaluation_is_sub_millisecond(rules_dir):
    ruleset, _ = load_rules_dir(rules_dir)
    event = {
        "ts": "2026-09-10T10:00:00.000Z",
        "type": "proc.exec",
        "proc": {
            "pid": 1,
            "ppid": 2,
            "exe": "/usr/bin/thing",
            "cmd": "thing",
            "sha256": "a" * 64,
            "signed": True,
        },
        "meta": {"parent_is_sensitive": False, "child_is_shell": False},
    }
    started = time.perf_counter()
    for _ in range(20000):
        ruleset.evaluate(event, now=1.0)
    per_call_us = (time.perf_counter() - started) / 20000 * 1e6
    assert per_call_us < 1000.0, per_call_us


def test_empty_ruleset_is_free():
    ruleset = RuleSet([])
    assert ruleset.evaluate({"type": "proc.exec"}, now=1.0) == []


def test_scoring_a_clean_event_is_cheap(store):
    from damavik.score import Scorer

    scorer = Scorer(store=store)
    event = {
        "ts": "2026-09-10T10:00:00.000Z",
        "type": "proc.exec",
        "proc": {"pid": 1, "exe": "/usr/bin/thing", "sha256": "b" * 64, "signed": True},
    }
    started = time.perf_counter()
    for index in range(5000):
        scorer.score({**event, "proc": {**event["proc"], "pid": index}})
    per_call_us = (time.perf_counter() - started) / 5000 * 1e6
    assert per_call_us < 1000.0, per_call_us


def test_bench_command_matches_the_library(config, attack_chain, capsys):
    from damavik.cli import main

    code = main(
        [
            "--state-dir",
            os.path.dirname(config.db_path()),
            "--rules-dir",
            config.rules["dir"],
            "--offline",
            "bench",
            "--events",
            "300",
            "--gate",
        ]
    )
    assert code == 0
    import json

    report = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert report["events"] == 300
    assert report["within_budget"] is True
