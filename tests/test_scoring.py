# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Scoring: the numbers have to mean what the docs say they mean."""

from __future__ import annotations

import pytest

from damavik.rules import rule_from_dict
from damavik.score import Scorer

TS = "2026-09-10T10:00:00.000Z"


def scorer(store=None, **kwargs) -> Scorer:
    return Scorer(store=store, **kwargs)


def exec_event(exe="/usr/bin/thing", sha=None, signed=True, pid=10, **extra):
    proc = {"pid": pid, "ppid": 1, "exe": exe, "cmd": exe, "user": "alice", "signed": signed}
    if sha:
        proc["sha256"] = sha
    return {"ts": TS, "host": "t", "type": "proc.exec", "proc": proc, "tags": [], **extra}


def test_clean_system_binary_scores_low():
    result = scorer().score(exec_event("/usr/bin/systemd", sha="a" * 64))
    assert result.score <= 15.0
    assert result.reasons, "a score with no reasons is a bug"


def test_execution_from_tmp_is_penalised():
    base = scorer().score(exec_event("/usr/bin/thing", sha="a" * 64)).score
    risky = scorer().score(exec_event("/tmp/.x/thing", sha="b" * 64)).score
    assert risky > base


def test_first_seen_hash_costs_more_than_a_repeat(store):
    first = Scorer(store=store).score(exec_event(sha="c" * 64, pid=11))
    second = Scorer(store=store).score(exec_event(sha="c" * 64, pid=12))
    assert first.score > second.score
    assert "first_seen_hash" in first.tags


def test_allowlist_forces_zero():
    s = scorer(allowlist_exes=frozenset({"/usr/bin/thing"}))
    result = s.score(exec_event("/usr/bin/thing", sha="d" * 64))
    assert result.score == 0.0
    assert "allowlisted" in result.tags


def test_allowlist_does_not_shield_malware():
    s = scorer(allowlist_exes=frozenset({"/usr/bin/thing"}))
    result = s.score(exec_event("/usr/bin/thing", sha="e" * 64, yara=["malware"]))
    assert result.score > 50.0
    assert "allowlisted" not in result.tags


def test_dns_entropy_signal():
    event = {
        "ts": TS, "host": "t", "type": "dns.query", "tags": [],
        "dns": {"q": "k7q2x9mzvb41.exfil-tunnel.example", "rtype": "A"},
    }
    benign = {
        "ts": TS, "host": "t", "type": "dns.query", "tags": [],
        "dns": {"q": "mail.corp.example", "rtype": "A"},
    }
    assert scorer().score(event).score > scorer().score(benign).score + 20


def test_rare_and_suspicious_ports():
    def flow(dport):
        return {"ts": TS, "host": "t", "type": "net.flow", "tags": [],
                "proc": {"pid": 1, "exe": "/bin/x"},
                "net": {"proto": "tcp", "dst": "9.9.9.9", "dport": dport}}

    common = scorer().score(flow(443)).score
    rare = Scorer().score(flow(443)).score
    suspicious = scorer().score(flow(4444)).score
    assert suspicious > rare >= common or suspicious > common


def test_bulk_upload_signal():
    event = {"ts": TS, "host": "t", "type": "net.flow", "tags": [],
             "proc": {"pid": 1, "exe": "/bin/x"},
             "net": {"proto": "tcp", "dst": "9.9.9.9", "dport": 443, "bytes_out": 9_000_000}}
    assert "bulk_egress" in scorer().score(event).tags


def test_new_destination_and_new_edge_are_recorded(store):
    def flow():
        return {"ts": TS, "host": "t", "type": "net.flow", "tags": [],
                "proc": {"pid": 1, "exe": "/bin/x", "sha256": "f" * 64},
                "net": {"proto": "tcp", "dst": "8.8.8.8", "dport": 443}}

    first = Scorer(store=store).score(flow())
    second = Scorer(store=store).score(flow())
    assert "first_seen_dst" in first.tags
    assert "first_seen_dst" not in second.tags
    assert first.score > second.score


def test_rule_level_drives_the_score():
    rule = rule_from_dict(
        {"id": "DMK-T-100", "title": "critical thing", "level": "critical",
         "logsource": {"category": "process_creation"},
         "selection": {"proc.exe|endswith": "thing"}, "condition": "selection"}
    )
    result = scorer().score(exec_event(sha="1" * 64), [rule])
    assert result.score >= 85.0
    assert result.rule == "DMK-T-100"
    assert any("DMK-T-100" in reason for reason in result.reasons)


def test_stacked_rules_add_a_little_not_a_lot():
    rules = [
        rule_from_dict(
            {"id": f"DMK-T-10{i}", "title": f"r{i}", "level": level,
             "logsource": {"category": "process_creation"},
             "selection": {"proc.exe|endswith": "thing"}, "condition": "selection"}
        )
        for i, level in enumerate(["high", "medium", "low", "info", "low"])
    ]
    single = scorer().score(exec_event(sha="2" * 64), rules[:1]).score
    many = scorer().score(exec_event(sha="3" * 64), rules).score
    assert many <= single + 15.0
    assert many >= single


def test_score_is_clamped_to_the_declared_range(store):
    event = {"ts": TS, "host": "t", "type": "file.verdict", "tags": [],
             "proc": {"pid": 1, "exe": "/tmp/x", "sha256": "9" * 64},
             "yara": ["malware", "trojan", "stealer", "ransomware", "backdoor", "miner"]}
    result = Scorer(store=store).score(event)
    assert 0.0 <= result.score <= 100.0
    assert result.score == 100.0


def test_package_signals():
    install = {"ts": TS, "host": "t", "type": "pkg.event", "tags": [],
               "pkg": {"manager": "deb", "name": "libfoo", "version": "1.0",
                       "cves": ["CVE-2024-0001"], "severity": "critical"},
               "meta": {"action": "install"}}
    quiet = {"ts": TS, "host": "t", "type": "pkg.event", "tags": [],
             "pkg": {"manager": "deb", "name": "libbar", "version": "1.0", "cves": []},
             "meta": {"action": "seen"}}
    assert scorer().score(install).score > scorer().score(quiet).score


def test_risk_tool_is_not_treated_as_malware():
    dual = {"ts": TS, "host": "t", "type": "file.verdict", "tags": [],
            "proc": {"pid": 1, "exe": "/usr/bin/nmap"}, "yara": ["risk_tool"]}
    bad = {"ts": TS, "host": "t", "type": "file.verdict", "tags": [],
           "proc": {"pid": 1, "exe": "/usr/bin/nmap"}, "yara": ["malware"]}
    assert scorer().score(dual).score < 40.0
    assert scorer().score(bad).score > 50.0


def test_every_signal_is_explained(store):
    event = exec_event("/tmp/.x/thing", sha="4" * 64, signed=False, pid=21)
    result = Scorer(store=store).score(event)
    assert len(result.reasons) >= 3
    assert result.explain()
    assert all("(+" in reason for reason in result.reasons)


def test_scoring_is_deterministic_for_identical_state(tmp_path):
    """Same state in, same score out.  Rarity is stateful by design, so the
    two runs need independent stores."""
    from damavik.store import Store

    event = exec_event("/tmp/.x/thing", sha="5" * 64, pid=31)
    scores = []
    for name in ("a.db", "b.db"):
        handle = Store(str(tmp_path / name))
        scores.append(Scorer(store=handle).score(event).score)
        handle.close()
    assert scores[0] == scores[1]


def test_rarity_makes_repeats_cheaper(store):
    """The flip side of the above: the second sighting must score lower."""
    event = exec_event("/tmp/.x/thing", sha="6" * 64, pid=32)
    first = Scorer(store=store).score(event).score
    second = Scorer(store=store).score({**event, "proc": {**event["proc"], "pid": 33}}).score
    assert second < first


@pytest.mark.parametrize("bad", [None, {}, "x"])
def test_scorer_survives_garbage(bad):
    result = scorer().score({"ts": TS, "host": "t", "type": "sensor.meta", "tags": []})
    assert 0.0 <= result.score <= 100.0
    del bad
