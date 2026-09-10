# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Rule engine: every shipped rule must have a true positive and a false positive."""

from __future__ import annotations

import os

import pytest

from damavik.rules import RuleSet, get_field, load_rule_file, load_rules_dir, rule_from_dict


def fired_ids(ruleset: RuleSet, events: list[dict], now: float = 1_000_000.0) -> set[str]:
    hits: set[str] = set()
    for event in events:
        hits.update(rule.rule_id for rule in ruleset.evaluate(event, now=now))
    return hits


@pytest.fixture(scope="module")
def shipped(rules_dir) -> RuleSet:
    ruleset, errors = load_rules_dir(rules_dir)
    assert errors == []
    return ruleset


# ------------------------------------------------------- shipped rule corpus
def test_ships_a_meaningful_rule_set(shipped):
    assert len(shipped) >= 15, "the plan commits to at least 15 starter rules"


def test_rule_ids_are_unique_and_namespaced(rules_dir):
    ruleset, _ = load_rules_dir(rules_dir)
    ids = ruleset.ids()
    assert len(ids) == len(set(ids)), "duplicate rule ids"
    for rule_id in ids:
        assert rule_id.startswith("DMK-"), rule_id


def test_every_rule_is_documented(rules_dir):
    for name in sorted(os.listdir(rules_dir)):
        if not name.endswith((".yml", ".yaml")):
            continue
        rule = load_rule_file(os.path.join(rules_dir, name))
        assert rule.title, name
        assert len(rule.description) > 40, f"{name}: description too thin to trust"
        assert rule.tags, f"{name}: rules must carry ATT&CK or policy tags"
        assert rule.level in ("info", "low", "medium", "high", "critical"), name


def test_every_shipped_rule_has_fixtures(shipped, rule_cases):
    missing = set(shipped.ids()) - set(rule_cases)
    assert not missing, f"rules without TP/FP fixtures: {sorted(missing)}"


@pytest.mark.parametrize("rule_id", sorted(__import__("json").load(
    open(os.path.join(os.path.dirname(__file__), "fixtures", "rule_cases.json"),
         encoding="utf-8"))))
def test_true_positive_fires(rule_id, rules_dir, rule_cases):
    path = _rule_path(rules_dir, rule_id)
    ruleset = RuleSet([load_rule_file(path)])
    hits = fired_ids(ruleset, rule_cases[rule_id]["tp"])
    assert rule_id in hits, f"{rule_id} did not fire on its true positive"


@pytest.mark.parametrize("rule_id", sorted(__import__("json").load(
    open(os.path.join(os.path.dirname(__file__), "fixtures", "rule_cases.json"),
         encoding="utf-8"))))
def test_false_positive_does_not_fire(rule_id, rules_dir, rule_cases):
    path = _rule_path(rules_dir, rule_id)
    ruleset = RuleSet([load_rule_file(path)])
    hits = fired_ids(ruleset, rule_cases[rule_id]["fp"])
    assert rule_id not in hits, f"{rule_id} fired on its false positive"


def _rule_path(rules_dir: str, rule_id: str) -> str:
    for name in os.listdir(rules_dir):
        if name.startswith(rule_id):
            return os.path.join(rules_dir, name)
    raise AssertionError(f"no file for {rule_id}")


# ------------------------------------------------------------- condition AST
def _rule(condition: str, selection: dict | None = None):
    return rule_from_dict(
        {
            "id": "DMK-T-000",
            "title": "test",
            "level": "low",
            "status": "stable",
            "logsource": {"category": "process_creation"},
            "sel_a": selection or {"proc.exe|endswith": "bash"},
            "sel_b": {"proc.user": "root"},
            "condition": condition,
        }
    )


BASH_ROOT = {"type": "proc.exec", "proc": {"exe": "/bin/bash", "user": "root"}}
BASH_ALICE = {"type": "proc.exec", "proc": {"exe": "/bin/bash", "user": "alice"}}
SH_ROOT = {"type": "proc.exec", "proc": {"exe": "/bin/sh", "user": "root"}}


@pytest.mark.parametrize(
    "condition,event,expected",
    [
        ("sel_a", BASH_ALICE, True),
        ("sel_a", SH_ROOT, False),
        ("sel_a and sel_b", BASH_ROOT, True),
        ("sel_a and sel_b", BASH_ALICE, False),
        ("sel_b or sel_a", SH_ROOT, True),
        ("sel_a and not sel_b", BASH_ALICE, True),
        ("sel_a and not sel_b", BASH_ROOT, False),
        ("(sel_a or sel_b) and not sel_b", BASH_ALICE, True),
        ("not sel_a", SH_ROOT, True),
    ],
)
def test_condition_algebra(condition, event, expected):
    assert _rule(condition).matches(event) is expected


def test_type_bucketing_skips_irrelevant_events():
    rule = _rule("sel_a")
    assert rule.matches({"type": "dns.query", "proc": {"exe": "/bin/bash"}}) is False


# ---------------------------------------------------------------- modifiers
@pytest.mark.parametrize(
    "clause,event,expected",
    [
        ({"proc.cmd|contains": "CURL"}, {"proc": {"cmd": "curl http://x"}}, True),
        ({"proc.exe|startswith": "/tmp"}, {"proc": {"exe": "/tmp/x"}}, True),
        ({"proc.exe|endswith": ".sh"}, {"proc": {"exe": "/a/b.sh"}}, True),
        ({"proc.cmd|re": "^curl\\s+-s"}, {"proc": {"cmd": "curl -s http://x"}}, True),
        ({"net.dport|gt": 1024}, {"net": {"dport": 8080}}, True),
        ({"net.dport|gt": 1024}, {"net": {"dport": 80}}, False),
        ({"net.dport|lte": 1024}, {"net": {"dport": 443}}, True),
        ({"pkg.cves|exists": True}, {"pkg": {"cves": ["CVE-1"]}}, True),
        ({"pkg.cves|exists": True}, {"pkg": {"cves": []}}, False),
        ({"proc.signed": False}, {"proc": {"signed": False}}, True),
        ({"proc.signed": False}, {"proc": {"signed": True}}, False),
        ({"net.dport": [443, 8443]}, {"net": {"dport": 8443}}, True),
        ({"yara|contains": "mal"}, {"yara": ["packer", "malware_x"]}, True),
        ({"proc.cmd|contains|all": ["curl", "-o"]}, {"proc": {"cmd": "curl -o x"}}, True),
        ({"proc.cmd|contains|all": ["curl", "wget"]}, {"proc": {"cmd": "curl -o x"}}, False),
    ],
)
def test_field_modifiers(clause, event, expected):
    rule = rule_from_dict(
        {
            "id": "DMK-T-001",
            "title": "t",
            "level": "low",
            "logsource": {"category": "any"},
            "selection": clause,
            "condition": "selection",
        }
    )
    assert rule.matches({"type": "proc.exec", **event}) is expected


def test_unknown_modifier_is_rejected():
    with pytest.raises(Exception, match="modifier"):
        rule_from_dict(
            {
                "id": "DMK-T-002", "title": "t", "level": "low",
                "logsource": {"category": "any"},
                "selection": {"proc.cmd|base64offset": "x"},
                "condition": "selection",
            }
        )


@pytest.mark.parametrize(
    "bad,fragment",
    [
        ({"id": "", "title": "t", "condition": "s", "s": {"a": 1}}, "missing 'id'"),
        ({"id": "X", "title": "", "condition": "s", "s": {"a": 1}}, "missing 'title'"),
        ({"id": "X", "title": "t", "s": {"a": 1}}, "missing 'condition'"),
        ({"id": "X", "title": "t", "level": "panic", "condition": "s", "s": {"a": 1}}, "level"),
        ({"id": "X", "title": "t", "condition": "nope", "s": {"a": 1}}, "unknown selection"),
        ({"id": "X", "title": "t", "condition": "s and", "s": {"a": 1}}, "condition"),
        ({"id": "X", "title": "t", "condition": "s", "s": {"a": 1},
          "logsource": {"category": "telepathy"}}, "logsource"),
        ({"id": "X", "title": "t", "condition": "s", "s": {}}, "empty"),
    ],
)
def test_invalid_rules_are_rejected(bad, fragment):
    payload = {"level": "low", "logsource": {"category": "any"}, **bad}
    with pytest.raises(Exception, match=fragment):
        rule_from_dict(payload)


def test_condition_needs_balanced_parens():
    with pytest.raises(Exception, match=r"\)"):
        _rule("(sel_a or sel_b")


# ------------------------------------------------------------- correlation
def test_correlation_fires_only_at_threshold():
    rule = rule_from_dict(
        {
            "id": "DMK-T-003", "title": "t", "level": "medium",
            "logsource": {"category": "network_connect"},
            "selection": {"net.dst|exists": True},
            "condition": "selection",
            "correlate": {"group_by": "net.dst", "window_s": 60, "min_count": 3},
        }
    )
    ruleset = RuleSet([rule])
    event = {"type": "net.flow", "net": {"dst": "1.2.3.4"}}
    assert fired_ids(ruleset, [event], now=100.0) == set()
    assert fired_ids(ruleset, [event], now=110.0) == set()
    assert fired_ids(ruleset, [event], now=120.0) == {"DMK-T-003"}


def test_correlation_window_expires():
    rule = rule_from_dict(
        {
            "id": "DMK-T-004", "title": "t", "level": "medium",
            "logsource": {"category": "network_connect"},
            "selection": {"net.dst|exists": True},
            "condition": "selection",
            "correlate": {"group_by": "net.dst", "window_s": 60, "min_count": 2},
        }
    )
    ruleset = RuleSet([rule])
    event = {"type": "net.flow", "net": {"dst": "1.2.3.4"}}
    fired_ids(ruleset, [event], now=0.0)
    assert fired_ids(ruleset, [event], now=1000.0) == set()


def test_correlation_groups_are_independent():
    rule = rule_from_dict(
        {
            "id": "DMK-T-005", "title": "t", "level": "medium",
            "logsource": {"category": "network_connect"},
            "selection": {"net.dst|exists": True},
            "condition": "selection",
            "correlate": {"group_by": "net.dst", "window_s": 60, "min_count": 2},
        }
    )
    ruleset = RuleSet([rule])
    a = {"type": "net.flow", "net": {"dst": "1.1.1.1"}}
    b = {"type": "net.flow", "net": {"dst": "2.2.2.2"}}
    assert fired_ids(ruleset, [a, b], now=1.0) == set()


# ------------------------------------------------------------------ loading
def test_load_rules_dir_reports_broken_files(tmp_path):
    (tmp_path / "bad.yml").write_text("title: no id here\n", encoding="utf-8")
    (tmp_path / "good.yml").write_text(
        "id: DMK-T-006\ntitle: ok\nlevel: low\nlogsource:\n  category: any\n"
        "selection:\n  type: proc.exec\ncondition: selection\n",
        encoding="utf-8",
    )
    ruleset, errors = load_rules_dir(str(tmp_path))
    assert len(ruleset) == 1
    assert len(errors) == 1


def test_load_rules_dir_missing_directory():
    ruleset, errors = load_rules_dir("/nonexistent/rules")
    assert len(ruleset) == 0
    assert errors


def test_deprecated_rules_are_skipped(tmp_path):
    (tmp_path / "old.yml").write_text(
        "id: DMK-T-007\ntitle: old\nlevel: low\nstatus: deprecated\n"
        "logsource:\n  category: any\nselection:\n  type: proc.exec\ncondition: selection\n",
        encoding="utf-8",
    )
    ruleset, errors = load_rules_dir(str(tmp_path))
    assert errors == []
    assert len(ruleset) == 0


def test_get_field_handles_missing_paths():
    assert get_field({"a": {"b": 1}}, "a.b") == 1
    assert get_field({"a": {}}, "a.b.c") is None
    assert get_field({}, "a") is None
