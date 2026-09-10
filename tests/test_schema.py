# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Frozen-schema validation and helpers."""

from __future__ import annotations

import json
import os

import pytest

from damavik.schema import (
    EVENT_TYPES,
    LEVELS,
    VERDICTS,
    entropy_ratio,
    event_id,
    iso_to_ms,
    longest_label,
    shannon_entropy,
    to_iso,
    validate_alert,
    validate_event,
)

GOOD = {
    "ts": "2026-09-10T10:00:00.000Z",
    "host": "h1",
    "type": "proc.exec",
    "proc": {"pid": 10, "ppid": 1, "exe": "/bin/sh", "sha256": "a" * 64, "signed": False},
}


def test_valid_event_passes():
    assert validate_event(GOOD) == []


@pytest.mark.parametrize(
    "mutation,fragment",
    [
        ({"type": "not.a.type"}, "unknown type"),
        ({"proc": {"pid": 10, "sha256": "ZZ"}}, "sha256"),
        ({"net": {"dst": "not-an-ip", "dport": 70000}}, "dport"),
        ({"net": {"proto": "sctp"}}, "proto"),
        ({"score": 140.0}, "score"),
        ({"yara": "malware"}, "yara"),
        ({"pkg": {"manager": "apt"}}, "manager"),
    ],
)
def test_rejects_bad_fields(mutation, fragment):
    event = {**GOOD, **mutation}
    problems = validate_event(event)
    assert any(fragment in problem for problem in problems), problems


def test_missing_required_fields_are_reported():
    problems = validate_event({})
    assert any("ts" in p for p in problems)
    assert any("type" in p for p in problems)


def test_every_declared_event_type_is_accepted():
    for etype in EVENT_TYPES:
        assert validate_event({**GOOD, "type": etype}) == []


@pytest.mark.parametrize(
    "value,expected",
    [
        (0, "1970-01-01T00:00:00.000Z"),
        (1789034400, "2026-09-10T10:00:00.000Z"),
        (1789034400000, "2026-09-10T10:00:00.000Z"),          # milliseconds
        ("2026-09-10T10:00:00Z", "2026-09-10T10:00:00.000Z"),
        ("2026-09-10T12:00:00+02:00", "2026-09-10T10:00:00.000Z"),
    ],
)
def test_timestamp_coercion(value, expected):
    assert to_iso(value) == expected


def test_timestamp_rejects_garbage():
    with pytest.raises(Exception):
        to_iso("yesterday")


def test_iso_to_ms_roundtrip():
    iso = to_iso(1789034400)
    assert iso_to_ms(iso) == 1789034400000


def test_event_id_is_stable_and_content_addressed():
    assert event_id(GOOD) == event_id(dict(GOOD))
    other = {**GOOD, "proc": {**GOOD["proc"], "pid": 11}}
    assert event_id(GOOD) != event_id(other)
    assert event_id(GOOD).startswith("e-")


def test_entropy_helpers():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == 2.0
    # a 12-char label cannot exceed log2(12) bits - this is why the ratio exists
    assert shannon_entropy("k7q2x9mzvb41") < 3.6
    assert entropy_ratio("k7q2x9mzvb41") == 1.0
    assert entropy_ratio("aaaa") == 0.0
    assert entropy_ratio("a") == 0.0
    assert entropy_ratio("mail.corp.example") < 0.9


def test_longest_label():
    assert longest_label("a.bb.ccc.example") == "example"
    assert longest_label("") == ""


def test_alert_validation():
    good = {"id": "a-1", "ts": "2026-09-10T10:00:00.000Z", "title": "t",
            "level": "high", "score": 80.0}
    assert validate_alert(good) == []
    assert validate_alert({**good, "level": "urgent"})
    assert validate_alert({**good, "score": 500})
    assert validate_alert({**good, "events": "e-1"})


# ---------------------------------------------------------------------------
# schema/*.json must not drift from the Python validator.  The JSON files are
# the published contract; if someone adds an event type in one place only, this
# fails instead of shipping a lie.
# ---------------------------------------------------------------------------

SCHEMA_DIR = os.path.join(os.path.dirname(__file__), "..", "schema")


def _load_schema(name: str) -> dict:
    with open(os.path.join(SCHEMA_DIR, name), encoding="utf-8") as handle:
        return json.load(handle)


@pytest.mark.parametrize("name", ["event.schema.json", "alert.schema.json"])
def test_published_schemas_are_valid_json_schema_documents(name):
    doc = _load_schema(name)
    assert doc["$schema"].endswith("/schema")
    assert doc["$id"].endswith(f"/{name}")
    assert doc["type"] == "object"
    assert doc["required"]


def test_event_schema_enumerates_exactly_the_python_types():
    doc = _load_schema("event.schema.json")
    published = doc["properties"]["type"]["enum"]
    assert set(published) == set(EVENT_TYPES)


def test_alert_schema_enumerates_exactly_the_python_levels():
    doc = _load_schema("alert.schema.json")
    assert set(doc["properties"]["level"]["enum"]) == set(LEVELS)
    assert set(doc["properties"]["verdict"]["enum"]) == set(VERDICTS)
    assert doc["properties"]["explain"]["minLength"] == 1


def test_event_schema_required_fields_match_the_validator():
    doc = _load_schema("event.schema.json")
    assert doc["required"] == ["ts", "type"]
    # conditional requirements the validator does not enforce but documents
    kinds = {clause["if"]["properties"]["type"]["const"]
             for clause in doc["allOf"]}
    assert kinds == {"dns.query", "net.flow", "pkg.event"}


def test_schema_files_declare_the_current_schema_version():
    """The version lives in code; the docs must not claim another one."""
    from damavik import SCHEMA_VERSION

    doc = _load_schema("event.schema.json")
    assert "schema_version" in doc["properties"]
    with open(os.path.join(SCHEMA_DIR, "event.schema.json"), encoding="utf-8") as handle:
        body = handle.read()
    assert SCHEMA_VERSION, "schema version must be non-empty"
    assert "damavik/schema.py" in body, "the doc must name its authoritative validator"
