# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Replay harness: captures must not rot as the calendar moves."""

from __future__ import annotations

import itertools
import json
import time

from damavik.replay import expand, rebase
from damavik.schema import iso_to_ms


def event(ts: str, pid: int = 1) -> str:
    return json.dumps(
        {
            "ts": ts,
            "type": "proc.exec",
            "host": "t",
            "proc": {"pid": pid, "exe": "/bin/x"},
        },
        sort_keys=True,
    )


def line_for(lines: list[str], index: int = 0) -> dict:
    return json.loads(list(lines)[index])


def test_rebase_lands_the_newest_event_on_the_target_clock():
    lines = [
        event("2020-01-01T00:00:00.000Z"),
        event("2020-01-01T00:00:10.000Z", pid=2),
    ]
    target = 1_800_000_000.0  # a fixed instant, so the test does not depend on now
    out = [json.loads(text) for text in rebase(lines, at=target)]
    assert iso_to_ms(out[-1]["ts"]) == int(target * 1000)
    assert iso_to_ms(out[0]["ts"]) == int(target * 1000) - 10_000


def test_rebase_preserves_every_interval():
    lines = [event(f"2020-01-01T00:00:{second:02d}.000Z", pid=second) for second in range(0, 30, 5)]
    out = [json.loads(text) for text in rebase(lines, at=1_800_000_000.0)]
    stamps = [iso_to_ms(item["ts"]) for item in out]
    gaps = [second - first for first, second in itertools.pairwise(stamps)]
    assert gaps == [5000] * (len(stamps) - 1)


def test_rebase_can_compress_a_capture():
    lines = [
        event("2020-01-01T00:00:00.000Z"),
        event("2020-01-01T01:00:00.000Z", pid=2),
    ]
    out = [json.loads(text) for text in rebase(lines, at=1_800_000_000.0, spacing=0.1)]
    stamps = [iso_to_ms(item["ts"]) for item in out]
    assert stamps[1] - stamps[0] == 6 * 60 * 1000  # an hour becomes six minutes


def test_rebase_drops_the_stale_content_addressed_id():
    """The id is derived from the timestamp, so it must not survive the shift."""
    line = json.dumps(
        {
            "id": "e-deadbeef",
            "ts": "2020-01-01T00:00:00.000Z",
            "type": "proc.exec",
            "proc": {"pid": 1, "exe": "/bin/x"},
        },
        sort_keys=True,
    )
    out = json.loads(next(iter(rebase([line], at=1_800_000_000.0))))
    assert "id" not in out


def test_rebase_passes_through_what_it_cannot_parse():
    junk = ["not json", json.dumps({"type": "proc.exec"}), ""]
    assert list(rebase(junk, at=1_800_000_000.0)) == [
        "not json",
        '{"type": "proc.exec"}',
    ]


def test_rebase_of_a_timeless_capture_is_identity():
    lines = [json.dumps({"type": "sensor.meta", "host": "t"})]
    assert [json.loads(text) for text in rebase(lines)] == [json.loads(lines[0])]


def test_rebased_capture_is_recent():
    """The property the demo depends on: no anchor, no rot."""
    out = [json.loads(text) for text in rebase([event("2020-01-01T00:00:00.000Z")])]
    age_s = time.time() - iso_to_ms(out[0]["ts"]) / 1000.0
    assert 0 <= age_s < 5


def test_expand_anchors_generated_events_near_now():
    """bench data has to survive retention and show up on a 24-hour timeline."""
    base = [
        event("2020-01-01T00:00:00.000Z", pid=1),
        event("2020-01-01T00:00:01.000Z", pid=2),
    ]
    generated = [json.loads(text) for text in expand(base, 500)]
    assert len(generated) == 500
    stamps = [iso_to_ms(item["ts"]) for item in generated]
    assert stamps == sorted(stamps), "generated stream must stay ordered"
    assert len(set(stamps)) == len(stamps), "and distinct, or ingest dedupes it away"
    # Ends now, and the whole stream is in the past: no future history.
    assert 0 <= time.time() - max(stamps) / 1000.0 < 5
    assert max(stamps) / 1000.0 <= time.time() + 1


def test_expand_keeps_process_trees_intact():
    base = [
        event("2020-01-01T00:00:00.000Z", pid=10),
        event("2020-01-01T00:00:01.000Z", pid=20),
    ]
    base[1] = json.dumps(
        {
            "ts": "2020-01-01T00:00:01.000Z",
            "type": "proc.exec",
            "host": "t",
            "proc": {"pid": 20, "ppid": 10, "exe": "/bin/x"},
        },
        sort_keys=True,
    )
    generated = [json.loads(text) for text in expand(base, 6)]
    for index in (0, 2, 4):
        child = generated[index + 1]["proc"]
        assert child["ppid"] == generated[index]["proc"]["pid"]
