# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Replay harness: put a recorded capture back on a usable clock, or stretch it.

Two jobs, both about time:

``rebase``
    Shift a capture onto the current clock, preserving the relative spacing of
    every event.  Shipped fixtures and demo captures carry absolute timestamps,
    and a monitor that stores events by timestamp must not treat a two-week-old
    demo as history to be pruned, or render it on a 24-hour timeline.  Used by
    ``damavik demo``, ``selftest`` and ``bench`` - all synthetic - and exposed
    as ``damavik run --file X --rebase`` for an operator who wants a capture to
    *look* live.  A real forensic reload should keep recorded time, which is
    why this is opt-in on ``run``.

``expand``
    Turn a capture into an arbitrarily long event stream.  Ingest deduplicates
    by content-addressed event id, which is correct - a sensor restart must not
    double-count history.  It also means naively repeating a capture measures
    nothing: every line after the first pass is dropped.  ``expand`` rewrites
    the fields that make an event unique (``proc.pid``, ``ts``, ``seq``) so each
    generated line is genuinely new, while keeping the shape - and thus the code
    path - of the original capture.  Used by ``damavik bench`` and the
    throughput tests.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable, Iterator
from typing import Any

from .schema import iso_to_ms, to_iso

#: Spacing between generated events, in seconds.  One second is dense enough to
#: be realistic for a busy host and loose enough that a 10 000-event benchmark
#: still fits inside a single afternoon.
EVENT_SPACING_S = 1


def _load(line: str) -> dict[str, Any] | None:
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return None
    return event if isinstance(event, dict) else None


def rebase(
    lines: Iterable[str], *, at: float | None = None, spacing: float | None = None
) -> Iterator[str]:
    """Yield ``lines`` with their timestamps shifted so the capture ends "now".

    The whole capture moves by a single constant offset - computed from its last
    event, so the newest event lands at ``at`` (default: now) - which preserves
    every interval in it.  Correlation windows, the dashboard timeline and
    retention then all agree with what the capture describes.

    ``spacing`` compresses or stretches the capture by that factor (``1.0`` is
    untouched, ``0.1`` replays it ten times faster).  Lines that are not JSON
    objects, or that carry no parseable ``ts``, are passed through untouched so
    a capture with mixed content still replays.
    """
    materialised = [line for line in lines if line.strip()]
    parsed: list[dict[str, Any] | None] = [_load(line) for line in materialised]
    stamps: list[int] = []
    for event in parsed:
        if event is None or not event.get("ts"):
            continue
        try:
            stamps.append(iso_to_ms(str(event["ts"])))
        except ValueError:
            continue
    if not stamps:
        yield from materialised
        return

    target = time.time() if at is None else float(at)
    # Anchor the offset on the newest event: a capture that ends "now" is a
    # capture whose last action just happened.
    offset_ms = int(target * 1000) - max(stamps)
    factor = 1.0 if spacing is None else max(0.0, float(spacing))
    newest = max(stamps)
    for line, event in zip(materialised, parsed, strict=True):
        if event is None or not event.get("ts"):
            yield line
            continue
        try:
            stamp = iso_to_ms(str(event["ts"]))
        except ValueError:
            yield line
            continue
        shifted = newest - int((newest - stamp) * factor) + offset_ms
        event["ts"] = to_iso(shifted / 1000.0)
        event.pop("id", None)  # the id is derived from the timestamp
        yield json.dumps(event, sort_keys=True)


def expand(lines: Iterable[str], count: int, *, base_epoch: int | None = None) -> Iterator[str]:
    """Yield ``count`` distinct JSONL events derived from ``lines``.

    Events are placed ``EVENT_SPACING_S`` apart and the stream *ends* at
    ``base_epoch`` (default: now), so its length scales with ``count`` instead
    of stretching into the future and a benchmark never generates history that
    retention would prune on sight.  A hard-coded anchor rots silently - that is
    how the shipped demo ended up ingesting a capture dated two weeks earlier.
    """
    base = [line for line in lines if line.strip()]
    if not base or count <= 0:
        return
    end_epoch = int(time.time()) if base_epoch is None else int(base_epoch)
    emitted = 0
    while emitted < count:
        for line in base:
            if emitted >= count:
                break
            event = _load(line)
            if event is None:
                continue
            event["seq"] = emitted
            stamp = end_epoch - (count - emitted) * EVENT_SPACING_S
            event["ts"] = to_iso(stamp)
            proc = event.get("proc")
            if isinstance(proc, dict) and proc.get("pid") is not None:
                # Keep parent/child relationships intact by offsetting the whole
                # tree rather than renumbering individual processes.
                offset = (emitted // max(1, len(base))) * 100000
                proc["pid"] = int(proc["pid"]) + offset
                if proc.get("ppid"):
                    proc["ppid"] = int(proc["ppid"]) + offset
            event.pop("id", None)  # force a fresh content-addressed id
            yield json.dumps(event, sort_keys=True)
            emitted += 1
