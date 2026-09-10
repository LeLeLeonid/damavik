# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Replay harness: turn a recorded capture into an arbitrarily long event stream.

Ingest deduplicates by content-addressed event id, which is correct - a sensor
restart must not double-count history.  It also means naively repeating a
capture measures nothing: every line after the first pass is dropped.

:func:`expand` therefore rewrites the fields that make an event unique
(``proc.pid``, ``ts``, ``seq``) so each generated line is genuinely new, while
keeping the shape - and thus the code path - of the original capture.  Used by
``damavik bench`` and by the throughput tests.
"""

from __future__ import annotations

import json
from typing import Iterable, Iterator

#: Epoch offset (seconds) applied between passes so timestamps stay ordered and
#: distinct.  One hour keeps generated events inside a plausible session.
PASS_OFFSET_S = 3600


def expand(lines: Iterable[str], count: int, *, base_epoch: int = 1789034400) -> Iterator[str]:
    """Yield ``count`` distinct JSONL events derived from ``lines``."""
    base = [line for line in lines if line.strip()]
    if not base:
        return
    emitted = 0
    passes = 0
    while emitted < count:
        for line in base:
            if emitted >= count:
                break
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            event["seq"] = emitted
            stamp = base_epoch + passes * PASS_OFFSET_S + emitted % PASS_OFFSET_S
            event["ts"] = "%s.%03dZ" % (
                __import__("time").strftime("%Y-%m-%dT%H:%M:%S", __import__("time").gmtime(stamp)),
                emitted % 1000,
            )
            proc = event.get("proc")
            if isinstance(proc, dict) and proc.get("pid") is not None:
                # Keep parent/child relationships intact by offsetting the whole
                # tree rather than renumbering individual processes.
                offset = (emitted // max(1, len(base))) * 100000
                proc["pid"] = int(proc["pid"]) + offset
                if proc.get("ppid"):
                    proc["ppid"] = int(proc["ppid"]) + offset
            event.pop("id", None)          # force a fresh content-addressed id
            yield json.dumps(event, sort_keys=True)
            emitted += 1
        passes += 1
