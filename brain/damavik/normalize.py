# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Ingest + normalize: raw sensor JSONL -> canonical events.

The sensor is untrusted input as far as the brain is concerned: it may be a
different version, a partial capture, or a hostile process writing to the pipe.
Every raw document therefore goes through a size cap, a strict parse, a
normalization pass that fills defaults and coerces types, and a schema check.
Anything that fails is counted and skipped - never raised into the pipeline.
"""

from __future__ import annotations

import json
import os
import socket
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from .schema import EVENT_TYPES, event_id, to_iso, validate_event

DEFAULT_MAX_EVENT_BYTES = 65536

#: Sensor field names accepted as aliases, mapped onto canonical paths.  This is
#: what lets a Sysmon-ish or eBPF-ish feed reach the same rules as our own
#: ``sensor`` without anyone rewriting the capture first.
_ALIASES: dict[str, str] = {
    "process_id": "proc.pid",
    "pid": "proc.pid",
    "parent_process_id": "proc.ppid",
    "ppid": "proc.ppid",
    "image": "proc.exe",
    "exe": "proc.exe",
    "path": "proc.exe",
    "command_line": "proc.cmd",
    "cmdline": "proc.cmd",
    "cmd": "proc.cmd",
    "hash_sha256": "proc.sha256",
    "sha256": "proc.sha256",
    "user_name": "proc.user",
    "user": "proc.user",
    "dest_ip": "net.dst",
    "dst_ip": "net.dst",
    "dst": "net.dst",
    "dest_port": "net.dport",
    "dport": "net.dport",
    "protocol": "net.proto",
    "query": "dns.q",
    "qname": "dns.q",
}


@dataclass
class IngestStats:
    """Counters for the ingest stage; surfaced via ``damavik status``."""

    lines: int = 0
    accepted: int = 0
    rejected: int = 0
    oversized: int = 0
    duplicates: int = 0
    reasons: dict[str, int] = field(default_factory=dict)

    def reject(self, reason: str) -> None:
        self.rejected += 1
        self.reasons[reason] = self.reasons.get(reason, 0) + 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "lines": self.lines,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "oversized": self.oversized,
            "duplicates": self.duplicates,
            "reasons": dict(self.reasons),
        }


def _set_path(event: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    node = event
    for part in parts[:-1]:
        child = node.get(part)
        if not isinstance(child, dict):
            child = {}
            node[part] = child
        node = child
    node[parts[-1]] = value


def normalize(raw: dict[str, Any], *, host: str | None = None) -> dict[str, Any]:
    """Coerce one raw sensor record into a canonical event dict."""
    event: dict[str, Any] = {}
    for key, value in raw.items():
        if key in ("proc", "net", "dns", "pkg", "yara", "tags", "meta") and isinstance(value, dict):
            event[key] = dict(value)
        elif key in ("yara", "tags") and isinstance(value, list):
            event[key] = list(value)
        elif key in ("ts", "host", "type", "seq", "boot_id", "sensor_id", "score", "rule"):
            event[key] = value
        elif key in _ALIASES:
            _set_path(event, _ALIASES[key], value)
        elif isinstance(value, dict):
            event.setdefault("meta", {})[key] = value
        else:
            event.setdefault("meta", {})[key] = value

    event["ts"] = to_iso(event.get("ts"))
    event.setdefault("host", host or socket.gethostname() or "unknown")
    if event.get("type") not in EVENT_TYPES:
        # Unknown types are kept, not dropped - but the original name is
        # preserved so an operator can see that a sensor spoke a newer schema.
        event.setdefault("meta", {})["original_type"] = event.get("type")
        event["type"] = "sensor.meta"
    if isinstance(event.get("proc"), dict):
        proc = event["proc"]
        if "signed" in proc and not isinstance(proc["signed"], bool):
            proc["signed"] = str(proc["signed"]).lower() in ("1", "true", "yes")
        sha = proc.get("sha256")
        if isinstance(sha, str):
            proc["sha256"] = sha.strip().lower()
    if isinstance(event.get("net"), dict):
        net = event["net"]
        if isinstance(net.get("proto"), str):
            net["proto"] = net["proto"].strip().lower()
        if isinstance(net.get("dport"), str) and net["dport"].isdigit():
            net["dport"] = int(net["dport"])
    if isinstance(event.get("dns"), dict):
        dns = event["dns"]
        if isinstance(dns.get("q"), str):
            dns["q"] = dns["q"].strip().rstrip(".").lower()
    event.setdefault("score", 0.0)
    event.setdefault("tags", [])
    event.setdefault("rule", None)
    event.setdefault("id", event_id(event))
    return event


def parse_line(
    line: str, *, host: str | None = None, max_bytes: int = DEFAULT_MAX_EVENT_BYTES
) -> tuple[dict[str, Any] | None, str | None]:
    """Parse one JSONL line.  Returns ``(event, None)`` or ``(None, reason)``."""
    stripped = line.strip()
    if not stripped:
        return None, "empty"
    if len(stripped.encode("utf-8", "replace")) > max_bytes:
        return None, "oversized"
    try:
        raw = json.loads(stripped)
    except json.JSONDecodeError:
        return None, "bad-json"
    if not isinstance(raw, dict):
        return None, "not-an-object"
    try:
        event = normalize(raw, host=host)
    except Exception:  # noqa: BLE001 - untrusted input must never kill the pipeline
        return None, "normalize-failed"
    problems = validate_event(event)
    if problems:
        return None, "schema: " + problems[0]
    return event, None


def iter_jsonl(
    stream: Iterable[str],
    *,
    host: str | None = None,
    max_bytes: int = DEFAULT_MAX_EVENT_BYTES,
    stats: IngestStats | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield canonical events from an iterable of raw JSONL lines."""
    seen: set[str] = set()
    for line in stream:
        if stats is not None:
            stats.lines += 1
        event, reason = parse_line(line, host=host, max_bytes=max_bytes)
        if event is None:
            if stats is not None and reason not in (None, "empty"):
                if reason == "oversized":
                    stats.oversized += 1
                else:
                    stats.reject(reason or "unknown")
            continue
        eid = event["id"]
        if eid in seen:
            if stats is not None:
                stats.duplicates += 1
            continue
        seen.add(eid)
        if stats is not None:
            stats.accepted += 1
        yield event


def read_lines(path: str) -> Iterator[str]:
    """Yield the raw lines of a capture, one place knowing how to open one.

    A capture is read as *text* rather than as events on purpose: the pipeline
    may need to rewrite timestamps first (``replay.rebase``), which is a line
    transform, and re-serialising an event to do that would lose fields the
    canonical schema does not name.
    """
    with open(os.path.expanduser(path), encoding="utf-8", errors="replace") as handle:
        yield from handle
