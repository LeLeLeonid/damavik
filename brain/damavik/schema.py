# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Canonical event / alert schema (frozen, versioned).

One schema for every platform.  Rules, storage, API and UI speak only this.
Validation is hand-rolled on purpose: it is ~200 lines, has zero dependencies,
and reports *every* problem it finds with a JSON path instead of stopping at
the first one - which matters because the sensor is untrusted input to the
brain and a malformed event must never take the pipeline down.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from datetime import datetime, timezone
from typing import Any

EVENT_TYPES = (
    "proc.exec",
    "net.flow",
    "dns.query",
    "file.verdict",
    "pkg.event",
    "sys.event",
    "alert",
    "sensor.meta",
)

LEVELS = ("info", "low", "medium", "high", "critical")
VERDICTS = ("unknown", "clean", "suspicious", "malicious")

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def is_ip_literal(text: str) -> bool:
    """True for any valid IPv4/IPv6 literal, including IPv4-mapped IPv6."""
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True

#: Fields whose type must be exactly as declared.  Unknown fields are allowed
#: (forward compatibility) but land in ``meta`` rather than being silently
#: promoted into scoring logic.
_SCALARS: dict[str, type | tuple[type, ...]] = {
    "ts": str,
    "host": str,
    "type": str,
    "seq": int,
    "boot_id": str,
    "sensor_id": str,
    "score": (int, float),
    "tags": list,
    "rule": (str, type(None)),
}


class EventError(ValueError):
    """Raised when a document cannot be coerced into a canonical event."""


def utcnow_iso() -> str:
    """Current time as RFC 3339 UTC with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def to_iso(value: Any) -> str:
    """Coerce epoch seconds/ms or ISO-8601 into canonical RFC 3339 UTC."""
    if value is None:
        return utcnow_iso()
    if isinstance(value, bool):
        raise EventError(f"timestamp cannot be a bool: {value!r}")
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 1e12:  # milliseconds
            seconds /= 1000.0
        if seconds > 1e15:  # microseconds
            seconds /= 1000.0
        return datetime.fromtimestamp(seconds, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise EventError("empty timestamp")
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise EventError(f"unparseable timestamp {value!r}") from exc
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    raise EventError(f"unsupported timestamp type {type(value).__name__}")


def iso_to_ms(iso: str) -> int:
    """Canonical ISO string -> epoch milliseconds (used for indexing/ordering)."""
    text = iso[:-1] + "+00:00" if iso.endswith("Z") else iso
    return int(datetime.fromisoformat(text).timestamp() * 1000)


def _require(obj: dict[str, Any], key: str, errors: list[str], path: str) -> None:
    if key not in obj or obj[key] in (None, ""):
        errors.append(f"{path}.{key}: required")


def validate_event(event: dict[str, Any]) -> list[str]:
    """Return a list of human-readable problems; empty list means valid."""
    errors: list[str] = []
    if not isinstance(event, dict):
        return ["event: must be an object"]
    for key, expected in _SCALARS.items():
        if key in event and event[key] is not None and not isinstance(event[key], expected):
            errors.append(f"{key}: expected {expected}, got {type(event[key]).__name__}")
    _require(event, "ts", errors, "event")
    _require(event, "type", errors, "event")
    etype = event.get("type")
    if etype not in EVENT_TYPES:
        errors.append(f"event.type: unknown type {etype!r}")
    if "host" in event and event["host"] is not None:
        _require(event, "host", errors, "event")

    proc = event.get("proc")
    if proc is not None:
        if not isinstance(proc, dict):
            errors.append("proc: must be an object")
        else:
            if "pid" in proc and not isinstance(proc["pid"], int):
                errors.append("proc.pid: expected int")
            sha = proc.get("sha256")
            if sha is not None and not (isinstance(sha, str) and _SHA256_RE.match(sha)):
                errors.append("proc.sha256: must be 64 lowercase hex chars")

    net = event.get("net")
    if net is not None:
        if not isinstance(net, dict):
            errors.append("net: must be an object")
        else:
            dport = net.get("dport")
            if dport is not None and not (isinstance(dport, int) and 0 <= dport <= 65535):
                errors.append("net.dport: must be an int in 0..65535")
            dst = net.get("dst")
            if dst is not None and not (isinstance(dst, str) and is_ip_literal(dst)):
                errors.append("net.dst: must be an IP literal (v4 or v6)")
            proto = net.get("proto")
            if proto is not None and proto not in ("tcp", "udp", "icmp"):
                errors.append(f"net.proto: unknown protocol {proto!r}")

    dns = event.get("dns")
    if dns is not None:
        if not isinstance(dns, dict):
            errors.append("dns: must be an object")
        else:
            _require(dns, "q", errors, "dns")
            answers = dns.get("answers")
            if answers is not None and not isinstance(answers, list):
                errors.append("dns.answers: must be a list")

    pkg = event.get("pkg")
    if pkg is not None:
        if not isinstance(pkg, dict):
            errors.append("pkg: must be an object")
        else:
            _require(pkg, "name", errors, "pkg")
            manager = pkg.get("manager")
            if manager is not None and manager not in ("deb", "rpm", "msi", "pip", "cargo",
                                                       "npm", "apk", "other"):
                errors.append(f"pkg.manager: unknown manager {manager!r}")

    score = event.get("score")
    if score is not None and isinstance(score, (int, float)) and not 0.0 <= score <= 100.0:
        errors.append("score: must be within 0..100")

    yara = event.get("yara")
    if yara is not None and not isinstance(yara, list):
        errors.append("yara: must be a list of tag strings")
    return errors


def validate_alert(alert: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(alert, dict):
        return ["alert: must be an object"]
    for key in ("id", "ts", "title", "level", "score"):
        if alert.get(key) in (None, ""):
            errors.append(f"alert.{key}: required")
    if alert.get("level") not in LEVELS:
        errors.append(f"alert.level: must be one of {LEVELS}")
    score = alert.get("score")
    if isinstance(score, (int, float)) and not 0.0 <= score <= 100.0:
        errors.append("alert.score: must be within 0..100")
    events = alert.get("events")
    if events is not None and not isinstance(events, list):
        errors.append("alert.events: must be a list of event ids")
    return errors


def event_id(event: dict[str, Any]) -> str:
    """Stable, content-addressed event id.

    Sensors may restart and lose their counters, so the id is derived from the
    (host, type, ts, pid, dst, q, sha256) tuple rather than a counter.
    """
    proc = event.get("proc") or {}
    net = event.get("net") or {}
    dns = event.get("dns") or {}
    basis = "|".join(
        str(x)
        for x in (
            event.get("host"),
            event.get("type"),
            event.get("ts"),
            proc.get("pid"),
            proc.get("exe"),
            net.get("dst"),
            net.get("dport"),
            dns.get("q"),
            proc.get("sha256"),
            event.get("seq"),
        )
    )
    return "e-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character; 0.0 for empty input."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0.0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def entropy_ratio(text: str) -> float:
    """Entropy normalised by the maximum possible for this length (0..1).

    Raw bits-per-character is the wrong test for random labels: a label of
    length n can carry at most log2(n) bits, so any fixed threshold is coupled
    to length (12 characters cap out at 3.585 bits).  A ratio of 0.9+ means
    "this looks generated" independently of how long it is.
    """
    length = len(text)
    if length < 2:
        return 0.0
    return round(shannon_entropy(text) / math.log2(length), 4)


def longest_label(domain: str) -> str:
    labels = [part for part in domain.split(".") if part]
    return max(labels, key=len) if labels else ""
