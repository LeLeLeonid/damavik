# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""alertd - turn scored events into ranked, deduplicated, explainable alerts.

Two noise controls matter more than any detection content:

1. **Deduplication with cooldown.**  A beacon that fires every 60 seconds would
   otherwise write 1440 identical alerts a day.  The dedup key is
   ``rule + primary IOC``, and only one alert per key per ``cooldown_s`` is
   emitted; later matches extend the existing alert's event list instead.
2. **Every alert carries the evidence.**  ``events`` holds the event ids and
   ``explain`` the reason strings from the scorer, so the dashboard can render
   the exact subgraph that caused it.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

from .schema import LEVELS, iso_to_ms, utcnow_iso, validate_alert

LEVEL_BY_SCORE = ((85.0, "critical"), (70.0, "high"), (50.0, "medium"), (30.0, "low"))
GENERIC_THRESHOLD = 70.0


def level_for_score(score: float) -> str:
    for threshold, level in LEVEL_BY_SCORE:
        if score >= threshold:
            return level
    return "info"


def _alert_id(dedup: str, ts: str) -> str:
    return "a-" + hashlib.sha256(f"{dedup}|{ts}".encode()).hexdigest()[:12]


@dataclass
class AlertSink:
    """Where alerts go: JSONL file, journal, SQLite, desktop notification."""

    store: Any = None
    journal: Any = None
    path: str | None = None
    notify: bool = False
    cooldown_s: float = 300.0
    min_score: float = 45.0
    _fh: Any = None

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def emit(self, alert: dict[str, Any]) -> None:
        problems = validate_alert(alert)
        if problems:
            raise ValueError(f"refusing to emit invalid alert: {'; '.join(problems)}")
        if self.journal is not None:
            self.journal.append({"kind": "alert", "alert": alert})
        if self.store is not None:
            self.store.insert_alert(alert)
        if self.path:
            self._append_jsonl(alert)
        if self.notify:
            self._notify(alert)

    def _append_jsonl(self, alert: dict[str, Any]) -> None:
        expanded = os.path.expanduser(self.path)
        parent = os.path.dirname(expanded)
        if parent:
            os.makedirs(parent, exist_ok=True)
        if self._fh is None:
            # Deliberately not a context manager: the handle is opened once per
            # process and reused for every alert, and `close()` owns it.
            self._fh = open(expanded, "a", encoding="utf-8")  # noqa: SIM115
        self._fh.write(json.dumps(alert, sort_keys=True) + "\n")
        self._fh.flush()

    def _notify(self, alert: dict[str, Any]) -> None:
        """Best-effort desktop notification.  Never raises, never blocks."""
        title = f"[{alert['level'].upper()}] {alert['title']}"[:120]
        body = f"{alert['explain'][:200]}" or alert["id"]
        try:
            if shutil.which("notify-send"):
                subprocess.run(  # noqa: S603 - fixed argv, no shell
                    ["notify-send", "-u", "critical", "-a", "damavik", title, body],
                    check=False,
                    timeout=2,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        except (OSError, subprocess.SubprocessError):
            pass


class AlertEngine:
    def __init__(
        self, sink: AlertSink, *, cooldown_s: float | None = None, min_score: float | None = None
    ) -> None:
        self.sink = sink
        self.cooldown_s = sink.cooldown_s if cooldown_s is None else cooldown_s
        self.min_score = sink.min_score if min_score is None else min_score

    # -- construction ------------------------------------------------------
    def build(self, event: dict[str, Any], score: Any, fired: list[Any]) -> dict[str, Any] | None:
        ts = event.get("ts") or utcnow_iso()
        if fired:
            rule = max(
                fired,
                key=lambda r: {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[r.level],
            )
            level = rule.level if rule.level in LEVELS else level_for_score(score.score)
            title = rule.title
            # A correlating rule (beacon, DNS burst) must collapse on its
            # group key - otherwise every event in the window writes its own
            # alert, which is exactly the noise this exists to prevent.
            group = self._correlation_key(rule, event)
            dedup = f"{rule.rule_id}|{group or self._primary_ioc(event)}"
            explain_parts = [f"{rule.rule_id}: {rule.explain}"]
        else:
            if score.score < max(self.min_score, GENERIC_THRESHOLD):
                return None
            level = level_for_score(score.score)
            title = "High-risk activity without a matching rule"
            dedup = f"generic|{self._primary_ioc(event)}"
            explain_parts = []
        explain_parts.extend(score.reasons)
        return {
            "id": _alert_id(dedup, ts),
            "ts": ts,
            "title": title,
            "level": level,
            "score": float(score.score),
            "rule": score.rule,
            "events": [event.get("id")] if event.get("id") else [],
            "iocs": self._iocs(event),
            "explain": "; ".join(part for part in explain_parts if part),
            "status": "open",
            "dedup": dedup,
        }

    def consider(
        self, event: dict[str, Any], score: Any, fired: list[Any]
    ) -> dict[str, Any] | None:
        """Build an alert, applying dedup/cooldown.  Returns None when suppressed."""
        alert = self.build(event, score, fired)
        if alert is None:
            return None
        if alert["score"] < self.min_score and not fired:
            return None
        if self._suppressed(alert, event):
            return None
        self.sink.emit(alert)
        return alert

    # -- noise control -----------------------------------------------------
    def _suppressed(self, alert: dict[str, Any], event: dict[str, Any]) -> bool:
        if self.sink.store is None or self.cooldown_s <= 0:
            return False
        last = self.sink.store.last_alert_ts_for_dedup(alert["dedup"])
        if not last:
            return False
        delta_ms = iso_to_ms(event.get("ts") or utcnow_iso()) - iso_to_ms(last)
        return 0 <= delta_ms < self.cooldown_s * 1000

    @staticmethod
    def _correlation_key(rule: Any, event: dict[str, Any]) -> str:
        spec = getattr(rule, "correlate", None)
        if not spec:
            return ""
        from .rules import get_field  # local import: avoids a cycle at module load

        return str(get_field(event, str(spec.get("group_by", ""))) or "")

    @staticmethod
    def _primary_ioc(event: dict[str, Any]) -> str:
        proc = event.get("proc") or {}
        net = event.get("net") or {}
        dns = event.get("dns") or {}
        pkg = event.get("pkg") or {}
        for value in (
            proc.get("sha256"),
            net.get("dst"),
            dns.get("q"),
            pkg.get("name"),
            proc.get("exe"),
        ):
            if value:
                return str(value)
        return event.get("type", "unknown")

    @staticmethod
    def _iocs(event: dict[str, Any]) -> dict[str, Any]:
        proc = event.get("proc") or {}
        net = event.get("net") or {}
        dns = event.get("dns") or {}
        pkg = event.get("pkg") or {}
        iocs: dict[str, Any] = {}
        if proc.get("sha256"):
            iocs["sha256"] = proc["sha256"]
        if proc.get("exe"):
            iocs["exe"] = proc["exe"]
        if proc.get("pid") is not None:
            iocs["pid"] = proc["pid"]
        if net.get("dst"):
            iocs["dst"] = net["dst"]
        if net.get("dport") is not None:
            iocs["dport"] = net["dport"]
        if dns.get("q"):
            iocs["domain"] = dns["q"]
        if pkg.get("name"):
            iocs["package"] = f"{pkg.get('manager', '?')}:{pkg['name']}"
            if pkg.get("cves"):
                iocs["cves"] = list(pkg["cves"])
        meta = event.get("meta") or {}
        for key in ("path", "port", "exe", "pid", "kind"):
            if meta.get(key) is not None:
                iocs[key] = meta[key]
        if not iocs:
            # An alert that points at nothing is useless: always name the type.
            iocs["type"] = event.get("type", "unknown")
        return iocs
