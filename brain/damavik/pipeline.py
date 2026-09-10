# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""The brain's pipeline: ingest -> normalize -> enrich -> score -> store.

One class owns the whole path so that the CLI, the dashboard and the tests all
exercise identical behaviour.  Nothing here touches the network except through
an :mod:`damavik.intel` plugin that the configuration explicitly enabled.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

from . import SCHEMA_VERSION
from .alerts import AlertEngine, AlertSink
from .config import Config
from .enrich import ContextEnricher, IntelEnricher
from .intel import providers_for
from .journal import Journal
from .normalize import IngestStats, iter_jsonl
from .rules import RuleSet, load_rules_dir
from .schema import utcnow_iso
from .score import Scorer, ScoreResult
from .store import Store


@dataclass
class PipelineStats:
    events: int = 0
    scored: int = 0
    alerts: int = 0
    rule_hits: dict[str, int] = field(default_factory=dict)
    started: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, Any]:
        return {
            "events": self.events,
            "scored": self.scored,
            "alerts": self.alerts,
            "rule_hits": dict(self.rule_hits),
            "elapsed_s": round(time.time() - self.started, 3),
        }


class Pipeline:
    def __init__(
        self,
        config: Config,
        *,
        store: Store | None = None,
        journal: Journal | None = None,
        rules: RuleSet | None = None,
        scorer: Scorer | None = None,
        alerts: AlertEngine | None = None,
        enrichers: Iterable[Any] = (),
    ) -> None:
        self.config = config
        self.store = store or Store(config.db_path())
        self.journal = journal or Journal(config.journal_path())
        self.rules = rules if rules is not None else load_rules_dir(config.rules.get("dir", "rules"))[0]
        self.scorer = scorer or Scorer.from_config(config, self.store)
        self.alerts = alerts or AlertEngine(
            AlertSink(
                store=self.store,
                journal=self.journal,
                path=config.alerts_path(),
                notify=bool(config.alerts.get("notify")),
                cooldown_s=float(config.alerts.get("cooldown_s", 300)),
                min_score=float(config.alerts.get("min_score", 45)),
            )
        )
        if enrichers:
            self.enrichers = list(enrichers)
        else:
            self.enrichers = [ContextEnricher(self.store)]
            enabled = providers_for(config, self.store)
            if enabled:
                self.enrichers.append(IntelEnricher(enabled))
        self.stats = PipelineStats()
        self._since_head = 0
        self.ingest_stats = IngestStats()
        self.host = config.resolved_host_id()
        self.store.set_meta("host_id", self.host)
        self.store.set_meta("schema_version", SCHEMA_VERSION)

    # -- stages ------------------------------------------------------------
    def enrich(self, event: dict[str, Any]) -> dict[str, Any]:
        """Run every enabled enricher in place; enrichers must never raise."""
        for enricher in self.enrichers:
            try:
                event = enricher(event) or event
            except Exception as exc:  # noqa: BLE001 - enrichment is a second opinion
                event.setdefault("meta", {})["enrich_error"] = f"{type(enricher).__name__}: {exc}"
        return event

    def process(self, event: dict[str, Any]) -> dict[str, Any]:
        """normalize -> enrich -> score -> store -> alert.  Returns the event."""
        self.stats.events += 1
        event.setdefault("host", self.host)
        event = self.enrich(event)
        fired = self.rules.evaluate(event)
        result: ScoreResult = self.scorer.score(event, fired)
        event["score"] = result.score
        event["tags"] = result.tags
        event["rule"] = result.rule
        event["reasons"] = result.reasons
        eid = self.store.insert_event(event, scored=result.as_dict())
        event["id"] = eid
        if self.journal is not None:
            self.journal.append({"kind": "event", "event": event})
            # The head hash is worth persisting, but not once per event: that
            # was a full upsert on the hot path for a value only read at
            # startup.  Every 64th event, plus unconditionally in finish().
            self._since_head += 1
            if self._since_head >= 64:
                self._since_head = 0
                self.store.set_meta("journal_head", self.journal._head)  # noqa: SLF001
        for rule in fired:
            self.stats.rule_hits[rule.rule_id] = self.stats.rule_hits.get(rule.rule_id, 0) + 1
        self.stats.scored += 1
        alert = self.alerts.consider(event, result, fired)
        if alert is not None:
            self.stats.alerts += 1
            event["alert"] = alert["id"]
        return event

    def process_lines(self, lines: Iterable[str]) -> Iterator[dict[str, Any]]:
        for event in iter_jsonl(
            lines,
            host=self.host,
            max_bytes=int(self.config.limits.get("max_event_bytes", 65536)),
            stats=self.ingest_stats,
        ):
            yield self.process(event)

    def run_file(self, path: str, *, limit: int | None = None) -> PipelineStats:
        """Run the pipeline over a JSONL capture file."""
        with open(os.path.expanduser(path), "r", encoding="utf-8", errors="replace") as handle:
            return self.run(handle, limit=limit)

    def run(self, stream: Iterable[str], *, limit: int | None = None) -> PipelineStats:
        for count, _ in enumerate(self.process_lines(stream), start=1):
            if limit is not None and count >= limit:
                break
        self.finish()
        return self.stats

    # -- lifecycle ---------------------------------------------------------
    def finish(self) -> None:
        self.journal.sync()
        if self.journal is not None:
            self._since_head = 0
            self.store.set_meta("journal_head", self.journal._head)  # noqa: SLF001
        self.store.flush_first_seen()
        self.store.set_meta("last_run", utcnow_iso())
        self.store.set_meta("dropped_events", str(self.ingest_stats.rejected))
        self.store.apply_retention(int(self.config.retention_days))

    def close(self) -> None:
        self.alerts.sink.close()
        self.journal.close()
        self.store.close()

    def __enter__(self) -> "Pipeline":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
