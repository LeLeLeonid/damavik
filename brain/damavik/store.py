# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""SQLite storage (WAL) - the queryable index over the journal.

Tables mirror the frozen schema plus the state the scorers need:

``events``       canonical events, indexed by time / pid / exe / dst / hash
``alerts``       ranked alerts with the event ids that caused them
``first_seen``   rarity state: first/last observation + count per key
``packages``     installed software inventory and its first/last sighting
``cves``         local OSV mirror, flattened to one row per affected range
``intel_cache``  provider verdicts with expiry (malicious 30d, clean 7d)
``flow_agg``     pre-aggregated flows per (day, process, destination)
``meta``         key/value bag (schema version, host id, chain head, drops)

Everything is retention-capped; ``damavik purge`` deletes the file.  There is
no network access anywhere in this module.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import threading
import time
from collections.abc import Iterable, Sequence
from typing import Any

from . import SCHEMA_VERSION
from .schema import event_id, iso_to_ms

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    eid     TEXT UNIQUE NOT NULL,
    ts      TEXT NOT NULL,
    ts_ms   INTEGER NOT NULL,
    host    TEXT,
    type    TEXT NOT NULL,
    pid     INTEGER,
    ppid    INTEGER,
    exe     TEXT,
    cmd     TEXT,
    sha256  TEXT,
    user    TEXT,
    dst     TEXT,
    dport   INTEGER,
    proto   TEXT,
    q       TEXT,
    score   REAL NOT NULL DEFAULT 0,
    tags    TEXT NOT NULL DEFAULT '[]',
    rule    TEXT,
    raw     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts    ON events(ts_ms);
CREATE INDEX IF NOT EXISTS idx_events_pid   ON events(pid);
CREATE INDEX IF NOT EXISTS idx_events_type  ON events(type);
CREATE INDEX IF NOT EXISTS idx_events_dst   ON events(dst);
CREATE INDEX IF NOT EXISTS idx_events_score ON events(score DESC);
CREATE INDEX IF NOT EXISTS idx_events_exe   ON events(exe);

CREATE TABLE IF NOT EXISTS alerts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    aid      TEXT UNIQUE NOT NULL,
    ts       TEXT NOT NULL,
    ts_ms    INTEGER NOT NULL,
    title    TEXT NOT NULL,
    level    TEXT NOT NULL,
    score    REAL NOT NULL,
    rule     TEXT,
    events   TEXT NOT NULL DEFAULT '[]',
    iocs     TEXT NOT NULL DEFAULT '{}',
    explain  TEXT NOT NULL DEFAULT '',
    status   TEXT NOT NULL DEFAULT 'open',
    dedup    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts_ms DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(dedup);

CREATE TABLE IF NOT EXISTS first_seen (
    key       TEXT PRIMARY KEY,
    kind      TEXT NOT NULL,
    first_ts  TEXT NOT NULL,
    last_ts   TEXT NOT NULL,
    count     INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_first_seen_kind ON first_seen(kind);

CREATE TABLE IF NOT EXISTS packages (
    manager   TEXT NOT NULL,
    name      TEXT NOT NULL,
    version   TEXT NOT NULL,
    source    TEXT,
    arch      TEXT,
    first_ts  TEXT NOT NULL,
    last_ts   TEXT NOT NULL,
    removed   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (manager, name)
);

CREATE TABLE IF NOT EXISTS cves (
    id          TEXT NOT NULL,
    ecosystem   TEXT NOT NULL,
    package     TEXT NOT NULL,
    introduced  TEXT,
    fixed       TEXT,
    last_affected TEXT,
    severity    TEXT,
    summary     TEXT,
    modified    TEXT,
    PRIMARY KEY (id, ecosystem, package, introduced, fixed)
);
CREATE INDEX IF NOT EXISTS idx_cves_pkg ON cves(ecosystem, package);

CREATE TABLE IF NOT EXISTS intel_cache (
    kind        TEXT NOT NULL,
    value       TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    score       REAL NOT NULL DEFAULT 0,
    source      TEXT,
    refs        TEXT NOT NULL DEFAULT '[]',
    fetched_ts  TEXT NOT NULL,
    expires_ts  TEXT NOT NULL,
    PRIMARY KEY (kind, value)
);

CREATE TABLE IF NOT EXISTS flow_agg (
    day       TEXT NOT NULL,
    pid       INTEGER,
    exe       TEXT,
    dst       TEXT NOT NULL,
    dport     INTEGER,
    proto     TEXT,
    conns     INTEGER NOT NULL DEFAULT 0,
    bytes_out INTEGER NOT NULL DEFAULT 0,
    bytes_in  INTEGER NOT NULL DEFAULT 0,
    first_ts  TEXT,
    last_ts   TEXT,
    PRIMARY KEY (day, pid, dst, dport, proto)
);
"""


def connect(path: str) -> sqlite3.Connection:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_SCHEMA)
    return conn


class Store:
    """Wrapper around the SQLite index.

    The dashboard serves requests from a thread pool, and ``sqlite3``
    connections are thread-affine by default, so each thread gets its own
    connection (WAL lets readers and the single writer coexist).  Writes are
    serialised through ``_lock``.
    """

    #: Repeat first-seen observations are counted in memory and written back in
    #: batches; a genuinely new key is always written immediately.
    FLUSH_AFTER = 512
    #: Bound on the per-lookup caches, so a long-running monitor cannot grow
    #: without limit.  Clearing is always safe: the next lookup re-queries.
    CACHE_LIMIT = 20000

    def __init__(self, path: str) -> None:
        self.path = os.path.expanduser(path)
        self._local = threading.local()
        self._lock = threading.RLock()
        self._connections: list[sqlite3.Connection] = []
        self._seen_counts: dict[str, int] = {}
        self._seen_last: dict[str, str] = {}
        self._seen_dirty: set[str] = set()
        self._proc_cache: dict[int, Any] = {}
        self._start_cache: dict[int, Any] = {}
        self._hash_cache: dict[str, set[str]] = {}
        self.set_meta("schema_version", SCHEMA_VERSION)

    @property
    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = connect(self.path)
            self._local.conn = conn
            with self._lock:
                self._connections.append(conn)
        return conn

    # -- meta --------------------------------------------------------------
    def set_meta(self, key: str, value: Any) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, str(value)),
            )

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    # -- events ------------------------------------------------------------
    def insert_event(self, event: dict[str, Any], *, scored: dict[str, Any] | None = None) -> str:
        """Insert a canonical event; returns its id.  Duplicates are ignored."""
        merged = dict(event)
        if scored:
            merged["score"] = scored.get("score", event.get("score", 0.0))
            merged["tags"] = scored.get("tags", event.get("tags", []))
            merged["rule"] = scored.get("rule", event.get("rule"))
        eid = merged.get("id") or event_id(merged)
        proc = merged.get("proc") or {}
        net = merged.get("net") or {}
        dns = merged.get("dns") or {}
        ts = merged["ts"]
        with self._lock:
            self.conn.execute(
                """INSERT OR IGNORE INTO events
                   (eid, ts, ts_ms, host, type, pid, ppid, exe, cmd, sha256, user,
                    dst, dport, proto, q, score, tags, rule, raw)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    eid,
                    ts,
                    iso_to_ms(ts),
                    merged.get("host"),
                    merged.get("type"),
                    proc.get("pid"),
                    proc.get("ppid"),
                    proc.get("exe"),
                    proc.get("cmd"),
                    proc.get("sha256"),
                    proc.get("user"),
                    net.get("dst"),
                    net.get("dport"),
                    net.get("proto"),
                    dns.get("q"),
                    float(merged.get("score") or 0.0),
                    json.dumps(merged.get("tags") or []),
                    merged.get("rule"),
                    json.dumps(merged, sort_keys=True),
                ),
            )
            self._invalidate_caches(merged)
            self._aggregate_flow(merged)
        return eid

    def _invalidate_caches(self, event: dict[str, Any]) -> None:
        """Drop cached lookups that this event may have made stale.

        Deliberately narrow.  Invalidating a PID on *every* event would make
        the caches useless, because the enricher asks about the same process
        over and over; only an event that can actually change an answer needs
        to evict it:

        * ``_start_cache`` — only a new ``proc.exec`` can change the first-exec
          time of a PID;
        * ``_proc_cache`` — only an event carrying an executable image can
          become the "most recent known attributes";
        * ``_hash_cache`` — a new (path, hash) pair extends the set in place.
        """
        proc = event.get("proc") or {}
        pid = proc.get("pid")
        if pid is not None:
            pid = int(pid)
            if event.get("type") == "proc.exec":
                self._start_cache.pop(pid, None)
            if proc.get("exe"):
                self._proc_cache.pop(pid, None)
        exe, sha = proc.get("exe"), proc.get("sha256")
        if exe and sha and exe in self._hash_cache:
            self._hash_cache[exe].add(sha)
        if len(self._proc_cache) >= self.CACHE_LIMIT:
            self._proc_cache.clear()
        if len(self._start_cache) >= self.CACHE_LIMIT:
            self._start_cache.clear()
        if len(self._hash_cache) >= self.CACHE_LIMIT:
            self._hash_cache.clear()

    def _aggregate_flow(self, event: dict[str, Any]) -> None:
        net = event.get("net")
        if not net or event.get("type") != "net.flow":
            return
        proc = event.get("proc") or {}
        day = event["ts"][:10]
        dst = net.get("dst") or ""
        # -1 means "not attributed to a process"; a real NULL would defeat the
        # primary key, because SQLite treats NULLs as distinct.
        pid = proc.get("pid") if proc.get("pid") is not None else -1
        self.conn.execute(
            """INSERT INTO flow_agg(day, pid, exe, dst, dport, proto, conns,
                                    bytes_out, bytes_in, first_ts, last_ts)
               VALUES (?,?,?,?,?,?,1,?,?,?,?)
               ON CONFLICT(day, pid, dst, dport, proto) DO UPDATE SET
                 conns = conns + 1,
                 bytes_out = bytes_out + excluded.bytes_out,
                 bytes_in  = bytes_in  + excluded.bytes_in,
                 exe = COALESCE(excluded.exe, exe),
                 last_ts = excluded.last_ts""",
            (
                day,
                pid,
                proc.get("exe"),
                dst,
                net.get("dport"),
                net.get("proto") or "tcp",
                int(net.get("bytes_out") or 0),
                int(net.get("bytes_in") or 0),
                event["ts"],
                event["ts"],
            ),
        )

    def events(
        self,
        *,
        limit: int = 50,
        etype: str | None = None,
        pid: int | None = None,
        min_score: float | None = None,
        since_ms: int | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if etype:
            clauses.append("type = ?")
            params.append(etype)
        if pid is not None:
            clauses.append("pid = ?")
            params.append(pid)
        if min_score is not None:
            clauses.append("score >= ?")
            params.append(min_score)
        if since_ms is not None:
            clauses.append("ts_ms >= ?")
            params.append(since_ms)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(int(limit))
        rows = self.conn.execute(
            f"SELECT * FROM events{where} ORDER BY ts_ms DESC, id DESC LIMIT ?", params
        ).fetchall()
        return [self._row_to_event(row) for row in rows]

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
        event = json.loads(row["raw"])
        event["id"] = row["eid"]
        event["score"] = row["score"]
        event["tags"] = json.loads(row["tags"] or "[]")
        return event

    def event_by_id(self, eid: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM events WHERE eid=?", (eid,)).fetchone()
        return self._row_to_event(row) if row else None

    def proc_info(self, pid: int) -> dict[str, Any] | None:
        """Most recent known attributes for a PID (used for ancestry context).

        Cached: the enricher asks for the same parents over and over.  The cache
        is invalidated by :meth:`insert_event`, so a PID that reappears (PID
        reuse) is re-read rather than answered from a stale row.
        """
        pid = int(pid)
        if pid in self._proc_cache:
            return self._proc_cache[pid]
        row = self.conn.execute(
            """SELECT pid, ppid, exe, cmd, sha256, user, ts, ts_ms FROM events
               WHERE pid=? AND exe IS NOT NULL ORDER BY ts_ms DESC, id DESC LIMIT 1""",
            (pid,),
        ).fetchone()
        value = dict(row) if row else None
        if len(self._proc_cache) < self.CACHE_LIMIT:
            self._proc_cache[pid] = value
        return value

    def first_exec_ts_ms(self, pid: int) -> int | None:
        """Epoch ms of the first ``proc.exec`` we recorded for a PID.

        Cached, and safe to cache permanently: the *first* exec of a PID never
        changes once recorded, and a new exec for that PID invalidates it.
        """
        pid = int(pid)
        if pid in self._start_cache:
            return self._start_cache[pid]
        row = self.conn.execute(
            "SELECT MIN(ts_ms) AS ts_ms FROM events WHERE pid=? AND type='proc.exec'",
            (pid,),
        ).fetchone()
        value = row["ts_ms"] if row else None
        value = int(value) if value else None
        if len(self._start_cache) < self.CACHE_LIMIT:
            self._start_cache[pid] = value
        return value

    def hashes_for_exe(self, exe: str) -> list[str]:
        """Every distinct hash this executable path has ever been seen with."""
        cached = self._hash_cache.get(exe)
        if cached is not None:
            return sorted(cached)
        rows = self.conn.execute(
            "SELECT DISTINCT sha256 FROM events WHERE exe=? AND sha256 IS NOT NULL", (exe,)
        ).fetchall()
        hashes = {row["sha256"] for row in rows}
        if len(self._hash_cache) < self.CACHE_LIMIT:
            self._hash_cache[exe] = hashes
        return sorted(hashes)

    def count_events(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"])

    # -- process tree ------------------------------------------------------
    def process_tree(self, root_pid: int | None = None) -> list[dict[str, Any]]:
        """Latest known (pid, ppid, exe) triples, as a nested tree."""
        rows = self.conn.execute(
            """SELECT pid, ppid, exe, MAX(ts_ms) AS ts_ms FROM events
               WHERE pid IS NOT NULL GROUP BY pid ORDER BY ts_ms"""
        ).fetchall()
        latest: dict[int, dict[str, Any]] = {}
        for row in rows:
            detail = self.conn.execute(
                """SELECT exe, cmd, sha256, user, MAX(score) AS score FROM events
                   WHERE pid=? AND exe IS NOT NULL""",
                (row["pid"],),
            ).fetchone()
            latest[int(row["pid"])] = {
                "pid": int(row["pid"]),
                "ppid": int(row["ppid"]) if row["ppid"] is not None else 0,
                "exe": (detail["exe"] if detail else None) or row["exe"] or "?",
                "cmd": detail["cmd"] if detail else None,
                "sha256": detail["sha256"] if detail else None,
                "user": detail["user"] if detail else None,
                "score": float(detail["score"] or 0.0) if detail else 0.0,
                "children": [],
            }
        roots: list[dict[str, Any]] = []
        for node in latest.values():
            parent = latest.get(node["ppid"])
            if parent is not None and parent is not node:
                parent["children"].append(node)
            else:
                roots.append(node)
        if root_pid is not None:
            node = latest.get(root_pid)
            return [node] if node else []
        return roots

    # -- alerts ------------------------------------------------------------
    def insert_alert(self, alert: dict[str, Any]) -> str:
        aid = alert["id"]
        with self._lock:
            self.conn.execute(
                """INSERT OR IGNORE INTO alerts
                   (aid, ts, ts_ms, title, level, score, rule, events, iocs, explain,
                    status, dedup)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    aid,
                    alert["ts"],
                    iso_to_ms(alert["ts"]),
                    alert["title"],
                    alert["level"],
                    float(alert["score"]),
                    alert.get("rule"),
                    json.dumps(alert.get("events") or []),
                    json.dumps(alert.get("iocs") or {}),
                    alert.get("explain", ""),
                    alert.get("status", "open"),
                    alert.get("dedup", ""),
                ),
            )
        return aid

    def alerts(self, *, limit: int = 50, status: str | None = None) -> list[dict[str, Any]]:
        if status:
            rows = self.conn.execute(
                "SELECT * FROM alerts WHERE status=? ORDER BY ts_ms DESC LIMIT ?",
                (status, int(limit)),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM alerts ORDER BY ts_ms DESC LIMIT ?", (int(limit),)
            ).fetchall()
        out = []
        for row in rows:
            out.append(
                {
                    "id": row["aid"],
                    "ts": row["ts"],
                    "title": row["title"],
                    "level": row["level"],
                    "score": row["score"],
                    "rule": row["rule"],
                    "events": json.loads(row["events"] or "[]"),
                    "iocs": json.loads(row["iocs"] or "{}"),
                    "explain": row["explain"],
                    "status": row["status"],
                }
            )
        return out

    def last_alert_ts_for_dedup(self, dedup: str) -> str | None:
        row = self.conn.execute(
            "SELECT ts FROM alerts WHERE dedup=? ORDER BY ts_ms DESC LIMIT 1", (dedup,)
        ).fetchone()
        return row["ts"] if row else None

    def count_alerts(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"])

    # -- first-seen / rarity ----------------------------------------------
    def touch_first_seen(self, kind: str, key: str, ts: str) -> tuple[bool, int]:
        """Record an observation.  Returns ``(is_first_time, total_count)``.

        This used to be a SELECT followed by an INSERT *or* an UPDATE — two or
        three statements, more than twice per event, and the largest single
        source of SQL in the pipeline.  Now:

        * a **first** sighting goes straight to SQLite in one upsert, so a
          crash can never make us announce the same "first sighting" twice;
        * a **repeat** sighting only bumps an in-memory counter, written back
          in batches, because ``count``/``last_ts`` are bookkeeping rather than
          detection state.
        """
        full = f"{kind}:{key}"
        cached = self._seen_counts.get(full)
        if cached is not None:
            count = cached + 1
            self._seen_counts[full] = count
            self._seen_last[full] = ts
            self._seen_dirty.add(full)
            if len(self._seen_dirty) >= self.FLUSH_AFTER:
                self.flush_first_seen()
            return False, count
        with self._lock:
            row = self.conn.execute(
                """INSERT INTO first_seen(key, kind, first_ts, last_ts, count)
                   VALUES (?,?,?,?,1)
                   ON CONFLICT(key) DO UPDATE SET
                     count = count + 1, last_ts = excluded.last_ts
                   RETURNING count""",
                (full, kind, ts, ts),
            ).fetchone()
            count = int(row["count"])
            self._seen_counts[full] = count
            self._seen_last[full] = ts
            if count > 1:  # cache was cold; the row already existed
                self._seen_dirty.add(full)
            return count == 1, count

    def flush_first_seen(self) -> None:
        """Write deferred first-seen counters back to SQLite."""
        if not self._seen_dirty:
            return
        with self._lock:
            rows = [(self._seen_counts[k], self._seen_last[k], k) for k in self._seen_dirty]
            self.conn.executemany("UPDATE first_seen SET count=?, last_ts=? WHERE key=?", rows)
            self._seen_dirty.clear()

    def first_seen(self, kind: str, key: str) -> dict[str, Any] | None:
        # Readers must not see stale counters: the write path defers them.
        self.flush_first_seen()
        row = self.conn.execute(
            "SELECT * FROM first_seen WHERE key=?", (f"{kind}:{key}",)
        ).fetchone()
        return dict(row) if row else None

    def rarest(self, limit: int = 20) -> list[dict[str, Any]]:
        # Ordering is by count, so deferred counters have to land first or the
        # "rarest" answer is wrong.
        self.flush_first_seen()
        rows = self.conn.execute(
            "SELECT * FROM first_seen ORDER BY count ASC, last_ts DESC LIMIT ?", (int(limit),)
        ).fetchall()
        return [dict(row) for row in rows]

    # -- packages ----------------------------------------------------------
    def upsert_package(
        self,
        manager: str,
        name: str,
        version: str,
        ts: str,
        *,
        source: str | None = None,
        arch: str | None = None,
    ) -> bool:
        """Insert or refresh a package.  Returns True when newly installed."""
        with self._lock:
            existing = self.conn.execute(
                "SELECT version, removed FROM packages WHERE manager=? AND name=?",
                (manager, name),
            ).fetchone()
            if existing is None:
                self.conn.execute(
                    "INSERT INTO packages(manager, name, version, source, arch, first_ts,"
                    " last_ts, removed) VALUES (?,?,?,?,?,?,?,0)",
                    (manager, name, version, source, arch, ts, ts),
                )
                return True
            self.conn.execute(
                "UPDATE packages SET version=?, last_ts=?, removed=0, "
                "source=COALESCE(?, source), arch=COALESCE(?, arch) WHERE manager=? AND name=?",
                (version, ts, source, arch, manager, name),
            )
            return bool(existing["removed"])

    def mark_removed(self, manager: str, name: str, ts: str) -> bool:
        with self._lock:
            cur = self.conn.execute(
                "UPDATE packages SET removed=1, last_ts=? WHERE manager=? AND name=? AND removed=0",
                (ts, manager, name),
            )
            return cur.rowcount > 0

    def packages(self, *, manager: str | None = None) -> list[dict[str, Any]]:
        if manager:
            rows = self.conn.execute(
                "SELECT * FROM packages WHERE manager=? ORDER BY name", (manager,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM packages ORDER BY manager, name").fetchall()
        return [dict(row) for row in rows]

    # -- CVEs --------------------------------------------------------------
    def upsert_cve(self, row: dict[str, Any]) -> None:
        with self._lock:
            self.conn.execute(
                """INSERT OR REPLACE INTO cves
                   (id, ecosystem, package, introduced, fixed, last_affected, severity,
                    summary, modified)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    row["id"],
                    row["ecosystem"],
                    row["package"],
                    row.get("introduced"),
                    row.get("fixed"),
                    row.get("last_affected"),
                    row.get("severity"),
                    row.get("summary"),
                    row.get("modified"),
                ),
            )

    def cves_for(self, ecosystem: str, package: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM cves WHERE ecosystem=? AND package=?", (ecosystem, package)
        ).fetchall()
        return [dict(row) for row in rows]

    # -- intel cache -------------------------------------------------------
    def cache_put(
        self, kind: str, value: str, verdict: dict[str, Any], ttl_s: float, ts: str
    ) -> None:
        expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + ttl_s))
        with self._lock:
            self.conn.execute(
                """INSERT OR REPLACE INTO intel_cache
                   (kind, value, verdict, score, source, refs, fetched_ts, expires_ts)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    kind,
                    value,
                    verdict.get("verdict", "unknown"),
                    float(verdict.get("score", 0.0)),
                    verdict.get("source"),
                    json.dumps(verdict.get("refs") or []),
                    ts,
                    expires,
                ),
            )

    def cache_get(self, kind: str, value: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM intel_cache WHERE kind=? AND value=?", (kind, value)
        ).fetchone()
        if row is None:
            return None
        if row["expires_ts"] < time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()):
            return None
        return {
            "verdict": row["verdict"],
            "score": row["score"],
            "source": row["source"],
            "refs": json.loads(row["refs"] or "[]"),
            "fetched_ts": row["fetched_ts"],
            "cached": True,
        }

    # -- flows -------------------------------------------------------------
    def flow_aggregates(
        self, *, pid: int | None = None, day: str | None = None, limit: int = 200
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if pid is not None:
            clauses.append("pid=?")
            params.append(pid)
        if day:
            clauses.append("day=?")
            params.append(day)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(int(limit))
        rows = self.conn.execute(
            f"SELECT * FROM flow_agg{where} ORDER BY conns DESC, bytes_out DESC LIMIT ?", params
        ).fetchall()
        return [dict(row) for row in rows]

    def timeline(self, *, hours: int = 24, bucket_minutes: int = 15) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT type, ts_ms, eid, score, exe, dst, q FROM events
               WHERE ts_ms >= ? ORDER BY ts_ms""",
            (int((time.time() - hours * 3600) * 1000),),
        ).fetchall()
        buckets: dict[int, dict[str, Any]] = {}
        span = bucket_minutes * 60 * 1000
        for row in rows:
            key = int(row["ts_ms"] // span) * span
            bucket = buckets.setdefault(
                key,
                {
                    "t": key,
                    "proc.exec": 0,
                    "net.flow": 0,
                    "dns.query": 0,
                    "pkg.event": 0,
                    "file.verdict": 0,
                    "sensor.meta": 0,
                    "max_score": 0.0,
                    "ids": [],
                },
            )
            etype = row["type"]
            if etype in bucket:
                bucket[etype] += 1
            bucket["max_score"] = max(bucket["max_score"], float(row["score"] or 0.0))
            if float(row["score"] or 0.0) >= 45.0 and len(bucket["ids"]) < 20:
                bucket["ids"].append(row["eid"])
        return [buckets[key] for key in sorted(buckets)]

    # -- maintenance -------------------------------------------------------
    def apply_retention(self, days: int) -> dict[str, int]:
        """Delete rows older than ``days``; ``0`` means keep everything.

        Called once when a run starts (``Pipeline.apply_storage_policy``), which
        is the only thing that keeps it honest: a capture replayed through the
        pipeline carries *recorded* timestamps, so pruning after ingest deletes
        the very batch the run was asked to process.
        """
        if days <= 0:
            return {"events": 0, "alerts": 0, "flows": 0}
        cutoff_ms = int((time.time() - days * 86400) * 1000)
        cutoff_day = time.strftime("%Y-%m-%d", time.gmtime(time.time() - days * 86400))
        with self._lock:
            events = self.conn.execute("DELETE FROM events WHERE ts_ms < ?", (cutoff_ms,)).rowcount
            alerts = self.conn.execute("DELETE FROM alerts WHERE ts_ms < ?", (cutoff_ms,)).rowcount
            flows = self.conn.execute("DELETE FROM flow_agg WHERE day < ?", (cutoff_day,)).rowcount
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return {"events": int(events or 0), "alerts": int(alerts or 0), "flows": int(flows or 0)}

    def summary(self) -> dict[str, Any]:
        def one(sql: str, *args: Any) -> Any:
            return self.conn.execute(sql, args).fetchone()[0]

        return {
            "schema_version": self.get_meta("schema_version"),
            "host": self.get_meta("host_id"),
            "events": one("SELECT COUNT(*) FROM events"),
            "alerts": one("SELECT COUNT(*) FROM alerts"),
            "open_alerts": one("SELECT COUNT(*) FROM alerts WHERE status='open'"),
            "packages": one("SELECT COUNT(*) FROM packages WHERE removed=0"),
            "packages_with_cve": one("SELECT COUNT(DISTINCT package) FROM cves"),
            "cves": one("SELECT COUNT(*) FROM cves"),
            "first_seen_keys": one("SELECT COUNT(*) FROM first_seen"),
            "intel_cache": one("SELECT COUNT(*) FROM intel_cache"),
            "top_score": one("SELECT COALESCE(MAX(score), 0) FROM events"),
            "db_bytes": os.path.getsize(self.path) if os.path.exists(self.path) else 0,
            "journal_head": self.get_meta("journal_head"),
            "dropped_events": self.get_meta("dropped_events", "0"),
        }

    def purge(self) -> None:
        with self._lock:
            for table in (
                "events",
                "alerts",
                "first_seen",
                "packages",
                "cves",
                "intel_cache",
                "flow_agg",
                "meta",
            ):
                self.conn.execute(f"DELETE FROM {table}")
            self.conn.execute("DELETE FROM sqlite_sequence WHERE name='events'")
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._seen_counts.clear()
            self._seen_last.clear()
            self._seen_dirty.clear()
            self._proc_cache.clear()
            self._start_cache.clear()
            self._hash_cache.clear()
            self.conn.execute("VACUUM")

    def close(self) -> None:
        self.flush_first_seen()
        with self._lock:
            for conn in self._connections:
                with contextlib.suppress(sqlite3.Error):
                    conn.close()
            self._connections.clear()
        self._local = threading.local()

    def bulk_insert_events(self, events: Iterable[dict[str, Any]]) -> int:
        total = 0
        for event in events:
            self.insert_event(event)
            total += 1
        return total

    def executemany(self, sql: str, rows: Sequence[Sequence[Any]]) -> None:
        with self._lock:
            self.conn.executemany(sql, rows)
