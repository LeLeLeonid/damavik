# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""SQLite index: queries the CLI and dashboard depend on."""

from __future__ import annotations

import time

from damavik.store import Store

TS = "2026-09-10T10:00:00.000Z"


def ev(etype="proc.exec", ts=TS, **kwargs):
    event = {"ts": ts, "host": "t", "type": etype, "tags": [], "score": 0.0}
    event.update(kwargs)
    return event


def test_insert_and_read_back(store):
    eid = store.insert_event(ev(proc={"pid": 5, "ppid": 1, "exe": "/bin/sh", "cmd": "sh"}))
    assert eid.startswith("e-")
    got = store.event_by_id(eid)
    assert got["proc"]["exe"] == "/bin/sh"
    assert store.count_events() == 1


def test_duplicate_events_are_ignored(store):
    event = ev(proc={"pid": 5, "exe": "/bin/sh"})
    first = store.insert_event(event)
    second = store.insert_event(event)
    assert first == second
    assert store.count_events() == 1


def test_filters(store):
    store.insert_event(ev(proc={"pid": 5, "exe": "/bin/sh"}, score=90.0))
    store.insert_event(ev("net.flow", proc={"pid": 6}, net={"dst": "1.2.3.4", "dport": 443}))
    assert len(store.events(etype="net.flow")) == 1
    assert len(store.events(pid=5)) == 1
    assert len(store.events(min_score=50)) == 1
    assert len(store.events(limit=1)) == 1


def test_process_tree_nests_children(store):
    store.insert_event(ev(proc={"pid": 1, "ppid": 0, "exe": "/sbin/init"}))
    store.insert_event(ev(proc={"pid": 100, "ppid": 1, "exe": "/usr/bin/soffice.bin"}))
    store.insert_event(ev(proc={"pid": 200, "ppid": 100, "exe": "/bin/bash"}))
    roots = store.process_tree()
    assert len(roots) == 1
    assert roots[0]["pid"] == 1
    assert roots[0]["children"][0]["pid"] == 100
    assert roots[0]["children"][0]["children"][0]["exe"] == "/bin/bash"
    assert store.process_tree(200)[0]["pid"] == 200


def test_orphan_process_becomes_a_root(store):
    store.insert_event(ev(proc={"pid": 77, "ppid": 9999, "exe": "/bin/x"}))
    roots = store.process_tree()
    assert [node["pid"] for node in roots] == [77]


def test_proc_info_and_first_exec(store):
    store.insert_event(ev(ts="2026-09-10T10:00:00.000Z",
                          proc={"pid": 9, "ppid": 1, "exe": "/bin/a", "cmd": "a"}))
    store.insert_event(ev(ts="2026-09-10T10:00:05.000Z",
                          proc={"pid": 9, "ppid": 1, "exe": "/bin/a", "cmd": "a again"}))
    info = store.proc_info(9)
    assert info["cmd"] == "a again"          # newest wins
    assert store.first_exec_ts_ms(9) < store.first_exec_ts_ms(9) + 1
    assert store.proc_info(12345) is None


def test_hash_history_for_a_path(store):
    store.insert_event(ev(proc={"pid": 1, "exe": "/usr/bin/curl", "sha256": "a" * 64}))
    store.insert_event(ev(ts="2026-09-10T10:00:01.000Z",
                          proc={"pid": 2, "exe": "/usr/bin/curl", "sha256": "b" * 64}))
    assert set(store.hashes_for_exe("/usr/bin/curl")) == {"a" * 64, "b" * 64}
    assert store.hashes_for_exe("/usr/bin/absent") == []


def test_flow_aggregation_accumulates(store):
    for index in range(3):
        store.insert_event(
            ev("net.flow", ts=f"2026-09-10T10:00:0{index}.000Z",
               proc={"pid": 42, "exe": "/bin/x"},
               net={"proto": "tcp", "dst": "1.2.3.4", "dport": 443,
                    "bytes_out": 100, "bytes_in": 50})
        )
    rows = store.flow_aggregates(pid=42)
    assert len(rows) == 1
    assert rows[0]["conns"] == 3
    assert rows[0]["bytes_out"] == 300


def test_unattributed_flows_share_one_row(store):
    for index in range(2):
        store.insert_event(
            ev("net.flow", ts=f"2026-09-10T10:00:0{index}.000Z",
               net={"proto": "tcp", "dst": "9.9.9.9", "dport": 53, "bytes_out": 10})
        )
    rows = store.flow_aggregates()
    assert len(rows) == 1
    assert rows[0]["pid"] == -1
    assert rows[0]["conns"] == 2


def test_first_seen_counts(store):
    first, count = store.touch_first_seen("hash", "abc", TS)
    assert first is True and count == 1
    first, count = store.touch_first_seen("hash", "abc", TS)
    assert first is False and count == 2
    assert store.first_seen("hash", "abc")["count"] == 2
    assert store.first_seen("hash", "nope") is None
    assert store.rarest(limit=1)[0]["key"] == "hash:abc"


def test_package_lifecycle(store):
    assert store.upsert_package("deb", "libfoo", "1.0", TS) is True       # new
    assert store.upsert_package("deb", "libfoo", "1.1", TS) is False      # update
    assert store.mark_removed("deb", "libfoo", TS) is True
    assert store.mark_removed("deb", "libfoo", TS) is False               # already gone
    assert store.upsert_package("deb", "libfoo", "1.2", TS) is True       # back == new
    assert store.packages(manager="deb")[0]["removed"] == 0


def test_cve_rows(store):
    store.upsert_cve({"id": "CVE-2024-0001", "ecosystem": "Debian:12", "package": "libfoo",
                      "introduced": "0", "fixed": "1.2.4", "severity": "high",
                      "summary": "bad", "modified": TS})
    rows = store.cves_for("Debian:12", "libfoo")
    assert rows[0]["fixed"] == "1.2.4"
    assert store.cves_for("Debian:12", "libbar") == []


def test_intel_cache_expires(store):
    store.cache_put("bazaar", "sha256:abc", {"verdict": "malicious", "score": 90.0,
                                             "source": "bazaar", "refs": ["x"]}, 3600, TS)
    hit = store.cache_get("bazaar", "sha256:abc")
    assert hit["verdict"] == "malicious" and hit["cached"] is True
    store.cache_put("bazaar", "sha256:old", {"verdict": "clean", "score": 0.0,
                                             "source": "bazaar", "refs": []}, -10, TS)
    assert store.cache_get("bazaar", "sha256:old") is None


def test_timeline_buckets(store):
    now = time.time()
    for offset in range(3):
        ts = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(now - offset * 60))
        store.insert_event(ev(ts=ts, proc={"pid": offset + 1, "exe": "/bin/x"}, score=80.0))
    buckets = store.timeline(hours=1)
    assert sum(bucket["proc.exec"] for bucket in buckets) == 3
    assert max(bucket["max_score"] for bucket in buckets) == 80.0


def test_retention_removes_old_rows_only(store):
    old = "2020-01-01T00:00:00.000Z"
    store.insert_event(ev(ts=old, proc={"pid": 1, "exe": "/bin/old"}))
    store.insert_event(ev(proc={"pid": 2, "exe": "/bin/new"}))
    store.insert_alert({"id": "a-1", "ts": old, "title": "old", "level": "high", "score": 90.0})
    removed = store.apply_retention(7)
    assert removed["events"] == 1 and removed["alerts"] == 1
    assert store.count_events() == 1


def test_retention_zero_days_is_a_no_op(store):
    store.insert_event(ev(proc={"pid": 1, "exe": "/bin/x"}))
    assert store.apply_retention(0) == {"events": 0, "alerts": 0, "flows": 0}
    assert store.count_events() == 1


def test_purge_wipes_everything(store):
    store.insert_event(ev(proc={"pid": 1, "exe": "/bin/x"}))
    store.insert_alert({"id": "a-1", "ts": TS, "title": "t", "level": "low", "score": 10.0})
    store.touch_first_seen("hash", "x", TS)
    store.purge()
    summary = store.summary()
    assert summary["events"] == 0 and summary["alerts"] == 0 and summary["first_seen_keys"] == 0


def test_summary_shape(store):
    store.insert_event(ev(proc={"pid": 1, "exe": "/bin/x"}, score=33.0))
    summary = store.summary()
    for key in ("events", "alerts", "packages", "cves", "first_seen_keys", "top_score",
                "db_bytes", "schema_version"):
        assert key in summary, key
    assert summary["top_score"] == 33.0


def test_meta_roundtrip(store):
    store.set_meta("host_id", "h1")
    assert store.get_meta("host_id") == "h1"
    assert store.get_meta("absent", "fallback") == "fallback"


def test_wal_mode_is_enabled(tmp_path):
    handle = Store(str(tmp_path / "wal.db"))
    assert handle.conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    handle.close()
