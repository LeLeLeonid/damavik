# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Hash-chained append-only journal.

The SQLite database is an *index* - it can be rebuilt, truncated or deleted.
The journal is the audit trail: every scored event and every alert is appended
as one JSON line whose ``h`` field is a SHA-256 over the previous line's hash
plus this record's canonical bytes.  An attacker who edits or deletes a line in
the middle breaks the chain from that point on, and ``damavik verify`` says
exactly where.

Framing (``dmk: j1``)::

    {"dmk":"j1","seq":0,"prev":null,"h":"<sha256>","rec":{...}}

This is deliberately not a blockchain and not a consensus protocol - it is a
tamper-*evidence* mechanism for a single host, which is all the threat model
requires.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

FRAME = "j1"
GENESIS = "0" * 64


def canonical(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8 safe."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def chain_hash(prev: str, record: Any, record_json: str | None = None) -> str:
    """Hash of ``prev`` + the canonical record.

    ``record_json`` lets a caller that already serialised the record (the
    writer does, to build the frame) reuse it instead of paying for a second
    ``json.dumps`` of the same object.
    """
    text = canonical(record) if record_json is None else record_json
    return hashlib.sha256((prev + text).encode("utf-8")).hexdigest()


@dataclass
class JournalEntry:
    seq: int
    prev: str
    h: str
    rec: dict[str, Any]


class Journal:
    """Append-only, hash-chained JSONL writer/reader.

    ``fsync_every`` trades durability for throughput.  Every record is written
    and flushed immediately, and the hash chain is complete on disk either way;
    the question is only how much the *OS* may still be holding.  With the
    default of 128, a power cut can lose up to 127 trailing records, and the
    chain still verifies for everything that survived.  Set ``fsync_every=1``
    for "never lose a record" at roughly one millisecond per event.

    A per-record fsync was tried and rejected: it cost ~1 ms per event, more
    than the rest of the pipeline combined, and the events are in SQLite as
    well.  Per-alert fsync was tried too, and rejected because alert volume is
    not bounded by anything the journal can rely on.
    """

    def __init__(self, path: str, *, fsync_every: int = 128) -> None:
        self.path = os.path.expanduser(path)
        self.fsync_every = max(1, int(fsync_every))
        self._lock = threading.Lock()
        self._head = GENESIS
        self._seq = 0
        self._fh: Any = None
        self._unflushed = 0
        self.corrupt: str | None = None
        self._load_state()

    # -- lifecycle ---------------------------------------------------------
    def _load_state(self) -> None:
        """Recover the chain head, or record that the chain is broken.

        Opening a tampered journal must not raise - ``damavik verify`` has to be
        able to report it - but appending to one must refuse, because extending
        a broken chain would launder the tampering.
        """
        if not os.path.exists(self.path):
            parent = os.path.dirname(self.path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            return
        last: JournalEntry | None = None
        try:
            for entry in self.read():
                last = entry
        except JournalCorrupt as exc:
            self.corrupt = str(exc)
            return
        if last is not None:
            self._head = last.h
            self._seq = last.seq + 1

    def _handle(self) -> Any:
        if self._fh is None:
            # One append handle for the life of the process, closed by close();
            # a per-record context manager would reopen the file per event.
            self._fh = open(self.path, "a", encoding="utf-8")  # noqa: SIM115
        return self._fh

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                if self._unflushed:
                    self._fh.flush()
                    os.fsync(self._fh.fileno())
                    self._unflushed = 0
                self._fh.close()
                self._fh = None

    def __enter__(self) -> Journal:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- write -------------------------------------------------------------
    def append(self, record: dict[str, Any]) -> JournalEntry:
        """Append one record to the chain."""
        if self.corrupt is not None:
            raise JournalCorrupt(-1, f"refusing to append to a broken chain: {self.corrupt}")
        with self._lock:
            prev = self._head
            seq = self._seq
            record_json = canonical(record)
            digest = chain_hash(prev, record, record_json)
            # Hand-built rather than canonical(frame): the record is already
            # serialised, and the key order below is exactly what sort_keys
            # would emit (dmk, h, prev, rec, seq), so the bytes are identical
            # while saving a second json.dumps per record.
            line = (
                f'{{"dmk":"{FRAME}","h":"{digest}","prev":"{prev}",'
                f'"rec":{record_json},"seq":{seq}}}'
            )
            handle = self._handle()
            handle.write(line + "\n")
            handle.flush()
            self._unflushed += 1
            if self._unflushed >= self.fsync_every:
                os.fsync(handle.fileno())
                self._unflushed = 0
            self._head = digest
            self._seq = seq + 1
            return JournalEntry(seq=seq, prev=prev, h=digest, rec=record)

    def sync(self) -> None:
        """Force pending records to stable storage."""
        with self._lock:
            if self._fh is not None and self._unflushed:
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self._unflushed = 0

    # -- read --------------------------------------------------------------
    def read(self) -> Iterator[JournalEntry]:
        if not os.path.exists(self.path):
            return
        with open(self.path, encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    frame = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise JournalCorrupt(lineno, f"invalid JSON: {exc}") from exc
                if frame.get("dmk") != FRAME:
                    raise JournalCorrupt(lineno, f"unknown frame {frame.get('dmk')!r}")
                yield JournalEntry(
                    seq=int(frame.get("seq", -1)),
                    prev=str(frame.get("prev", "")),
                    h=str(frame.get("h", "")),
                    rec=frame.get("rec") or {},
                )


class JournalCorrupt(Exception):
    def __init__(self, lineno: int, reason: str) -> None:
        super().__init__(f"line {lineno}: {reason}")
        self.lineno = lineno
        self.reason = reason


@dataclass
class VerifyReport:
    ok: bool
    entries: int
    first_bad_line: int | None
    reason: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "entries": self.entries,
            "first_bad_line": self.first_bad_line,
            "reason": self.reason,
        }


def verify(journal: Journal) -> VerifyReport:
    """Walk the chain and report the first inconsistency, if any."""
    prev = GENESIS
    count = 0
    try:
        for entry in journal.read():
            count += 1
            if entry.seq != count - 1:
                return VerifyReport(False, count, entry.seq + 1, f"expected seq {count - 1}")
            if entry.prev != prev:
                return VerifyReport(
                    False, count, entry.seq + 1, "prev hash does not match previous record"
                )
            expected = chain_hash(prev, entry.rec)
            if expected != entry.h:
                return VerifyReport(False, count, entry.seq + 1, "record hash mismatch (tampered?)")
            prev = entry.h
    except JournalCorrupt as exc:
        return VerifyReport(False, count, exc.lineno, exc.reason)
    return VerifyReport(True, count, None, None)
