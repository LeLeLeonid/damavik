# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Hash-chained journal: tamper evidence must actually detect tampering."""

from __future__ import annotations

import json

from damavik.journal import GENESIS, Journal, JournalCorrupt, chain_hash, verify


def test_chain_verifies_when_untouched(tmp_path):
    path = str(tmp_path / "journal.jsonl")
    with Journal(path) as journal:
        for index in range(5):
            journal.append({"kind": "event", "n": index})
    report = verify(Journal(path))
    assert report.ok is True
    assert report.entries == 5
    assert report.first_bad_line is None


def test_empty_journal_verifies(tmp_path):
    report = verify(Journal(str(tmp_path / "absent.jsonl")))
    assert report.ok and report.entries == 0


def test_editing_a_record_is_detected(tmp_path):
    path = tmp_path / "journal.jsonl"
    with Journal(str(path)) as journal:
        journal.append({"kind": "alert", "level": "high"})
        journal.append({"kind": "alert", "level": "high"})
    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["rec"]["level"] = "info"          # attacker downgrades the alert
    lines[0] = json.dumps(tampered, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = verify(Journal(str(path)))
    assert report.ok is False
    assert report.first_bad_line == 1
    assert "hash mismatch" in (report.reason or "")


def test_deleting_a_record_is_detected(tmp_path):
    path = tmp_path / "journal.jsonl"
    with Journal(str(path)) as journal:
        for index in range(4):
            journal.append({"n": index})
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]                                # attacker hides one event
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = verify(Journal(str(path)))
    assert report.ok is False


def test_truncating_the_tail_verifies(tmp_path):
    """Dropping the newest entries is indistinguishable from a clean shorter log."""
    path = tmp_path / "journal.jsonl"
    with Journal(str(path)) as journal:
        for index in range(4):
            journal.append({"n": index})
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
    report = verify(Journal(str(path)))
    assert report.ok is True and report.entries == 2


def test_appending_reopens_and_continues_the_chain(tmp_path):
    path = str(tmp_path / "journal.jsonl")
    with Journal(path) as journal:
        journal.append({"n": 0})
    with Journal(path) as journal:
        entry = journal.append({"n": 1})
        assert entry.seq == 1
        assert entry.prev != GENESIS
    report = verify(Journal(path))
    assert report.ok and report.entries == 2


def test_garbage_line_is_reported(tmp_path):
    """A valid record followed by non-JSON must point at the broken line."""
    path = tmp_path / "journal.jsonl"
    with Journal(str(path)) as journal:
        journal.append({"n": 0})
    with path.open("a", encoding="utf-8") as handle:
        handle.write("not json at all\n")
    report = verify(Journal(str(path)))
    assert report.ok is False
    assert report.first_bad_line == 2
    assert "invalid JSON" in (report.reason or "")


def test_appending_to_a_corrupt_journal_is_refused(tmp_path):
    """Extending a broken chain would launder the tampering, so it must fail."""
    path = tmp_path / "journal.jsonl"
    path.write_text('{"dmk":"j9","seq":0}\n', encoding="utf-8")
    journal = Journal(str(path))
    assert journal.corrupt is not None
    try:
        journal.append({"n": 1})
        raise AssertionError("append should have been refused")
    except JournalCorrupt:
        pass
    journal.close()


def test_unknown_frame_is_rejected(tmp_path):
    path = tmp_path / "journal.jsonl"
    path.write_text('{"dmk":"j9","seq":0}\n', encoding="utf-8")
    report = verify(Journal(str(path)))
    assert report.ok is False
    assert "frame" in (report.reason or "")


def test_chain_hash_is_order_sensitive():
    record = {"a": 1}
    assert chain_hash(GENESIS, record) != chain_hash("f" * 64, record)
    assert chain_hash(GENESIS, record) == chain_hash(GENESIS, {"a": 1})


def test_canonical_serialisation_is_stable():
    from damavik.journal import canonical

    assert canonical({"b": 1, "a": [1, 2]}) == '{"a":[1,2],"b":1}'
