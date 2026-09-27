# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Reference sensor: /proc parsing must be right, and its output must be canonical."""

from __future__ import annotations

import json
import os
import socket

import pytest
from damavik import sensorpy
from damavik.schema import validate_event
from damavik.sensorpy import ProcSensor, hash_file, parse_dns_line, read_process

TCP_SAMPLE = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000 100 0 0 10 0
   1: 0100007F:E3F6 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000 100 0 0 10 0
   2: 1800000A:E4F7 2DDA6EB9:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 33333 1 0000 100 0 0 10 0
"""

TCP6_SAMPLE = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 44444 1 0000 100 0 0 10 0
   1: 0000000000000000FFFF00001800000A:E4F8 0000000000000000FFFF00000100007F:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 55555 1 0000 100 0 0 10 0
"""


@pytest.fixture()
def fake_proc(monkeypatch):
    files = {
        "/proc/net/tcp": TCP_SAMPLE,
        "/proc/net/tcp6": TCP6_SAMPLE,
        "/proc/net/udp": "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        "/proc/net/udp6": "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
    }

    def _read(path):
        return files.get(path, "")

    monkeypatch.setattr(sensorpy, "_read", _read)
    monkeypatch.setattr(sensorpy, "inode_to_pid", lambda: {"33333": 4242})
    monkeypatch.setattr(
        sensorpy,
        "read_process",
        lambda pid, do_hash=True: (
            sensorpy.ProcessInfo(pid=pid, ppid=1, exe="/bin/browser") if pid == 4242 else None
        ),
    )
    return files


def test_hex_ipv4_is_little_endian():
    assert sensorpy._hex_ip("0100007F", socket.AF_INET) == "127.0.0.1"
    assert sensorpy._hex_ip("1800000A", socket.AF_INET) == "10.0.0.24"
    assert sensorpy._hex_ip("2DDA6EB9", socket.AF_INET) == "185.110.218.45"


def test_hex_ipv6_is_word_reversed():
    assert (
        sensorpy._hex_ip("0000000000000000FFFF00000100007F", socket.AF_INET6) == "::ffff:127.0.0.1"
    )


def test_hex_port():
    assert sensorpy._hex_port("1F90") == 8080
    assert sensorpy._hex_port("01BB") == 443
    assert sensorpy._hex_port("nope") == 0


def test_flows_are_parsed_and_listeners_skipped(fake_proc):
    flows = sensorpy.read_flows()
    destinations = {(flow.dst, flow.dport) for flow in flows}
    assert ("0.0.0.0", 0) not in destinations  # the LISTEN row is dropped
    assert ("185.110.218.45", 443) in destinations  # byte-reversed remote
    assert any(flow.state == "ESTABLISHED" for flow in flows)


def test_listeners_can_be_included(fake_proc):
    assert any(flow.state == "LISTEN" for flow in sensorpy.read_flows(include_listen=True))


def test_flows_are_attributed_to_a_pid(fake_proc):
    flows = sensorpy.read_flows()
    owners = sensorpy.inode_to_pid()
    attributed = [flow for flow in flows if flow.inode in owners]
    assert attributed and owners[attributed[0].inode] == 4242


def test_poll_flows_emits_canonical_events(fake_proc):
    sensor = ProcSensor(host="test")
    lines = list(sensor.poll_flows())
    assert lines
    for line in lines:
        event = json.loads(line)
        assert validate_event(event) == [], event
        assert event["type"] == "net.flow"
        assert event["host"] == "test"
        assert event["sensor_id"] == "sensor-py"
    attributed = [json.loads(line) for line in lines if "proc" in json.loads(line)]
    assert any(event["proc"]["pid"] == 4242 for event in attributed)


def test_flows_are_reported_once_per_destination(fake_proc):
    sensor = ProcSensor(host="test")
    first = len(list(sensor.poll_flows()))
    second = len(list(sensor.poll_flows()))
    assert first > 0
    assert second == 0


def test_flows_can_be_disabled(fake_proc):
    sensor = ProcSensor(host="test", flows=False)
    assert list(sensor.poll_flows()) == []


def test_poll_exec_emits_canonical_events():
    """Runs against the real /proc: at least this test process must appear."""
    sensor = ProcSensor(host="test", exec_hash=False)
    events = [json.loads(line) for line in sensor.poll_exec()]
    assert events
    pids = {event["proc"]["pid"] for event in events}
    assert os.getpid() in pids
    for event in events:
        assert validate_event(event) == [], event
    assert sensor.stats.procs_seen == len(events)


def test_poll_exec_is_idempotent():
    sensor = ProcSensor(host="test", exec_hash=False)
    first = len(list(sensor.poll_exec()))
    assert len(list(sensor.poll_exec())) == 0
    assert first > 0


def test_seq_monotonically_increases():
    sensor = ProcSensor(host="test")
    lines = [json.loads(line) for line in list(sensor.poll_exec())[:5]]
    seqs = [event["seq"] for event in lines]
    assert seqs == sorted(seqs)
    assert len(set(seqs)) == len(seqs)


def test_run_once_writes_and_exits(fake_proc, tmp_path):
    out = tmp_path / "events.jsonl"
    sensor = ProcSensor(host="test")
    with out.open("w", encoding="utf-8") as handle:
        sensor.run(out=handle, once=True)
    assert out.read_text(encoding="utf-8").strip()


def test_hash_file(tmp_path):
    target = tmp_path / "bin"
    target.write_bytes(b"#!/bin/sh\necho hi\n")
    digest = hash_file(str(target))
    assert digest and len(digest) == 64
    assert hash_file(str(tmp_path / "absent")) is None


def test_hash_file_refuses_oversize_files(tmp_path):
    target = tmp_path / "big"
    target.write_bytes(b"x" * 1024)
    assert hash_file(str(target), max_bytes=10) is None


def test_read_process_handles_a_dead_pid():
    assert read_process(2**22) is None


def test_uid_to_user_falls_back_to_the_number():
    assert sensorpy.uid_to_user("0") in ("root", "0")
    assert sensorpy.uid_to_user("not-a-number") == "not-a-number"


@pytest.mark.parametrize(
    "line,expected",
    [
        ("dnsmasq[1]: query[A] evil.example from 10.0.0.5", ("evil.example", "A")),
        (
            "client @0x7f 10.0.0.5#53: query: evil.example IN TXT +E",
            ("evil.example", "TXT"),
        ),
        ("unrelated log line", None),
    ],
)
def test_dns_log_parsing(line, expected):
    assert parse_dns_line(line) == expected


def test_stats_shape(fake_proc):
    sensor = ProcSensor(host="test")
    list(sensor.poll())
    data = sensor.stats.as_dict()
    assert set(data) == {"procs_seen", "flows_seen", "hashed", "skipped_hash", "errors"}
