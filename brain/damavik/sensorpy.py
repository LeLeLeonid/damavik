# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Reference sensor (pure stdlib, no root required).

The Rust eBPF sensor is the production path, but it needs root, a BTF-capable
kernel and a Rust toolchain - none of which a contributor cloning the repo, or
CI, can be assumed to have.  This module emits the *identical* JSONL event
stream by polling ``/proc``, so the whole pipeline (sensor -> brain -> alerts ->
dashboard) is runnable and testable everywhere, and the demo capture is
reproducible.

Coverage, stated honestly:

===================  ============================================
``proc.exec``        yes - new PIDs, with exe/cmdline/user/sha256
``net.flow``         yes - from ``/proc/net/{tcp,udp}{,6}``, with
                     per-PID attribution when the fd table is
                     readable (same-user processes)
``dns.query``        no - needs a kernel hook; use the eBPF sensor
                     or ``--dns-tail`` on a resolver log
``pkg.event``        via ``damavik pkg-list --scan`` (dpkg status parsing)
===================  ============================================
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

PROC = "/proc"
MAX_HASH_BYTES = 64 * 1024 * 1024

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def _hex_ip(value: str, family: socket.AddressFamily) -> str:
    """Convert the little-endian hex address from /proc/net/* to text."""
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return ""
    if family == socket.AF_INET:
        return socket.inet_ntop(socket.AF_INET, raw[::-1])
    # IPv6: 16 bytes stored as four little-endian 32-bit words
    words = [raw[i : i + 4][::-1] for i in range(0, 16, 4)]
    return socket.inet_ntop(socket.AF_INET6, b"".join(words))


def _hex_port(value: str) -> int:
    try:
        return int(value, 16)
    except ValueError:
        return 0


@dataclass
class ProcessInfo:
    pid: int
    ppid: int
    comm: str = ""
    exe: str = ""
    cmd: str = ""
    user: str = ""
    sha256: str | None = None


@dataclass
class FlowInfo:
    proto: str
    src: str
    sport: int
    dst: str
    dport: int
    state: str
    inode: str = ""
    pid: int | None = None


@dataclass
class SensorStats:
    procs_seen: int = 0
    flows_seen: int = 0
    hashed: int = 0
    skipped_hash: int = 0
    errors: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "procs_seen": self.procs_seen,
            "flows_seen": self.flows_seen,
            "hashed": self.hashed,
            "skipped_hash": self.skipped_hash,
            "errors": dict(self.errors),
        }


def _read(path: str) -> str:
    try:
        with open(path, "rb") as handle:
            return handle.read().decode("utf-8", "replace")
    except OSError:
        return ""


def hash_file(path: str, *, max_bytes: int = MAX_HASH_BYTES) -> str | None:
    """SHA-256 of a file, or None when it is unreadable or too large.

    Large binaries are skipped rather than partially hashed: a truncated hash
    is worse than no hash, because it looks authoritative.
    """
    try:
        if os.path.getsize(path) > max_bytes:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def uid_to_user(uid: str) -> str:
    try:
        import pwd

        return pwd.getpwuid(int(uid)).pw_name
    except (ImportError, KeyError, ValueError):
        return uid


def read_process(pid: int, *, do_hash: bool = True) -> ProcessInfo | None:
    stat = _read(f"{PROC}/{pid}/stat")
    if not stat:
        return None
    # comm may contain spaces and parentheses, so split around the last ')'.
    try:
        open_paren = stat.index("(")
        close_paren = stat.rindex(")")
    except ValueError:
        return None
    comm = stat[open_paren + 1 : close_paren]
    fields = stat[close_paren + 2 :].split()
    ppid = int(fields[1]) if len(fields) > 1 else 0
    info = ProcessInfo(pid=pid, ppid=ppid, comm=comm)
    try:
        info.exe = os.readlink(f"{PROC}/{pid}/exe")
    except OSError:
        info.exe = ""
    cmdline = _read(f"{PROC}/{pid}/cmdline")
    info.cmd = cmdline.replace("\x00", " ").strip()[:1024]
    status = _read(f"{PROC}/{pid}/status")
    for line in status.splitlines():
        if line.startswith("Uid:"):
            info.user = uid_to_user(line.split(":", 1)[1].split()[0])
            break
    if do_hash and info.exe and os.path.isfile(info.exe):
        info.sha256 = hash_file(info.exe)
    return info


def list_pids() -> list[int]:
    try:
        return sorted(int(name) for name in os.listdir(PROC) if name.isdigit())
    except OSError:
        return []


def inode_to_pid() -> dict[str, int]:
    """Map socket inodes to owning PIDs.  Only readable for our own processes."""
    mapping: dict[str, int] = {}
    for pid in list_pids():
        fd_dir = f"{PROC}/{pid}/fd"
        try:
            entries = os.listdir(fd_dir)
        except OSError:
            continue
        for entry in entries:
            try:
                target = os.readlink(os.path.join(fd_dir, entry))
            except OSError:
                continue
            if target.startswith("socket:["):
                mapping[target[8:-1]] = pid
    return mapping


def read_flows(*, include_listen: bool = False) -> list[FlowInfo]:
    flows: list[FlowInfo] = []
    for name, proto, family in (
        ("tcp", "tcp", socket.AF_INET),
        ("tcp6", "tcp", socket.AF_INET6),
        ("udp", "udp", socket.AF_INET),
        ("udp6", "udp", socket.AF_INET6),
    ):
        text = _read(f"{PROC}/net/{name}")
        for line in text.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 10:
                continue
            local, remote, state, inode = parts[1], parts[2], parts[3], parts[9]
            if not include_listen and state == "0A":
                continue
            if ":" not in local or ":" not in remote:
                continue
            local_addr, local_port = local.rsplit(":", 1)
            remote_addr, remote_port = remote.rsplit(":", 1)
            flows.append(
                FlowInfo(
                    proto=proto,
                    src=_hex_ip(local_addr, family),
                    sport=_hex_port(local_port),
                    dst=_hex_ip(remote_addr, family),
                    dport=_hex_port(remote_port),
                    state=TCP_STATES.get(state.upper(), state),
                    inode=inode,
                )
            )
    return flows


@dataclass
class ProcSensor:
    """Polling sensor that yields canonical JSONL event strings."""

    host: str = ""
    exec_hash: bool = True
    flows: bool = True
    stats: SensorStats = field(default_factory=SensorStats)
    _seen_pids: set[int] = field(default_factory=set)
    _seen_flows: set[tuple] = field(default_factory=set)
    _seq: int = 0

    def __post_init__(self) -> None:
        self.host = self.host or socket.gethostname() or "unknown"
        self.boot_id = _read(f"{PROC}/sys/kernel/random/boot_id").strip()

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _emit(self, etype: str, **fields: Any) -> str:
        event: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
            "host": self.host,
            "type": etype,
            "seq": self._next_seq(),
            "boot_id": self.boot_id,
            "sensor_id": "sensor-py",
            "tags": [],
            "score": 0.0,
        }
        event.update(fields)
        return json.dumps(event, sort_keys=True)

    # -- one pass ----------------------------------------------------------
    def poll_exec(self) -> Iterator[str]:
        for pid in list_pids():
            if pid in self._seen_pids:
                continue
            self._seen_pids.add(pid)
            info = read_process(pid, do_hash=self.exec_hash)
            if info is None:
                continue
            self.stats.procs_seen += 1
            if info.sha256:
                self.stats.hashed += 1
            elif self.exec_hash:
                self.stats.skipped_hash += 1
            proc = {
                "pid": info.pid,
                "ppid": info.ppid,
                "exe": info.exe or info.comm,
                "cmd": info.cmd,
                "user": info.user,
            }
            if info.sha256:
                proc["sha256"] = info.sha256
            yield self._emit("proc.exec", proc=proc)

    def poll_flows(self) -> Iterator[str]:
        if not self.flows:
            return
        owners = inode_to_pid()
        for flow in read_flows():
            key = (flow.proto, flow.dst, flow.dport, flow.pid or owners.get(flow.inode, 0))
            if key in self._seen_flows:
                continue
            self._seen_flows.add(key)
            self.stats.flows_seen += 1
            pid = owners.get(flow.inode)
            event: dict[str, Any] = {
                "net": {
                    "proto": flow.proto,
                    "src": flow.src,
                    "sport": flow.sport,
                    "dst": flow.dst,
                    "dport": flow.dport,
                    "state": flow.state,
                    "bytes_out": 0,
                    "bytes_in": 0,
                }
            }
            if pid is not None:
                info = read_process(pid, do_hash=False)
                event["proc"] = {
                    "pid": pid,
                    "ppid": info.ppid if info else 0,
                    "exe": (info.exe if info else "") or "",
                }
            yield self._emit("net.flow", **event)

    def poll(self) -> Iterator[str]:
        yield from self.poll_exec()
        yield from self.poll_flows()

    # -- loop --------------------------------------------------------------
    def run(self, interval: float = 2.0, out: Any = None, *, once: bool = False) -> None:
        out = out or sys.stdout
        try:
            while True:
                for line in self.poll():
                    out.write(line + "\n")
                out.flush()
                if once:
                    break
                time.sleep(interval)
        except (KeyboardInterrupt, BrokenPipeError):
            pass


_DNSMASQ_RE = re.compile(r"query\[(\w+)\]\s+(\S+)\s+from")
_BIND_RE = re.compile(r"query:\s+(\S+)\s+IN\s+(\w+)")


def parse_dns_line(line: str) -> tuple[str, str] | None:
    """Extract ``(qname, rtype)`` from a resolver log line, or None.

    Resolver logs are not standardised, so this understands the two formats we
    actually see: dnsmasq (``query[A] name from 1.2.3.4``) and BIND
    (``client @0x... 1.2.3.4#5353: query: name IN A``).  Everything else is
    ignored.  This exists so the DNS scorer can be exercised on a box without
    eBPF; it is not a substitute for the kernel probe.
    """
    match = _DNSMASQ_RE.search(line)
    if match:
        return match.group(2), match.group(1).upper()
    match = _BIND_RE.search(line)
    if match:
        return match.group(1), match.group(2).upper()
    return None


def tail_dns_log(path: str, sensor: ProcSensor, out: Any) -> None:
    """Follow a resolver log and emit ``dns.query`` events forever."""
    with open(path, encoding="utf-8", errors="replace") as handle:
        handle.seek(0, os.SEEK_END)
        while True:
            line = handle.readline()
            if not line:
                time.sleep(0.5)
                continue
            parsed = parse_dns_line(line)
            if parsed is None:
                continue
            qname, rtype = parsed
            event = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
                "host": sensor.host,
                "type": "dns.query",
                "dns": {"q": qname, "rtype": rtype, "answers": []},
            }
            out.write(json.dumps(event, sort_keys=True) + "\n")
            out.flush()
