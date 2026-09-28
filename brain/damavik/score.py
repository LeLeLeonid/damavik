# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Scoring: first-seen + rarity + intrinsic risk -> 0..100 with an explanation.

Division of labour, stated plainly so nobody re-implements it:

* **rules** express *behaviour patterns* (office app spawns a shell, egress two
  seconds after exec, DNS label entropy).  They fire or they do not.
* **scoring** expresses *how unusual this is on this host* - first-seen hashes,
  first-seen destinations, rare (binary, destination) tuples, execution from a
  world-writable directory.

Every point added appends a human-readable reason.  The alert's ``explain``
field is the concatenation of those reasons, which is how the "no black-box
verdicts, ever" rule is enforced: a score with no reasons is a bug, and
``damavik selftest`` checks for it.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .schema import entropy_ratio, longest_label

#: Directories that should never host a long-lived binary.
WORLD_WRITABLE_EXEC_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/")

#: Ports that are common enough that using them carries no signal.
DEFAULT_COMMON_PORTS = frozenset({22, 53, 80, 443, 465, 587, 993, 995, 5353})

#: Ports that are rarely legitimate egress from an endpoint.
SUSPICIOUS_PORTS = frozenset({1337, 31337, 4444, 5555, 6666, 6667, 6697, 8888, 12345, 31338})

LEVEL_BONUS = {"info": 5.0, "low": 15.0, "medium": 35.0, "high": 60.0, "critical": 85.0}

#: YARA / intel tag weights.  ``risk_tool`` is deliberately low: dual-use admin
#: tooling is not malware and must not dominate the score.
TAG_WEIGHTS = {
    "malware": 60.0,
    "trojan": 55.0,
    "stealer": 55.0,
    "rat": 55.0,
    "backdoor": 50.0,
    "miner": 45.0,
    "ransomware": 60.0,
    "packer": 22.0,
    "obfuscated": 18.0,
    "exploit": 40.0,
    "risk_tool": 15.0,
    "admin_tool": 12.0,
    "intel_malicious": 55.0,
    "intel_suspicious": 22.0,
}

EXFIL_BYTES = 5 * 1024 * 1024


@dataclass
class ScoreResult:
    score: float
    tags: list[str]
    reasons: list[str]
    rule: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "tags": list(self.tags),
            "reasons": list(self.reasons),
            "rule": self.rule,
        }

    def explain(self) -> str:
        return "; ".join(self.reasons) if self.reasons else "no individual signals"


@dataclass
class Scorer:
    """Stateful scorer: rarity needs the first-seen table."""

    store: Any = None
    allowlist_exes: frozenset[str] = frozenset()
    allowlist_hashes: frozenset[str] = frozenset()
    common_ports: frozenset[int] = DEFAULT_COMMON_PORTS
    entropy_ratio_threshold: float = 0.9
    entropy_min_len: int = 12

    @classmethod
    def from_config(cls, config: Any, store: Any = None) -> Scorer:
        scoring = getattr(config, "scoring", {}) or {}
        return cls(
            store=store,
            allowlist_exes=frozenset(scoring.get("allowlist_exes") or []),
            allowlist_hashes=frozenset(scoring.get("allowlist_hashes") or []),
            common_ports=frozenset(scoring.get("common_ports") or DEFAULT_COMMON_PORTS),
        )

    # -- helpers -----------------------------------------------------------
    def _touch(self, kind: str, key: str, ts: str) -> tuple[bool, int]:
        if self.store is None or not key:
            return False, 0
        return self.store.touch_first_seen(kind, key, ts)

    def _add(self, result: ScoreResult, points: float, tag: str, reason: str) -> None:
        if points == 0:
            return
        result.score += points
        if tag and tag not in result.tags:
            result.tags.append(tag)
        result.reasons.append(f"{reason} (+{points:g})")

    # -- entry point -------------------------------------------------------
    def score(self, event: dict[str, Any], fired_rules: Iterable[Any] = ()) -> ScoreResult:
        result = ScoreResult(score=0.0, tags=[], reasons=[], rule=None)
        # Tags already attached upstream (sensor YARA verdicts, enrichment such
        # as supply_chain_shift) are evidence, not noise: keep them.
        for tag in list(event.get("tags") or []) + list(event.get("yara") or []):
            if str(tag) not in result.tags:
                result.tags.append(str(tag))
        etype = event.get("type")
        ts = event.get("ts", "")
        proc = event.get("proc") or {}
        exe = proc.get("exe") or ""

        if etype == "proc.exec":
            self._score_exec(event, proc, exe, ts, result)
        elif etype == "net.flow":
            self._score_flow(event, proc, exe, ts, result)
        elif etype == "dns.query":
            self._score_dns(event, ts, result)
        elif etype == "file.verdict":
            self._score_verdict(event, proc, exe, ts, result)
        elif etype == "pkg.event":
            self._score_package(event, ts, result)

        self._apply_tag_weights(event, result)
        self._apply_rules(list(fired_rules), result)
        self._apply_allowlist(proc, exe, result)
        result.score = round(max(0.0, min(100.0, result.score)), 1)
        return result

    # -- per-type signals --------------------------------------------------
    def _score_exec(
        self, event: dict[str, Any], proc: dict[str, Any], exe: str, ts: str, result: ScoreResult
    ) -> None:
        lowered = exe.lower()
        for directory in WORLD_WRITABLE_EXEC_DIRS:
            if lowered.startswith(directory):
                self._add(
                    result,
                    18.0,
                    "exec_from_tmp",
                    f"executed from world-writable location {directory}",
                )
                break
        sha = proc.get("sha256")
        if sha:
            first, count = self._touch("hash", sha, ts)
            if first:
                self._add(result, 12.0, "first_seen_hash", f"first sighting of sha256 {sha[:12]}…")
            elif count <= 2:
                self._add(result, 5.0, "rare_hash", f"hash seen only {count} times on this host")
        else:
            self._add(result, 4.0, "no_hash", "executable was not hashed at exec time")
        if proc.get("signed") is False:
            self._add(result, 6.0, "unsigned", "binary is not code-signed")
        if exe and not lowered.startswith(
            ("/usr/", "/bin/", "/sbin/", "/lib", "/opt/", "c:\\windows\\")
        ):
            self._add(result, 6.0, "non_system_path", f"non-standard install path {exe}")
        if proc.get("cmd"):
            self._touch("cmd", str(proc["cmd"])[:200], ts)

    def _score_flow(
        self, event: dict[str, Any], proc: dict[str, Any], exe: str, ts: str, result: ScoreResult
    ) -> None:
        net = event.get("net") or {}
        dst = net.get("dst") or ""
        dport = net.get("dport")
        first_dst, _ = self._touch("dst", dst, ts) if dst else (False, 0)
        if first_dst:
            self._add(result, 10.0, "first_seen_dst", f"first connection to {dst}")
        tuple_key = f"{proc.get('sha256') or exe}|{dst}|{dport}"
        if dst:
            first_tuple, count = self._touch("edge", tuple_key, ts)
            if first_tuple:
                self._add(
                    result,
                    8.0,
                    "rare_edge",
                    f"new (binary, destination, port) edge to {dst}:{dport}",
                )
            elif count <= 2:
                self._add(result, 3.0, "rare_edge", "edge seen only a couple of times")
        if isinstance(dport, int):
            if dport in SUSPICIOUS_PORTS:
                self._add(result, 14.0, "suspicious_port", f"egress to unusual port {dport}")
            elif dport not in self.common_ports and dport > 1024:
                self._add(result, 6.0, "rare_port", f"egress to uncommon port {dport}")
        bytes_out = int(net.get("bytes_out") or net.get("bytes") or 0)
        if bytes_out >= EXFIL_BYTES:
            self._add(
                result,
                12.0,
                "bulk_egress",
                f"{bytes_out / 1048576:.1f} MiB uploaded in one flow",
            )

    def _score_dns(self, event: dict[str, Any], ts: str, result: ScoreResult) -> None:
        dns = event.get("dns") or {}
        qname = str(dns.get("q") or "")
        if not qname:
            return
        label = longest_label(qname)
        ratio = entropy_ratio(label)
        if len(label) >= self.entropy_min_len and ratio >= self.entropy_ratio_threshold:
            self._add(
                result,
                25.0,
                "dns_high_entropy",
                f"label '{label[:24]}' carries {ratio:.2f} of its maximum entropy",
            )
        if qname.count(".") >= 4:
            self._add(result, 8.0, "dns_deep", f"{qname.count('.') + 1} label levels in '{qname}'")
        if len(qname) >= 60:
            self._add(result, 10.0, "dns_long", f"{len(qname)}-character query name")
        first, _ = self._touch("domain", qname, ts)
        if first:
            self._add(result, 6.0, "first_seen_domain", f"first lookup of {qname}")
        if (dns.get("rtype") or "").upper() == "TXT":
            self._add(result, 10.0, "dns_txt", "TXT lookup (a classic tunnel channel)")

    def _score_verdict(
        self, event: dict[str, Any], proc: dict[str, Any], exe: str, ts: str, result: ScoreResult
    ) -> None:
        for tag in event.get("yara") or []:
            if tag not in result.tags:
                result.tags.append(str(tag))
        verdict = (event.get("meta") or {}).get("intel_verdict")
        if verdict in ("malicious", "suspicious"):
            tag = f"intel_{verdict}"
            if tag not in result.tags:
                result.tags.append(tag)
            self._add(result, 0.0, "", f"intel provider returned '{verdict}' for this file")

    def _score_package(self, event: dict[str, Any], ts: str, result: ScoreResult) -> None:
        pkg = event.get("pkg") or {}
        action = str(pkg.get("action") or event.get("meta", {}).get("action") or "install")
        if action in ("install", "new"):
            self._add(result, 8.0, "pkg_new", f"package {pkg.get('name')} newly installed")
            cves = pkg.get("cves") or []
            if cves:
                severity = str(pkg.get("severity") or "medium").lower()
                points = {"low": 15.0, "medium": 30.0, "high": 45.0, "critical": 60.0}.get(
                    severity, 30.0
                )
                self._add(
                    result,
                    points,
                    "pkg_cve",
                    f"installed with known vulnerabilities: {', '.join(map(str, cves[:3]))}",
                )
        elif action == "downgrade":
            self._add(result, 20.0, "pkg_downgrade", f"package {pkg.get('name')} was downgraded")

    # -- cross-cutting -----------------------------------------------------
    def _apply_tag_weights(self, event: dict[str, Any], result: ScoreResult) -> None:
        applied: set[str] = set()
        for tag in list(result.tags):
            weight = TAG_WEIGHTS.get(str(tag))
            if weight and tag not in applied:
                applied.add(tag)
                if tag not in result.tags:
                    result.tags.append(str(tag))
                self._add(result, weight, "", f"tag '{tag}'")

    def _apply_rules(self, fired: list[Any], result: ScoreResult) -> None:
        if not fired:
            return
        fired.sort(key=lambda rule: LEVEL_BONUS.get(rule.level, 0.0), reverse=True)
        top = fired[0]
        result.rule = top.rule_id
        bonus = LEVEL_BONUS.get(top.level, 15.0)
        self._add(
            result,
            bonus,
            f"rule:{top.rule_id}",
            f"rule {top.rule_id} ({top.level}): {top.title}",
        )
        extra = min(len(fired) - 1, 3) * 5.0
        if extra:
            others = ", ".join(rule.rule_id for rule in fired[1:4])
            self._add(result, extra, "rules_stacked", f"additional rules matched: {others}")

    def _apply_allowlist(self, proc: dict[str, Any], exe: str, result: ScoreResult) -> None:
        if not self.allowlist_exes and not self.allowlist_hashes:
            return
        hard = {"malware", "trojan", "stealer", "rat", "ransomware", "backdoor", "intel_malicious"}
        if hard & set(result.tags):
            result.reasons.append("allowlist ignored: hard malicious tag present")
            return
        if exe in self.allowlist_exes or (
            proc.get("sha256") in self.allowlist_hashes and proc.get("sha256")
        ):
            result.score = 0.0
            result.tags.append("allowlisted")
            result.reasons.append("allowlisted by configuration (score forced to 0)")
