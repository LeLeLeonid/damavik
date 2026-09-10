# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Local OSV mirror: load, index and match vulnerability records offline.

OSV.dev publishes per-ecosystem dumps
(``https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip``)
with no API key.  ``damavik osv-sync`` downloads only the ecosystems that are
actually present on the host and stores them as one JSON file per advisory in
``~/.local/share/damavik/osv/``; everything after that is a local file read.

Matching follows the OSV spec's range semantics: ``introduced`` is inclusive,
``fixed`` is exclusive, ``last_affected`` is inclusive, and an explicit
``versions`` list is an exact match.  ``introduced: "0"`` means "all versions".
"""

from __future__ import annotations

import json
import os
import zipfile
from dataclasses import dataclass, field
from typing import Any, Iterable

from .versions import compare

#: dpkg/rpm manager name -> OSV ecosystem prefix.
MANAGER_TO_ECOSYSTEM = {
    "deb": "Debian",
    "rpm": "Red Hat",
    "apk": "Alpine",
    "pip": "PyPI",
    "cargo": "crates.io",
    "npm": "npm",
    "go": "Go",
}


@dataclass
class Range:
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None

    def matches(self, version: str, ecosystem: str) -> bool:
        if self.introduced not in (None, "", "0"):
            if compare(version, self.introduced, ecosystem) < 0:
                return False
        if self.fixed:
            if compare(version, self.fixed, ecosystem) >= 0:
                return False
            return True
        if self.last_affected:
            return compare(version, self.last_affected, ecosystem) <= 0
        # introduced-only ranges affect everything from that version onwards.
        return self.introduced is not None


@dataclass
class Advisory:
    id: str
    ecosystem: str
    package: str
    ranges: list[Range] = field(default_factory=list)
    versions: list[str] = field(default_factory=list)
    severity: str = "unknown"
    summary: str = ""
    modified: str = ""
    aliases: list[str] = field(default_factory=list)

    def affects(self, version: str) -> bool:
        if version in self.versions:
            return True
        return any(rng.matches(version, self.ecosystem) for rng in self.ranges)

    def as_rows(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        base = {
            "id": self.id,
            "ecosystem": self.ecosystem,
            "package": self.package,
            "severity": self.severity,
            "summary": self.summary,
            "modified": self.modified,
        }
        if self.ranges:
            for rng in self.ranges:
                rows.append(
                    {
                        **base,
                        "introduced": rng.introduced,
                        "fixed": rng.fixed,
                        "last_affected": rng.last_affected,
                    }
                )
        elif self.versions:
            for version in self.versions:
                rows.append(
                    {
                        **base,
                        "introduced": version,
                        "fixed": None,
                        "last_affected": version,
                    }
                )
        else:
            rows.append({**base, "introduced": None, "fixed": None, "last_affected": None})
        return rows


def _severity_of(record: dict[str, Any]) -> str:
    ecosystem_specific = {}
    for affected in record.get("affected") or []:
        ecosystem_specific = affected.get("ecosystem_specific") or ecosystem_specific
    urgency = str(ecosystem_specific.get("urgency") or "").lower()
    if urgency in ("low", "medium", "high", "critical", "unimportant", "not yet assigned"):
        return urgency if urgency in ("low", "medium", "high", "critical") else "unknown"
    for entry in record.get("severity") or []:
        score = str(entry.get("score") or "")
        if "CVSS" in str(entry.get("type", "")) and score:
            return "high"
    database_specific = record.get("database_specific") or {}
    level = str(database_specific.get("severity") or "").lower()
    if level == "moderate":
        return "medium"
    if level in ("low", "medium", "high", "critical"):
        return level
    return "unknown"


def parse_record(record: dict[str, Any]) -> list[Advisory]:
    """Flatten one OSV record into one Advisory per (ecosystem, package)."""
    advisories: list[Advisory] = []
    rid = str(record.get("id") or "")
    if not rid:
        return advisories
    severity = _severity_of(record)
    aliases = [str(a) for a in (record.get("aliases") or [])]
    for affected in record.get("affected") or []:
        package = affected.get("package") or {}
        ecosystem = str(package.get("ecosystem") or "")
        name = str(package.get("name") or "")
        if not ecosystem or not name:
            continue
        ranges: list[Range] = []
        for rng in affected.get("ranges") or []:
            if str(rng.get("type", "")).upper() not in ("SEMVER", "ECOSYSTEM"):
                continue  # GIT ranges need commit data we do not mirror
            events = rng.get("events") or []
            current = Range()
            for event in events:
                if not isinstance(event, dict):
                    continue
                if "introduced" in event:
                    current = Range(introduced=str(event["introduced"]))
                elif "fixed" in event:
                    current.fixed = str(event["fixed"])
                    ranges.append(current)
                    current = Range()
                elif "last_affected" in event:
                    current.last_affected = str(event["last_affected"])
                    ranges.append(current)
                    current = Range()
            if current.introduced is not None:
                ranges.append(current)
        advisories.append(
            Advisory(
                id=rid,
                ecosystem=ecosystem,
                package=name,
                ranges=ranges,
                versions=[str(v) for v in (affected.get("versions") or [])],
                severity=severity,
                summary=str(record.get("summary") or record.get("details") or "")[:400],
                modified=str(record.get("modified") or ""),
                aliases=aliases,
            )
        )
    return advisories


class OsvMirror:
    """In-memory index over the on-disk mirror, keyed by ecosystem:package."""

    def __init__(self, directory: str | None = None) -> None:
        self.directory = os.path.expanduser(directory) if directory else None
        self.index: dict[str, list[Advisory]] = {}

    # -- loading -----------------------------------------------------------
    def add_record(self, record: dict[str, Any]) -> int:
        added = 0
        for advisory in parse_record(record):
            self.index.setdefault(f"{advisory.ecosystem}:{advisory.package}", []).append(advisory)
            added += 1
        return added

    def load_dir(self, directory: str | None = None) -> int:
        target = os.path.expanduser(directory or self.directory or "")
        if not target or not os.path.isdir(target):
            return 0
        count = 0
        for name in sorted(os.listdir(target)):
            path = os.path.join(target, name)
            if name.endswith(".json") and os.path.isfile(path):
                try:
                    with open(path, "r", encoding="utf-8") as handle:
                        record = json.load(handle)
                except (OSError, json.JSONDecodeError):
                    continue
                if isinstance(record, dict):
                    count += self.add_record(record)
            elif name.endswith(".zip") and zipfile.is_zipfile(path):
                count += self._load_zip(path)
        self.directory = target
        return count

    def _load_zip(self, path: str) -> int:
        count = 0
        with zipfile.ZipFile(path) as archive:
            for member in archive.namelist():
                if not member.endswith(".json"):
                    continue
                try:
                    record = json.loads(archive.read(member).decode("utf-8", "replace"))
                except (json.JSONDecodeError, KeyError, RuntimeError):
                    continue
                if isinstance(record, dict):
                    count += self.add_record(record)
        return count

    def load_into_store(self, store: Any) -> int:
        """Persist the loaded mirror into the ``cves`` table for SQL access."""
        total = 0
        for advisories in self.index.values():
            for advisory in advisories:
                for row in advisory.as_rows():
                    store.upsert_cve(row)
                    total += 1
        return total

    # -- matching ----------------------------------------------------------
    def match(self, ecosystem: str, package: str, version: str) -> list[Advisory]:
        key = f"{ecosystem}:{package}"
        hits = [adv for adv in self.index.get(key, []) if adv.affects(version)]
        if hits:
            return hits
        # Fall back to a bare-ecosystem match ("Debian" for "Debian:12").
        base = ecosystem.split(":", 1)[0]
        merged: list[Advisory] = []
        for key, advisories in self.index.items():
            if key.startswith(f"{base}:") and key.endswith(f":{package}"):
                merged.extend(adv for adv in advisories if adv.affects(version))
        return merged

    def match_manager(self, manager: str, package: str, version: str,
                      *, distro: str = "") -> list[Advisory]:
        base = MANAGER_TO_ECOSYSTEM.get(manager, manager.capitalize())
        ecosystem = f"{base}:{distro}" if distro else base
        return self.match(ecosystem, package, version)

    def advisories(self) -> Iterable[Advisory]:
        for advisories in self.index.values():
            yield from advisories

    def stats(self) -> dict[str, Any]:
        return {
            "advisories": sum(len(v) for v in self.index.values()),
            "packages_indexed": len(self.index),
            "directory": self.directory,
        }
