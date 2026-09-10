# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""pkgwatch - software inventory, new-arrival detection, CVE matching.

Sources, in preference order:

1. ``osquery`` scheduled queries (``deb_packages`` / ``rpm_packages`` /
   ``programs``) streamed in as ``pkg.event`` rows - the documented path.
2. Direct parsing of ``/var/lib/dpkg/status`` so the module is testable and
   usable on a box without osquery (``damavik pkg-scan``).

State lives in the ``packages`` table: first-seen timestamp, last-seen
timestamp and a ``removed`` flag.  A package that reappears after being absent
counts as new again, which is what makes "installed yesterday, gone today"
visible.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .osv import MANAGER_TO_ECOSYSTEM, OsvMirror
from .schema import utcnow_iso

#: Package-name hints that a package can open or use the network.  This is a
#: coarse prior, not a capability analysis - it only ever adds a little score
#: and a tag, never an alert on its own.
NETWORK_HINTS = (
    "net", "http", "curl", "wget", "ssh", "tls", "ssl", "socket", "proxy",
    "dns", "ldap", "samba", "nfs", "rpc", "mail", "smtp", "imap", "pop3",
    "ftp", "telnet", "rsync", "vpn", "wireguard", "openssl", "gnutls",
)

DPKG_STATUS_DEFAULT = "/var/lib/dpkg/status"


@dataclass
class PackageChange:
    manager: str
    name: str
    version: str
    action: str  # install | update | downgrade | remove | seen
    first_seen: str = ""
    cves: list[str] = field(default_factory=list)
    severity: str = "unknown"
    net_capable: bool = False
    summary: str = ""

    def as_event(self, ts: str, host: str) -> dict[str, Any]:
        return {
            "ts": ts,
            "host": host,
            "type": "pkg.event",
            "tags": [],
            "score": 0.0,
            "pkg": {
                "manager": self.manager,
                "name": self.name,
                "version": self.version,
                "cves": list(self.cves),
                "severity": self.severity,
            },
            "meta": {
                "action": self.action,
                "first_seen": self.first_seen,
                "net_capable": self.net_capable,
                "summary": self.summary,
            },
        }


def looks_network_capable(name: str, description: str = "") -> bool:
    text = f"{name} {description}".lower()
    return any(hint in text for hint in NETWORK_HINTS)


_STATUS_HEADER = re.compile(r"^(Package|Version|Status|Architecture|Description):\s?(.*)$")


def parse_dpkg_status(text: str) -> list[dict[str, str]]:
    """Parse ``/var/lib/dpkg/status`` into installed package records."""
    packages: list[dict[str, str]] = []
    current: dict[str, str] = {}
    last_key = ""
    for line in text.splitlines():
        if not line.strip():
            if current.get("Package") and "install ok installed" in current.get("Status", ""):
                packages.append(current)
            current = {}
            last_key = ""
            continue
        if line.startswith((" ", "\t")):
            if last_key:
                current[last_key] += " " + line.strip()
            continue
        match = _STATUS_HEADER.match(line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip()
        current[key] = value
        last_key = key if key in ("Description",) else ""
    if current.get("Package") and "install ok installed" in current.get("Status", ""):
        packages.append(current)
    return [
        {
            "manager": "deb",
            "name": pkg["Package"],
            "version": pkg.get("Version", "0"),
            "arch": pkg.get("Architecture", ""),
            "description": pkg.get("Description", ""),
        }
        for pkg in packages
    ]


def read_dpkg_status(path: str = DPKG_STATUS_DEFAULT) -> list[dict[str, str]]:
    expanded = os.path.expanduser(path)
    if not os.path.isfile(expanded):
        return []
    with open(expanded, "r", encoding="utf-8", errors="replace") as handle:
        return parse_dpkg_status(handle.read())


@dataclass
class PkgWatch:
    store: Any
    mirror: OsvMirror | None = None
    host: str = "localhost"
    distro: str = ""

    def scan(self, packages: Iterable[dict[str, str]], *, ts: str | None = None) -> list[PackageChange]:
        """Diff an inventory snapshot against stored state; emit pkg events."""
        ts = ts or utcnow_iso()
        changes: list[PackageChange] = []
        for pkg in packages:
            manager = pkg.get("manager", "deb")
            name = str(pkg.get("name", "")).strip()
            version = str(pkg.get("version", "0")).strip()
            if not name:
                continue
            is_new = self.store.upsert_package(
                manager, name, version, ts,
                source=pkg.get("source"), arch=pkg.get("arch"),
            )
            advisories: list[Any] = []
            if self.mirror is not None:
                advisories = self.mirror.match_manager(
                    manager, name, version, distro=self.distro
                )
            cves = sorted({adv.id for adv in advisories})
            severity = "unknown"
            if advisories:
                order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
                severity = max(
                    (adv.severity for adv in advisories),
                    key=lambda value: order.get(value, 0),
                )
            action = "install" if is_new else "seen"
            if not is_new and cves:
                action = "cve"
            changes.append(
                PackageChange(
                    manager=manager,
                    name=name,
                    version=version,
                    action=action,
                    first_seen=ts,
                    cves=cves,
                    severity=severity,
                    net_capable=looks_network_capable(name, pkg.get("description", "")),
                    summary=(advisories[0].summary if advisories else ""),
                )
            )
        return changes

    def diff_removed(self, packages: Iterable[dict[str, str]], *, ts: str | None = None) -> list[PackageChange]:
        """Mark packages that vanished from the inventory."""
        ts = ts or utcnow_iso()
        present = {(p.get("manager", "deb"), p["name"]) for p in packages if p.get("name")}
        removed: list[PackageChange] = []
        for row in self.store.packages():
            key = (row["manager"], row["name"])
            if key in present or row["removed"]:
                continue
            if self.store.mark_removed(row["manager"], row["name"], ts):
                removed.append(
                    PackageChange(
                        manager=row["manager"],
                        name=row["name"],
                        version=row["version"],
                        action="remove",
                        first_seen=row["first_ts"],
                    )
                )
        return removed

    def vulnerable(self) -> list[dict[str, Any]]:
        """Installed packages with a matching advisory in the local mirror."""
        out: list[dict[str, Any]] = []
        if self.mirror is None:
            return out
        for row in self.store.packages():
            if row["removed"]:
                continue
            hits = self.mirror.match_manager(
                row["manager"], row["name"], row["version"], distro=self.distro
            )
            if hits:
                out.append(
                    {
                        "manager": row["manager"],
                        "name": row["name"],
                        "version": row["version"],
                        "cves": sorted({adv.id for adv in hits}),
                        "severity": max(
                            (adv.severity for adv in hits),
                            key=lambda value: {"critical": 4, "high": 3, "medium": 2,
                                               "low": 1}.get(value, 0),
                        ),
                        "ecosystem": MANAGER_TO_ECOSYSTEM.get(row["manager"], row["manager"]),
                    }
                )
        return out
