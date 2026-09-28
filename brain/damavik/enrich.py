# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Enrichment: add context the sensor cannot know, and optional intel.

Enrichment runs between normalize and score.  Two enrichers ship:

``ContextEnricher``
    Purely local, always on.  Adds the fields rules need to express ancestry
    and rarity - parent executable, process age, registrable domain, DNS label
    entropy, and "this path ran a different hash before".  Doing this in the
    brain keeps the sensor thin and lets the same logic serve every platform.

``IntelEnricher``
    Only instantiated when the configuration enabled at least one provider.
    Adds ``intel_malicious`` / ``intel_suspicious`` tags.  A verdict is a
    signal: it moves the score, it never decides on its own.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from .schema import entropy_ratio, iso_to_ms, longest_label, shannon_entropy

#: Office/browser parents that should never spawn a shell.  Windows names are
#: lower-cased; matching is done on the lower-cased basename.
SENSITIVE_PARENTS = frozenset(
    {
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
        "onenote.exe",
        "msaccess.exe",
        "soffice",
        "soffice.bin",
        "libreoffice",
        "thunderbird.exe",
        "chrome.exe",
        "firefox.exe",
        "msedge.exe",
        "brave.exe",
        "acrobat.exe",
        "acrord32.exe",
        "evince",
        "okular",
    }
)

SHELLS = frozenset(
    {
        "sh",
        "bash",
        "dash",
        "zsh",
        "ksh",
        "fish",
        "csh",
        "tcsh",
        "cmd.exe",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "cmd",
        "powershell",
    }
)

INTERPRETERS = frozenset(
    {
        "python",
        "python2",
        "python3",
        "python3.11",
        "perl",
        "ruby",
        "lua",
        "php",
        "node",
        "tclsh",
        "wish",
        "osascript",
    }
)

#: Substrings searched in a command line.
DOWNLOAD_TOOLS = (
    "curl",
    "wget",
    "nc ",
    "ncat",
    "netcat",
    "socat",
    "aria2c",
    "bitsadmin",
    "certutil",
    "invoke-webrequest",
    "| sh",
    "|sh",
    "/dev/tcp/",
)

#: Basenames that *are* downloaders.
DOWNLOADER_BASENAMES = frozenset(
    {
        "curl",
        "wget",
        "nc",
        "ncat",
        "netcat",
        "socat",
        "aria2c",
        "bitsadmin",
        "certutil.exe",
        "telnet",
        "telnet.exe",
        "ftp",
        "ftp.exe",
    }
)


def basename(path: str) -> str:
    text = str(path or "").replace("\\", "/").rstrip("/")
    return text.rsplit("/", 1)[-1].lower()


def registrable_domain(qname: str) -> str:
    """Naive eTLD+1.

    A real implementation needs the Public Suffix List, which is a ~250 KB data
    file we would have to vendor and keep updated.  For grouping DNS queries
    the naive "last two labels" answer is wrong for ``co.uk`` and friends, and
    that only means slightly coarser grouping - it never produces a false
    "different domain" split.  Documented, not hidden.
    """
    labels = [part for part in str(qname).split(".") if part]
    if len(labels) <= 2:
        return ".".join(labels)
    return ".".join(labels[-2:])


class ContextEnricher:
    """Local-only context.  Never raises, never blocks, never touches network."""

    name = "context"

    def __init__(self, store: Any) -> None:
        self.store = store

    def __call__(self, event: dict[str, Any]) -> dict[str, Any]:
        etype = event.get("type")
        proc = event.get("proc")
        if isinstance(proc, dict):
            self._enrich_proc(event, proc)
        if etype == "dns.query" and isinstance(event.get("dns"), dict):
            self._enrich_dns(event["dns"], event)
        if isinstance(event.get("net"), dict):
            self._enrich_net(event["net"], event)
        return event

    def _enrich_net(self, net: dict[str, Any], event: dict[str, Any]) -> None:
        """Classify the destination so rules can talk about *egress*.

        The sensor reports every socket it can see, loopback included, so a rule
        that just says "six connections to one destination" fires on local IPC
        and on the LAN: measured on an idle box, 36 connections to 127.0.0.1 and
        26 to the host's own address were enough to alert.  A monitor that cries
        wolf on a quiet machine is worse than no monitor.

        ``is_local``  - loopback, unspecified, multicast, link-local: never leaves
                        the host, so it can never be egress.
        ``is_private`` - RFC1918 / CGNAT / ULA / reserved space: a LAN hop.
                        Rules that mean "on the internet" filter these out too;
                        a LAN destination is reported and scored either way.
        """
        destination = str(net.get("dst") or "")
        if not destination:
            return
        try:
            address = ipaddress.ip_address(destination)
        except ValueError:
            return
        meta = event.setdefault("meta", {})
        local = (
            address.is_loopback
            or address.is_unspecified
            or address.is_multicast
            or address.is_link_local
        )
        meta["is_local"] = local
        meta["is_private"] = not local and bool(address.is_private)

    def _enrich_proc(self, event: dict[str, Any], proc: dict[str, Any]) -> None:
        ppid = proc.get("ppid")
        if ppid and "parent_exe" not in proc:
            parent = self.store.proc_info(int(ppid))
            if parent:
                proc["parent_exe"] = parent.get("exe") or ""
                proc["parent_cmd"] = (parent.get("cmd") or "")[:512]
        parent_exe = basename(proc.get("parent_exe") or "")
        exe = basename(proc.get("exe") or "")
        meta = event.setdefault("meta", {})
        meta["exe_base"] = exe
        meta["parent_base"] = parent_exe
        meta["parent_is_sensitive"] = parent_exe in SENSITIVE_PARENTS
        meta["child_is_shell"] = exe in SHELLS
        meta["child_is_interpreter"] = exe in INTERPRETERS
        meta["parent_is_shell"] = parent_exe in SHELLS
        meta["child_is_downloader"] = exe in DOWNLOADER_BASENAMES
        cmd = str(proc.get("cmd") or "").lower()
        meta["cmd_has_download_tool"] = any(tool in cmd for tool in DOWNLOAD_TOOLS)
        meta["cmd_is_encoded"] = any(
            flag in cmd
            for flag in (
                "-enc",
                "-encodedcommand",
                "-e ",
                "-nop",
                "-w hidden",
                "-windowstyle hidden",
                "frombase64string",
                "-noni",
            )
        )

        pid = proc.get("pid")
        if pid is not None and event.get("ts"):
            first_ms = self.store.first_exec_ts_ms(int(pid))
            if first_ms:
                meta["age_ms"] = max(0, iso_to_ms(event["ts"]) - int(first_ms))

        sha = proc.get("sha256")
        exe_path = proc.get("exe")
        if sha and exe_path and event.get("type") == "proc.exec":
            previous = self.store.hashes_for_exe(exe_path)
            if previous and sha not in previous:
                meta["hash_changed"] = True
                meta["previous_hashes"] = previous[:5]
                event.setdefault("tags", []).append("supply_chain_shift")

    def _enrich_dns(self, dns: dict[str, Any], event: dict[str, Any]) -> None:
        qname = str(dns.get("q") or "")
        dns["root"] = registrable_domain(qname)
        label = longest_label(qname)
        meta = event.setdefault("meta", {})
        meta["dns_entropy"] = shannon_entropy(label)
        meta["dns_entropy_ratio"] = entropy_ratio(label)
        meta["dns_label_len"] = len(label)
        meta["dns_qname_len"] = len(qname)


class IntelEnricher:
    """Optional second opinion from enabled providers."""

    name = "intel"

    def __init__(self, providers: list[Any], *, limit: int = 3) -> None:
        self.providers = list(providers)
        self.limit = limit

    def __call__(self, event: dict[str, Any]) -> dict[str, Any]:
        targets: list[tuple[str, str]] = []
        proc = event.get("proc") or {}
        net = event.get("net") or {}
        dns = event.get("dns") or {}
        if proc.get("sha256"):
            targets.append(("sha256", str(proc["sha256"])))
        if dns.get("q"):
            targets.append(("domain", str(dns["q"])))
        if net.get("dst"):
            targets.append(("ip", str(net["dst"])))
        if not targets:
            return event
        hits: list[dict[str, Any]] = []
        for kind, value in targets[: self.limit]:
            for provider in self.providers:
                if not provider.supports(kind):
                    continue
                verdict = provider.lookup(kind, value)
                if verdict.verdict in ("malicious", "suspicious"):
                    hits.append(verdict.as_dict())
                    tag = f"intel_{verdict.verdict}"
                    if tag not in event.setdefault("tags", []):
                        event["tags"].append(tag)
                    break
        if hits:
            event.setdefault("meta", {})["intel"] = hits
        return event
