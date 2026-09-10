# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""MalwareBazaar (abuse.ch) - keyless hash lookups.  Default-off.

API: ``POST https://mb-api.abuse.ch/api/v1/`` with ``query=get_info``.  No API
key is required for queries.  We send only the SHA-256, which is a hash of a
file that is already on the box - no file content ever leaves.
"""

from __future__ import annotations

import urllib.parse

from .base import IntelError, Provider, Verdict

API = "https://mb-api.abuse.ch/api/v1/"


class MalwareBazaar(Provider):
    name = "bazaar"
    kinds = ("sha256",)
    rate = 0.5  # ~1 request / 2 s, far below the documented free tier
    capacity = 10.0
    requires_key = False
    base_url = API

    def _fetch(self, kind: str, value: str) -> Verdict:
        form = urllib.parse.urlencode({"query": "get_info", "hash": value}).encode()
        data = self._get_json(
            API,
            {"Content-Type": "application/x-www-form-urlencoded"},
            form,
        )
        if not isinstance(data, dict):
            raise IntelError("unexpected response shape")
        status = str(data.get("query_status", ""))
        if status == "hash_not_found":
            return Verdict(kind=kind, value=value, verdict="clean", source=self.name)
        if status != "ok":
            raise IntelError(f"query_status={status}")
        entries = data.get("data") or []
        if not entries:
            return Verdict(kind=kind, value=value, verdict="unknown", source=self.name)
        entry = entries[0] if isinstance(entries[0], dict) else {}
        tags = [str(tag) for tag in (entry.get("tags") or [])]
        signature = str(entry.get("signature") or "")
        refs = []
        if entry.get("intelligence", {}).get("references"):
            refs = [str(r) for r in entry["intelligence"]["references"][:5]]
        verdict = "malicious" if (signature or tags) else "suspicious"
        result = Verdict(
            kind=kind,
            value=value,
            verdict=verdict,
            source=self.name,
            refs=refs,
        )
        result.tags = tags  # type: ignore[attr-defined]
        result.signature = signature  # type: ignore[attr-defined]
        return result
