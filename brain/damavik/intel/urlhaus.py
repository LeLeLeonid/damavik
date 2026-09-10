# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""URLhaus (abuse.ch) - keyless host/URL lookups.  Default-off."""

from __future__ import annotations

import urllib.parse

from .base import IntelError, Provider, Verdict

API = "https://urlhaus-api.abuse.ch/v1/"


class URLhaus(Provider):
    name = "urlhaus"
    kinds = ("domain", "url")
    rate = 0.5
    capacity = 10.0
    requires_key = False
    base_url = API

    def _fetch(self, kind: str, value: str) -> Verdict:
        endpoint = "host" if kind == "domain" else "url"
        form = urllib.parse.urlencode({endpoint: value}).encode()
        data = self._get_json(
            API + endpoint + "/",
            {"Content-Type": "application/x-www-form-urlencoded"},
            form,
        )
        if not isinstance(data, dict):
            raise IntelError("unexpected response shape")
        status = str(data.get("query_status", ""))
        if status in ("no_results", "host_not_found"):
            return Verdict(kind=kind, value=value, verdict="clean", source=self.name)
        if status not in ("ok",):
            raise IntelError(f"query_status={status}")
        urls = data.get("urls") or []
        active = [u for u in urls if isinstance(u, dict) and u.get("url_status") == "online"]
        verdict = "malicious" if active else ("suspicious" if urls else "clean")
        refs = [str(u.get("url")) for u in active[:5] if u.get("url")]
        return Verdict(kind=kind, value=value, verdict=verdict, source=self.name, refs=refs)
