# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Intel plugin interface.

Every provider is untrusted input.  The rules that follow are enforced here so
an individual plugin cannot forget them:

* a hard response size cap (default 1 MiB) - a hostile or broken endpoint must
  not be able to exhaust memory;
* strict JSON parsing - anything that is not an object is ``unknown``;
* a token bucket per provider, so a bug cannot burn a free-tier quota;
* a disk cache with asymmetric TTLs (malicious 30 days, clean 7 days) so repeat
  lookups never hit the network;
* a verdict is a *signal*, never truth: it contributes score, it cannot by
  itself produce a "malicious" conclusion.

``offline=True`` short-circuits every network plugin: this is the kill-switch
behind ``damavik --offline``.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

VERDICTS = ("unknown", "clean", "suspicious", "malicious")
VERDICT_SCORE = {"unknown": 0.0, "clean": 0.0, "suspicious": 45.0, "malicious": 90.0}

#: Cache lifetimes, in seconds.  Asymmetric on purpose: a clean verdict can go
#: stale quickly (a binary can be weaponised later), a malicious one cannot.
TTL_MALICIOUS = 30 * 86400
TTL_SUSPICIOUS = 14 * 86400
TTL_CLEAN = 7 * 86400
TTL_UNKNOWN = 3600

#: Kinds a provider may be asked about.
KINDS = ("sha256", "ip", "domain", "url", "package")


@dataclass
class Verdict:
    kind: str
    value: str
    verdict: str = "unknown"
    score: float = 0.0
    source: str = ""
    refs: list[str] = field(default_factory=list)
    ts: str = ""
    cached: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "verdict": self.verdict,
            "score": self.score,
            "source": self.source,
            "refs": list(self.refs),
            "ts": self.ts,
            "cached": self.cached,
        }

    @classmethod
    def unknown(cls, kind: str, value: str, *, source: str = "") -> Verdict:
        return cls(kind=kind, value=value, verdict="unknown", source=source or cls.__name__)


@dataclass
class TokenBucket:
    """Simple rate limiter: ``rate`` tokens per second, up to ``capacity``."""

    rate: float
    capacity: float
    _tokens: float = field(init=False)
    _last: float = field(init=False)

    def __post_init__(self) -> None:
        self._tokens = float(self.capacity)
        self._last = time.monotonic()

    def take(self, amount: float = 1.0, *, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        elapsed = max(0.0, now - self._last)
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last = now
        if self._tokens >= amount:
            self._tokens -= amount
            return True
        return False


class IntelError(RuntimeError):
    """Provider misbehaved (bad JSON, oversize body, HTTP error)."""


Transport = Callable[..., tuple[int, bytes]]


def http_request(
    url: str,
    headers: dict[str, str],
    max_bytes: int,
    data: bytes | None = None,
) -> tuple[int, bytes]:
    """Standard-library HTTP.  Kept in one place so tests can swap it out."""
    import urllib.error
    import urllib.request

    if not url.startswith("https://"):
        raise IntelError("refusing non-HTTPS request")
    request = urllib.request.Request(
        url, data=data, headers={"User-Agent": "damavik/0.1", **headers}
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - https only
            body = response.read(max_bytes + 1)
            return int(response.status), body
    except urllib.error.HTTPError as exc:
        return int(exc.code), b""
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise IntelError(f"transport failure: {exc}") from exc


#: Backwards-compatible alias.
http_get = http_request


class Provider:
    """Base class for a cloud intel provider.

    Subclasses implement :meth:`_fetch` and declare ``name``, ``kinds`` and a
    default ``rate``/``capacity`` for their free tier.
    """

    name = "provider"
    kinds: tuple[str, ...] = ()
    rate = 0.1
    capacity = 5.0
    requires_key = False
    base_url = ""

    def __init__(
        self,
        *,
        store: Any = None,
        offline: bool = False,
        api_key: str | None = None,
        transport: Transport | None = None,
        max_bytes: int = 1048576,
        rate: float | None = None,
        capacity: float | None = None,
    ) -> None:
        self.store = store
        self.offline = offline
        self.api_key = api_key
        self.transport = transport or http_get
        self.max_bytes = max_bytes
        self.bucket = TokenBucket(
            rate=self.rate if rate is None else rate,
            capacity=self.capacity if capacity is None else capacity,
        )
        self.calls = 0
        self.cache_hits = 0
        self.rate_limited = 0
        self.errors = 0

    # -- public API --------------------------------------------------------
    def supports(self, kind: str) -> bool:
        return kind in self.kinds

    def lookup(self, kind: str, value: str) -> Verdict:
        """Cached, rate-limited, size-capped lookup.  Never raises."""
        if not value or not self.supports(kind):
            return Verdict.unknown(kind, value, source=self.name)
        if self.offline:
            return Verdict.unknown(kind, value, source=f"{self.name}:offline")
        cached = self._cache_get(kind, value)
        if cached is not None:
            self.cache_hits += 1
            return cached
        if self.requires_key and not self.api_key:
            return Verdict.unknown(kind, value, source=f"{self.name}:no-key")
        if not self.bucket.take():
            self.rate_limited += 1
            return Verdict.unknown(kind, value, source=f"{self.name}:rate-limited")
        try:
            verdict = self._fetch(kind, value)
        except (IntelError, ValueError, KeyError, json.JSONDecodeError) as exc:
            self.errors += 1
            return Verdict.unknown(kind, value, source=f"{self.name}:error:{exc}")
        self.calls += 1
        if verdict.verdict not in VERDICTS:
            verdict.verdict = "unknown"
        verdict.score = VERDICT_SCORE.get(verdict.verdict, 0.0)
        verdict.source = verdict.source or self.name
        verdict.ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._cache_put(verdict)
        return verdict

    # -- subclass hook -----------------------------------------------------
    def _fetch(self, kind: str, value: str) -> Verdict:  # pragma: no cover - abstract
        raise NotImplementedError

    # -- cache -------------------------------------------------------------
    def _cache_get(self, kind: str, value: str) -> Verdict | None:
        if self.store is None:
            return None
        row = self.store.cache_get(self.name, f"{kind}:{value}")
        if row is None:
            return None
        return Verdict(
            kind=kind,
            value=value,
            verdict=row["verdict"],
            score=float(row["score"]),
            source=row["source"] or self.name,
            refs=list(row["refs"]),
            ts=row["fetched_ts"],
            cached=True,
        )

    def _cache_put(self, verdict: Verdict) -> None:
        if self.store is None:
            return
        ttl = {
            "malicious": TTL_MALICIOUS,
            "suspicious": TTL_SUSPICIOUS,
            "clean": TTL_CLEAN,
        }.get(verdict.verdict, TTL_UNKNOWN)
        self.store.cache_put(
            self.name, f"{verdict.kind}:{verdict.value}", verdict.as_dict(), ttl, verdict.ts
        )

    # -- helpers -----------------------------------------------------------
    def _get_json(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> Any:
        status, body = self.transport(url, headers or {}, self.max_bytes, data)
        if status == 404:
            return None
        if status >= 400:
            raise IntelError(f"HTTP {status}")
        if len(body) > self.max_bytes:
            raise IntelError("response exceeds size cap")
        data_obj = json.loads(body.decode("utf-8", "replace"))
        if not isinstance(data_obj, (dict, list)):
            raise IntelError("response is not a JSON object")
        return data_obj
