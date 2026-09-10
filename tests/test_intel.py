# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Intel plugins: untrusted input, quotas, caching and the offline kill-switch."""

from __future__ import annotations

import json

import pytest

from damavik.intel.base import TTL_CLEAN, TTL_MALICIOUS, Provider, TokenBucket, Verdict
from damavik.intel.bazaar import MalwareBazaar
from damavik.intel.urlhaus import URLhaus


class FakeProvider(Provider):
    name = "fake"
    kinds = ("sha256",)
    rate = 1.0
    capacity = 2.0

    def __init__(self, payload=None, status: int = 200, **kwargs):
        super().__init__(**kwargs)
        self.payload = payload if payload is not None else {"verdict": "malicious"}
        self.status = status
        self.urls: list[str] = []

    def _fetch(self, kind: str, value: str) -> Verdict:
        data = self._get_json("https://example.invalid/api", {}, None)
        return Verdict(kind=kind, value=value, verdict=str(data.get("verdict", "unknown")))


def transport(body: bytes, status: int = 200):
    def _transport(url, headers, max_bytes, data=None):
        return status, body[: max_bytes + 1]

    return _transport


# ------------------------------------------------------------ offline switch
def test_offline_returns_unknown_without_calling_out():
    calls = []

    def spy(url, headers, max_bytes, data=None):
        calls.append(url)
        return 200, b"{}"

    provider = FakeProvider(offline=True, transport=spy)
    verdict = provider.lookup("sha256", "a" * 64)
    assert verdict.verdict == "unknown"
    assert calls == []


def test_unsupported_kind_is_ignored():
    provider = FakeProvider(transport=transport(b"{}"))
    assert provider.lookup("ip", "1.2.3.4").verdict == "unknown"


def test_empty_value_is_ignored():
    provider = FakeProvider(transport=transport(b"{}"))
    assert provider.lookup("sha256", "").verdict == "unknown"


def test_missing_key_is_not_a_network_call():
    provider = FakeProvider(transport=transport(b"{}"))
    provider.requires_key = True
    assert provider.lookup("sha256", "a" * 64).source.endswith("no-key")


# ---------------------------------------------------------------- rate limit
def test_token_bucket_limits_bursts():
    bucket = TokenBucket(rate=1.0, capacity=2.0)
    now = 100.0
    assert bucket.take(now=now)
    assert bucket.take(now=now)
    assert bucket.take(now=now) is False
    assert bucket.take(now=now + 1.0)          # one token refilled


def test_rate_limited_lookup_does_not_raise():
    provider = FakeProvider(
        transport=transport(b'{"verdict":"malicious"}'), rate=0.0, capacity=1.0
    )
    first = provider.lookup("sha256", "a" * 64)
    second = provider.lookup("sha256", "b" * 64)
    assert first.verdict == "malicious"
    assert second.verdict == "unknown"
    assert provider.rate_limited == 1


# ---------------------------------------------------------------- hardening
def test_oversized_response_is_refused():
    provider = FakeProvider(transport=transport(b"x" * 5000), max_bytes=100)
    assert provider.lookup("sha256", "a" * 64).verdict == "unknown"
    assert provider.errors == 1


def test_non_json_response_is_refused():
    provider = FakeProvider(transport=transport(b"<html>not json</html>"))
    assert provider.lookup("sha256", "a" * 64).verdict == "unknown"


def test_json_scalar_response_is_refused():
    provider = FakeProvider(transport=transport(b"42"))
    assert provider.lookup("sha256", "a" * 64).verdict == "unknown"


def test_http_error_becomes_unknown():
    provider = FakeProvider(transport=transport(b"", status=500))
    assert provider.lookup("sha256", "a" * 64).verdict == "unknown"


def test_unexpected_verdict_string_is_normalised():
    provider = FakeProvider(transport=transport(b'{"verdict": "DEFINITELY_EVIL"}'))
    assert provider.lookup("sha256", "a" * 64).verdict == "unknown"


# ------------------------------------------------------------------- caching
def test_second_lookup_is_served_from_cache(store):
    provider = FakeProvider(store=store, transport=transport(b'{"verdict":"malicious"}'))
    first = provider.lookup("sha256", "a" * 64)
    second = provider.lookup("sha256", "a" * 64)
    assert first.cached is False
    assert second.cached is True
    assert provider.calls == 1
    assert provider.cache_hits == 1


def test_cache_ttl_is_asymmetric():
    assert TTL_MALICIOUS > TTL_CLEAN
    assert TTL_MALICIOUS == 30 * 86400
    assert TTL_CLEAN == 7 * 86400


# --------------------------------------------------------------- real plugins
def test_bazaar_known_hash_is_malicious():
    body = json.dumps(
        {
            "query_status": "ok",
            "data": [{"signature": "AgentTesla", "tags": ["exe", "rat"],
                      "intelligence": {"references": ["https://example/x"]}}],
        }
    ).encode()
    provider = MalwareBazaar(transport=transport(body))
    verdict = provider.lookup("sha256", "a" * 64)
    assert verdict.verdict == "malicious"
    assert verdict.refs == ["https://example/x"]


def test_bazaar_unknown_hash_is_clean():
    provider = MalwareBazaar(transport=transport(b'{"query_status":"hash_not_found"}'))
    assert provider.lookup("sha256", "a" * 64).verdict == "clean"


def test_bazaar_api_error_is_unknown():
    provider = MalwareBazaar(transport=transport(b'{"query_status":"illegal_argument"}'))
    assert provider.lookup("sha256", "a" * 64).verdict == "unknown"


def test_bazaar_only_accepts_https():
    """The transport must refuse to downgrade a provider to plain HTTP."""
    provider = MalwareBazaar()
    provider.transport = None
    from damavik.intel.base import IntelError, http_request

    with pytest.raises(IntelError):
        http_request("http://mb-api.abuse.ch/api/v1/", {}, 1024)


def test_urlhaus_active_url_is_malicious():
    body = json.dumps(
        {"query_status": "ok", "urls": [{"url": "https://bad/x", "url_status": "online"}]}
    ).encode()
    provider = URLhaus(transport=transport(body))
    assert provider.lookup("url", "https://bad/x").verdict == "malicious"


def test_urlhaus_offline_only_is_suspicious():
    body = json.dumps(
        {"query_status": "ok", "urls": [{"url": "https://bad/x", "url_status": "offline"}]}
    ).encode()
    provider = URLhaus(transport=transport(body))
    assert provider.lookup("url", "https://bad/x").verdict == "suspicious"


def test_urlhaus_no_results_is_clean():
    provider = URLhaus(transport=transport(b'{"query_status":"no_results"}'))
    assert provider.lookup("domain", "example.com").verdict == "clean"


def test_provider_stats_are_exposed():
    provider = FakeProvider(transport=transport(b'{"verdict":"clean"}'))
    provider.lookup("sha256", "a" * 64)
    provider.lookup("sha256", "b" * 64)
    assert provider.calls == 2


def test_verdict_serialisation():
    verdict = Verdict(kind="sha256", value="x", verdict="clean", source="t")
    data = verdict.as_dict()
    assert data["verdict"] == "clean" and data["cached"] is False


def test_providers_for_config_respects_offline(config):
    from damavik.intel import providers_for

    assert providers_for(config) == []
