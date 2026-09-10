# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Optional cloud intel providers.

Everything in this package is **default-off**.  The MVP works with zero of it
enabled: ``offline: true`` (or ``damavik --offline``) makes the whole directory
inert and the system keeps detecting.
"""

from __future__ import annotations

from .base import (  # noqa: F401
    KINDS,
    TTL_CLEAN,
    TTL_MALICIOUS,
    VERDICTS,
    IntelError,
    Provider,
    TokenBucket,
    Verdict,
    http_get,
)
from .bazaar import MalwareBazaar  # noqa: F401
from .urlhaus import URLhaus  # noqa: F401


def providers_for(config: object, store: object | None = None) -> list[Provider]:
    """Instantiate the providers the configuration actually enabled."""
    import os

    enabled = getattr(config, "enabled_intel", lambda: {})()
    out: list[Provider] = []
    offline = bool(getattr(config, "offline", False))
    max_bytes = int(getattr(config, "limits", {}).get("max_response_bytes", 1048576))
    if "bazaar" in enabled:
        out.append(MalwareBazaar(store=store, offline=offline, max_bytes=max_bytes))
    if "urlhaus" in enabled:
        out.append(URLhaus(store=store, offline=offline, max_bytes=max_bytes))
    for name, cls in (("abuseipdb", None), ("otx", None), ("vt", None)):
        if name in enabled:  # keyed providers land in P5
            key_env = str(enabled[name].get("key_env", ""))
            if key_env and not os.environ.get(key_env):
                continue
    return out


__all__ = [
    "KINDS",
    "TTL_CLEAN",
    "TTL_MALICIOUS",
    "VERDICTS",
    "IntelError",
    "MalwareBazaar",
    "Provider",
    "TokenBucket",
    "URLhaus",
    "Verdict",
    "http_get",
    "providers_for",
]
