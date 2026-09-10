# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Configuration loading, defaults and validation.

Config is YAML (see ``config/damavik.example.yaml``).  Keys are validated
against a known set; an unknown key is a hard error, because a typo in
``offline: true`` silently disabling the kill-switch is exactly the failure
mode a security tool must not have.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from typing import Any

from .miniyaml import YamlError, loads

CONFIG_FILENAME = "damavik.yaml"
DEFAULT_CONFIG_PATHS = (
    "./damavik.yaml",
    "./config/damavik.yaml",
    "~/.config/damavik/damavik.yaml",
    "/etc/damavik/damavik.yaml",
)

#: Every key we know about, as ``"section.key"``.  Kept flat and explicit so the
#: validator can point at the exact typo.
KNOWN_KEYS = frozenset(
    {
        "host_id",
        "offline",
        "retention_days",
        "state_dir",
        "sensor.flows",
        "sensor.dns",
        "sensor.exec_hash",
        "sensor.yara",
        "sensor.poll_interval_s",
        "osquery.enabled",
        "osquery.interval_s",
        "osquery.pack",
        "intel.osv_mirror.enabled",
        "intel.osv_mirror.sync",
        "intel.osv_mirror.dir",
        "intel.bazaar.enabled",
        "intel.urlhaus.enabled",
        "intel.abuseipdb.enabled",
        "intel.abuseipdb.key_env",
        "intel.otx.enabled",
        "intel.otx.key_env",
        "intel.vt.enabled",
        "intel.vt.key_env",
        "dashboard.enabled",
        "dashboard.bind",
        "dashboard.port",
        "dashboard.token_env",
        "alerts.path",
        "alerts.notify",
        "alerts.webhook",
        "alerts.cooldown_s",
        "alerts.min_score",
        "limits.max_event_bytes",
        "limits.max_response_bytes",
        "scoring.allowlist_exes",
        "scoring.allowlist_hashes",
        "scoring.common_ports",
        "rules.dir",
    }
)

LOOPBACK_BINDS = frozenset({"127.0.0.1", "::1", "localhost"})


class ConfigError(ValueError):
    """Invalid or contradictory configuration."""


@dataclass
class Config:
    """Validated runtime configuration."""

    host_id: str = "auto"
    offline: bool = False
    retention_days: int = 7
    state_dir: str = "~/.local/state/damavik"
    sensor: dict[str, Any] = field(
        default_factory=lambda: {
            "flows": True,
            "dns": True,
            "exec_hash": True,
            "yara": True,
            "poll_interval_s": 2.0,
        }
    )
    osquery: dict[str, Any] = field(
        default_factory=lambda: {"enabled": False, "interval_s": 60, "pack": "osquery/packs/damavik.conf"}
    )
    intel: dict[str, Any] = field(
        default_factory=lambda: {
            # Keyless providers are still opt-in: the MVP ships with every
            # network path off so `--offline` is the *default*, not the escape.
            "osv_mirror": {"enabled": True, "sync": "weekly", "dir": "~/.local/share/damavik/osv"},
            "bazaar": {"enabled": False},
            "urlhaus": {"enabled": False},
            "abuseipdb": {"enabled": False, "key_env": "ABUSEIPDB_KEY"},
            "otx": {"enabled": False, "key_env": "OTX_KEY"},
            "vt": {"enabled": False, "key_env": "VT_KEY"},
        }
    )
    dashboard: dict[str, Any] = field(
        default_factory=lambda: {
            "enabled": True,
            "bind": "127.0.0.1",
            "port": 8787,
            "token_env": "DAMAVIK_TOKEN",
        }
    )
    alerts: dict[str, Any] = field(
        default_factory=lambda: {
            "path": "alerts.log",
            "notify": True,
            "webhook": None,
            "cooldown_s": 300,
            "min_score": 45.0,
        }
    )
    limits: dict[str, Any] = field(
        default_factory=lambda: {"max_event_bytes": 65536, "max_response_bytes": 1048576}
    )
    scoring: dict[str, Any] = field(
        default_factory=lambda: {
            "allowlist_exes": [
                "/usr/bin/systemd",
                "/usr/lib/systemd/systemd",
                "/sbin/init",
            ],
            "allowlist_hashes": [],
            "common_ports": [22, 53, 80, 443, 465, 587, 993, 995, 5353],
        }
    )
    rules: dict[str, Any] = field(default_factory=lambda: {"dir": "rules"})
    source_path: str | None = None

    def resolved_host_id(self) -> str:
        if self.host_id and self.host_id != "auto":
            return self.host_id
        return socket.gethostname() or "unknown"

    def resolved_state_dir(self) -> str:
        return os.path.expanduser(self.state_dir)

    def db_path(self) -> str:
        return os.path.join(self.resolved_state_dir(), "damavik.db")

    def journal_path(self) -> str:
        return os.path.join(self.resolved_state_dir(), "journal.jsonl")

    def alerts_path(self) -> str:
        path = os.path.expanduser(str(self.alerts.get("path", "alerts.log")))
        if os.path.isabs(path):
            return path
        return os.path.join(self.resolved_state_dir(), path)

    def enabled_intel(self) -> dict[str, dict[str, Any]]:
        """Providers that may run.  ``offline`` overrides everything."""
        if self.offline:
            return {}
        return {
            name: dict(spec)
            for name, spec in self.intel.items()
            if isinstance(spec, dict) and spec.get("enabled")
        }


def _flatten(prefix: str, node: dict[str, Any], out: dict[str, Any]) -> None:
    for key, value in node.items():
        dotted = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            _flatten(dotted, value, out)
        else:
            out[dotted] = value


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _as_dict(node: Any) -> dict[str, Any]:
    if node is None:
        return {}
    if not isinstance(node, dict):
        raise ConfigError(f"expected a mapping, got {type(node).__name__}")
    return node


def validate(data: dict[str, Any]) -> list[str]:
    """Return every configuration problem found (empty list == valid)."""
    errors: list[str] = []
    flat: dict[str, Any] = {}
    _flatten("", _as_dict(data), flat)
    for key in flat:
        if key not in KNOWN_KEYS:
            errors.append(f"{key}: unknown configuration key")
    if "retention_days" in data:
        days = data["retention_days"]
        if not isinstance(days, int) or days < 0:
            errors.append("retention_days: must be a non-negative integer")
    dash = _as_dict(data.get("dashboard"))
    bind = dash.get("bind")
    if bind is not None and bind not in LOOPBACK_BINDS:
        errors.append(
            f"dashboard.bind: {bind!r} is not a loopback address - the MVP is "
            "localhost-only by design; there is no override"
        )
    port = dash.get("port")
    if port is not None and (not isinstance(port, int) or not 1 <= port <= 65535):
        errors.append("dashboard.port: must be an int in 1..65535")
    if "offline" in data and not isinstance(data["offline"], bool):
        errors.append("offline: must be a boolean")
    for provider, spec in _as_dict(data.get("intel")).items():
        spec = _as_dict(spec)
        if spec.get("enabled") and spec.get("key_env") and not os.environ.get(
            str(spec["key_env"])
        ):
            errors.append(
                f"intel.{provider}: enabled but {spec['key_env']} is not set in the environment"
            )
    return errors


def from_dict(data: dict[str, Any], *, source_path: str | None = None) -> Config:
    problems = validate(data)
    if problems:
        raise ConfigError("; ".join(problems))
    base = Config()
    merged = _deep_merge(
        {
            "host_id": base.host_id,
            "offline": base.offline,
            "retention_days": base.retention_days,
            "state_dir": base.state_dir,
            "sensor": base.sensor,
            "osquery": base.osquery,
            "intel": base.intel,
            "dashboard": base.dashboard,
            "alerts": base.alerts,
            "limits": base.limits,
            "scoring": base.scoring,
            "rules": base.rules,
        },
        _as_dict(data),
    )
    known = {f.name for f in Config.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    kwargs = {k: v for k, v in merged.items() if k in known and k != "source_path"}
    cfg = Config(**kwargs)
    cfg.source_path = source_path
    return cfg


def load(path: str | os.PathLike[str] | None = None) -> Config:
    """Load config from ``path``, or the first default location that exists."""
    candidates = [str(path)] if path else list(DEFAULT_CONFIG_PATHS)
    for candidate in candidates:
        expanded = os.path.expanduser(candidate)
        if os.path.isfile(expanded):
            try:
                with open(expanded, "r", encoding="utf-8") as handle:
                    data = loads(handle.read()) or {}
            except (OSError, YamlError) as exc:
                raise ConfigError(f"{expanded}: {exc}") from exc
            return from_dict(_as_dict(data), source_path=expanded)
    if path:
        raise ConfigError(f"config file not found: {path}")
    return Config()
