# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Dashboard: one stdlib HTTP server, localhost only, no build step.

Security properties, enforced in code rather than in documentation:

* the socket refuses to bind to anything but a loopback address, and there is
  no flag to change that in the MVP;
* every ``/api/*`` request must carry the session token (``Authorization:
  Bearer`` or ``?token=``), printed once at startup and derived from the
  ``DAMAVIK_TOKEN`` environment variable when set;
* responses are JSON built from the local SQLite index - no template engine,
  no remote asset, no CDN, no websockets.  The UI polls.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..config import LOOPBACK_BINDS, Config
from ..osv import OsvMirror
from ..pkgwatch import PkgWatch
from ..store import Store

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
MAX_BODY = 65536


class Api:
    """Read-only data access for the UI.  One instance per server."""

    def __init__(self, config: Config, store: Store | None = None) -> None:
        self.config = config
        self.store = store or Store(config.db_path())

    def health(self) -> dict[str, Any]:
        return {"ok": True, "offline": self.config.offline}

    def summary(self) -> dict[str, Any]:
        data = self.store.summary()
        data["offline"] = self.config.offline
        data["enabled_intel"] = sorted(self.config.enabled_intel())
        data["rules_dir"] = self.config.rules.get("dir")
        return data

    def alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        out = []
        for alert in self.store.alerts(limit=limit):
            alert["subgraph"] = self.subgraph(alert)
            out.append(alert)
        return out

    def subgraph(self, alert: dict[str, Any]) -> dict[str, Any]:
        """The exact evidence behind an alert: events, process, flows, DNS."""
        events = [self.store.event_by_id(eid) for eid in alert.get("events", [])]
        events = [event for event in events if event]
        pid = alert.get("iocs", {}).get("pid")
        return {
            "events": events,
            "process": self.store.proc_info(int(pid)) if pid else None,
            "flows": self.store.flow_aggregates(pid=int(pid), limit=25) if pid else [],
            "dns": list(self.store.events(etype="dns.query", limit=25)),
        }

    def tree(self, pid: int | None = None) -> list[dict[str, Any]]:
        return self.store.process_tree(pid)

    def flows(self, pid: int | None = None, limit: int = 200) -> dict[str, Any]:
        rows = self.store.flow_aggregates(pid=pid, limit=limit)
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        host_id = self.config.resolved_host_id()
        nodes[host_id] = {"id": host_id, "kind": "host", "score": 0.0}
        for row in rows:
            proc_id = f"pid:{row['pid']}" if row["pid"] is not None else "pid:unknown"
            exe = os.path.basename(str(row["exe"] or "unknown"))
            nodes.setdefault(
                proc_id, {"id": proc_id, "kind": "process", "label": exe, "score": 0.0}
            )
            dst = row["dst"] or "unknown"
            nodes.setdefault(dst, {"id": dst, "kind": "remote", "label": dst, "score": 0.0})
            edges.append(
                {
                    "from": host_id,
                    "to": proc_id,
                    "conns": row["conns"],
                    "bytes": row["bytes_out"] + row["bytes_in"],
                    "score": 0.0,
                }
            )
            edges.append(
                {
                    "from": proc_id,
                    "to": dst,
                    "conns": row["conns"],
                    "bytes": row["bytes_out"] + row["bytes_in"],
                    "score": self._edge_score(row),
                    "dport": row["dport"],
                    "proto": row["proto"],
                }
            )
        for edge in edges:
            node = nodes.get(edge["to"])
            if node is not None:
                node["score"] = max(float(node.get("score") or 0.0), float(edge["score"]))
        return {"nodes": list(nodes.values()), "edges": edges}

    @staticmethod
    def _edge_score(row: dict[str, Any]) -> float:
        score = 0.0
        if row["dport"] in (1337, 4444, 5555, 6667, 31337):
            score += 40.0
        if row["conns"] >= 6:
            score += 20.0
        if row["bytes_out"] >= 5 * 1024 * 1024:
            score += 25.0
        return min(100.0, score)

    def timeline(self, hours: int = 24) -> list[dict[str, Any]]:
        return self.store.timeline(hours=hours)

    def packages(self) -> dict[str, Any]:
        mirror = OsvMirror(self.config.intel.get("osv_mirror", {}).get("dir"))
        mirror.load_dir()
        watch = PkgWatch(store=self.store, mirror=mirror, host=self.config.resolved_host_id())
        packages = self.store.packages()
        return {
            "packages": packages,
            "vulnerable": watch.vulnerable(),
            "mirror": mirror.stats(),
        }

    def event(self, eid: str) -> dict[str, Any] | None:
        return self.store.event_by_id(eid)


def _load_static(name: str) -> tuple[bytes, str]:
    types = {
        ".html": "text/html; charset=utf-8",
        ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".svg": "image/svg+xml",
    }
    path = os.path.join(STATIC_DIR, name)
    if not os.path.isfile(path):
        return b"", "text/plain"
    with open(path, "rb") as handle:
        return handle.read(), types.get(os.path.splitext(name)[1], "application/octet-stream")


def make_handler(api: Api, token: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "damavik/0.1"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002
            pass

        # -- helpers -------------------------------------------------------
        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _json(self, status: int, payload: Any) -> None:
            self._send(
                status,
                json.dumps(payload, sort_keys=True, default=str).encode("utf-8"),
                "application/json; charset=utf-8",
            )

        def _authorized(self, query: dict[str, list[str]]) -> bool:
            header = self.headers.get("Authorization", "")
            if header.startswith("Bearer ") and secrets.compare_digest(header[7:], token):
                return True
            supplied = query.get("token", [""])[0]
            return bool(supplied) and secrets.compare_digest(supplied, token)

        # -- routes --------------------------------------------------------
        def do_GET(self) -> None:  # noqa: N802 - http.server API
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            path = parsed.path
            if path in ("/", "/index.html"):
                body, ctype = _load_static("index.html")
                self._send(200, body, ctype)
                return
            if path in ("/dash.js", "/dash.css"):
                body, ctype = _load_static(path.lstrip("/"))
                self._send(200 if body else 404, body, ctype)
                return
            if not path.startswith("/api/"):
                self._send(404, b"not found", "text/plain")
                return
            if not self._authorized(query):
                self._json(401, {"error": "unauthorized"})
                return
            try:
                self._api(path, query)
            except Exception as exc:  # noqa: BLE001 - never leak a traceback to the socket
                self._json(500, {"error": str(exc)})

        def _api(self, path: str, query: dict[str, list[str]]) -> None:
            def one(name: str, default: str = "") -> str:
                return query.get(name, [default])[0]

            def number(name: str, default: int) -> int:
                try:
                    return int(one(name, str(default)))
                except ValueError:
                    return default

            if path == "/api/health":
                self._json(200, api.health())
            elif path == "/api/summary":
                self._json(200, api.summary())
            elif path == "/api/alerts":
                self._json(200, {"alerts": api.alerts(limit=number("limit", 50))})
            elif path == "/api/tree":
                pid = one("pid")
                self._json(200, {"roots": api.tree(int(pid) if pid else None)})
            elif path == "/api/flows":
                pid = one("pid")
                self._json(200, api.flows(int(pid) if pid else None, limit=number("limit", 200)))
            elif path == "/api/timeline":
                self._json(200, {"buckets": api.timeline(hours=number("hours", 24))})
            elif path == "/api/packages":
                self._json(200, api.packages())
            elif path == "/api/event":
                event = api.event(one("id"))
                self._json(200 if event else 404, event or {"error": "not found"})
            elif path == "/api/events":
                self._json(
                    200,
                    {
                        "events": api.store.events(
                            limit=number("limit", 100),
                            etype=one("type") or None,
                            pid=int(one("pid")) if one("pid") else None,
                            min_score=float(one("min_score")) if one("min_score") else None,
                        )
                    },
                )
            else:
                self._json(404, {"error": f"unknown endpoint {path}"})

    return Handler


def serve(config: Config, *, token: str | None = None, store: Store | None = None) -> int:
    bind = str(config.dashboard.get("bind", "127.0.0.1"))
    port = int(config.dashboard.get("port", 8787))
    if bind not in LOOPBACK_BINDS:
        print(
            f"refusing to bind dashboard to {bind}: Damavik's dashboard is "
            "localhost-only by design; there is no override",
            flush=True,
        )
        return 2
    session_token = (
        token
        or os.environ.get(str(config.dashboard.get("token_env", "DAMAVIK_TOKEN")), "")
        or secrets.token_urlsafe(16)
    )
    api = Api(config, store=store)
    handler = make_handler(api, session_token)
    httpd = ThreadingHTTPServer((bind, port), handler)
    httpd.daemon_threads = True
    url = f"http://{bind}:{port}/?token={session_token}"
    print(f"damavik dashboard on {url}", flush=True)
    print("token: " + session_token, flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()
        api.store.close()
    return 0


def serve_in_thread(
    config: Config, *, port: int = 0, token: str = "test-token"
) -> tuple[Any, int, threading.Thread]:
    """Start the dashboard on an ephemeral port for tests.  Returns (server, port, thread)."""
    api = Api(config)
    handler = make_handler(api, token)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    bound_port = int(httpd.server_address[1])
    return httpd, bound_port, thread
