# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Dashboard: localhost-only, token-authenticated, JSON-only API."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest

from damavik.dash.server import Api, serve, serve_in_thread
from damavik.pipeline import Pipeline

TOKEN = "test-token"


@pytest.fixture()
def server(config, attack_chain):  # noqa: ANN001
    pipeline = Pipeline(config)
    pipeline.run_file(attack_chain)
    httpd, port, thread = serve_in_thread(config, port=0, token=TOKEN)
    yield f"http://127.0.0.1:{port}", pipeline
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)
    pipeline.close()


def get(url, token=TOKEN, raw=False):  # noqa: ANN001
    request = urllib.request.Request(url)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=5) as response:
        body = response.read()
        return body if raw else json.loads(body)


def test_index_is_served_without_a_token(server):
    base, _ = server
    html = get(f"{base}/", token=None, raw=True).decode()
    assert "damavik" in html
    assert "/dash.js" in html


def test_static_assets_are_served(server):
    base, _ = server
    assert b"scoreColor" in get(f"{base}/dash.js", token=None, raw=True)
    assert b"--bg" in get(f"{base}/dash.css", token=None, raw=True)


def test_static_assets_contain_no_cdn_references(server):
    base, _ = server
    for asset in ("/dash.js", "/dash.css", "/"):
        body = get(f"{base}{asset}", token=None, raw=True).decode()
        assert "http://" not in body and "https://" not in body, asset


def test_api_requires_a_token(server):
    base, _ = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        get(f"{base}/api/summary", token=None)
    assert exc.value.code == 401


def test_wrong_token_is_rejected(server):
    base, _ = server
    with pytest.raises(urllib.error.HTTPError):
        get(f"{base}/api/summary", token="wrong")


def test_query_string_token_also_works(server):
    base, _ = server
    assert get(f"{base}/api/health?token={TOKEN}")["ok"] is True


def test_health(server):
    base, _ = server
    assert get(f"{base}/api/health") == {"ok": True, "offline": True}


def test_summary(server):
    base, _ = server
    summary = get(f"{base}/api/summary")
    assert summary["events"] == 35
    assert summary["alerts"] > 0
    assert summary["offline"] is True


def test_tree_endpoint(server):
    base, _ = server
    roots = get(f"{base}/api/tree")["roots"]
    assert roots
    names = json.dumps(roots)
    assert "soffice.bin" in names


def test_tree_for_one_pid(server):
    base, _ = server
    roots = get(f"{base}/api/tree?pid=2000")["roots"]
    assert len(roots) == 1 and roots[0]["pid"] == 2000


def test_flows_endpoint_builds_a_graph(server):
    base, _ = server
    graph = get(f"{base}/api/flows?limit=100")
    kinds = {node["kind"] for node in graph["nodes"]}
    assert "host" in kinds and "process" in kinds and "remote" in kinds
    assert graph["edges"]
    assert any(edge["score"] > 0 for edge in graph["edges"]), "the 4444 edge must be scored"


def test_timeline_endpoint(server):
    base, _ = server
    buckets = get(f"{base}/api/timeline?hours=240000")["buckets"]
    assert buckets
    assert sum(bucket["dns.query"] for bucket in buckets) == 12


def test_alerts_endpoint_includes_the_subgraph(server):
    base, _ = server
    alerts = get(f"{base}/api/alerts?limit=5")["alerts"]
    assert alerts
    for alert in alerts:
        assert alert["explain"]
        assert "subgraph" in alert
        assert "events" in alert["subgraph"]


def test_packages_endpoint(server):
    base, _ = server
    payload = get(f"{base}/api/packages")
    assert set(payload) == {"packages", "vulnerable", "mirror"}


def test_single_event_lookup(server):
    base, _ = server
    events = get(f"{base}/api/events?limit=1")["events"]
    event = get(f"{base}/api/event?id={events[0]['id']}")
    assert event["id"] == events[0]["id"]


def test_unknown_event_is_404(server):
    base, _ = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        get(f"{base}/api/event?id=e-nope")
    assert exc.value.code == 404


def test_unknown_endpoint_is_404(server):
    base, _ = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        get(f"{base}/api/nope")
    assert exc.value.code == 404


def test_unknown_path_is_404(server):
    base, _ = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        get(f"{base}/secret", token=None)
    assert exc.value.code == 404


def test_non_loopback_bind_is_refused(config, capsys):
    config.dashboard["bind"] = "0.0.0.0"
    assert serve(config) == 2
    assert "localhost-only" in capsys.readouterr().out


def test_api_object_works_without_a_server(config, attack_chain):
    with Pipeline(config) as pipeline:
        pipeline.run_file(attack_chain)
        api = Api(config, store=pipeline.store)
        assert api.health()["ok"] is True
        assert api.summary()["events"] == 35
        assert api.tree()
        assert api.flows()["nodes"]
        assert api.timeline(hours=240000)
        assert api.packages()["packages"] is not None


def test_edge_scoring_rules():
    assert Api._edge_score({"dport": 4444, "conns": 1, "bytes_out": 0}) >= 40
    assert Api._edge_score({"dport": 443, "conns": 10, "bytes_out": 0}) >= 20
    assert Api._edge_score({"dport": 443, "conns": 1, "bytes_out": 6_000_000}) >= 25
    assert Api._edge_score({"dport": 443, "conns": 1, "bytes_out": 10}) == 0
