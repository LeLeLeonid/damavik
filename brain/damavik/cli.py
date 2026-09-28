# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""``damavik`` command line interface.

Everything the dashboard shows is reachable here, because a box under attack
is often a box you are on over SSH.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any

from . import SCHEMA_VERSION, __version__
from .config import Config, ConfigError
from .config import load as load_config
from .journal import Journal
from .journal import verify as verify_journal
from .osv import OsvMirror
from .pipeline import Pipeline
from .pkgwatch import PkgWatch, read_dpkg_status
from .rules import load_rules_dir
from .schema import utcnow_iso, validate_event
from .sensorpy import ProcSensor, tail_dns_log
from .store import Store

LEVEL_COLOR = {
    "critical": "\033[31m",
    "high": "\033[91m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[37m",
}
RESET = "\033[0m"


def use_color(stream: Any = None) -> bool:
    """Colour only for a real terminal, and never when ``NO_COLOR`` is set.

    A monitor's output gets piped into grep and log shippers more often than it
    gets read, so escape codes must be opt-out-by-default, not opt-in.
    """
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    stream = stream if stream is not None else sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def _level_color(level: str, use: bool) -> tuple[str, str]:
    """ANSI prefix/suffix pair for a level; both empty when colour is off."""
    if not use:
        return "", ""
    return LEVEL_COLOR.get(level, ""), RESET


def _emit(obj: Any, as_json: bool, human: str) -> None:
    if as_json:
        print(json.dumps(obj, sort_keys=True, default=str))
    else:
        print(human)


def repo_root() -> str:
    """The checkout root, derived from the package location.

    Defaults for ``rules/`` and the demo fixture must not depend on the current
    working directory: the documented way to run the brain is ``cd brain &&
    python3 -m damavik.cli …``, and an installed copy has neither ``rules/`` nor
    ``tests/`` next to the CWD.
    """
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def package_data_dir() -> str:
    """Where a ``pip install`` keeps the vendored rules and fixtures."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def data_candidates(name: str) -> list[str]:
    """Every place a shipped path may live, most specific first.

    The current directory, the checkout root, the copy vendored inside the
    installed package (``damavik/data/``, which ``pip install`` ships), then
    ``/usr/share/damavik`` where ``packaging/install.sh`` puts things.

    Overrides are *not* part of this search: ``--rules-dir``/``--fixture`` and
    the ``DAMAVIK_*`` variables (see ``config.ENV_OVERRIDES``) are applied by
    the caller, so there is exactly one mechanism per override.
    """
    return [
        os.path.join(os.getcwd(), name),
        os.path.join(repo_root(), name),
        os.path.join(package_data_dir(), name),
        os.path.join("/usr/share/damavik", name),
    ]


def find_data(name: str, override: str | None = None) -> str:
    """Resolve a shipped data path (``rules``, the demo capture) to something real.

    ``override`` is taken verbatim - an operator who named a path means it, and
    a wrong path must be reported as such rather than silently replaced by a
    default.  Everything else falls back to the first existing entry of
    :func:`data_candidates`, or, when nothing exists, the current-directory
    candidate, so the error message points somewhere the operator can act on.
    """
    if override:
        return os.path.expanduser(override)
    candidates = data_candidates(name)
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return candidates[0]


def data_hint(name: str) -> str:
    """One line telling an operator where a shipped path comes from."""
    return (
        f"hint: {name} ships with the checkout, with `pip install` and with "
        "`packaging/install.sh` (which installs it under /usr/share/damavik).  "
        "Pass the path explicitly to use your own copy."
    )


DEFAULT_RULES = "rules"
DEFAULT_FIXTURE = os.path.join("tests", "fixtures", "attack-chain.jsonl")


def _config(args: argparse.Namespace) -> Config:
    cfg = load_config(getattr(args, "config", None))
    if getattr(args, "offline", False):
        cfg.offline = True
    if getattr(args, "state_dir", None):
        cfg.state_dir = args.state_dir
    if getattr(args, "rules_dir", None):
        cfg.rules["dir"] = args.rules_dir
    elif cfg.rules.get("dir") in (None, "", "rules"):
        cfg.rules["dir"] = find_data(DEFAULT_RULES)
    return cfg


def _score_bar(score: float, width: int = 10) -> str:
    filled = int(round(score / 100.0 * width))
    return "#" * filled + "." * (width - filled)


# ---------------------------------------------------------------- subcommands
def cmd_run(args: argparse.Namespace) -> int:
    cfg = _config(args)
    with Pipeline(cfg) as pipeline:
        if args.file:
            pipeline.run_file(args.file, rebase=args.rebase)
        else:
            pipeline.run(sys.stdin)
        stats = pipeline.stats.as_dict()
        stats["ingest"] = pipeline.ingest_stats.as_dict()
        stats["rules_loaded"] = len(pipeline.rules)
        _emit(
            stats,
            args.json,
            f"events={stats['events']} alerts={stats['alerts']} "
            f"rules={stats['rules_loaded']} rejected={stats['ingest']['rejected']}",
        )
        removed = stats["retention_removed"]
        if removed["events"] or removed["alerts"]:
            print(
                f"retention: pruned {removed['events']} events and {removed['alerts']} "
                f"alerts older than {cfg.retention_days} days from the inherited index",
                file=sys.stderr,
            )
        if stats["stale_capture_s"]:
            days = stats["stale_capture_s"] / 86400.0
            print(
                f"note: the newest event in this capture is {days:.1f} days old "
                f"(retention_days={cfg.retention_days}, dashboard window 24 h). "
                "Re-run with --rebase to replay it on the current clock.",
                file=sys.stderr,
            )
    return 0


def cmd_sensor(args: argparse.Namespace) -> int:
    cfg = _config(args)
    sensor = ProcSensor(
        host=cfg.resolved_host_id(),
        exec_hash=bool(cfg.sensor.get("exec_hash", True)),
        flows=bool(cfg.sensor.get("flows", True)),
    )
    # Held open for the life of the command and closed in the finally block
    # below; a sensor writing one event at a time must not reopen per event.
    out = open(args.out, "a", encoding="utf-8") if args.out else sys.stdout  # noqa: SIM115
    try:
        if args.dns_tail:
            import threading

            threading.Thread(
                target=tail_dns_log, args=(args.dns_tail, sensor, out), daemon=True
            ).start()
        sensor.run(interval=args.interval, out=out, once=args.once)
    finally:
        if out is not sys.stdout:
            out.close()
    return 0


def cmd_tail(args: argparse.Namespace) -> int:
    cfg = _config(args)
    store = Store(cfg.db_path())
    last_id = 0
    try:
        while True:
            rows = store.events_since(last_id)
            for row_id, event in rows:
                last_id = row_id
                score = float(event.get("score", 0.0))
                if args.alerts_only and score < float(cfg.alerts.get("min_score", 45)):
                    continue
                exe = (event.get("proc") or {}).get("exe") or ""
                target = (
                    exe
                    or (event.get("net") or {}).get("dst")
                    or (event.get("dns") or {}).get("q")
                    or ""
                )
                _emit(
                    event,
                    args.json,
                    f"{event.get('ts')} {str(event.get('type')):13s} [{_score_bar(score)}] "
                    f"{score:5.1f} {target[:60]:60s} {','.join(event.get('tags') or [])}",
                )
            if args.once:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        store.close()
    return 0


def cmd_ps_tree(args: argparse.Namespace) -> int:
    cfg = _config(args)
    store = Store(cfg.db_path())
    roots = store.process_tree(args.pid)
    store.close()

    def render(node: dict[str, Any], prefix: str, is_last: bool, out: list[str]) -> None:
        connector = "└─ " if is_last else "├─ "
        name = os.path.basename(node["exe"] or "?") or "?"
        score = float(node["score"] or 0.0)
        out.append(
            f"{prefix}{connector}{node['pid']:>6} {name:<28} "
            f"{(node['user'] or '-'):<10} [{_score_bar(score, 6)}] {score:5.1f}"
        )
        children = sorted(node["children"], key=lambda child: child["pid"])
        extension = "   " if is_last else "│  "
        for index, child in enumerate(children):
            render(child, prefix + extension, index == len(children) - 1, out)

    lines: list[str] = []
    for index, root in enumerate(sorted(roots, key=lambda n: n["pid"])):
        render(root, "", index == len(roots) - 1, lines)
    if args.json:
        print(json.dumps(roots, sort_keys=True, default=str))
    else:
        print("\n".join(lines) if lines else "(no processes recorded yet)")
    return 0


def cmd_flows(args: argparse.Namespace) -> int:
    cfg = _config(args)
    store = Store(cfg.db_path())
    rows = store.flow_aggregates(pid=args.pid, limit=args.limit)
    store.close()
    if args.json:
        print(json.dumps(rows, sort_keys=True, default=str))
        return 0
    if not rows:
        print("(no flows recorded yet)")
        return 0
    print(f"{'pid':>6} {'proto':5} {'destination':<40} {'port':>6} {'conns':>6} {'out':>10}")
    for row in rows:
        print(
            f"{str(row['pid'] or '-'):>6} {row['proto'] or '-':5} {row['dst']:<40} "
            f"{str(row['dport'] or '-'):>6} {row['conns']:>6} {row['bytes_out']:>10}"
        )
    return 0


def cmd_top_risks(args: argparse.Namespace) -> int:
    cfg = _config(args)
    store = Store(cfg.db_path())
    events = store.top_events(limit=int(args.limit))
    store.close()
    if args.json:
        print(json.dumps(events, sort_keys=True, default=str))
        return 0
    if not events:
        print("(nothing recorded yet)")
        return 0
    for event in events:
        proc = event.get("proc") or {}
        net = event.get("net") or {}
        dns = event.get("dns") or {}
        target = proc.get("exe") or net.get("dst") or dns.get("q") or "-"
        score = float(event.get("score", 0.0))
        print(
            f"{score:5.1f} [{_score_bar(score, 8)}] {event.get('ts')} "
            f"{str(event.get('type')):12s} {os.path.basename(str(target))[:44]:44s} "
            f"{','.join(event.get('tags') or [])[:40]}"
        )
    return 0


def cmd_alerts(args: argparse.Namespace) -> int:
    cfg = _config(args)
    store = Store(cfg.db_path())
    alerts = store.alerts(limit=args.limit, status=args.status)
    store.close()
    if args.json:
        print(json.dumps(alerts, sort_keys=True, default=str))
        return 0
    if not alerts:
        print("(no alerts)")
        return 0
    colour = use_color()
    for alert in alerts:
        color, reset = _level_color(alert["level"], colour)
        print(
            f"{color}{alert['level'].upper():8s}{reset} {alert['score']:5.1f} {alert['ts']} "
            f"{alert['id']}  {alert['title']}"
        )
        if args.verbose:
            print(f"         rule: {alert['rule'] or '-'}   events: {','.join(alert['events'])}")
            print(f"         why : {alert['explain']}")
            if alert["iocs"]:
                print(f"         iocs: {json.dumps(alert['iocs'], sort_keys=True)}")
    return 0


def _osv_dir(cfg: Config, override: str | None) -> str:
    """Mirror directory: flag > config > default."""
    if override:
        return override
    return str((cfg.intel.get("osv_mirror") or {}).get("dir") or "~/.local/share/damavik/osv")


def cmd_pkg_list(args: argparse.Namespace) -> int:
    cfg = _config(args)
    with Pipeline(cfg) as pipeline:
        mirror = OsvMirror(_osv_dir(cfg, args.osv_dir))
        mirror.load_dir()
        watch = PkgWatch(store=pipeline.store, mirror=mirror, host=cfg.resolved_host_id())
        scan: dict[str, Any] | None = None
        if args.scan:
            scan = _scan_packages(pipeline, watch, args)
        packages = pipeline.store.packages(manager=args.manager)
        vulnerable = watch.vulnerable()
    if args.json:
        print(
            json.dumps(
                {"scan": scan, "packages": packages, "vulnerable": vulnerable}, sort_keys=True
            )
        )
        return 0
    if scan:
        print(
            f"scanned {scan['scanned']} packages, {scan['changes']} changes, "
            f"{scan['removed']} removed"
        )
    print(f"{len(packages)} packages tracked, {len(vulnerable)} with a known CVE")
    for item in vulnerable[: args.limit]:
        print(
            f"  {item['severity']:8s} {item['manager']}:{item['name']} {item['version']}"
            f"  -> {', '.join(item['cves'][:4])}"
        )
    return 0


def _scan_packages(pipeline: Pipeline, watch: PkgWatch, args: argparse.Namespace) -> dict[str, Any]:
    """Diff the inventory and turn the findings into ``pkg.event`` rows.

    Returns the scan summary.  Only *news* becomes events - a new install, a
    package that now matches the OSV mirror, or a removal - so a steady-state
    scan of an unchanged host writes nothing.  The first scan on a host is a
    baseline: it records the inventory and stays silent, because "everything was
    installed since the previous scan" is true of every package on a fresh
    install.
    """
    snapshot = read_dpkg_status(args.dpkg_status)
    baseline = not pipeline.store.packages()
    changes = watch.scan(snapshot)
    removed = watch.diff_removed(snapshot)
    scan: dict[str, Any] = {
        "scanned": len(snapshot),
        "changes": len(changes),
        "removed": len(removed),
        "baseline": baseline,
        "events": 0,
        "alerts": 0,
    }
    if baseline:
        return scan
    # ``seen`` means "already known and nothing new to say about it".  Only new
    # arrivals (``install``, which includes a package that came back) and
    # departures are news.  A package that merely *stays* installed and
    # vulnerable is reported by ``vulnerable()``; re-emitting it on every scan
    # would be one repeat alert per poll, and there is no per-package advisory
    # state to tell "newly vulnerable" from "still vulnerable" (P1).
    interesting = [change for change in changes if change.action != "seen"] + removed
    pipeline.apply_storage_policy()
    for change in interesting:
        pipeline.process(change.as_event(utcnow_iso(), pipeline.host))
    pipeline.finish()
    scan["events"] = len(interesting)
    scan["alerts"] = pipeline.stats.alerts
    return scan


def cmd_osv_sync(args: argparse.Namespace) -> int:
    cfg = _config(args)
    directory = _osv_dir(cfg, args.dir)
    mirror = OsvMirror(directory)
    loaded = mirror.load_dir(directory)
    store = Store(cfg.db_path())
    rows = mirror.load_into_store(store) if args.index else 0
    stats = mirror.stats()
    stats["rows_indexed"] = rows
    store.set_meta("osv_dir", directory)
    store.close()
    _emit(
        stats,
        args.json,
        f"loaded {stats['advisories']} advisories from {directory}, indexed {rows} rows",
    )
    if loaded == 0:
        print(
            f"hint: place OSV records (*.json) or an ecosystem all.zip in {mirror.directory}",
            file=sys.stderr,
        )
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    cfg = _config(args)
    path = cfg.journal_path()
    if not os.path.exists(path):
        # A missing journal is not automatically fine: if the index has events,
        # the audit trail was deleted, and "OK: 0 entries" would be a gate that
        # cannot fail.
        indexed = 0
        if os.path.exists(cfg.db_path()):
            store = Store(cfg.db_path())
            try:
                indexed = store.count_events()
            finally:
                store.close()
        if indexed:
            _emit(
                {"ok": False, "entries": 0, "reason": "journal missing", "path": path},
                args.json,
                f"journal MISSING at {path} but {indexed} events are indexed: "
                "the audit trail was deleted, not never written",
            )
            return 2
        _emit(
            {"ok": True, "entries": 0, "reason": "no journal yet", "path": path},
            args.json,
            f"no journal yet at {path}: nothing has been ingested on this host",
        )
        return 0
    journal = Journal(path)
    report = verify_journal(journal)
    _emit(
        report.as_dict(),
        args.json,
        f"journal {'OK' if report.ok else 'BROKEN'}: {report.entries} entries"
        + (f", first bad line {report.first_bad_line}: {report.reason}" if not report.ok else ""),
    )
    journal.close()
    return 0 if report.ok else 2


def cmd_status(args: argparse.Namespace) -> int:
    cfg = _config(args)
    store = Store(cfg.db_path())
    summary = store.summary()
    ruleset, errors = load_rules_dir(cfg.rules.get("dir", "rules"))
    summary["rules"] = len(ruleset)
    summary["rule_errors"] = errors
    summary["config"] = cfg.source_path or "(defaults)"
    summary["offline"] = cfg.offline
    summary["enabled_intel"] = sorted(cfg.enabled_intel())
    store.close()
    if args.json:
        print(json.dumps(summary, sort_keys=True, default=str))
        return 0
    for key, value in sorted(summary.items()):
        print(f"{key:20s} {value}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .dash.server import serve

    cfg = _config(args)
    if args.port:
        cfg.dashboard["port"] = args.port
    return serve(cfg)


def cmd_purge(args: argparse.Namespace) -> int:
    cfg = _config(args)
    if not args.yes:
        print("refusing to purge without --yes", file=sys.stderr)
        return 2
    store = Store(cfg.db_path())
    store.purge()
    store.close()
    journal_path = cfg.journal_path()
    if os.path.exists(journal_path):
        os.remove(journal_path)
    alerts = cfg.alerts_path()
    if os.path.exists(alerts):
        os.remove(alerts)
    print("purged database, journal and alerts")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Schema-check a JSONL capture.  Used by CI on every fixture.

    This walks raw lines rather than the normalised stream, because ingest
    already rejects what it cannot use - validating only the survivors would
    report a clean bill of health for a broken sensor.
    """
    from .normalize import parse_line

    total = accepted = problems = 0
    with open(os.path.expanduser(args.file), encoding="utf-8", errors="replace") as handle:
        for lineno, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            total += 1
            event, reason = parse_line(line)
            if event is None:
                problems += 1
                if reason not in (None, "empty"):
                    print(f"line {lineno}: {reason}")
                continue
            errors = validate_event(event)
            if errors:
                problems += 1
                print(f"line {lineno}: {'; '.join(errors)}")
                continue
            accepted += 1
    print(f"validated {total} lines from {args.file}: {accepted} ok, {problems} invalid")
    return 1 if problems else 0


def cmd_selftest(args: argparse.Namespace) -> int:
    """End-to-end proof that an install works, without root or network."""
    from .pipeline import Pipeline

    failures: list[str] = []
    ruleset, errors = load_rules_dir(find_data(DEFAULT_RULES, args.rules_dir))
    if errors:
        failures.extend(errors)
    if len(ruleset) == 0:
        failures.append("no rules loaded")
    fixture = find_data(DEFAULT_FIXTURE, args.fixture)
    if not os.path.exists(fixture):
        failures.append(f"demo fixture missing: {fixture}")
        failures.append(data_hint(DEFAULT_FIXTURE))
        _emit({"ok": False, "failures": failures}, args.json, "selftest FAILED")
        return 1
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(
            state_dir=tmp,
            rules={"dir": find_data(DEFAULT_RULES, args.rules_dir)},
            offline=True,
            alerts={"path": "alerts.log", "notify": False, "cooldown_s": 0, "min_score": 45},
        )
        with Pipeline(cfg) as pipeline:
            pipeline.run_file(fixture, rebase=True)
            stats = pipeline.stats.as_dict()
            summary = pipeline.store.summary()
            summary_alerts = pipeline.store.alerts(limit=100)
            dropped = [
                alert["id"] for alert in summary_alerts if not alert.get("explain", "").strip()
            ]
            report = verify_journal(pipeline.journal)
        if stats["events"] == 0:
            failures.append("no events were processed")
        if stats["alerts"] == 0:
            failures.append("the attack-chain fixture produced no alerts")
        if not report.ok:
            failures.append(f"journal chain broken: {report.reason}")
        if dropped:
            failures.append(f"alerts with no explanation: {', '.join(dropped)}")
        # Assert the *stored* result, not the in-memory counters.  A previous
        # version of this function reported "selftest OK ... alerts=27" while
        # the index held zero rows, which made it a gate that could not fail -
        # and it is the gate `packaging/install.sh` refuses to install without.
        if summary["events"] != stats["events"]:
            failures.append(
                f"only {summary['events']} of {stats['events']} events are in the index"
            )
        if int(summary["alerts"]) != len(summary_alerts) or not summary_alerts:
            failures.append(
                f"the index holds {summary['alerts']} alerts but returned {len(summary_alerts)}"
            )
        ranked = [alert for alert in summary_alerts if alert["level"] in ("high", "critical")]
        if not ranked:
            failures.append("no alert reached high or critical - the chain is not detected")
        if stats["retention_removed"]["events"]:
            failures.append(
                f"retention pruned {stats['retention_removed']['events']} events during the run"
            )
    result = {
        "ok": not failures,
        "version": __version__,
        "schema_version": SCHEMA_VERSION,
        "rules": len(ruleset),
        "stats": stats,
        "summary": summary,
        "alerts": len(summary_alerts),
        "journal": report.as_dict(),
        "failures": failures,
    }
    _emit(
        result,
        args.json,
        f"selftest {'OK' if not failures else 'FAILED'}: rules={len(ruleset)} "
        f"events={stats['events']} alerts={stats['alerts']} "
        f"stored_alerts={len(summary_alerts)} "
        f"journal={'ok' if report.ok else 'broken'}",
    )
    for failure in failures:
        print(f"  ! {failure}", file=sys.stderr)
    return 0 if not failures else 1


def cmd_bench(args: argparse.Namespace) -> int:
    """Measure the pipeline's own budgets."""
    import tempfile

    from .replay import expand

    fixture = find_data(DEFAULT_FIXTURE, args.fixture)
    with open(fixture, encoding="utf-8") as handle:
        base_lines = [line for line in handle if line.strip()]
    if not base_lines:
        print(f"no events in {fixture}", file=sys.stderr)
        return 1
    lines = list(expand(base_lines, args.events))
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(
            state_dir=tmp,
            rules={"dir": find_data(DEFAULT_RULES, args.rules_dir)},
            offline=True,
            alerts={"path": "alerts.log", "notify": False, "cooldown_s": 0, "min_score": 45},
        )
        started = time.perf_counter()
        with Pipeline(cfg) as pipeline:
            pipeline.run(lines)
            elapsed = time.perf_counter() - started
            count = pipeline.stats.events
            rules = len(pipeline.rules)
        per_event_us = (elapsed / count) * 1e6 if count else 0.0
        rule_budget_us = per_event_us / rules if rules else 0.0
        rss_kb = _rss_kb()
    result = {
        "events": count,
        "rules": rules,
        "elapsed_s": round(elapsed, 4),
        "us_per_event": round(per_event_us, 1),
        "us_per_event_per_rule": round(rule_budget_us, 2),
        "rss_kb": rss_kb,
        "budget_us_per_event": 1000.0,
        "within_budget": per_event_us <= 1000.0,
    }
    print(json.dumps(result, sort_keys=True))
    if args.gate and not result["within_budget"]:
        print("budget gate FAILED", file=sys.stderr)
        return 1
    return 0


def _rss_kb() -> int:
    try:
        with open("/proc/self/status", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Load the demo capture into a throwaway state dir and print what happened."""
    import tempfile

    fixture = find_data(DEFAULT_FIXTURE, args.fixture)
    if not os.path.exists(fixture):
        print(f"missing fixture: {fixture}", file=sys.stderr)
        print(data_hint(DEFAULT_FIXTURE), file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(
            state_dir=tmp,
            rules={"dir": find_data(DEFAULT_RULES, args.rules_dir)},
            offline=True,
            alerts={"path": "alerts.log", "notify": False, "cooldown_s": 0, "min_score": 45},
        )
        with Pipeline(cfg) as pipeline:
            # The shipped capture is synthetic: replay it on the current clock
            # so the demo, the timeline and retention all agree, today and in a
            # year's time.
            pipeline.run_file(fixture, rebase=True)
            alerts = pipeline.store.alerts(limit=args.limit)
            stats = pipeline.stats.as_dict()
        if args.json:
            print(json.dumps({"stats": stats, "alerts": alerts}, sort_keys=True, default=str))
            return 0
        print(
            f"processed {stats['events']} events -> {stats['alerts']} alerts "
            f"(showing {len(alerts)})\n"
        )
        for alert in alerts:
            print(f"  [{alert['level'].upper():8s}] {alert['score']:5.1f}  {alert['title']}")
            print(f"             why: {alert['explain'][:110]}")
    return 0


# ------------------------------------------------------------------- plumbing
def add_runtime_options(parser: argparse.ArgumentParser, *, suppress: bool = False) -> None:
    """The options that apply to every subcommand.

    They are accepted both before and after the subcommand.  ``suppress`` (used
    for the per-subcommand copies) keeps argparse from resetting a value that
    was already parsed at the top level.
    """
    default: Any = argparse.SUPPRESS if suppress else None
    parser.add_argument("--config", default=default, metavar="PATH", help="path to damavik.yaml")
    parser.add_argument(
        "--offline",
        action="store_true",
        default=default,
        help="kill every intel plugin for this run",
    )
    parser.add_argument(
        "--state-dir", default=default, metavar="PATH", help="override the state directory"
    )
    parser.add_argument(
        "--rules-dir", default=default, metavar="PATH", help="override the rules directory"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="damavik",
        description="Local-first threat monitor.  Nothing leaves the box.",
    )
    parser.add_argument("--version", action="version", version=f"damavik {__version__}")
    add_runtime_options(parser)
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name: str, func: Any, help_text: str) -> argparse.ArgumentParser:
        child = sub.add_parser(name, help=help_text, description=help_text)
        # Runtime options also after the subcommand: the systemd units ship
        # `damavik run --config /etc/damavik/damavik.yaml`, and a global-only
        # --config turned that into "unrecognized arguments" - a service that
        # could never start.  SUPPRESS keeps a value given before the
        # subcommand when none is given after it.
        add_runtime_options(child, suppress=True)
        child.set_defaults(func=func)
        return child

    run = add("run", cmd_run, "read JSONL events from stdin or a file and run the pipeline")
    run.add_argument("--file", help="read from a file instead of stdin")
    run.add_argument(
        "--rebase",
        action="store_true",
        help="replay a capture on the current clock, preserving its spacing "
        "(default: keep the recorded timestamps)",
    )
    run.add_argument("--json", action="store_true")

    sensor = add("sensor", cmd_sensor, "run the pure-Python reference sensor (no root needed)")
    sensor.add_argument("--interval", type=float, default=2.0)
    sensor.add_argument("--once", action="store_true", help="one poll pass, then exit")
    sensor.add_argument("--out", help="append JSONL to this file instead of stdout")
    sensor.add_argument("--dns-tail", help="tail a resolver log for dns.query events")

    tail = add("tail", cmd_tail, "stream recorded events")
    tail.add_argument("--alerts-only", action="store_true")
    tail.add_argument("--once", action="store_true")
    tail.add_argument("--interval", type=float, default=1.0)
    tail.add_argument("--json", action="store_true")

    tree = add("ps-tree", cmd_ps_tree, "render the process tree with risk scores")
    tree.add_argument("--pid", type=int)
    tree.add_argument("--json", action="store_true")

    flows = add("flows", cmd_flows, "aggregated flows, optionally for one PID")
    flows.add_argument("--pid", type=int)
    flows.add_argument("--limit", type=int, default=50)
    flows.add_argument("--json", action="store_true")

    top = add("top-risks", cmd_top_risks, "highest-scored events")
    top.add_argument("--limit", type=int, default=20)
    top.add_argument("--json", action="store_true")

    alerts = add("alerts", cmd_alerts, "the alert inbox")
    alerts.add_argument("--limit", type=int, default=20)
    alerts.add_argument("--status")
    alerts.add_argument("-v", "--verbose", action="store_true")
    alerts.add_argument("--json", action="store_true")

    pkg = add("pkg-list", cmd_pkg_list, "package inventory and CVE matches")
    pkg.add_argument("--manager")
    pkg.add_argument("--osv-dir", help="OSV mirror directory (default: config)")
    pkg.add_argument("--scan", action="store_true", help="refresh from /var/lib/dpkg/status")
    pkg.add_argument("--dpkg-status", default="/var/lib/dpkg/status")
    pkg.add_argument("--limit", type=int, default=20)
    pkg.add_argument("--json", action="store_true")

    osv = add("osv-sync", cmd_osv_sync, "load the local OSV mirror into the index")
    osv.add_argument("--dir", help="directory holding OSV records or all.zip")
    osv.add_argument("--index", action="store_true", help="also write the cves table")
    osv.add_argument("--json", action="store_true")

    verify = add("verify", cmd_verify, "verify the hash-chained journal")
    verify.add_argument("--json", action="store_true")

    status = add("status", cmd_status, "counts, config and rule health")
    status.add_argument("--json", action="store_true")

    serve = add("serve", cmd_serve, "run the localhost dashboard")
    serve.add_argument("--port", type=int)

    purge = add("purge", cmd_purge, "delete every trace Damavik has stored")
    purge.add_argument("--yes", action="store_true")

    validate = add("validate", cmd_validate, "schema-check a JSONL capture")
    validate.add_argument("file")

    selftest = add("selftest", cmd_selftest, "prove the install works, offline, no root")
    selftest.add_argument("--fixture")
    selftest.add_argument("--json", action="store_true")

    bench = add("bench", cmd_bench, "measure pipeline throughput against the budgets")
    bench.add_argument("--events", type=int, default=2000)
    bench.add_argument("--fixture")
    bench.add_argument("--gate", action="store_true", help="exit non-zero if over budget")

    demo = add("demo", cmd_demo, "run the shipped attack-chain capture and show the alerts")
    demo.add_argument("--fixture")
    demo.add_argument("--limit", type=int, default=20)
    demo.add_argument("--json", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
