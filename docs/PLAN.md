<!--
SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
SPDX-License-Identifier: GPL-3.0-only
-->

# Damavik: audit, MVP fixes, roadmap

Written after a full read of the repository plus hands-on runs of every command
on a Linux box (no root, no network).  Findings are ordered by what they cost
the *product*, and every one names the evidence that produced it.

**Headline:** the architecture was already sound; four defects made the
product look broken.  One storage rule deleted the batch it had just ingested
(25 of 376 tests red, `demo` showing nothing, `selftest` passing over an empty
database); correlation windows ran on wall-clock time, so replays were
meaningless as timelines; the egress rules alerted on loopback and LAN
traffic, so a quiet box produced alerts; and the documented way to install the
CLI (`pip install ./brain`) failed outright because the package metadata
reached outside the package root.  All four are fixed and regression-tested.
Everything else below is either hygiene or roadmap.

---

## 1. What is built

| Layer | State |
|---|---|
| Brain (`brain/damavik`, stdlib only) | 20 modules: normalize, enrich, 20-rule Sigma-subset engine, scorer, hash-chained journal, SQLite index, alerts with dedup/cooldown, JSON API + zero-dependency dashboard |
| Sensor | `sensor-py` polls `/proc` (exec + flows). The eBPF sensor does not exist yet; DNS needs `--dns-tail` |
| Rules | 20 rules across process/file/network/DNS/persistence/supply-chain, each with TP+FP fixtures |
| Packaging | POSIX `install.sh` with DRY_RUN, two hardened systemd units, a `pip install` that works |
| Gates | ruff lint + format, pytest, end-to-end selftest, perf gate (1 ms/event), REUSE licence check |

A coherent P0 product: a local-first, dependency-free host monitor whose value
is *explainable* alerting with no cloud.

## 2. P0 — fixed in this pass

### 2.1 Retention deleted the batch the run had just ingested

`Pipeline.finish()` called `Store.apply_retention(7)` — the config default —
which deletes rows with `ts_ms < now - 7d`.  A replayed capture carries its
*recorded* timestamps, so any capture older than a week was deleted by the same
call that ingested it.

Evidence on the checkout as shipped (fixture dated 2026-09-10, run 2026-09-27):

```
$ python3 -m damavik.cli demo
processed 35 events -> 27 alerts (showing 0)      # 27 counted, 0 in the database

$ python3 -m damavik.cli run --file tests/fixtures/attack-chain.jsonl
events=35 alerts=24 rules=20 rejected=0
$ python3 -m damavik.cli status
events 0   alerts 0                               # deleted at finish()

$ python3 -m pytest ../tests -q
25 failed, 351 passed
```

Blast radius: `demo` (the first-run experience), every command that reads the
index after a replay, all dashboard endpoints, 25 tests, the perf harness.

It hid behind a broken safety net: `selftest` — which `install.sh` refuses to
install without — asserted on *in-memory* counters and never checked the index,
so it printed `selftest OK: rules=20 events=35 alerts=27 journal=ok` over an
empty database.  A gate that cannot fail is worse than no gate.

**Fix.** Retention prunes the index a run *inherits*, once, when the run starts
(`Pipeline.apply_storage_policy`).  A run never prunes the batch it is
processing.  `selftest` now asserts the stored evidence: event count, alert
count, at least one high/critical alert, explanations present, journal intact.

### 2.2 Correlation ran on the wall clock instead of the event clock

`RuleSet.evaluate()` defaulted `now` to `time.time()`, so a replay — demo,
bench, forensic reload, every test — squeezed hours of capture into
microseconds: "10 queries to one domain in 60 s" and "6 connections to one
destination in 120 s" fired on *every* replay regardless of spacing, and two
genuinely separate bursts would merge.  Windows now follow the event's `ts`
(wall clock only as a fallback for events with no usable timestamp), buckets are
inserted in order so an out-of-order event cannot inflate a count, and the
window map is bounded (`RuleSet.WINDOW_LIMIT`) so a long-lived monitor cannot
leak.

### 2.3 Egress rules alerted on traffic that never leaves the host

Measured on an idle box with the shipped sensor, before the fix:

```
$ damavik sensor --once | damavik run ...     # nobody using the machine
{"events": 143, "alerts": 2, "rule_hits": {"DMK-N-003": 52}}
MEDIUM 49.0  Repeated egress to one destination (beacon proxy)
```

36 of those connections were to `127.0.0.1` and 26 to the host's own address:
local IPC, reported by the sensor and then scored as egress.  The enricher now
classifies each destination (`meta.is_local` for loopback/unspecified/
multicast/link-local, `meta.is_private` for RFC1918/ULA/reserved), and the four
network rules use it: DMK-N-001/002/004 ignore non-egress, and DMK-N-003
("repeated egress", the weakest signal) also ignores LAN destinations.  Flow
records are still stored, scored and shown in the graph either way — they just
stop raising alerts.  The same box now reports `alerts: 0, rule_hits: {}`.

### 2.4 The shipped demo capture rotted

Absolute timestamps in a fixture mean the dashboard's default 24-hour timeline
renders empty once the calendar moves.  `replay.rebase()` shifts a capture onto
the current clock while preserving every interval; `demo`, `selftest` and
`bench` use it, `run --file X --rebase` exposes it, and `run --file` stays
forensic by default (recorded time, with a note when the batch is older than the
retention window).  `replay.expand()` — the benchmark generator — now *ends* at
now instead of being anchored to a hard-coded epoch, so it cannot generate
history that retention prunes on sight or that lands in the future.

### 2.5 Every installed path was broken

The repository runs in place, which is why none of this showed up in the test
suite: `cd brain && python3 -m damavik.cli …` is the path that gets exercised.
The two paths an operator actually follows - `pip install .` and
`sudo ./packaging/install.sh` - were both dead, for six separate reasons.

**a. `pip install` failed at the metadata stage.**  `brain/pyproject.toml`
declared `readme = "../README.md"`, and setuptools refuses to read outside the
package root:

```
$ pip install ./brain
distutils.errors.DistutilsOptionError: Cannot access '/…/brain/../README.md'
(or anything outside '/…/brain')
```

**b. …and behind it, an installed brain had no data.**  With the build fixed, the
wheel still carried neither the ruleset nor the demo capture, and
`cli.find_data()` looked only at the CWD, the checkout and `/usr/share/damavik`.
An installed copy reported `rules directory not found` and could not score a
single event.  **Fix:** one manifest at the repository root
(`package-dir = {"" = "brain"}` keeps the in-place layout working), the ruleset
and demo capture vendored under `brain/damavik/data/` and shipped as package
data, `find_data()` (now built on `data_candidates()`) extended to look there,
and `tests/test_packaging.py` failing if the vendored copies drift from `rules/`
and `tests/fixtures/`.

**c. The installer's launcher could not import its own code.**

```
$ python3 /usr/share/damavik/damavik/cli.py --version
ImportError: attempted relative import with no known parent package
```

`packaging/install.sh` wrote `exec python3 "$SHARE_DIR/damavik/cli.py" "$@"`.
`cli.py` is a module inside a package and uses relative imports, so the command
the installer put in `/usr/local/bin` - the one both units call - failed before
printing a usage line.  **Fix:** the launcher runs
`PYTHONPATH="$SHARE_DIR" python3 -m damavik.cli "$@"`, and the installer now
verifies the **installed** command (`"$BIN_DIR/damavik" --offline selftest`)
instead of only the checkout it was built from.  A gate that could not fail is
why this shipped; `install.sh` also stopped needing root for prefix installs, so
CI can run it end to end.

**d. The units monitored nothing, and one of them killed itself every 120 s.**

* `damavik-brain.service` ran `damavik run` with `StandardInput=null`: the brain
  reads EOF, ingests nothing, exits 0 - and a `Type=simple` unit with
  `Restart=on-failure` is then simply inactive.  It never scored an event and
  never served the dashboard its description promised.
* `damavik-sensor.service` was `BindsTo=damavik-brain.service`, so when the
  brain unit went inactive, the sensor unit was stopped with it: enable both and
  the host ends up with no monitor at all.
* The same unit set `WatchdogSec=120s`, which requires a `WATCHDOG=1` ping on
  `$NOTIFY_SOCKET`.  Nothing in Damavik speaks `sd_notify`, so systemd killed a
  healthy sensor every two minutes and `Restart=always` restarted it - a
  self-inflicted gap in the journal every 120 s.
* `Environment=DAMAVIK_STATE_DIR=/var/lib/damavik` and
  `DAMAVIK_RULES_DIR=/usr/share/damavik/rules` were ignored: `config.load()` read
  the file and nothing else, so a hardened unit (ProtectHome,
  ProtectSystem=strict) would have tried to write `~/.local/state/damavik` and
  failed to start.

**Fix:** the monitor is one self-contained unit (`damavik-sensor.service`:
`sensor | run`), the dashboard is its own unit (`damavik-dashboard.service`:
`serve`), neither binds to the other, the watchdog is gone until the sensor can
send a real liveness ping, and `config.apply_env()` gives the units their
`DAMAVIK_*` overrides with the documented precedence *file < environment <
command line*.  A split sensor/brain deployment over a socket needs a reason to
exist first, and that reason is the eBPF sensor in P1.

**e. `--config` only worked before the subcommand.**  The units ship
`damavik run --config /etc/damavik/damavik.yaml`; argparse rejected that with
`unrecognized arguments` because `--config`, `--offline`, `--state-dir` and
`--rules-dir` were registered globally only.  They are now accepted in both
positions (`add_runtime_options`, with `SUPPRESS` defaults so a value given
before the subcommand survives).  Same class of bug: a service that could never
start.

**f. `damavik verify` said OK when there was nothing to verify.**  A missing
journal printed `journal OK: 0 entries` and exited 0, so deleting the audit
trail looked exactly like a fresh install.  It now reports "no journal yet:
nothing has been ingested on this host" (exit 0) only when the index is empty
too, and `journal MISSING … but N events are indexed: the audit trail was
deleted, not never written` (exit 2) otherwise.

### 2.6 The repo's own gates were red

| Gate | Before | After |
|---|---|---|
| `pytest tests/ -q` | 25 failed, 351 passed | 418 passed in ~16 s |
| `ruff check brain tests` | 89 errors | clean |
| `ruff format --check` | 32 files unformatted | clean |
| `pip install .` + `damavik selftest` outside the checkout | `DistutilsOptionError`, then 0 rules | installs, `selftest OK` |
| `install.sh` + the installed launcher | `ImportError`, units inert | installs, `selftest OK`, units run their own `ExecStart` |
| `damavik demo` | "27 alerts (showing 0)" | 20 ranked alerts, each with reasons |
| `damavik selftest` | passed while proving nothing | asserts stored evidence |
| idle-box live run | 2 false-positive alerts | 0 alerts, evidence still scored |
| `reuse lint` (CI licensing job) | not compliant: no `LICENSES/`, one invalid expression | 104/104 files, compliant |

Also fixed: `validate`'s dead `accepted` counter (a clean file printed "0 ok"),
README's stale test count, `sensorpy`'s docstring pointing at a command that
does not exist (`pkg-scan`), and the licensing gate (missing
`LICENSES/GPL-3.0-only.txt`).

### 2.7 Second pass: the code that did nothing, and one bug it was hiding

A read-through of every module with `vulture`, an AST scan for symbols with no
caller outside their own module, and a caller-by-caller grep of each public
method. Two kinds of finding, and the second kind is why this section exists.

**Deleted outright** - dead config keys, dead methods, dead helpers:

| Removed | Why it was dead |
|---|---|
| `sensor.yara`, `osquery.*`, `intel.abuseipdb/otx/vt`, `alerts.webhook` | accepted by the config schema (and in the example YAML, and in `getattr`-style option bags) with no code behind any of them |
| `osquery/` pack + its `.license` sidecar | nothing consumed the log lines; the pack configured a source that does not exist yet |
| `normalize.now_event`, `read_file`; `Store.bulk_insert_events`/`executemany`, `rarest`, `cves_for`; `Scorer.seen_tuples`; `RuleSet._fired`; `AlertSink.notified`; `IntelEnricher.lookups`; `dash.MAX_BODY`; `versions.order_key`; `serve_in_thread` | no caller outside their own tests (or at all); `serve_in_thread` lives in `tests/test_dash.py` now, where it is used |
| `cmd_tail`'s and `cmd_top_risks`'s raw SQL | replaced by `Store.events_since`/`Store.top_events` - one definition of "the newest events" instead of two queries and a `store.conn` reach-through |

**Found by the same walk, and fixed instead of deleted**: `PackageChange.as_event`
built the `pkg.event` rows that `DMK-V-001` (known CVE) and `DMK-V-002` (new
network-capable package) select on - and no code path ever called it. `pkg-list
--scan` diffed the inventory, printed a count and dropped the findings, so on a
live host the two package rules could never fire: twenty rules in `status`, two
of them decorative. `--scan` now runs its findings through the pipeline
(index, journal, alerts, `verify`), with the first scan on a host treated as a
baseline that stays silent - otherwise a fresh install alerts on the entire
operating system it came with. `test_pkg_scan_*` covers both halves.

Wiring the scanner up turned up a second, nastier bug in the same command:
`read_dpkg_status` returns `[]` for a missing or unreadable file, and the diff
read that as "none of the stored packages are installed any more" - a failed
`open()` on `/var/lib/dpkg/status` wrote hundreds of removal events into the
audit trail, i.e. false history.  An empty inventory with a non-empty store is
now a hard error: the scan changes nothing and exits 1, because a scan is what
a timer runs and "file not readable" must not look like a clean pass.

The same check was run on `file.verdict`/`yara`: there is no YARA scanner in the
repo either, but those fields are an *input* contract (documented in
`schema/event.schema.json`, exercised by the shipped capture), not an internal
path the code forgets to call. They stay, and README now documents that a
`yara` tag list is where an external scanner reports findings.


## 3. P1 — next, in this order

1. **eBPF sensor (`sensor/`, Rust + aya).**  The only path to DNS visibility and
   to execution events a poller cannot lose: `/proc` polling misses short-lived
   processes, which is precisely the malware case.  Emit the same JSONL, keep
   `sensor-py` as the no-root fallback and CI data source.  While rewriting the
   sensor, teach it `sd_notify` and bring back a *real* `WatchdogSec=`: today the
   unit has no way to distinguish a hung monitor from a quiet host.
2. **Alert lifecycle.**  Every alert is `open` forever: no ack, no resolve, no
   "I have seen this".  An inbox that can only grow gets ignored.  Needs schema,
   `alerts --ack`, dashboard affordance, and an interaction with dedup.
3. **Process-tree and flow-graph scale.**  `Store.process_tree()` issues one
   detail query per PID (N+1) and `/api/flows` rebuilds every node on every
   4-second poll: fine for a 3 k-event demo, not for a week on a busy host.
4. **Rule tuning with a feedback path.**  `falsepositives:` is parsed and
   unused.  Add `alerts --false-positive` to write the event into
   `tests/fixtures/rule_cases.json` — the contribution model the README asks
   for — and use it to tune the remaining noisy rules (DMK-N-002 in particular
   fires on any newly-executed process that opens a socket; it needs a
   first-seen-destination or rarity term, not just age).
5. **Timeline honesty.**  Views are wall-clock relative; a capture that is not
   current renders as an empty page.  Say "showing data from <range>" and offer
   a range picker.
6. **Correlation state on disk.**  Windows live in memory, so a brain restart
   forgets a ten-minute burst.
7. **OSV autosync.**  Loader, matcher and `cves` table exist; nothing fetches or
   schedules a mirror, and the default mirror directory is outside what the
   packaged unit may write.
8. **osquery/rpm ingestion.**  The dpkg reader is the only package source.  An
   osquery differential consumer (autoruns, listeners, rpm/apk inventories)
   needs a real mapping into `sys.event`/`pkg.event`, which does not exist yet;
   shipping the pack without the consumer was worse than not shipping it.

## 4. P2 — hygiene, do while touching the area

* `Journal.sync()` guards against `self.journal is None`, which cannot happen.
* `Store` caches are keyed by PID/path and only cleared at a size cap; fine
  today, worth a TTL once the brain runs for weeks.
* `intel.osv_mirror.dir` defaults to `~/.local/share/damavik/osv`, which the
  packaged unit cannot read (`ProtectHome=yes`) - and `pkg-list --scan` under
  the shipped unit therefore finds no advisories.  The mirror has to follow
  `$DAMAVIK_STATE_DIR` the way `alerts.path` already does, or the scan has to
  report "mirror not loaded" loudly instead of as `0` matches.
* `packaging/install.sh` copies the tree and writes a launcher; a `pip install .`
  is now a working alternative, so the two paths should share one definition of
  "installed" instead of drifting apart again.
* `rule_cases.json` fixtures carry enrichment fields by hand (`meta.is_local`).
  A small fixture builder that runs the enricher would remove the duplication.
* `pkg-list --scan` cannot tell "still vulnerable" from "newly vulnerable" - the
  `packages` row keeps a version, not the advisory set that matched it.  Today
  that is why a rescan of an unchanged host is silent instead of repeating an
  alert per poll; per-package advisory state removes the compromise.
* Removal inference trusts the snapshot completely: a *partially* read dpkg
  database (truncated file, a parse that stops early) still reads as a mass
  removal.  Only the empty case is guarded; a size heuristic or a checksum of
  the inventory is the real fix.
* Windows artefacts in the rules (`cmd.exe`, `powershell.exe`) imply support
  that does not exist.  README says Linux-only; the rules should carry the same
  note so nobody deploys them expecting Windows coverage.

## 5. P3 — explicitly out of scope

Kernel rootkits, fileless/LOTL chains, a fleet console, a hosted service, a
Windows/macOS sensor, active response.  Damavik is alert-only and local-first by
design; anything that breaks those two sentences is a different product.

## 6. How this was verified

Commands run on the checkout after the fixes, not claims:

* `pytest tests/ -q` → 418 passed in ~16 s, no network, no root.
* `reuse lint` → compliant (104/104 files), the same version CI runs.
* Every CI gate re-run locally as one pass: `ruff check`, `ruff format --check,
  pytest`, `selftest`, the `demo` smoke check, `bench --events 5000 --gate`,
  the rule/schema/privacy jobs and `reuse lint` - 12/12 pass.
* `ruff check brain tests`, `ruff format --check brain tests` → clean.
* `damavik demo` → "processed 35 events -> 27 alerts (showing 20)".
* Fresh venv: `pip install .` then, from `/tmp`, `damavik selftest` →
  `selftest OK: rules=20 events=35 alerts=27 stored_alerts=27 journal=ok`.
* `ALLOW_NONROOT=1 PREFIX=/tmp/fakeroot … sh packaging/install.sh` → exit 0 and
  "the installed command selftest: OK"; then, from `/tmp` with the units'
  `Environment=` lines, the installed launcher ran the units' own `ExecStart`
  (`sensor --once | run --config …` → 124 events, 20 rules, state under
  `$DAMAVIK_STATE_DIR`, `$HOME` untouched) and `serve` answered `/api/summary`.
  The single alert in that capture was DMK-P-002 firing on the `socat` relay
  started in this session to expose the dashboard - a true positive.
* `verify`: fresh state → "no journal yet", exit 0; journal deleted with 35
  events indexed → exit 2, "the audit trail was deleted, not never written";
  tampered record → exit 2, `first bad line 1`; re-serialised record → OK.
* `damavik selftest` → `rules=20 events=35 alerts=27 stored_alerts=27 journal=ok`.
* `damavik bench --events 2000 --gate` → within budget (1 ms/event; measured
  ~0.5 ms/event, ~26 MB RSS).
* Live round trip: `sensor --once` → 125 events → `run` → 0 alerts on an idle
  box, 125 events stored, `verify` OK.
* Dashboard over HTTP: index/JS/CSS served, every `/api/*` route answered, 401
  without a token, 404s for unknown routes, `demo` data renders in every view.
* `pkg-list --scan` on a live `/var/lib/dpkg/status`: first scan is a silent
  baseline; adding a network-capable package produces an event, a score and a
  `DMK-V-002` alert; a third scan of the unchanged host produces nothing.
* Regression tests added for each P0: retention vs. replayed captures
  (`test_pipeline`), event-clock correlation and bounded windows (`test_rules`),
  rebase/expand (`test_replay`), stale-capture reporting and the stored-evidence
  selftest (`test_cli`), loopback/LAN egress (`test_pipeline` + rule fixtures),
  vendored-data drift and lookup order (`test_packaging`).
