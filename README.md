# DAMAVIK

**дамавік** — the house guardian spirit. A local-first host threat monitor.

It watches process executions, network flows, DNS queries and installed
packages on your machine, scores them locally, and shows you the result as a
process tree and a connection graph. Python 3.11+, no dependencies, no
services, no accounts, **no telemetry**, and it works fully **offline**.
The dashboard binds **127.0.0.1** only. It is **alert-only**: it never kills,
blocks or quarantines.

## Run it

```sh
cd brain
python3 -m damavik.cli demo          # shipped attack chain -> ranked alerts
python3 -m damavik.cli selftest      # proves the install works, offline, no root
python3 -m damavik.cli sensor | python3 -m damavik.cli run   # monitor this box
python3 -m damavik.cli serve         # dashboard on 127.0.0.1 (prints a token)
python3 -m damavik.cli ps-tree       # live process tree, scored
```

Every command takes `--json`. Install it as a command from the repository
root: `pip install .` (or `pip install --user .`). The wheel carries the
ruleset and a demo capture, so `damavik selftest` works outside a checkout;
`DAMAVIK_RULES_DIR`/`--rules-dir` point it at your own rules instead.

A capture is replayed with the timestamps it was recorded with - that is the
point of a forensic reload. `damavik run --file capture.jsonl --rebase` replays
it on the current clock instead, which is what `demo`, `selftest` and `bench` do
internally, so a shipped fixture cannot age into an empty dashboard.

## Install it as a service

```sh
sudo ./packaging/install.sh            # DRY_RUN=1 to preview, ENABLE=0 to skip starting
```

No package manager, no downloads: the installer copies this checkout to
`/usr/share/damavik`, writes `/usr/local/bin/damavik`, keeps an existing
`/etc/damavik/damavik.yaml`, creates the state directory and installs two
hardened units — `damavik-sensor.service` (the whole monitor: `sensor | run`)
and `damavik-dashboard.service` (`serve` on 127.0.0.1). It then runs the
*installed* command's `selftest` and fails loudly if that does not work.
Installs into a prefix you own need no root: `ALLOW_NONROOT=1 PREFIX=~/.local
./packaging/install.sh`.

Every setting in `damavik.yaml` can be overridden from the environment, which is
how the units pin their paths (`file < environment < command line`):
`DAMAVIK_STATE_DIR`, `DAMAVIK_RULES_DIR`, `DAMAVIK_HOST_ID`,
`DAMAVIK_RETENTION_DAYS`, `DAMAVIK_OFFLINE`.

## Commands

| | |
|---|---|
| `sensor` | emit events from `/proc` (`--once`, `--interval`, `--out`, `--dns-tail`) |
| `run` | score a stream or `--file` (`--rebase` replays on the current clock) |
| `alerts` | ranked alerts; `-v` adds explanations and IOCs |
| `ps-tree` | process tree with a risk score per node |
| `flows` | aggregated connections, `--pid` to filter |
| `top-risks` | highest-scored events |
| `tail` | live journal stream, `--alerts-only` |
| `pkg-list` | package inventory, `--scan` to diff and match CVEs |
| `osv-sync` | load a local OSV mirror into the index |
| `status` | counts, config path, rule health |
| `verify` | journal integrity; exit 2 names the first bad line |
| `validate` | schema-check a capture |
| `selftest` | end-to-end proof the install works: rules, stored alerts, journal |
| `bench` | throughput and memory against the budgets, `--gate` for CI |
| `purge` | delete database, journal and alerts (`--yes`) |

## How it decides

Two layers, never a black box:

1. **Rules** (`rules/DMK-*.yml`, Sigma-subset) express behaviour: office app
   spawns a shell, egress within 2 s of an exec, six connections to one
   destination in two minutes, a 30-character label with near-random entropy.
2. **Scoring** expresses *unusualness on this host*: first-seen hash,
   first-seen destination, new (binary, destination, port) edge, execution
   from a world-writable directory, a known path with a changed hash.

Every point appends a reason, and the alert carries them. An alert with an
empty explanation fails `selftest`. Optional cloud lookups (hash/domain
verdicts, local CVE mirror) are **off by default** and `--offline` is a real
kill-switch.

### Time, retention and replays

Correlation windows ("six connections to one destination in two minutes") are
measured on the **event clock**, not the wall clock: a capture replayed in a
millisecond still correlates on the timeline it recorded, and a live sensor
behaves identically because its timestamps *are* now.

`retention_days` prunes the index a run **inherits**, at the moment that run
starts. A run never deletes the batch it is processing - otherwise
`run --file capture.jsonl` on anything older than the window would ingest every
event and delete every event in the same call, leaving `demo` reporting
"27 alerts (showing 0)" over an empty database.

## Development

```sh
python3 -m pytest tests/ -q          # 417 tests, ~16 s, no network, no root
python3 -m damavik.cli bench --gate  # performance budgets
python3 -m ruff check brain tests && python3 -m ruff format --check brain tests
```

[`docs/PLAN.md`](docs/PLAN.md) is the audit that produced the current shape of
the project: what was broken, why, and what is queued behind it.

Every rule ships with a true-positive and a false-positive fixture; the suite
fails otherwise. False-positive reports are the most useful contribution: send
the event and we add it as a regression test before changing the rule.

## Status

P0. ~0.5 ms per event through the whole pipeline with 20 rules, ~26 MB
resident. The Linux eBPF sensor is not built yet — `sensor-py` (reading
`/proc`) is the current data source and covers `proc.exec` and `net.flow`, not
DNS. It will not find kernel rootkits or fileless living-off-the-land chains.

## License

GPL-3.0-only — see [`LICENSE`](LICENSE). No third-party runtime dependencies.
