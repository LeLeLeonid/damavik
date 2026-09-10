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

Every command takes `--json`. Install as a command: `pip install --user ./brain`.

## Commands

| | |
|---|---|
| `sensor` | emit events from `/proc` (`--once`, `--interval`, `--out`, `--dns-tail`) |
| `run` | score a stream or `--file`, write the index + journal + alerts |
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
| `selftest` | end-to-end proof the install works |
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

## Development

```sh
python3 -m pytest tests/ -q          # 381 tests, ~14 s, no network, no root
python3 -m damavik.cli bench --gate  # performance budgets
```

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
