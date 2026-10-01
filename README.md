# Supply Chain Governance

A small, local-first Python CLI for tracking software components, dependency
relationships, vulnerability observations, and their immediate impact.

The initial release is intentionally compact. It provides a durable SQLite
schema and deterministic CLI output that can grow into a broader SBOM and
supply-chain governance product.

## Quick start

```bash
python3 -m supply_guard.cli demo
python3 -m unittest discover -s tests -p 'test_*.py'
```

To keep a local catalog:

```bash
python3 -m supply_guard.cli --database catalog.db init
python3 -m supply_guard.cli --database catalog.db add-component api pypi fastapi 0.115.0
python3 -m supply_guard.cli --database catalog.db add-component api pypi gunicorn 21.2.0
python3 -m supply_guard.cli --database catalog.db add-dependency api pypi gunicorn 21.2.0 api pypi fastapi 0.115.0
python3 -m supply_guard.cli --database catalog.db add-vulnerability CVE-2026-1000 fastapi high
python3 -m supply_guard.cli --database catalog.db summary
```

`add-dependency` records that one component depends on another, using the
full identity (service, ecosystem, name, version) of both ends; both must
already be registered in the same service. A vulnerability hitting a
component then also affects every component that depends on it, directly
or transitively. `delete-dependency` removes a relationship (deleting a
missing one is a no-op success).

`impact` prints the affected-component details as a JSON array, one record
per affected component and vulnerability observation, each with the full
component identity, vulnerability id and matched name, severity, whether
the hit is direct, and the dependency path from the component to the
directly hit component (shortest path; ties pick the lexicographically
smallest node sequence). Filter with `--service` alone, or with
`--service` plus `--ecosystem`, `--name` and `--version` for a single
component; unknown services or components yield an empty array.

All data lives in the SQLite database and survives reopening; the summary
counts affected components (directly or transitively), deduplicated
vulnerability pairs, and the highest severity across them.
