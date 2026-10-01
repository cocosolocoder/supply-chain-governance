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
python3 -m supply_guard.cli --database catalog.db add-vulnerability CVE-2026-1000 fastapi high
python3 -m supply_guard.cli --database catalog.db summary
```

## Dependency impact tracking

Register "A depends on B" between two components of the same service. Both
ends must already be registered and are located by service, ecosystem, name
and version:

```bash
python3 -m supply_guard.cli --database catalog.db add-component api pypi web 2.0.0
python3 -m supply_guard.cli --database catalog.db add-dependency api pypi web 2.0.0 api pypi fastapi 0.115.0
python3 -m supply_guard.cli --database catalog.db remove-dependency api pypi web 2.0.0 api pypi fastapi 0.115.0
```

A vulnerability that directly hits a component also affects everything that
depends on it, transitively. `summary` counts all directly and indirectly
affected components, and `impact` prints the per-component explanation as
JSON — filterable by `--service` or by full component identity
(`--service` together with `--ecosystem --name --version`):

```bash
python3 -m supply_guard.cli --database catalog.db impact
python3 -m supply_guard.cli --database catalog.db impact --service api
python3 -m supply_guard.cli --database catalog.db impact --service api --ecosystem pypi --name web --version 2.0.0
```

Each impact record carries the affected component identity, the vulnerability
id and matched name, the severity, whether the hit is direct, and the
shortest dependency path from the component to a directly hit component.
