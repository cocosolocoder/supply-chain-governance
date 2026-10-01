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

## Local OSV advisories

Import a JSON file holding an array of OSV records under a named source. The
source applies catalog-wide (across every service). Re-importing the same
source replaces all of its records; an empty array clears it; other sources
and manual vulnerabilities are kept.

```bash
python3 -m supply_guard.cli --database catalog.db import-osv internal-advisory osv.json
```

Only PyPI packages are matched. Package names are case-insensitive and treat
runs of dots, underscores and hyphens as equivalent (`Django_Foo` matches
`django-foo`); npm components with the same name are never direct hits.
Versions follow PEP 440 ordering (pre-releases and local versions included),
and both `affected[].versions` and `ECOSYSTEM` ranges are matched as a union.
An interval includes `introduced`, excludes `fixed`, includes
`last_affected`; `"introduced": "0"` means no lower bound and a trailing
`introduced` leaves no upper bound, so a fix can be re-introduced later.

Records need a non-empty `id`. Severity is read from
`database_specific.severity` (`low`/`medium`/`high`/`critical`); when missing
it defaults to `medium` and the impact record marks the default. Records with
a valid `withdrawn` timestamp no longer participate. Any other ecosystem,
range type, event kind, unparseable advisory version, inverted interval or
illegal event order rejects the whole import without touching existing data.
A candidate component whose version cannot be parsed makes `impact` and
`summary` fail and names the component.

`impact` shows imported advisories per source: each (component, source,
vulnerability id, matched package) appears once, carrying the shortest
dependency path, the terminal matched version condition and the severity
basis. `summary` counts imported vulnerabilities by (id, normalized package)
over records that actually hit; manual vulnerabilities keep their original
rules and are counted separately even when they share an id.

