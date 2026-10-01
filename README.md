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

## CycloneDX 1.5 manifest imports

A whole component list with its dependency relationships can be registered in
one step from a local CycloneDX 1.5 JSON file. The service and source name
identify where the data comes from; a source name is unique within a service:

```bash
python3 -m supply_guard.cli --database catalog.db import-sbom api ci-build-42 bom.json
```

Only documents with `bomFormat` = `CycloneDX` and `specVersion` = `1.5` are
accepted, and `components` must be an array. Each component needs a unique
non-empty `bom-ref` and a `purl` that contains a version; only the `pypi` and
`npm` package types are supported. Percent-encoding in purls is decoded and
npm scoped names keep their scope (e.g. `pkg:npm/%40angular/core@16.2.0`
becomes `@angular/core` 16.2.0). Refs that resolve to the same ecosystem,
package name and version are merged into one component; a component-level
`version` field must match the purl version.

`metadata.component` is treated as the manifest root only: its `bom-ref` must
not be reused by a component, components must not depend on it, and its
outgoing relationships are not registered. Unknown dependency refs, nested
components, unsupported package types, missing versions and self-dependencies
(after identity merging) reject the whole manifest. Dependency cycles are
allowed, duplicate relationships count once, and a missing `dependencies`
array means no relationships.

Re-importing the same service/source replaces that source's components and
relationships; an empty `components` array clears the source. Data that is
still declared by another source or registered manually (including the
endpoints of manually registered relationships) is kept; everything else is
deleted. Components and relationships already in a database, or added later
with `add-component`/`add-dependency`, count as manual registrations.
`remove-dependency` only revokes the manual registration, so relationships
other sources still declare keep participating in impact queries.

On success the command prints the source's component count and the numbers of
components and relationships actually added and deleted. Unreadable files,
invalid JSON, wrong field types and failed ref/identity checks exit non-zero
with an error (and the offending record) on standard error and leave the
existing catalog untouched. Imports only read the given local file and make
no network requests.

The same functionality is available from Python:

```python
from supply_guard.catalog import Catalog

catalog = Catalog("catalog.db")
result = catalog.import_cyclonedx("api", "ci-build-42", "bom.json")
print(result)
```
