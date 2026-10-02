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

## Local vulnerability exemptions

A user can request an exemption for **one specific impact record**, another
user approves or rejects it, and an approval can later be revoked. Requests
and their full processing history live in the local database; databases from
earlier releases keep working (the exemption tables are created on open).

A request pins the affected component (`service ecosystem name version`),
the vulnerability id, the matched package name and the vulnerability source.
The source is omitted for a manually registered vulnerability and given by
name for an imported OSV record — the two are distinguished. The scope is
exactly that record: other versions, services, sources and dependent
components each need their own request, and exempting a directly hit library
does **not** exempt components that depend on it. The request is refused if
the target impact record does not currently exist.

```bash
# Manual vulnerability (no trailing source)
python3 -m supply_guard.cli --database catalog.db request-exemption \
    EXM-2026-001 api pypi urllib3 2.2.2 CVE-2026-1000 urllib3 \
    --applicant alice --reason "mitigated by egress proxy" \
    --expires-at 2026-12-31T23:59:59+08:00
# Imported OSV record (named source)
python3 -m supply_guard.cli --database catalog.db request-exemption \
    EXM-2026-002 api pypi flask 1.5.0 CVE-2026-777 flask nvd \
    --applicant alice --reason "accept risk" \
    --expires-at 2026-12-31T23:59:59+08:00

python3 -m supply_guard.cli --database catalog.db approve-exemption \
    EXM-2026-001 --handler bob --note "controls verified"
python3 -m supply_guard.cli --database catalog.db reject-exemption \
    EXM-2026-002 --handler bob --note "fix instead"
python3 -m supply_guard.cli --database catalog.db revoke-exemption \
    EXM-2026-001 --handler bob --note "compensating control removed"
python3 -m supply_guard.cli --database catalog.db exemption-show EXM-2026-001
python3 -m supply_guard.cli --database catalog.db exemption-list --status approved
```

Request rules:

- the request id, applicant, reason and timezone-aware expiry are required;
  the expiry must be later than the submission instant (naive timestamps and
  invalid times are rejected);
- retrying the **same id with identical content** returns the original
  request; the same id with different content is an error;
- one scope may have at most one unexpired pending **or** approved request at
  a time.

Decision rules:

- only pending requests can be approved/rejected; only approved, unexpired
  requests can be revoked; handler and note must be non-empty;
- the applicant cannot approve their own request;
- approval re-checks that the target still exists and records the severity in
  force at that moment. If the current severity later rises above the
  approved level, the exemption stops applying and the report flags it as out
  of approval scope;
- deciding an expired request is an error. Empty fields, invalid timestamps,
  illegal transitions and unknown ids error out without altering the record.

Every request and each decision stores the actor, timestamp, reason and the
before/after status, and the result is saved together with its history. Two
processes processing the same request concurrently produce at most one state
change.

## Risk report

`risk-report` emits JSON over the **current** impacts — directory (SBOM),
vulnerability withdrawal and dependency removal always take their present
value. Each entry keeps the source, severity, direct/indirect flag and
dependency path, and shows whether it is exempted, the linked request id and,
when not exempted, why:

```bash
python3 -m supply_guard.cli --database catalog.db risk-report
python3 -m supply_guard.cli --database catalog.db risk-report --service api
python3 -m supply_guard.cli --database catalog.db risk-report \
    --at 2026-06-30T00:00:00+00:00
```

- `unhandled_component_count` counts distinct components that still have at
  least one unexempted record; `highest_severity` considers only unexempted
  records and is `null` when none remain;
- `--at` is a timezone-aware evaluation instant used **only** to judge whether
  an exemption term is in force; it defaults to now. Times compare in UTC and
  an exemption stops at its expiry instant. It does not freeze the directory
  or approval state;
- when an impact disappears (SBOM replacement, withdrawal, removed
  dependency) it leaves the report, but the request and history remain
  queryable; if the same scope reappears while the approval, severity and
  term still hold, the exemption resumes. A changed dependency path does not
  change the scope — the report shows the latest path;
- output ordering is stable, and queries/reports never modify approval
  history; identical data and evaluation instant reproduce the same output
  after reopening the database.
