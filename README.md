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

`remove-dependency` only revokes the relationship's **manual registration**. If
the same relationship is still declared by any SBOM source it stays in the
catalog and keeps participating in impact analysis; only a relationship with no
remaining source declaration leaves the catalog. When that happens, each of
the two endpoints is then judged on its own: a component leaves the catalog
only when it is not manually registered, is declared by no source, and is no
longer an endpoint of any other manual dependency. The two ends are therefore
retained or removed independently — deleting one relationship never clears a
whole component group — and the decision uses the full identity of service,
ecosystem, package name and version, so identically named components in other
services or versions are unaffected. Summaries, impact paths and the risk
report reflect the result immediately; no further SBOM import is needed.
Removing a component never removes vulnerability source data or exemption
requests and their history, which stay queryable by their original ids.
Targeting a relationship or endpoint that does not exist succeeds without
changing the catalog (and does not sweep unrelated components); empty identity
fields are still rejected.

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

The catalog may register component versions that PEP 440 cannot parse; such a
component only becomes a query error when an OSV record matches its package
name and the version has to be compared. A `--service`-scoped `impact` or
`risk-report` builds its graph from that service alone, so a bad version in
another service neither fails the query nor mixes into the results: the
selected service gets its complete direct and indirect impacts, and a full
component identity still lets the target's own dependencies participate in
matching, so transitive hits are never lost. A component within the selected
service (including one only reached transitively) whose version cannot be
parsed is still an error naming service, ecosystem, package and version, and
the command exits non-zero — it is never silently skipped. A service with no
registered components yields an empty impact list and a risk report whose
impact and unhandled-component counts are zero with a null highest severity.
Directory-wide queries (`summary` and unscoped `impact`/`risk-report`) keep
the existing version-error behavior.

## SBOM imports (CycloneDX and SPDX)

`import-sbom` takes a service, a source name and a JSON file. The format is
recognized automatically: CycloneDX 1.5 (`bomFormat`/`specVersion`) and
SPDX 2.3 (`spdxVersion: SPDX-2.3`) are both accepted, including through the
Python `Catalog.import_sbom` / `import_sbom_file` entry points.

```bash
python3 -m supply_guard.cli --database catalog.db import-sbom api src ./api.spdx.json
```

SPDX rules:

- `spdxVersion` must be `SPDX-2.3`, `packages` must be an array (an empty
  array clears the source declaration), and the document and every package
  must carry a unique, non-empty `SPDXID`; a package id must not repeat and
  must not equal the document id.
- each package gets its component identity from the `externalRefs` entry
  whose `referenceType` is `purl`; only versioned PyPI and npm packages are
  supported, npm scopes and percent-decoding behave exactly as for
  CycloneDX. A missing/unparseable/unsupported purl, or several purls that
  resolve to different identities, rejects the import; repeated purls for
  the same identity merge. `versionInfo`, when present, must equal the purl
  version; the display `name` never participates in identity matching.
- relationships use `A DEPENDS_ON B` (A depends on B) and
  `A DEPENDENCY_OF B` (B depends on A); equivalent statements register once.
  Both ends must reference packages in this document — unknown ids, external
  document references and self-dependencies produced by merging are
  rejected, while cycles between distinct packages are allowed. `DESCRIBES`
  and other non-dependency relationship types are ignored, the document
  itself is not a component, and a missing `relationships` key counts as an
  empty array (a present one must be an array).
- packages that share an identity are merged and all relationships are
  interpreted against the merged components, so package/relationship order
  never changes the result.

Re-importing the same service and source replaces the previous declaration,
including when the source switches between CycloneDX and SPDX; two lists are
never accumulated. Other sources, manually registered components and
dependencies (and the endpoints manual dependencies need) are preserved.
The success output is the same import statistics for both formats, counted
over the merged components and relationships, so importing identical
content again adds or removes nothing. Summaries, impact paths and the risk
report reflect the new list immediately; existing exemptions and their
history remain and continue to apply against current impact. File, JSON or
validation failures return a non-zero status naming the offending object
and leave the previous source declaration and all other business data
unchanged.

## Local OSV vulnerability sources

`import-osv` loads vulnerability records from a local JSON file into a named
source. The source name scopes the **whole catalog**, not a single service:
importing the same name again replaces that source's records everywhere.

### File format

The file's top level is an **array of records**. Each record carries:

- `id` — required, non-empty, unique within the file;
- `affected` — a non-empty array. Each entry names a `package` (`ecosystem`
  plus `name`) and its version conditions. Only the **PyPI** ecosystem is
  supported (case-insensitive), and versions compare per **PEP 440**. The
  conditions are explicit `versions` and `ECOSYSTEM` `ranges` built from
  `introduced` / `fixed` / `last_affected` events; every affected entry must
  declare its **own** non-empty conditions (a non-empty `versions` list or at
  least one valid range — an open-ended range or one starting at `"0"` is a
  condition too). Two entries never share conditions: an entry whose package
  name is identical to another entry's, or only differs by PyPI
  normalization (`Foo_Bar` vs `foo-bar`), is still rejected when it omits or
  empties both `versions` and `ranges`. When several valid entries target the
  same normalized package name, their conditions merge into one
  vulnerability/package source record and import counts do not multiply per
  entry. The example below uses explicit versions only;
- `database_specific.severity` — optional, one of `low`, `medium`, `high`,
  `critical`. When it is absent the record is stored as `medium` with
  `severity_basis: "default"`. That medium is a **local fallback, not a
  rating the source declared** — `impact` and `risk-report` distinguish the
  two through `severity_basis` (`"declared"` vs `"default"`), so a defaulted
  medium is never misread as the source's assessment;
- `withdrawn` — optional timestamp. A withdrawn record is stored but does
  **not** participate in impact analysis.

### Example

`osv.json`:

```json
[
  {
    "id": "CVE-2026-2001",
    "affected": [
      {
        "package": {"ecosystem": "PyPI", "name": "Flask"},
        "versions": ["1.5.0"]
      }
    ],
    "database_specific": {"severity": "high"}
  },
  {
    "id": "CVE-2026-2002",
    "affected": [
      {
        "package": {"ecosystem": "PyPI", "name": "urllib3"},
        "versions": ["2.2.2"]
      }
    ]
  },
  {
    "id": "CVE-2026-2003",
    "affected": [
      {
        "package": {"ecosystem": "PyPI", "name": "requests"},
        "versions": ["2.31.0"]
      }
    ],
    "withdrawn": "2026-02-01T00:00:00Z"
  },
  {
    "id": "CVE-2026-2004",
    "affected": [
      {
        "package": {"ecosystem": "PyPI", "name": "django"},
        "versions": ["4.2.0"]
      }
    ]
  }
]
```

Register a PyPI library and an upper-level component that depends on it, then
import the source — all against the same local database:

```bash
python3 -m supply_guard.cli --database catalog.db init
python3 -m supply_guard.cli --database catalog.db add-component api pypi flask 1.5.0
python3 -m supply_guard.cli --database catalog.db add-component api pypi urllib3 2.2.2
python3 -m supply_guard.cli --database catalog.db add-component api pypi web 2.0.0
python3 -m supply_guard.cli --database catalog.db add-dependency api pypi web 2.0.0 api pypi flask 1.5.0
python3 -m supply_guard.cli --database catalog.db import-osv nvd ./osv.json
# 导入漏洞记录: 4 条
```

`impact` then shows the library hit directly and the upper-level component
affected through the dependency (abridged):

```json
[
  {
    "component": {"service": "api", "ecosystem": "pypi", "name": "flask", "version": "1.5.0"},
    "vulnerability": "CVE-2026-2001",
    "source": "nvd",
    "severity": "high",
    "severity_basis": "declared",
    "direct": true,
    "matched_conditions": ["==1.5.0"],
    "path": [{"service": "api", "ecosystem": "pypi", "name": "flask", "version": "1.5.0"}]
  },
  {
    "component": {"service": "api", "ecosystem": "pypi", "name": "urllib3", "version": "2.2.2"},
    "vulnerability": "CVE-2026-2002",
    "source": "nvd",
    "severity": "medium",
    "severity_basis": "default",
    "direct": true,
    "matched_conditions": ["==2.2.2"],
    "path": [{"service": "api", "ecosystem": "pypi", "name": "urllib3", "version": "2.2.2"}]
  },
  {
    "component": {"service": "api", "ecosystem": "pypi", "name": "web", "version": "2.0.0"},
    "vulnerability": "CVE-2026-2001",
    "source": "nvd",
    "severity": "high",
    "severity_basis": "declared",
    "direct": false,
    "matched_conditions": ["==1.5.0"],
    "path": [
      {"service": "api", "ecosystem": "pypi", "name": "web", "version": "2.0.0"},
      {"service": "api", "ecosystem": "pypi", "name": "flask", "version": "1.5.0"}
    ]
  }
]
```

Each record identifies the providing `source`, the effective `severity` (with
its basis), and the dependency `path` from the affected component to the
directly hit one — `web` is flagged `direct: false` with the path
`web → flask`. `summary` for this catalog reports `漏洞数量: 2`,
`受影响组件: 3`, `最高风险: high`.

### Reading the three counts

The same import produces three different numbers, and all three are expected:

- the **import success count** (`导入漏洞记录: 4 条`) counts the split
  (vulnerability, package) combinations stored for the source — including
  combinations that match no registered component (CVE-2026-2004/django) and
  withdrawn ones (CVE-2026-2003);
- `summary`'s **漏洞数量** counts only vulnerabilities with at least one
  actual hit (CVE-2026-2001 and CVE-2026-2002 here). Imported vulnerabilities
  are deduplicated by id and normalized package name **across sources**, so
  the same CVE for the same package imported from two sources counts once;
  manually registered vulnerabilities are counted separately, even under the
  same id;
- `impact` and `risk-report` keep **one record per (component, vulnerability,
  source, matched package)**: source differences are preserved (the same CVE
  from two sources yields two records), and one vulnerability can affect
  several components (CVE-2026-2001 yields records for both `flask` and
  `web`).

### Replacing a source

Re-importing a source name **replaces** its previous records; two imports
never accumulate. Vulnerabilities absent from the new file stop being
provided by that source, and their impacts disappear immediately. An empty
array (`[]`) clears the source entirely, and withdrawn records never
participate in impact analysis either way. Other sources and manually
registered vulnerabilities are untouched, so clearing one source does **not**
necessarily remove a component's risk — the same CVE may still arrive from
another source or from a manual registration.

Continuing the example, re-importing `nvd` with a file that lists only
CVE-2026-2001 drops CVE-2026-2002 from the source: the `urllib3` impact
record disappears while `flask` and `web` remain affected, and `summary`
falls to `漏洞数量: 1`. Importing `[]` under `nvd` afterwards would remove
those too — but a manual `add-vulnerability CVE-2026-2001 flask high` would
keep `flask` (and transitively `web`) at risk regardless.

### Failed imports change nothing

If the file cannot be read, is not valid JSON, or **any** record fails
validation, the command exits non-zero with an error naming the offending
record, and the source keeps its previous content — the valid records earlier
in the file are not partially imported, and all other business data
(components, dependencies, exemptions and their history) is untouched:

```bash
python3 -m supply_guard.cli --database catalog.db import-osv nvd ./broken.json
# error: 记录 1: affected[0] 的生态系统 'npm' 不受支持，仅支持 PyPI   (exit 1)
python3 -m supply_guard.cli --database catalog.db import-osv nvd ./missing.json
# error: 无法读取文件 ./missing.json: ...                            (exit 1)
```

The same applies when one affected entry omits its own version conditions
even though another entry of the same record carries conditions for the same
or a normalization-equivalent package:

```json
[
  {
    "id": "CVE-2026-3001",
    "affected": [
      {"package": {"ecosystem": "PyPI", "name": "Foo_Bar"}, "versions": ["1.0"]},
      {"package": {"ecosystem": "PyPI", "name": "foo-bar"}}
    ]
  }
]
```

```bash
python3 -m supply_guard.cli --database catalog.db import-osv nvd ./noshares.json
# error: 记录 0: affected[1]（包 foo-bar）缺少版本条件：必须提供非空 versions 或至少一个合法 ECOSYSTEM ranges  (exit 1)
```

The error always names the record index in the file, the `affected` entry
index and that entry's package name, and swapping the two entries only moves
the reported entry index — the import still fails.

After either failure, `summary`, `impact` and `risk-report` keep reporting
exactly what the last successful import established.

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

Both the submission existence check and the approval re-check evaluate the
target **service only**, exactly like a `--service`-scoped report: an
unparseable component version in another service (even for the same package
name) never blocks requesting or approving this service's exemption, while
the service's own complete dependency graph is still considered, so an
upstream component reached only through dependencies counts as affected. A
component within the target service whose version has to be compared with an
OSV record but cannot be parsed still fails the request or approval, naming
the component's full identity; it is never skipped to claim the impact does
or does not exist. If the target impact is gone at approval time the
approval fails and the request stays pending with its history intact.
Directory-wide queries keep the existing version-error behavior.

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
- retrying the **same id with identical content** confirms the original
  submission and returns the stored request exactly as it stands at query
  time — even when the retry happens at or after the expiry instant, after
  the request was approved/rejected/revoked, or after the target impact
  disappeared. The confirmation never extends the term, rewrites the
  approved risk level, re-checks the current impact or adds history events;
  the same id with any different content (scope, applicant, reason or
  expiry) is a conflict error that leaves the stored request untouched, no
  matter that the old request has expired;
- one scope may have at most one unexpired pending **or** approved request at
  a time. Confirming an old id does not re-occupy a scope its expiry
  released, so the old record and a later legitimate request for that scope
  are both kept.

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

`exemption-list` (and `Catalog.list_exemptions`) reads the selected requests
and their processing history from one consistent database snapshot, so the
whole list — membership, the current status, the decision/revocation note and
the attached history — always reflects a single saved state. When another
process approves, rejects, revokes or submits while the list is being read,
the list may show either the state just before that save or the state just
after it, but never a mixture: an old status row never loses its history or
gains the newer event, and a request entering or leaving the filtered status
mid-read never causes a missing, mismatched or foreign history entry (or a
query error). A later query sees the completed processing. The read never
writes; inside a caller-managed transaction it reports what that transaction
can see and leaves committing or rolling back to the caller, and a database
error while reading fails the whole query instead of returning half a list,
with the connection still usable afterwards.

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
