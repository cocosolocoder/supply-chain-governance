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

`import-osv` loads vulnerability data from a local OSV-style JSON file. The
existing exemption flow already refers to these as *imported OSV records*
(named source) as opposed to *manually registered vulnerabilities* (no
source); this section explains how the file is imported and how to read the
numbers that follow. Unlike an SBOM import, which is scoped to one service
and source, an OSV source name is **global to the whole directory**: its
records can match components in any service.

```bash
python3 -m supply_guard.cli --database catalog.db import-osv nvd ./osv.json
```

### File format

The top-level JSON value is an **array of records** — not a single object and
not an object wrapping a list.

- every record needs a non-empty `id` and a non-empty `affected` array; an
  `affected` entry may repeat when one record covers several packages;
- only the **PyPI** ecosystem is accepted (`package.ecosystem` is matched
  case-insensitively). Package names are normalized per PEP 503 (case folded,
  runs of `-`, `_` and `.` collapsed) before matching, and every version
  comparison is **PEP 440**;
- an affected package declares when it is vulnerable using either or both of:
  - explicit versions, `"versions": ["2.31.0"]` — an installed component
    matches when its version equals one of them under PEP 440 equivalence;
  - `"ranges"` of `"type": "ECOSYSTEM"` with ordered `introduced` /
    `fixed` / `last_affected` events, where `"introduced": "0"` means no
    lower bound. Other range and event types are rejected;
- an optional `"database_specific": {"severity": "low|medium|high|critical"}`
  declares the rating. Without it the record is stored at severity **medium**
  with `severity_basis: "default"`. That medium is the catalog's fallback for
  an unrated record — it is **not** a severity the vulnerability source
  claims. A declared rating is stored with `severity_basis: "declared"`;
- an optional `"withdrawn"` timestamp keeps the row stored but removes it
  from every impact analysis.

The worked example below uses ECOSYSTEM ranges only.

### Worked example

Using one local database, register a PyPI library and an upper component that
depends on it, then import a vulnerability source:

```bash
python3 -m supply_guard.cli --database catalog.db init
python3 -m supply_guard.cli --database catalog.db add-component shop pypi requests 2.31.0
python3 -m supply_guard.cli --database catalog.db add-component shop pypi webfront 1.4.0
python3 -m supply_guard.cli --database catalog.db add-dependency \
    shop pypi webfront 1.4.0 shop pypi requests 2.31.0
python3 -m supply_guard.cli --database catalog.db import-osv nvd ./osv.json
```

`osv.json` contains three records. The first matches `requests 2.31.0`; the
second names `urllib3`, which no registered component uses; the third would
match the version but is withdrawn:

```json
[
  {
    "id": "CVE-2026-2001",
    "affected": [
      {
        "package": { "ecosystem": "PyPI", "name": "requests" },
        "ranges": [
          {
            "type": "ECOSYSTEM",
            "events": [
              { "introduced": "2.3.0" },
              { "fixed": "2.32.0" }
            ]
          }
        ]
      }
    ]
  },
  {
    "id": "CVE-2026-2002",
    "affected": [
      {
        "package": { "ecosystem": "PyPI", "name": "urllib3" },
        "ranges": [
          {
            "type": "ECOSYSTEM",
            "events": [
              { "introduced": "0" },
              { "fixed": "1.26.18" }
            ]
          }
        ]
      }
    ]
  },
  {
    "id": "CVE-2026-2003",
    "affected": [
      {
        "package": { "ecosystem": "PyPI", "name": "requests" },
        "ranges": [
          {
            "type": "ECOSYSTEM",
            "events": [
              { "introduced": "2.0.0" },
              { "fixed": "2.40.0" }
            ]
          }
        ]
      }
    ],
    "withdrawn": "2026-03-01T00:00:00Z"
  }
]
```

The import prints `导入漏洞记录: 3 条`, and `summary` then reports
`组件数量: 2`, `受影响组件: 2`, `漏洞数量: 1`, `最高风险: medium`. Only
one vulnerability actually hits, yet both components are affected: the
library directly and the upper component through its dependency. `impact`
prints the two records that let you tell the source, risk level and
dependency path apart:

```json
[
  {
    "component": { "service": "shop", "ecosystem": "pypi",
                   "name": "requests", "version": "2.31.0" },
    "vulnerability": "CVE-2026-2001",
    "source": "nvd",
    "matched_name": "requests",
    "severity": "medium",
    "severity_basis": "default",
    "direct": true,
    "matched_conditions": [ ">=2.3.0,<2.32.0" ],
    "path": [
      { "service": "shop", "ecosystem": "pypi",
        "name": "requests", "version": "2.31.0" }
    ]
  },
  {
    "component": { "service": "shop", "ecosystem": "pypi",
                   "name": "webfront", "version": "1.4.0" },
    "vulnerability": "CVE-2026-2001",
    "source": "nvd",
    "matched_name": "requests",
    "severity": "medium",
    "severity_basis": "default",
    "direct": false,
    "matched_conditions": [ ">=2.3.0,<2.32.0" ],
    "path": [
      { "service": "shop", "ecosystem": "pypi",
        "name": "webfront", "version": "1.4.0" },
      { "service": "shop", "ecosystem": "pypi",
        "name": "requests", "version": "2.31.0" }
    ]
  }
]
```

`source` names the import (`nvd`; `null` would mark a manual vulnerability),
`severity`/`severity_basis` give the level and whether the source declared it,
`direct` distinguishes the hit library from the indirectly affected upper
component, and `path` is the shortest dependency chain from the component to a
directly hit one. Explicit-version hits render as `==2.31.0` and a fully open
range as `*`. The same fields appear per entry in `risk-report`.

### Replacing a source

Re-importing is the central operation, and it works per source name across
the **whole directory**:

- importing the **same source name again replaces** that source's old
  records; the two files are never accumulated;
- any vulnerability the new file no longer lists is **no longer provided by
  this source** — its impact records disappear on the next query;
- an **empty array `[]` clears the source** (`导入漏洞记录: 0 条`);
- a record carrying `withdrawn` is kept in the database but never joins
  impact analysis, so it neither appears in `impact` nor raises a component's
  risk.

Replacement is scoped to the one named source. Records from **other OSV
sources and manually registered vulnerabilities stay in force**, so clearing
one source does not necessarily clear a component's risk. Continuing the
example, import the same CVE from a second source that declares a rating:

```bash
python3 -m supply_guard.cli --database catalog.db import-osv ghsa ./ghsa.json
```

with `ghsa.json` declaring `CVE-2026-2001` for package `Requests` (the same
normalized name) and `"database_specific": {"severity": "high"}`:

```json
[
  {
    "id": "CVE-2026-2001",
    "affected": [
      {
        "package": { "ecosystem": "PyPI", "name": "Requests" },
        "ranges": [
          {
            "type": "ECOSYSTEM",
            "events": [
              { "introduced": "2.3.0" },
              { "fixed": "2.32.0" }
            ]
          }
        ]
      }
    ],
    "database_specific": { "severity": "high" }
  }
]
```

Both
components now have a `ghsa` record (`high`, `declared`) **and** the `nvd`
record (`medium`, `default`). Clearing `nvd` with an empty array removes only
the `nvd` records; the `ghsa` records — and a manual
`add-vulnerability CVE-2026-9000 requests low`, whose source is `null` —
still mark both components affected. Source replacements never touch the SBOM
component/dependency graph or exemption requests and their history; when an
impact disappears its request simply remains queryable, exactly as described
in the risk-report section.

### The three counts

The numbers shown at each stage answer different questions:

- **import count (`导入漏洞记录: N 条`)** is the number of *(vulnerability id,
  package)* combinations written after splitting: one record that lists two
  affected packages counts as two. It counts every combination in the file,
  including ones that hit no component and withdrawn ones — in the example it
  is 3 even though only one combination ever matches.
- **`summary` 漏洞数量** counts only vulnerabilities that **actually hit a
  component**. Imported vulnerabilities are deduplicated by *vulnerability id
  and normalized package name across sources*: the same `CVE-2026-2001` from
  both `nvd` and `ghsa` counts once, so the example stays at one. Manually
  registered vulnerabilities are counted independently of imported ones.
- **`impact` and `risk-report` keep source differences**: the same CVE from
  two sources is one summary vulnerability but a separate impact record per
  source, each with its own severity. The same vulnerability may also affect
  several components (the library and everything that depends on it), so
  `impact_count` is records — sources × components × vulnerabilities — not a
  vulnerability count. `risk-report` additionally reports
  `unhandled_component_count` (distinct components with an unexempted record)
  and `highest_severity` over unexempted records only.

### When a replacement fails

A replacement is atomic: the file must be readable, be valid JSON, and **every
record** must pass validation (PyPI-only ecosystem, parseable PEP 440
versions, legal ECOSYSTEM event order, a valid `withdrawn` timestamp, no
duplicate record `id` in the file). If any of these fails the command exits
non-zero and prints the offending object, for example:

```text
error: 记录 1: affected[0] 的生态系统 'npm' 不受支持，仅支持 PyPI
error: 文件 ./broken.json 不是有效的 JSON: ...
error: 无法读取文件 ./missing.json: [Errno 2] No such file or directory: ...
```

On failure the source's **previous records are retained wholesale** and all
other business data (other sources, manual vulnerabilities, components,
dependencies and exemptions) is unchanged. Earlier, valid records in the
rejected file are **not** partially imported — a source is either fully
replaced or left as it was.

Importing OSV sources changes neither the existing SBOM/dependency behavior
nor matching, counting or exemption approval rules: matching stays
name-normalized PyPI plus PEP 440, the three counts above keep their
definitions, and exemption requests continue to pin the source by name (the
`nvd` argument in the exemption examples).

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
