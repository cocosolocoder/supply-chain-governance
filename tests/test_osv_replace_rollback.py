"""Regression tests for local OSV source replacement failing *during* the save.

``import_osv`` validates the whole file before writing, so the existing
failure cases all reject bad input (bad JSON, missing file, malformed record,
duplicate id, an affected entry without its own version conditions) before a
single database statement runs. These tests cover the other half of the
contract: input that is fully valid, whose replacement of the source has
already started - the source's previous rows were withdrawn inside the
transaction and part of the new content was already written - and that then
hits a real database write error partway through inserting the new rows.

Such a failure must end the import as a failure (raise, never return the
success count) and roll the whole replacement back atomically: the target
source must keep exactly the content the last successful import established,
including:

* original vulnerability ids, normalized package names and version
  conditions;
* risk levels and whether each came from the source's declaration or the
  local default (``severity_default``);
* withdrawn status (withdrawn rows are stored but never enter impact);
* combinations that match no registered component, and multi-package
  vulnerabilities whose import count is per (vulnerability, package) - the id
  merely surviving must not be read as the old data being whole;

while the following, which the replacement must never touch, stay byte-for-byte
identical before and after: summary, per-service impact (direct hits and
dependency propagation with the old conditions/levels and unchanged paths),
the risk report at the same evaluation instant (exemption links, unhandled
component count, highest severity), approved-unexpired exemptions with their
original scope and approved level, pending requests, and the full processing
history. Source names are global, so impacts of the same source in different
services and the rows of another source carrying the same vulnerability id
(plus a manual registration under that id) must all survive; components and
dependencies are not part of what an OSV replacement owns.

The contrast class proves save-before-write validation rejections really run
no SQL (so they are not mistaken for mid-save coverage), and the success
class keeps the established public behavior: a valid replacement commits,
and ``[]`` clears the source.
"""

import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import main

TARGET_SOURCE = "nvd"
OTHER_SOURCE = "vendor"
# A vulnerability id shared across the target source, another source and a
# manual registration - a rollback must preserve all three independently.
SHARED_CVE = "CVE-2026-0001"
DEFAULT_CVE = "CVE-2026-0002"
UNUSED_CVE = "CVE-2026-0003"
WITHDRAWN_CVE = "CVE-2026-0004"
NEW_CVE = "CVE-2026-0005"
APPROVED_EXEMPTION = "EXM-2026-0001"
PENDING_EXEMPTION = "EXM-2026-0002"

# Fixed instants keep the exemption term and every report deterministic.
SUBMITTED_AT = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
APPROVED_AT = datetime(2026, 1, 2, 0, 0, tzinfo=timezone.utc)
EXPIRES_AT = "2026-12-31T23:59:59+00:00"
EVAL_AT = "2026-06-01T00:00:00+00:00"


def affected(package, **conditions):
    """One affected entry: ``affected("flask", versions=[...])``."""
    entry = {"package": {"ecosystem": "PyPI", "name": package}}
    entry.update(conditions)
    return entry


def osv_record(identifier, entries, severity=None, withdrawn=None):
    record = {"id": identifier, "affected": entries}
    if severity is not None:
        record["database_specific"] = {"severity": severity}
    if withdrawn is not None:
        record["withdrawn"] = withdrawn
    return record


def interval(*events):
    return {"type": "ECOSYSTEM", "events": list(events)}


# The target source's original content - what the last successful import
# established and what a failed replacement must leave intact. It exercises
# every field the task calls out: a multi-package CVE (sharedlib hit in both
# services + extralib, the latter anchored to the api-only upstream), a
# declared high, an open-ended-ish ECOSYSTEM range condition with *defaulted*
# medium on the same id as a manual critical, a combination matching no
# registered component (UNUSED_CVE), and a withdrawn record.
OLD_RECORDS = [
    osv_record(
        SHARED_CVE,
        [
            affected("sharedlib", versions=["1.0.0"]),
            affected("extralib", versions=["3.0.0"]),
        ],
        severity="high",
    ),
    osv_record(
        DEFAULT_CVE,
        [
            affected(
                "flask",
                ranges=[interval({"introduced": "1.0"}, {"fixed": "2.0"})],
            )
        ],
    ),
    osv_record(UNUSED_CVE, [affected("unmatchedlib", versions=["9.9.9"])]),
    osv_record(
        WITHDRAWN_CVE,
        [affected("withdrawnlib", versions=["1.0.0"])],
        withdrawn="2026-02-01T00:00:00Z",
    ),
]

# Fully valid replacement content that genuinely differs: the shared CVE is
# modified (critical instead of high) and gains a brand-new package
# combination; a brand-new vulnerability NEW_CVE spans flask and the same
# new package. All of it must be gone after a mid-save failure.
NEW_RECORDS = [
    osv_record(
        SHARED_CVE,
        [
            affected("sharedlib", versions=["1.0.0"]),
            affected("newpack", versions=["1.0.0"]),
        ],
        severity="critical",
    ),
    osv_record(
        NEW_CVE,
        [
            affected("flask", versions=["1.5.0"]),
            affected("newpack", versions=["1.0.0"]),
        ],
        severity="high",
    ),
]

# Where the write error is injected. ``newpack`` is brand-new and appears
# twice in the replacement; the trigger fires on its first INSERT (the
# modified SHARED_CVE row, second overall) after one new row (the retained
# sharedlib combination) was already re-written - so a partial write provably
# happened inside the transaction before the error.
FAIL_PACKAGE = "newpack"

# A write error injected into the save itself. The trigger lives in the same
# database the import writes to, so the failure goes through SQLite exactly
# like a real disk/constraint error: the INSERT aborts, and the surrounding
# replacement transaction must roll back.
SAVE_FAILURE_TRIGGER = f"""
CREATE TRIGGER fail_osv_save
BEFORE INSERT ON osv_vulnerabilities
WHEN NEW.package_name = '{FAIL_PACKAGE}'
BEGIN
    SELECT RAISE(ABORT, 'injected osv-save write error');
END
"""


def build_catalog(database: str | Path) -> Catalog:
    """Create the pre-replacement scenario shared by every regression case.

    Two services (``api`` and ``worker``) register the same PyPI package
    ``sharedlib`` 1.0.0. In ``api``, an application depends on sharedlib and
    on flask 1.5.0; an isolated upstream ``extralib`` 3.0.0 is registered on
    its own. A global OSV source TARGET_SOURCE carries OLD_RECORDS, another
    source OTHER_SOURCE provides the same SHARED_CVE at a different (low,
    declared) level, and a manual critical is registered for DEFAULT_CVE on
    flask. The application's indirect SHARED_CVE/target-source impact has an
    approved, unexpired exemption; its indirect manual DEFAULT_CVE impact has
    a still-pending request.
    """
    catalog = Catalog(database)
    catalog.import_osv(TARGET_SOURCE, OLD_RECORDS)
    catalog.import_osv(
        OTHER_SOURCE,
        [
            osv_record(
                SHARED_CVE,
                [affected("sharedlib", versions=["1.0.0"])],
                severity="low",
            )
        ],
    )
    catalog.add_vulnerability(DEFAULT_CVE, "flask", "critical")
    for service, name, version in (
        ("api", "app", "1.0.0"),
        ("api", "sharedlib", "1.0.0"),
        ("api", "flask", "1.5.0"),
        ("api", "extralib", "3.0.0"),
        ("worker", "sharedlib", "1.0.0"),
    ):
        catalog.add_component(service, "pypi", name, version)
    catalog.add_dependency(
        "api", "pypi", "app", "1.0.0", "api", "pypi", "sharedlib", "1.0.0"
    )
    catalog.add_dependency(
        "api", "pypi", "app", "1.0.0", "api", "pypi", "flask", "1.5.0"
    )
    catalog.request_exemption(
        APPROVED_EXEMPTION,
        "api", "pypi", "app", "1.0.0",
        SHARED_CVE, "sharedlib", TARGET_SOURCE,
        applicant="alice",
        reason="egress proxy compensates the transitive sharedlib exposure",
        expires_at=EXPIRES_AT,
        submitted_at=SUBMITTED_AT,
    )
    catalog.approve_exemption(
        APPROVED_EXEMPTION, handler="bob", note="compensating controls verified",
        decided_at=APPROVED_AT,
    )
    catalog.request_exemption(
        PENDING_EXEMPTION,
        "api", "pypi", "app", "1.0.0",
        DEFAULT_CVE, "flask", None,
        applicant="alice",
        reason="manual flask observation awaiting triage",
        expires_at=EXPIRES_AT,
        submitted_at=SUBMITTED_AT,
    )
    return catalog


def osv_rows(catalog: Catalog) -> list[tuple]:
    """All OSV source rows as comparable tuples, ordered, with conditions text."""
    return [
        tuple(row)
        for row in catalog.connection.execute(
            """
            SELECT source, id, package_name, severity, severity_default,
                   withdrawn, conditions
            FROM osv_vulnerabilities
            ORDER BY source, id, package_name
            """
        )
    ]


def manual_rows(catalog: Catalog) -> list[tuple]:
    return [
        tuple(row)
        for row in catalog.connection.execute(
            "SELECT id, component_name, severity FROM vulnerabilities "
            "ORDER BY id, component_name"
        )
    ]


def component_rows(catalog: Catalog) -> list[tuple]:
    return [
        tuple(row)
        for row in catalog.connection.execute(
            "SELECT service, ecosystem, name, version, manual FROM components "
            "ORDER BY service, ecosystem, name, version"
        )
    ]


def take_snapshot(catalog: Catalog) -> dict:
    """Everything a failed replacement must leave untouched."""
    summary = catalog.summary()
    return {
        "osv": osv_rows(catalog),
        "manual": manual_rows(catalog),
        "components": component_rows(catalog),
        "summary": (
            summary.components,
            summary.affected_components,
            summary.vulnerabilities,
            summary.highest_severity,
        ),
        # The same registered components queried before/after must keep using
        # the old conditions and old levels, direct and propagated, in both
        # services - source names carry no service isolation.
        "impact_api": catalog.impact(service="api"),
        "impact_worker": catalog.impact(service="worker"),
        "report_api": catalog.risk_report(service="api", evaluated_at=EVAL_AT),
        "report_worker": catalog.risk_report(
            service="worker", evaluated_at=EVAL_AT
        ),
        "exemption_approved": catalog.get_exemption(APPROVED_EXEMPTION),
        "exemption_pending": catalog.get_exemption(PENDING_EXEMPTION),
        "list_approved": catalog.list_exemptions(status="approved"),
        "list_pending": catalog.list_exemptions(status="pending"),
    }


class OsvReplacementSaveFailureRollbackTests(unittest.TestCase):
    """A write error after the save started rolls the whole replacement back."""

    def _trace_failed_import(self, catalog: Catalog) -> list[str]:
        """Run the replacement, recording the SQL it executes; it must raise."""
        statements: list[str] = []
        catalog.connection.set_trace_callback(statements.append)
        try:
            with self.assertRaises(sqlite3.Error) as caught:
                catalog.import_osv(TARGET_SOURCE, NEW_RECORDS)
        finally:
            catalog.connection.set_trace_callback(None)
        # A save-stage database error, not a record validation ValueError:
        # the input already passed validation.
        self.assertNotIsInstance(caught.exception, ValueError)
        self.assertEqual(type(caught.exception), sqlite3.IntegrityError)
        return [statement.strip() for statement in statements]

    def _assert_old_source_explicitly_intact(self, catalog: Catalog) -> None:
        rows = osv_rows(catalog)
        # Exactly the five old target-source combinations plus the other
        # source's one - nothing added, nothing dropped, nothing modified.
        self.assertEqual(len(rows), 6)
        by_key = {(row[0], row[1], row[2]): row for row in rows}
        self.assertEqual(set(by_key), {
            (TARGET_SOURCE, SHARED_CVE, "sharedlib"),
            (TARGET_SOURCE, SHARED_CVE, "extralib"),
            (TARGET_SOURCE, DEFAULT_CVE, "flask"),
            (TARGET_SOURCE, UNUSED_CVE, "unmatchedlib"),
            (TARGET_SOURCE, WITHDRAWN_CVE, "withdrawnlib"),
            (OTHER_SOURCE, SHARED_CVE, "sharedlib"),
        })

        shared = by_key[(TARGET_SOURCE, SHARED_CVE, "sharedlib")]
        extra = by_key[(TARGET_SOURCE, SHARED_CVE, "extralib")]
        defaulted = by_key[(TARGET_SOURCE, DEFAULT_CVE, "flask")]
        unused = by_key[(TARGET_SOURCE, UNUSED_CVE, "unmatchedlib")]
        withdrawn = by_key[(TARGET_SOURCE, WITHDRAWN_CVE, "withdrawnlib")]
        other = by_key[(OTHER_SOURCE, SHARED_CVE, "sharedlib")]
        # Tuple layout from osv_rows:
        # 0 source, 1 id, 2 package_name, 3 severity, 4 severity_default,
        # 5 withdrawn, 6 conditions.

        # Original level + declared basis on every combination of the
        # multi-package CVE, not just the one whose id happens to remain.
        self.assertEqual(shared[3], "high")
        self.assertEqual(shared[4], 0)
        self.assertEqual(extra[3], "high")
        self.assertEqual(extra[4], 0)
        # 等级来自默认值：medium + severity_default=1，条件是旧区间。
        self.assertEqual(defaulted[3], "medium")
        self.assertEqual(defaulted[4], 1)
        self.assertEqual(
            json.loads(defaulted[6]),
            [
                {
                    "type": "interval",
                    "introduced": "1.0",
                    "fixed": "2.0",
                    "last_affected": None,
                }
            ],
        )
        # Even combinations hitting no component survive the rollback.
        self.assertEqual(unused[3], "medium")
        self.assertEqual(unused[4], 1)
        self.assertEqual(
            json.loads(unused[6]),
            [{"type": "explicit", "version": "9.9.9"}],
        )
        # Withdrawn status is restored too (and its defaulted medium level).
        self.assertEqual(withdrawn[5], "2026-02-01T00:00:00Z")
        self.assertEqual(withdrawn[3], "medium")
        self.assertEqual(withdrawn[4], 1)
        # The other source's same-id row is untouched (its own declared low).
        self.assertEqual(other[3], "low")
        self.assertEqual(other[4], 0)

        # No replacement-new vulnerability or package combination lingers.
        keys = set(by_key)
        self.assertNotIn((TARGET_SOURCE, NEW_CVE, "flask"), keys)
        self.assertNotIn((TARGET_SOURCE, NEW_CVE, "newpack"), keys)
        self.assertNotIn((TARGET_SOURCE, SHARED_CVE, "newpack"), keys)
        self.assertNotIn("newpack", {row[2] for row in rows})

    def _assert_report_semantics(self, catalog: Catalog) -> None:
        # Direct + propagated impacts in api use old conditions/levels:
        # sharedlib (direct), extralib (direct, api-only), flask (direct),
        # and app indirectly through both upstreams - per (component, CVE,
        # source, matched package).
        records = catalog.impact(service="api")
        index = {
            (
                record["component"]["name"],
                record["vulnerability"],
                record["source"],
                record["matched_name"],
            ): record
            for record in records
        }
        self.assertEqual(
            {(c, v, s) for c, v, s, _ in index},
            {
                ("app", SHARED_CVE, OTHER_SOURCE),
                ("app", SHARED_CVE, TARGET_SOURCE),
                ("app", DEFAULT_CVE, None),
                ("app", DEFAULT_CVE, TARGET_SOURCE),
                ("extralib", SHARED_CVE, TARGET_SOURCE),
                ("flask", DEFAULT_CVE, None),
                ("flask", DEFAULT_CVE, TARGET_SOURCE),
                ("sharedlib", SHARED_CVE, OTHER_SOURCE),
                ("sharedlib", SHARED_CVE, TARGET_SOURCE),
            },
        )

        # app -> sharedlib indirect, old declared-high target record.
        app_nvd = index[("app", SHARED_CVE, TARGET_SOURCE, "sharedlib")]
        self.assertFalse(app_nvd["direct"])
        self.assertEqual(app_nvd["severity"], "high")
        self.assertEqual(app_nvd["severity_basis"], "declared")
        self.assertEqual(app_nvd["matched_conditions"], ["==1.0.0"])
        self.assertEqual(
            [node["name"] for node in app_nvd["path"]], ["app", "sharedlib"]
        )
        # app -> flask indirect, old defaulted-medium nvd record + manual
        # critical, each its own record.
        app_manual = index[("app", DEFAULT_CVE, None, "flask")]
        self.assertFalse(app_manual["direct"])
        self.assertEqual(app_manual["severity"], "critical")
        self.assertIsNone(app_manual["severity_basis"])
        app_default = index[("app", DEFAULT_CVE, TARGET_SOURCE, "flask")]
        self.assertFalse(app_default["direct"])
        self.assertEqual(app_default["severity"], "medium")
        self.assertEqual(app_default["severity_basis"], "default")
        self.assertEqual(app_default["matched_conditions"], [">=1.0,<2.0"])
        self.assertEqual(
            [node["name"] for node in app_default["path"]], ["app", "flask"]
        )
        # Direct terminals.
        self.assertTrue(index[("sharedlib", SHARED_CVE, TARGET_SOURCE, "sharedlib")]["direct"])
        self.assertTrue(index[("flask", DEFAULT_CVE, TARGET_SOURCE, "flask")]["direct"])
        self.assertTrue(index[("extralib", SHARED_CVE, TARGET_SOURCE, "extralib")]["direct"])

        # worker: the global source's old high record (and the other source's
        # low record) for sharedlib survive there too.
        worker = catalog.impact(service="worker")
        worker_keys = {
            (r["vulnerability"], r["source"], r["severity"], r["severity_basis"])
            for r in worker
        }
        self.assertEqual(worker_keys, {
            (SHARED_CVE, TARGET_SOURCE, "high", "declared"),
            (SHARED_CVE, OTHER_SOURCE, "low", "declared"),
        })

        # At the fixed evaluation instant: app's nvd SHARED_CVE record is
        # exempted by the approved request at its original approved level;
        # everything else stays unhandled - including the pending manual one.
        report = catalog.risk_report(service="api", evaluated_at=EVAL_AT)
        by_key = {
            (
                entry["component"]["name"],
                entry["vulnerability"],
                entry["source"],
            ): entry
            for entry in report["impacts"]
        }
        exempted = by_key[("app", SHARED_CVE, TARGET_SOURCE)]
        self.assertTrue(exempted["exempted"])
        self.assertEqual(exempted["exemption_request"], APPROVED_EXEMPTION)
        self.assertIsNone(exempted["not_exempt_reason"])
        self.assertFalse(by_key[("app", SHARED_CVE, OTHER_SOURCE)]["exempted"])
        self.assertFalse(by_key[("app", DEFAULT_CVE, None)]["exempted"])
        self.assertFalse(by_key[("app", DEFAULT_CVE, TARGET_SOURCE)]["exempted"])
        # The pending request stays linked but is not an exemption.
        self.assertEqual(
            by_key[("app", DEFAULT_CVE, None)]["exemption_request"],
            PENDING_EXEMPTION,
        )
        self.assertEqual(report["unhandled_component_count"], 4)
        self.assertEqual(report["highest_severity"], "critical")

        worker_report = catalog.risk_report(
            service="worker", evaluated_at=EVAL_AT
        )
        self.assertTrue(
            all(not entry["exempted"] for entry in worker_report["impacts"])
        )
        self.assertEqual(worker_report["unhandled_component_count"], 1)
        self.assertEqual(worker_report["highest_severity"], "high")

    def _run_failure_scenario(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)
            snapshot = take_snapshot(catalog)
            self._assert_report_semantics(catalog)

            catalog.connection.execute(SAVE_FAILURE_TRIGGER)
            statements = self._trace_failed_import(catalog)

            # The replacement really had started inside one transaction:
            # BEGIN, the old rows withdrawn, and at least one new row written
            # (the retained sharedlib combination) before the error. The
            # failed INSERT was attempted for the failing package.
            self.assertTrue(
                any(s == "BEGIN" or s.startswith("BEGIN") for s in statements)
            )
            self.assertTrue(
                any(
                    s.startswith("DELETE FROM osv_vulnerabilities")
                    for s in statements
                ),
                "target-source withdrawal never ran",
            )
            inserts = [
                s for s in statements
                if s.startswith("INSERT INTO osv_vulnerabilities")
            ]
            self.assertGreaterEqual(
                len(inserts), 1, "no replacement row was written before failing"
            )
            # The whole partial replacement rolled back, never committed.
            self.assertIn("ROLLBACK", statements)
            self.assertNotIn("COMMIT", statements)

            # The call failed - there is no success count - and the old source
            # is fully restored on the same connection, with all surrounding
            # business data and reports identical.
            self._assert_old_source_explicitly_intact(catalog)
            self.assertEqual(take_snapshot(catalog), snapshot)
            self._assert_report_semantics(catalog)

            catalog.connection.execute("DROP TRIGGER IF EXISTS fail_osv_save")
            catalog.close()

            # Durable rollback: reopening the file shows the identical state.
            reopened = Catalog(database)
            self.assertEqual(osv_rows(reopened), snapshot["osv"])
            self.assertEqual(take_snapshot(reopened), snapshot)
            self._assert_report_semantics(reopened)

            # Re-importing the old content is a pure no-op (same five
            # combinations, count unchanged), proving the failed attempt lost
            # the source no attribution; the count is per (vuln, package).
            count = reopened.import_osv(TARGET_SOURCE, OLD_RECORDS)
            self.assertEqual(count, 5)
            self.assertEqual(osv_rows(reopened), snapshot["osv"])
            self.assertEqual(
                reopened.get_exemption(APPROVED_EXEMPTION),
                snapshot["exemption_approved"],
            )
            reopened.close()

    def test_save_failure_after_partial_write_rolls_back_entire_replace(self) -> None:
        self._run_failure_scenario()

    def test_cli_mid_save_failure_exits_nonzero_without_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            setup = build_catalog(database)
            snapshot = take_snapshot(setup)
            # Install the same trigger through the catalog's connection, then
            # hand the file to a fresh CLI invocation against the same content.
            setup.connection.execute(SAVE_FAILURE_TRIGGER)
            setup.close()

            new_file = Path(directory, "new.json")
            new_file.write_text(json.dumps(NEW_RECORDS))

            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                # The CLI only turns validation ValueErrors into a friendly
                # non-zero status; an unexpected save-stage database error
                # surfaces as an exception (process non-zero) - it must never
                # be swallowed into a success line.
                with self.assertRaises(sqlite3.Error):
                    main([
                        "--database", database,
                        "import-osv", TARGET_SOURCE, str(new_file),
                    ])
            self.assertNotIn("导入漏洞记录", stdout.getvalue())

            catalog = Catalog(database)
            self.assertEqual(take_snapshot(catalog), snapshot)
            self._assert_old_source_explicitly_intact(catalog)
            self._assert_report_semantics(catalog)
            catalog.close()


class OsvReplacementValidationFailureContrastTests(unittest.TestCase):
    """Pre-save validation rejections must not be mistaken for this coverage.

    A bad array rejects while it is being parsed, before the database
    transaction begins: no statement runs at all. That makes it observably
    different from the save-failure case (partial INSERTs then ROLLBACK).
    """

    def test_invalid_records_fail_before_any_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)
            snapshot = take_snapshot(catalog)

            bad_cases = [
                # Unsupported ecosystem.
                [
                    {
                        "id": "CVE-2026-9001",
                        "affected": [
                            {
                                "package": {"ecosystem": "npm", "name": "flask"},
                                "versions": ["1.0"],
                            }
                        ],
                    }
                ],
                # An affected entry missing its own conditions even though a
                # normalization-equivalent sibling carries some.
                [
                    osv_record(
                        "CVE-2026-9002",
                        [
                            affected("Foo_Bar", versions=["1.0"]),
                            affected("foo-bar"),
                        ],
                    )
                ],
                # Duplicate id within the file.
                [
                    osv_record("CVE-2026-9003", [affected("a", versions=["1.0"])]),
                    osv_record("CVE-2026-9003", [affected("b", versions=["1.0"])]),
],
            ]
            for bad in bad_cases:
                with self.subTest(bad=bad[0]["id"]):
                    statements: list[str] = []
                    catalog.connection.set_trace_callback(statements.append)
                    try:
                        with self.assertRaises(ValueError):
                            catalog.import_osv(TARGET_SOURCE, bad)
                    finally:
                        catalog.connection.set_trace_callback(None)
                    self.assertFalse(
                        [s for s in statements if s.strip()],
                        "validation must reject before any SQL runs",
                    )
                    self.assertEqual(take_snapshot(catalog), snapshot)
            catalog.close()


class OsvReplacementSuccessPreservedTests(unittest.TestCase):
    """A valid replacement still commits and [] still clears the source."""

    def test_valid_replacement_commits_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)

            count = catalog.import_osv(TARGET_SOURCE, NEW_RECORDS)
            # Counted per (vulnerability, package): 2 combinations per record.
            self.assertEqual(count, 4)
            keys = {
                (row[1], row[2]) for row in osv_rows(catalog)
                if row[0] == TARGET_SOURCE
            }
            self.assertEqual(keys, {
                (SHARED_CVE, "sharedlib"),
                (SHARED_CVE, "newpack"),
                (NEW_CVE, "flask"),
                (NEW_CVE, "newpack"),
            })
            # The modification took effect: SHARED_CVE is now critical.
            shared = next(
                row for row in osv_rows(catalog)
                if (row[0], row[1], row[2])
                == (TARGET_SOURCE, SHARED_CVE, "sharedlib")
            )
            self.assertEqual(shared[3], "critical")
            self.assertEqual(shared[4], 0)
            # Old-only combos (extralib, flask/default, unmatched, withdrawn)
            # and the old withdrawn/unmatched rows left the target source.
            target = {
                (row[1], row[2]) for row in osv_rows(catalog)
                if row[0] == TARGET_SOURCE
            }
            self.assertNotIn((DEFAULT_CVE, "flask"), target)
            self.assertNotIn((SHARED_CVE, "extralib"), target)
            self.assertNotIn((UNUSED_CVE, "unmatchedlib"), target)
            self.assertNotIn((WITHDRAWN_CVE, "withdrawnlib"), target)
            # Other source and manual rows survive a successful replacement.
            self.assertEqual(len([r for r in osv_rows(catalog) if r[0] == OTHER_SOURCE]), 1)
            self.assertEqual(len(manual_rows(catalog)), 1)

            # New content now drives impact: flask 1.5.0 is hit by NEW_CVE;
            # extralib is no longer hit by this source (only manual/other
            # remain as before). Old DEFAULT_CVE/osv record disappeared, so
            # flask keeps only the manual critical record.
            records = catalog.impact(service="api")
            present = {
                (r["component"]["name"], r["vulnerability"], r["source"])
                for r in records
            }
            self.assertIn(("flask", NEW_CVE, TARGET_SOURCE), present)
            self.assertNotIn(("flask", DEFAULT_CVE, TARGET_SOURCE), present)
            self.assertNotIn(("extralib", SHARED_CVE, TARGET_SOURCE), present)
            catalog.close()

    def test_empty_array_clears_target_source_but_keeps_rest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)

            self.assertEqual(catalog.import_osv(TARGET_SOURCE, []), 0)
            self.assertEqual(
                [r for r in osv_rows(catalog) if r[0] == TARGET_SOURCE], []
            )
            # Clearing one source does not remove the same CVE from elsewhere:
            # other source + manual registration keep flask/sharedlib at risk.
            present = {
                (r["component"]["name"], r["vulnerability"], r["source"])
                for r in catalog.impact(service="api")
            }
            self.assertIn(("sharedlib", SHARED_CVE, OTHER_SOURCE), present)
            self.assertIn(("flask", DEFAULT_CVE, None), present)
            self.assertFalse(
                [p for p in present if p[2] == TARGET_SOURCE],
                "clearing the target source must remove all its impacts",
            )
            catalog.close()

    def test_cli_success_still_reports_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            setup = build_catalog(database)
            setup.close()
            new_file = Path(directory, "new.json")
            new_file.write_text(json.dumps(NEW_RECORDS))

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main([
                    "--database", database,
                    "import-osv", TARGET_SOURCE, str(new_file),
                ])
            self.assertEqual(status, 0)
            self.assertIn("导入漏洞记录: 4 条", output.getvalue())


if __name__ == "__main__":
    unittest.main()
