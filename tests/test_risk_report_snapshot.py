"""Regression tests: one risk report must observe one consistent directory.

The failure mode these tests pin down: another process replaces data in the
same database while a risk report is being assembled. The report reads the
directory in several statements (components, dependency edges, manual
observations, OSV source records, exemption requests), and without one
surrounding read transaction each statement observes the newest committed
state. When an SBOM replacement changes ``app -> lib`` into
``app -> bridge -> lib`` mid-report, the report can explain the old component
list with the new dependency graph: path reconstruction reaches the new
``bridge`` node that is absent from the old component map and crashes, or
older impacts get linked against approval state committed only moments later.

A report must instead be wholly pre-update or wholly post-update: every path
is a complete path whose nodes all exist in the observed state, direct and
indirect flags, vulnerability sources, matched conditions, exemption links,
counts and the highest severity all correspond to that one state. The tests
drive the interleave deterministically with a trace callback that starts a
competing writer on a second connection at a precise point in the report's
read sequence; the writer blocks on the report's read lock until the report
finishes.
"""

import io
import json
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import main

SERVICE = "svc"
OTHER_SERVICE = "other"
EVAL_AT = "2027-01-01T00:00:00+00:00"
EXPIRES_AT = "2030-12-31T23:59:59+00:00"
REQUEST_ID = "EXM-2026-1001"


def cyclonedx(names, edges):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "bom-ref": name,
                "purl": f"pkg:pypi/{name}@1.0.0",
                "version": "1.0.0",
            }
            for name in names
        ],
        "dependencies": [
            {"ref": dependent, "dependsOn": [dependency]}
            for dependent, dependency in edges
        ],
    }


# Directory state A: app depends directly on lib.
SBOM_A = cyclonedx(["app", "lib"], [("app", "lib")])
# Directory state B: one extra hop through bridge.
SBOM_B = cyclonedx(
    ["app", "bridge", "lib"], [("app", "bridge"), ("bridge", "lib")]
)
# A state with app on its own (lib and the edge leave with the replacement).
SBOM_APP_ONLY = cyclonedx(["app"], [])

OLD_PATHS = {("app", "lib"), ("lib",)}
NEW_PATHS = {("app", "bridge", "lib"), ("bridge", "lib"), ("lib",)}


def osv_record(identifier, package, *, severity="high"):
    record = {
        "id": identifier,
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": package},
                "versions": ["1.0.0"],
            }
        ],
    }
    if severity is not None:
        record["database_specific"] = {"severity": severity}
    return record


OSV_A = [osv_record("CVE-1", "lib", severity="high")]
OSV_B = [osv_record("CVE-2", "app", severity="critical")]


def path_names(entry):
    return tuple(node["name"] for node in entry["path"])


def report_paths(report):
    return {path_names(entry) for entry in report["impacts"]}


class InterleavingReportTests(unittest.TestCase):
    """A replacement committed while a report reads cannot split the state."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name, "catalog.db"))
        self.catalog = Catalog(self.database)

    def tearDown(self):
        self.catalog.close()
        self.directory.cleanup()

    def _build_state_a(self):
        self.catalog.import_sbom(SERVICE, "src", SBOM_A)
        self.catalog.add_vulnerability("CVE-1", "lib", "high")

    def _replace_when_report_reads(self, trigger_sql, action):
        """Start ``action`` on a second connection when the report reads a
        statement whose text contains ``trigger_sql``.

        The trigger fires while the report already holds its read
        transaction's SHARED lock, so the writer reaches and blocks on its
        commit until the report finishes. Returns a join handle.
        """
        database = self.database
        started = threading.Event()

        def writer():
            other = Catalog(database)
            other.connection.execute("PRAGMA busy_timeout = 30000")
            try:
                started.wait()
                action(other)
            finally:
                other.close()

        thread = threading.Thread(target=writer)
        thread.start()
        armed = {"fired": False}

        def tracer(statement):
            if not armed["fired"] and trigger_sql in statement:
                armed["fired"] = True
                started.set()
                # Let the writer reach the blocked commit while the report
                # keeps the read lock.
                time.sleep(0.5)

        self.catalog.connection.set_trace_callback(tracer)
        return thread, armed

    def _stop_trace_and_join(self, thread):
        self.catalog.connection.set_trace_callback(None)
        thread.join(timeout=30)
        self.assertFalse(thread.is_alive(), "competing writer never finished")

    def test_sbom_replace_mid_report_report_is_wholly_old_then_wholly_new(self):
        self._build_state_a()
        thread, armed = self._replace_when_report_reads(
            "FROM dependencies",
            lambda other: other.import_sbom(SERVICE, "src", SBOM_B),
        )
        report_during = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVAL_AT
        )
        self._stop_trace_and_join(thread)
        self.assertTrue(armed["fired"])

        # The report that ran against the old state must not mention bridge
        # at all: two records, the direct app -> lib path and the lib hit.
        self.assertEqual(report_paths(report_during), OLD_PATHS)
        self.assertEqual(report_during["impact_count"], 2)
        self.assertEqual(report_during["unhandled_component_count"], 2)
        self.assertEqual(report_during["highest_severity"], "high")
        for entry in report_during["impacts"]:
            for node in entry["path"]:
                # Every path node exists in the state the report observed.
                self.assertNotEqual(node["name"], "bridge")

        # Once the replacement committed, the next report is wholly new.
        report_after = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVAL_AT
        )
        self.assertEqual(report_paths(report_after), NEW_PATHS)
        self.assertEqual(report_after["impact_count"], 3)
        self.assertEqual(report_after["unhandled_component_count"], 3)
        self.assertEqual(report_after["highest_severity"], "high")
        app_entry = next(
            entry
            for entry in report_after["impacts"]
            if entry["component"]["name"] == "app"
        )
        self.assertFalse(app_entry["direct"])
        self.assertEqual(
            [node["name"] for node in app_entry["path"]],
            ["app", "bridge", "lib"],
        )

    def test_unscoped_report_gets_the_same_snapshot_guarantee(self):
        self._build_state_a()
        thread, armed = self._replace_when_report_reads(
            "FROM dependencies",
            lambda other: other.import_sbom(SERVICE, "src", SBOM_B),
        )
        report_during = self.catalog.risk_report(evaluated_at=EVAL_AT)
        self._stop_trace_and_join(thread)
        self.assertTrue(armed["fired"])
        self.assertEqual(report_paths(report_during), OLD_PATHS)
        self.assertEqual(report_during["impact_count"], 2)

        report_after = self.catalog.risk_report(evaluated_at=EVAL_AT)
        self.assertEqual(report_paths(report_after), NEW_PATHS)
        self.assertEqual(report_after["impact_count"], 3)

    def test_osv_replace_mid_report_keeps_one_source_state(self):
        self.catalog.import_sbom(SERVICE, "src", SBOM_A)
        self.catalog.import_osv("osrc", OSV_A)
        thread, armed = self._replace_when_report_reads(
            "FROM osv_vulnerabilities",
            lambda other: other.import_osv("osrc", OSV_B),
        )
        report_during = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVAL_AT
        )
        self._stop_trace_and_join(thread)
        self.assertTrue(armed["fired"])

        # Old source state: CVE-1 hits lib directly and app indirectly.
        self.assertEqual(report_paths(report_during), OLD_PATHS)
        self.assertEqual(
            sorted(entry["vulnerability"] for entry in report_during["impacts"]),
            ["CVE-1", "CVE-1"],
        )
        self.assertEqual(report_during["impact_count"], 2)
        self.assertEqual(report_during["highest_severity"], "high")
        for entry in report_during["impacts"]:
            self.assertEqual(entry["source"], "osrc")

        # New source state: CVE-2 hits app directly at critical; lib is free.
        report_after = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVAL_AT
        )
        self.assertEqual(report_paths(report_after), {("app",)})
        self.assertEqual(report_after["impact_count"], 1)
        self.assertEqual(report_after["unhandled_component_count"], 1)
        self.assertEqual(report_after["highest_severity"], "critical")
        app_entry = report_after["impacts"][0]
        self.assertTrue(app_entry["direct"])
        self.assertEqual(app_entry["vulnerability"], "CVE-2")
        self.assertEqual(app_entry["matched_conditions"], ["==1.0.0"])

    def test_approval_committed_mid_report_is_seen_only_by_the_next_report(self):
        self._build_state_a()
        self.catalog.request_exemption(
            REQUEST_ID,
            SERVICE, "pypi", "lib", "1.0.0",
            "CVE-1", "lib", None,
            applicant="alice",
            reason="pending while the first report is assembled",
            expires_at=EXPIRES_AT,
        )
        thread, armed = self._replace_when_report_reads(
            "FROM exemption_requests",
            lambda other: other.approve_exemption(
                REQUEST_ID, handler="bob", note="approved mid-report"
            ),
        )
        report_during = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVAL_AT
        )
        self._stop_trace_and_join(thread)
        self.assertTrue(armed["fired"])

        lib_entry = next(
            entry
            for entry in report_during["impacts"]
            if entry["component"]["name"] == "lib"
        )
        # The approval committed by the other process cannot reach this
        # report: the old impact is still judged against the pending state.
        self.assertFalse(lib_entry["exempted"])
        self.assertEqual(lib_entry["exemption_request"], REQUEST_ID)
        self.assertIn("待审批", lib_entry["not_exempt_reason"])
        self.assertEqual(report_during["unhandled_component_count"], 2)
        self.assertEqual(report_during["highest_severity"], "high")

        report_after = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVAL_AT
        )
        lib_after = next(
            entry
            for entry in report_after["impacts"]
            if entry["component"]["name"] == "lib"
        )
        self.assertTrue(lib_after["exempted"])
        self.assertEqual(lib_after["exemption_request"], REQUEST_ID)
        self.assertIsNone(lib_after["not_exempt_reason"])
        # app's indirect record has no request and is the one unhandled
        # component; the highest severity comes from the actual returned
        # impacts and exemption result, not any other state.
        self.assertEqual(report_after["unhandled_component_count"], 1)
        self.assertEqual(report_after["highest_severity"], "high")

    def test_service_filter_keeps_other_services_out_under_concurrency(self):
        self._build_state_a()
        # A second service with its own components and vulnerability.
        self.catalog.import_sbom(
            OTHER_SERVICE, "src", cyclonedx(["tool", "util"], [("tool", "util")])
        )
        self.catalog.add_vulnerability("CVE-9", "util", "critical")
        thread, _ = self._replace_when_report_reads(
            "FROM dependencies",
            lambda other: other.import_sbom(
                OTHER_SERVICE, "src", cyclonedx(["tool"], [])
            ),
        )
        report = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVAL_AT
        )
        self._stop_trace_and_join(thread)

        self.assertEqual(report["service"], SERVICE)
        self.assertTrue(report["impacts"])
        self.assertTrue(
            all(entry["component"]["service"] == SERVICE for entry in report["impacts"])
        )
        self.assertEqual(report_paths(report), OLD_PATHS)
        self.assertEqual(report["impact_count"], 2)

    def test_report_is_read_only(self):
        self._build_state_a()

        def dump_tables():
            return {
                table: {
                    tuple(row)
                    for row in self.catalog.connection.execute(
                        f"SELECT * FROM {table}"
                    )
                }
                for table in (
                    "components",
                    "dependencies",
                    "vulnerabilities",
                    "sources",
                    "component_sources",
                    "dependency_sources",
                    "osv_vulnerabilities",
                    "exemption_requests",
                    "exemption_events",
                )
            }

        before = dump_tables()
        statements = []
        self.catalog.connection.set_trace_callback(statements.append)
        report = self.catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
        self.catalog.connection.set_trace_callback(None)
        after = dump_tables()

        self.assertEqual(before, after)
        write_verbs = (
            "INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE",
            "DROP", "ALTER",
        )
        for statement in statements:
            normalized = statement.lstrip().upper()
            self.assertFalse(
                any(normalized.startswith(verb) for verb in write_verbs),
                f"risk report issued a write statement: {statement}",
            )
        self.assertFalse(self.catalog.connection.in_transaction)
        self.assertEqual(report_paths(report), OLD_PATHS)


class CallerTransactionTests(unittest.TestCase):
    """A report inside a caller's open transaction sees the caller's own
    uncommitted changes and must never commit or roll them back."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name, "catalog.db"))
        self.catalog = Catalog(self.database)
        self.catalog.import_sbom(SERVICE, "src", SBOM_A)
        self.catalog.add_vulnerability("CVE-1", "lib", "high")

    def tearDown(self):
        self.catalog.close()
        self.directory.cleanup()

    def test_uncommitted_caller_changes_are_visible_and_left_open(self):
        self.catalog.connection.execute("BEGIN IMMEDIATE")
        self.catalog.connection.execute(
            "INSERT INTO vulnerabilities(id, component_name, severity) "
            "VALUES (?, ?, ?)",
            ("CVE-8", "lib", "critical"),
        )
        try:
            report = self.catalog.risk_report(
                service=SERVICE, evaluated_at=EVAL_AT
            )
            # The report runs inside the caller's transaction: the
            # uncommitted observation is visible and raises the top severity.
            self.assertTrue(
                self.catalog.connection.in_transaction,
                "the report must not close the caller's transaction",
            )
            self.assertEqual(report["highest_severity"], "critical")
            self.assertIn(
                "CVE-8",
                {entry["vulnerability"] for entry in report["impacts"]},
            )
        finally:
            self.catalog.connection.rollback()

        self.assertFalse(self.catalog.connection.in_transaction)
        report_after = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVAL_AT
        )
        self.assertNotIn(
            "CVE-8",
            {entry["vulnerability"] for entry in report_after["impacts"]},
        )
        self.assertEqual(report_after["highest_severity"], "high")


class VersionErrorSnapshotTests(unittest.TestCase):
    """A version-match failure releases the snapshot and names the component;
    the same Catalog object stays queryable and updatable afterwards."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name, "catalog.db"))
        self.catalog = Catalog(self.database)
        # bad@not-a-version is registered as a component; PEP 440 only has to
        # parse it once an OSV record matches the package name.
        self.catalog.import_sbom(
            SERVICE,
            "src",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "bom-ref": "bad",
                        "purl": "pkg:pypi/bad@not-a-version",
                        "version": "not-a-version",
                    }
                ],
                "dependencies": [],
            },
        )
        self.catalog.import_osv("osrc", [osv_record("CVE-7", "bad")])

    def tearDown(self):
        self.catalog.close()
        self.directory.cleanup()

    def test_error_names_component_releases_snapshot_and_object_recovers(self):
        for scope in (SERVICE, None):
            with self.subTest(scope=scope):
                with self.assertRaises(ValueError) as caught:
                    self.catalog.risk_report(service=scope, evaluated_at=EVAL_AT)
                message = str(caught.exception)
                for piece in (SERVICE, "pypi", "bad", "not-a-version"):
                    self.assertIn(piece, message)
            # No half-open read transaction is left behind on failure.
            self.assertFalse(self.catalog.connection.in_transaction)

        # A different, clean service is still queryable on the same object.
        self.catalog.import_sbom(
            OTHER_SERVICE, "src", cyclonedx(["app"], [])
        )
        other_report = self.catalog.risk_report(
            service=OTHER_SERVICE, evaluated_at=EVAL_AT
        )
        self.assertEqual(other_report["impact_count"], 0)
        self.assertEqual(other_report["unhandled_component_count"], 0)
        self.assertIsNone(other_report["highest_severity"])

        # Removing the matching OSV condition clears the error, and the same
        # object can then both query and update again.
        self.assertEqual(self.catalog.import_osv("osrc", []), 0)
        recovered = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVAL_AT
        )
        self.assertEqual(recovered["impact_count"], 0)
        self.assertEqual(self.catalog.summary().components, 2)

        self.assertEqual(self.catalog.import_osv("osrc", [osv_record("CVE-7", "bad")]), 1)
        with self.assertRaises(ValueError):
            self.catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
        self.assertFalse(self.catalog.connection.in_transaction)


class AtInstantTests(unittest.TestCase):
    """--at only judges exemption terms; it never rewinds the directory."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name, "catalog.db"))
        self.catalog = Catalog(self.database)
        self.catalog.import_sbom(SERVICE, "src", SBOM_A)
        self.catalog.add_vulnerability("CVE-1", "lib", "high")
        self.catalog.request_exemption(
            REQUEST_ID,
            SERVICE, "pypi", "lib", "1.0.0",
            "CVE-1", "lib", None,
            applicant="alice",
            reason="approved for the old directory state",
            expires_at=EXPIRES_AT,
        )
        self.catalog.approve_exemption(REQUEST_ID, handler="bob", note="ok")

    def tearDown(self):
        self.catalog.close()
        self.directory.cleanup()

    def test_past_instant_does_not_restore_replaced_components_or_impacts(self):
        in_force = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVAL_AT
        )
        self.assertEqual(in_force["impact_count"], 2)
        self.assertTrue(
            next(
                entry
                for entry in in_force["impacts"]
                if entry["component"]["name"] == "lib"
            )["exempted"]
        )

        # The source is replaced: lib and its edge leave the current catalog.
        self.catalog.import_sbom(SERVICE, "src", SBOM_APP_ONLY)
        self.assertEqual(self.catalog.summary().components, 1)

        # An evaluation instant earlier than the submission/approval must not
        # reconstruct the old component list or its impacts: the report sees
        # the current empty-impact directory at every --at.
        for instant in ("2025-01-01T00:00:00+00:00", EVAL_AT):
            with self.subTest(instant=instant):
                report = self.catalog.risk_report(
                    service=SERVICE, evaluated_at=instant
                )
                self.assertEqual(report["impact_count"], 0)
                self.assertEqual(report["unhandled_component_count"], 0)
                self.assertIsNone(report["highest_severity"])
                self.assertEqual(report["impacts"], [])

        # The approval history is untouched by the queries and the
        # replacement; it stays queryable with its original state.
        request = self.catalog.get_exemption(REQUEST_ID)
        self.assertEqual(request["status"], "approved")
        self.assertEqual(request["approved_severity"], "high")
        self.assertEqual(
            [event["action"] for event in request["events"]],
            ["request", "approve"],
        )


class CliConcurrentReportTests(unittest.TestCase):
    """The CLI entry point stays correct while another process writes."""

    def test_cli_reports_are_always_one_complete_state(self):
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            setup = Catalog(database)
            setup.import_sbom(SERVICE, "src", SBOM_A)
            setup.add_vulnerability("CVE-1", "lib", "high")
            setup.close()

            writer = Catalog(database)
            writer.connection.execute("PRAGMA busy_timeout = 30000")
            go = threading.Event()
            stop = threading.Event()

            def replace_loop():
                go.wait()
                next_bom = SBOM_B
                delays = (0, 0.001, 0.003, 0.007, 0.015, 0.03)
                while not stop.is_set():
                    for delay in delays:
                        if stop.is_set():
                            return
                        time.sleep(delay)
                        writer.import_sbom(SERVICE, "src", next_bom)
                        next_bom = SBOM_A if next_bom is SBOM_B else SBOM_B

            thread = threading.Thread(target=replace_loop)
            thread.start()
            try:
                go.set()
                for _ in range(20):
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        status = main(
                            [
                                "--database", database,
                                "risk-report", "--service", SERVICE,
                                "--at", EVAL_AT,
                            ]
                        )
                    # A report never crashes on a missing path node and never
                    # emits a hybrid path: whatever it observed is one of the
                    # two complete directory states.
                    self.assertEqual(status, 0, stderr.getvalue())
                    report = json.loads(stdout.getvalue())
                    paths = report_paths(report)
                    self.assertIn(paths, (OLD_PATHS, NEW_PATHS))
                    if paths == OLD_PATHS:
                        self.assertEqual(report["impact_count"], 2)
                    else:
                        self.assertEqual(report["impact_count"], 3)
            finally:
                stop.set()
                thread.join(timeout=30)
                writer.close()
            self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
