"""Regression tests for risk-report consistency across interleaved saves.

Scenario: one application (``app``) depends on one library (``lib``) inside a
single service. One OSV source (``nvd``) hits the library's exact version, so
the library is directly affected and the application indirectly; nothing else
is vulnerable. Only the application's indirect impact has an exemption
request - unexpired, pending, submitted by alice; the library has none. The
report is evaluated at one fixed, timezone-aware instant inside the request's
term; that instant only judges the term, while the approval state is always
the currently saved one.

Another user then performs two saves from a second connection, in order:

1. replace the same-named OSV source with a record that still hits the same
   version but raises the severity from ``high`` to ``critical``;
2. approve the application's request (approver != applicant), which records
   the severity in force at approval time - ``critical``.

A report read that interleaves with these saves must always reflect exactly
one complete saved state:

* state A (before the source update): both impacts ``high``, the application
  linked to the pending request, two unhandled components, highest ``high``;
* state B (source updated, not yet approved): both impacts ``critical``, the
  application still linked to the pending request, two unhandled components,
  highest ``critical``;
* state C (approved): both impacts ``critical``, only the application's
  indirect impact exempted, the library's direct impact still unhandled, one
  unhandled component, highest ``critical``.

The forbidden mixture is a ``high`` application impact exempted through the
``critical`` approval - impact facts and exemption facts stitched from two
different states. Each record's source, direct/indirect flag, dependency path
and not-exempt reason must likewise belong to the reported state, both impact
records are always present, and once the interleaved reads finish a fresh
report shows the saved new state. Querying only after all saves would not
exercise any of this, so the saves are committed strictly inside the report's
read window. Reports themselves are read-only: they never change the
request's status, the approved severity or the processing history, which
contains exactly the submission and approval events.
"""

import contextlib
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import main


SERVICE = "api"
OSV_SOURCE = "nvd"
CVE = "CVE-2026-4001"
REQUEST_ID = "EXM-2026-001"
APPLICANT = "alice"
APPROVER = "bob"
EXPIRES_AT = "2030-01-01T00:00:00+00:00"
# Fixed, timezone-aware evaluation instant inside the request's term.
EVALUATED_AT = "2026-12-01T00:00:00+00:00"
EVALUATED_AT_STORED = "2026-12-01T00:00:00.000000Z"
PENDING_REASON = "豁免申请尚在待审批"


def lib_records(severity: str) -> list[dict]:
    """One OSV vulnerability hitting exactly lib 1.0.0 at ``severity``."""
    return [
        {
            "id": CVE,
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "lib"},
                    "versions": ["1.0.0"],
                }
            ],
            "database_specific": {"severity": severity},
        }
    ]


def seed(catalog: Catalog) -> None:
    """The application, its library, the high OSV hit and the pending request."""
    catalog.add_component(SERVICE, "pypi", "app", "1.0.0")
    catalog.add_component(SERVICE, "pypi", "lib", "1.0.0")
    catalog.add_dependency(
        SERVICE, "pypi", "app", "1.0.0", SERVICE, "pypi", "lib", "1.0.0"
    )
    catalog.import_osv(OSV_SOURCE, lib_records("high"))
    catalog.request_exemption(
        REQUEST_ID, SERVICE, "pypi", "app", "1.0.0",
        CVE, "lib", OSV_SOURCE,
        applicant=APPLICANT,
        reason="mitigated by egress proxy",
        expires_at=EXPIRES_AT,
    )


def build_catalog(database: str) -> Catalog:
    catalog = Catalog(database)
    # WAL lets the second connection commit while a read snapshot is held, so
    # the saves land strictly inside the report's read window without either
    # connection blocking on the other.
    catalog.connection.execute("PRAGMA journal_mode=WAL")
    seed(catalog)
    return catalog


def report_for(catalog: Catalog) -> dict:
    return catalog.risk_report(service=SERVICE, evaluated_at=EVALUATED_AT)


def impacts_by_component(report: dict) -> dict:
    return {record["component"]["name"]: record for record in report["impacts"]}


class RiskReportStateAssertions:
    """The three complete states and the mixtures that must never appear."""

    def assert_impact_record(
        self,
        record: dict,
        *,
        severity: str,
        direct: bool,
        exempted: bool,
        request: str | None,
        reason: str | None,
        path: list[str],
    ) -> None:
        # Source, identity, direct/indirect flag, dependency path and the
        # not-exempt reason all belong to the same reported state.
        self.assertEqual(record["vulnerability"], CVE)
        self.assertEqual(record["source"], OSV_SOURCE)
        self.assertEqual(record["matched_name"], "lib")
        self.assertEqual(record["severity"], severity)
        self.assertEqual(record["severity_basis"], "declared")
        self.assertEqual(record["direct"], direct)
        self.assertEqual(record["matched_conditions"], ["==1.0.0"])
        self.assertEqual([node["name"] for node in record["path"]], path)
        self.assertEqual(
            [node["service"] for node in record["path"]], [SERVICE] * len(path)
        )
        self.assertEqual(record["exempted"], exempted)
        self.assertEqual(record["exemption_request"], request)
        self.assertEqual(record["not_exempt_reason"], reason)

    def assert_common_shape(self, report: dict) -> dict:
        self.assertEqual(report["evaluated_at"], EVALUATED_AT_STORED)
        self.assertEqual(report["service"], SERVICE)
        # Both impact records are always present.
        self.assertEqual(report["impact_count"], 2)
        impacts = impacts_by_component(report)
        self.assertEqual(set(impacts), {"app", "lib"})
        return impacts

    def assert_state_a(self, report: dict) -> None:
        """Before the source update: high impacts, pending request."""
        impacts = self.assert_common_shape(report)
        self.assertEqual(report["unhandled_component_count"], 2)
        self.assertEqual(report["highest_severity"], "high")
        self.assert_impact_record(
            impacts["lib"], severity="high", direct=True, exempted=False,
            request=None, reason=None, path=["lib"],
        )
        self.assert_impact_record(
            impacts["app"], severity="high", direct=False, exempted=False,
            request=REQUEST_ID, reason=PENDING_REASON, path=["app", "lib"],
        )

    def assert_state_b(self, report: dict) -> None:
        """Source updated to critical, approval not yet saved."""
        impacts = self.assert_common_shape(report)
        self.assertEqual(report["unhandled_component_count"], 2)
        self.assertEqual(report["highest_severity"], "critical")
        self.assert_impact_record(
            impacts["lib"], severity="critical", direct=True, exempted=False,
            request=None, reason=None, path=["lib"],
        )
        self.assert_impact_record(
            impacts["app"], severity="critical", direct=False, exempted=False,
            request=REQUEST_ID, reason=PENDING_REASON, path=["app", "lib"],
        )

    def assert_state_c(self, report: dict) -> None:
        """Approval saved: only the application's indirect impact is exempted."""
        impacts = self.assert_common_shape(report)
        self.assertEqual(report["unhandled_component_count"], 1)
        self.assertEqual(report["highest_severity"], "critical")
        self.assert_impact_record(
            impacts["lib"], severity="critical", direct=True, exempted=False,
            request=None, reason=None, path=["lib"],
        )
        self.assert_impact_record(
            impacts["app"], severity="critical", direct=False, exempted=True,
            request=REQUEST_ID, reason=None, path=["app", "lib"],
        )

    def assert_no_mixed_state(self, report: dict) -> None:
        """Impact facts and exemption facts must come from one state."""
        impacts = self.assert_common_shape(report)
        app = impacts["app"]
        lib = impacts["lib"]
        # One OSV source state per report: the two records never disagree.
        self.assertEqual(app["severity"], lib["severity"])
        # The specific forbidden mixture: a high application impact exempted
        # through the critical approval saved after the source update.
        self.assertFalse(
            app["severity"] == "high" and app["exempted"],
            "high 的应用影响不应使用 critical 审批而被豁免",
        )
        if app["exempted"]:
            self.assertEqual(app["severity"], "critical")
        # The library never has a request, exempted or not.
        self.assertFalse(lib["exempted"])
        self.assertIsNone(lib["exemption_request"])


class RiskReportSequentialStateTests(RiskReportStateAssertions, unittest.TestCase):
    """The three states, walked in order at one fixed evaluation instant."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        seed(self.catalog)

    def tearDown(self) -> None:
        self.catalog.close()

    def test_states_transition_whole_and_evaluation_instant_only_judges_term(self):
        # State A: high source, pending request.
        self.assert_state_a(report_for(self.catalog))

        # State B: the replacement raises the severity; the saved request is
        # untouched and still pending at the same evaluation instant.
        self.catalog.import_osv(OSV_SOURCE, lib_records("critical"))
        self.assert_state_b(report_for(self.catalog))

        # State C: approval records the severity now in force (critical) and
        # exempts only the application's indirect impact.
        saved = self.catalog.approve_exemption(
            REQUEST_ID, APPROVER, "controls verified"
        )
        self.assertEqual(saved["status"], "approved")
        self.assertEqual(saved["approved_severity"], "critical")
        self.assert_state_c(report_for(self.catalog))

        # The request detail carries exactly the submission and approval
        # events; the reports added nothing to the history.
        detail = self.catalog.get_exemption(REQUEST_ID)
        self.assertEqual(
            [event["action"] for event in detail["events"]],
            ["request", "approve"],
        )
        self.assertEqual(detail["applicant"], APPLICANT)
        self.assertEqual(detail["approver"], APPROVER)
        self.assertEqual(detail["approved_severity"], "critical")

    def test_unscoped_report_matches_service_scoped_content(self):
        self.catalog.import_osv(OSV_SOURCE, lib_records("critical"))
        self.catalog.approve_exemption(REQUEST_ID, APPROVER, "ok")
        scoped = report_for(self.catalog)
        unscoped = self.catalog.risk_report(evaluated_at=EVALUATED_AT)
        self.assertEqual(unscoped["service"], None)
        self.assertEqual(unscoped["impacts"], scoped["impacts"])
        self.assertEqual(unscoped["unhandled_component_count"], 1)
        self.assertEqual(unscoped["highest_severity"], "critical")


class RiskReportInterleavedSaveTests(RiskReportStateAssertions, unittest.TestCase):
    """Saves landing mid-report are seen whole or not at all."""

    def _run_interleaved(self, writer_action, barrier_predicate):
        """Run one report while a second connection saves in its read window.

        A trace barrier on the reader's first statement matching
        ``barrier_predicate`` releases the writer only once the report's
        earlier reads have completed, then waits for every save to commit
        before letting that statement run. The report therefore provably
        straddles the commits: with per-statement autocommit reads it would
        stitch the pre-save impacts to the post-save exemption state; with
        one read snapshot every fact stays pinned to the state the report
        opened on.
        """
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        database = str(Path(directory.name, "catalog.db"))
        catalog = build_catalog(database)
        self.addCleanup(catalog.close)

        proceed = threading.Event()
        committed = threading.Event()
        errors: list[BaseException] = []

        def save() -> None:
            proceed.wait(30)
            other = Catalog(database)
            try:
                writer_action(other)
            except BaseException as exc:  # report every writer failure
                errors.append(exc)
            finally:
                other.close()
                committed.set()

        thread = threading.Thread(target=save)
        thread.start()

        fired = {"done": False}

        def barrier(sql: str) -> None:
            normalized = " ".join(sql.split()).upper()
            if not fired["done"] and barrier_predicate(normalized):
                fired["done"] = True
                catalog.connection.set_trace_callback(None)
                proceed.set()
                # Block the report here until the saves have committed, so
                # its remaining reads provably race the commits.
                self.assertTrue(committed.wait(30))

        catalog.connection.set_trace_callback(barrier)
        try:
            report = report_for(catalog)
        finally:
            catalog.connection.set_trace_callback(None)
            # Release the writer even when the report failed before reaching
            # the barrier, so no writer thread outlives the temporary
            # directory.
            proceed.set()

        thread.join(30)
        self.assertFalse(thread.is_alive())
        self.assertTrue(fired["done"], "the interleave barrier never fired")
        self.assertTrue(committed.wait(15))
        self.assertEqual(errors, [])
        return report, catalog, database

    @staticmethod
    def _on_exemption_read(sql: str) -> bool:
        # The report's last read: the exemption links. The impact records
        # (including the OSV severity) were already derived from the old
        # state, so a replace+approve landing here is exactly the window
        # that could stitch high impacts to the critical approval.
        return sql.startswith("SELECT ROWID AS RID")

    @staticmethod
    def _on_osv_read(sql: str) -> bool:
        # The OSV record read itself, after components and edges were read.
        return sql.startswith("SELECT SOURCE, ID, PACKAGE_NAME")

    @staticmethod
    def _replace_then_approve(other: Catalog) -> None:
        other.import_osv(OSV_SOURCE, lib_records("critical"))
        other.approve_exemption(REQUEST_ID, APPROVER, "controls verified")

    def test_replace_and_approve_between_impact_and_exemption_reads(self):
        report, catalog, _ = self._run_interleaved(
            self._replace_then_approve, self._on_exemption_read
        )

        # Pinned to the pre-save state: both impacts high, the request still
        # pending. Never the mixture of a high application impact exempted
        # through the critical approval.
        self.assert_state_a(report)
        self.assert_no_mixed_state(report)
        self.assertFalse(catalog.connection.in_transaction)

        # The approval saved the severity in force at approval time.
        detail = catalog.get_exemption(REQUEST_ID)
        self.assertEqual(detail["status"], "approved")
        self.assertEqual(detail["approved_severity"], "critical")
        self.assertEqual(
            [event["action"] for event in detail["events"]],
            ["request", "approve"],
        )

        # After the interleaved read, a fresh report shows the saved state.
        self.assert_state_c(report_for(catalog))
        self.assertFalse(catalog.connection.in_transaction)

    def test_replace_and_approve_before_osv_read(self):
        report, catalog, _ = self._run_interleaved(
            self._replace_then_approve, self._on_osv_read
        )

        # The snapshot opened on the component read, before either commit:
        # the whole report answers for the pre-update state even though both
        # saves committed before the OSV rows were read.
        self.assert_state_a(report)
        self.assert_no_mixed_state(report)

        self.assert_state_c(report_for(catalog))

    def test_source_replace_between_impact_and_exemption_reads(self):
        report, catalog, database = self._run_interleaved(
            lambda other: other.import_osv(OSV_SOURCE, lib_records("critical")),
            self._on_exemption_read,
        )

        # Only the source moved: the report stays pinned to the pre-update
        # state, pending link included.
        self.assert_state_a(report)
        self.assert_no_mixed_state(report)

        # The next report shows the intermediate state whole: critical
        # impacts, still-pending request, two unhandled components.
        self.assert_state_b(report_for(catalog))

        # Once the approval is also saved, the report shows the final state.
        approver = Catalog(database)
        try:
            approver.approve_exemption(REQUEST_ID, APPROVER, "controls verified")
        finally:
            approver.close()
        self.assert_state_c(report_for(catalog))


class RiskReportReadOnlyTests(RiskReportStateAssertions, unittest.TestCase):
    """Reports never modify the saved request, its decision or its history."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        seed(self.catalog)
        self.catalog.import_osv(OSV_SOURCE, lib_records("critical"))
        self.catalog.approve_exemption(REQUEST_ID, APPROVER, "controls verified")

    def tearDown(self) -> None:
        self.catalog.close()

    def _exemption_tables(self):
        requests = [
            tuple(row)
            for row in self.catalog.connection.execute(
                "SELECT * FROM exemption_requests ORDER BY id"
            )
        ]
        events = [
            tuple(row)
            for row in self.catalog.connection.execute(
                "SELECT request_id, seq, occurred_at, actor, action, reason, "
                "from_status, to_status FROM exemption_events "
                "ORDER BY request_id, seq"
            )
        ]
        return requests, events

    def test_report_issues_only_reads_and_changes_nothing(self):
        before = self._exemption_tables()
        statements: list[str] = []
        self.catalog.connection.set_trace_callback(statements.append)
        try:
            for _ in range(3):
                self.assert_state_c(report_for(self.catalog))
            self.catalog.risk_report(evaluated_at=EVALUATED_AT)
        finally:
            self.catalog.connection.set_trace_callback(None)

        normalized = [" ".join(s.split()).upper() for s in statements]
        write_prefixes = (
            "INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE", "DROP",
            "ALTER", "PRAGMA", "ATTACH", "DETACH", "COMMIT",
            "BEGIN IMMEDIATE", "SAVEPOINT", "RELEASE",
        )
        for statement in normalized:
            self.assertTrue(
                statement.startswith(("SELECT", "BEGIN", "ROLLBACK")),
                f"risk-report issued a non-read statement: {statement}",
            )
            self.assertFalse(
                statement.startswith(write_prefixes),
                f"risk-report must stay read-only: {statement}",
            )
        # Every self-opened snapshot is rolled back, never committed.
        self.assertNotIn("COMMIT", normalized)
        self.assertEqual(normalized.count("BEGIN"), normalized.count("ROLLBACK"))
        self.assertFalse(self.catalog.connection.in_transaction)

        # Status, approved severity and history are exactly as saved.
        self.assertEqual(self._exemption_tables(), before)
        detail = self.catalog.get_exemption(REQUEST_ID)
        self.assertEqual(detail["status"], "approved")
        self.assertEqual(detail["approved_severity"], "critical")
        self.assertEqual(
            [event["action"] for event in detail["events"]],
            ["request", "approve"],
        )


class RiskReportCliTests(RiskReportStateAssertions, unittest.TestCase):
    """The CLI risk-report is the same feature as the Python query."""

    def test_cli_report_matches_python_result_at_each_state(self):
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = Catalog(database)
            seed(catalog)

            def run_cli():
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), \
                        contextlib.redirect_stderr(stderr):
                    status = main([
                        "--database", database, "risk-report",
                        "--service", SERVICE, "--at", EVALUATED_AT,
                    ])
                self.assertEqual(status, 0)
                self.assertEqual(stderr.getvalue(), "")
                return json.loads(stdout.getvalue())

            self.assert_state_a(run_cli())
            catalog.import_osv(OSV_SOURCE, lib_records("critical"))
            self.assert_state_b(run_cli())
            catalog.approve_exemption(REQUEST_ID, APPROVER, "controls verified")
            report = run_cli()
            self.assert_state_c(report)
            self.assertEqual(report, report_for(catalog))
            catalog.close()


if __name__ == "__main__":
    unittest.main()
