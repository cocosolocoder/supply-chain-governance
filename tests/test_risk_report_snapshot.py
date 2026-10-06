"""Regression tests for risk-report consistency across concurrent saves.

One service ``api`` has an application ``app 1.0.0`` depending on a library
``lib 1.0.0``. A single OSV source hits exactly ``lib 1.0.0``, so the library
carries a direct impact and the application an indirect one; nothing else is
vulnerable. Only the application's indirect impact has an exemption request:
submitted by one user, unexpired, pending approval by another. The report is
evaluated at a fixed, timezone-aware moment inside the request term - the
moment only judges the term; the approval state is always the currently saved
one.

Another user then performs two saves: first replacing the same-named source
with a record that still hits the same version but raises the level from
``high`` to ``critical``, then approving the application's request (the saved
approved level is therefore ``critical``). A report read interleaved with
these saves must always answer for exactly one complete saved state:

* before the source update: both impacts ``high``, the application linked to
  its pending request;
* after the source update but before the approval: both impacts ``critical``,
  the application still linked to the pending request;
* after the approval: both impacts ``critical``, only the application's
  indirect impact exempted, the library's direct impact still unhandled.

A mixture - in particular a ``high`` application impact exempted by the
``critical`` approval - must never appear. Both impact records are always
kept; the unhandled component count is two before the approval and one after;
the highest unhandled level follows the source update from ``high`` to
``critical`` and stays ``critical`` once the application is approved. Source
attribution, the direct/indirect flags, the dependency paths and the
not-exempt reasons always belong to the state the report shows.

The interleaving tests run the saves from a second connection strictly inside
the report's read window (WAL mode, a trace barrier on the exemption-request
read), because querying only after all saves cannot catch a report that
stitches two states together. After the interleaved read, a fresh report on
the same Catalog shows the saved new state. Report queries are read-only:
they never change the request status, the saved approved level or the
processing history, and the request detail contains exactly the submission
and approval events.
"""

import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import main

SERVICE = "api"
ECOSYSTEM = "pypi"
APP = "app"
LIB = "lib"
VERSION = "1.0.0"
OSV_SOURCE = "nvd"
CVE = "CVE-2026-9001"
REQUEST_ID = "EXM-2026-9001"

SUBMITTED_AT = datetime(2026, 1, 10, 0, 0, tzinfo=timezone.utc)
APPROVED_AT = datetime(2026, 2, 1, 0, 0, tzinfo=timezone.utc)
EXPIRES_AT = "2030-12-31T23:59:59+00:00"
# Fixed, timezone-aware evaluation moment inside the request term.
EVAL_AT = "2026-06-01T00:00:00+00:00"
EVAL_AT_TEXT = "2026-06-01T00:00:00.000000Z"
# A moment inside the term but before the recorded approval instant: the
# saved approval state still governs, the moment only judges the term.
EVAL_BEFORE_DECISION = "2026-01-15T00:00:00+00:00"
# A moment past the term.
EVAL_AFTER_EXPIRY = "2031-01-01T00:00:00+00:00"

PENDING_REASON = "豁免申请尚在待审批"
EXPIRED_REASON = "豁免已于 2030-12-31T23:59:59.000000Z 到期"


def identity(name: str) -> dict:
    return {
        "service": SERVICE,
        "ecosystem": ECOSYSTEM,
        "name": name,
        "version": VERSION,
    }


def osv_record(severity: str) -> dict:
    """The one OSV record of the source, hitting exactly lib 1.0.0."""
    return {
        "id": CVE,
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": LIB},
                "versions": [VERSION],
            }
        ],
        "database_specific": {"severity": severity},
    }


HIGH_RECORDS = [osv_record("high")]
# The replacement: same id, same package, same hit version, higher level.
CRITICAL_RECORDS = [osv_record("critical")]


def seed_catalog(catalog: Catalog) -> None:
    """The application, its library, the high source and the pending request."""
    catalog.add_component(SERVICE, ECOSYSTEM, APP, VERSION)
    catalog.add_component(SERVICE, ECOSYSTEM, LIB, VERSION)
    catalog.add_dependency(
        SERVICE, ECOSYSTEM, APP, VERSION,
        SERVICE, ECOSYSTEM, LIB, VERSION,
    )
    catalog.import_osv(OSV_SOURCE, HIGH_RECORDS)
    # Only the application's indirect impact gets a request; the library's
    # direct impact never does. Applicant and approver are different users.
    catalog.request_exemption(
        REQUEST_ID,
        SERVICE, ECOSYSTEM, APP, VERSION,
        CVE, LIB, OSV_SOURCE,
        applicant="alice",
        reason="accept the indirect exposure for the term",
        expires_at=EXPIRES_AT,
        submitted_at=SUBMITTED_AT,
    )


def build_catalog(database: str | Path = ":memory:") -> Catalog:
    catalog = Catalog(database)
    seed_catalog(catalog)
    return catalog


def upgrade_source(catalog: Catalog) -> None:
    """The other user's first save: same source name, level now critical."""
    catalog.import_osv(OSV_SOURCE, CRITICAL_RECORDS)


def approve(catalog: Catalog) -> dict:
    """The other user's second save: approve the application's request."""
    return catalog.approve_exemption(
        REQUEST_ID,
        handler="bob",
        note="compensating controls verified",
        decided_at=APPROVED_AT,
    )


def app_entry(severity: str, *, exempted: bool, reason: str | None) -> dict:
    """The application's indirect impact record as the report carries it."""
    return {
        "component": identity(APP),
        "vulnerability": CVE,
        "source": OSV_SOURCE,
        "matched_name": LIB,
        "severity": severity,
        "severity_basis": "declared",
        "direct": False,
        "matched_conditions": ["==1.0.0"],
        "path": [identity(APP), identity(LIB)],
        "exempted": exempted,
        "exemption_request": REQUEST_ID,
        "not_exempt_reason": reason,
    }


def lib_entry(severity: str) -> dict:
    """The library's direct impact record; no request is ever linked."""
    return {
        "component": identity(LIB),
        "vulnerability": CVE,
        "source": OSV_SOURCE,
        "matched_name": LIB,
        "severity": severity,
        "severity_basis": "declared",
        "direct": True,
        "matched_conditions": ["==1.0.0"],
        "path": [identity(LIB)],
        "exempted": False,
        "exemption_request": None,
        "not_exempt_reason": None,
    }


def expected_report(severity: str, *, approved: bool) -> dict:
    """The one complete report of each reachable saved state."""
    if approved:
        app = app_entry(severity, exempted=True, reason=None)
        unhandled = 1
        # The library's unexempted direct hit keeps the level critical.
        highest = "critical"
    else:
        app = app_entry(severity, exempted=False, reason=PENDING_REASON)
        unhandled = 2
        highest = severity
    return {
        "evaluated_at": EVAL_AT_TEXT,
        "service": SERVICE,
        "impact_count": 2,
        "unhandled_component_count": unhandled,
        "highest_severity": highest,
        # Impact sorting is by component name: app before lib.
        "impacts": [app, lib_entry(severity)],
    }


# The only three complete states an interleaved report may show.
BEFORE_UPDATE = expected_report("high", approved=False)
UPDATED_PENDING = expected_report("critical", approved=False)
APPROVED = expected_report("critical", approved=True)


def expected_scope() -> dict:
    return {
        "service": SERVICE,
        "ecosystem": ECOSYSTEM,
        "name": APP,
        "version": VERSION,
        "vulnerability": CVE,
        "matched_name": LIB,
        "source": OSV_SOURCE,
    }


def exemption_data(catalog: Catalog) -> tuple:
    """The raw saved exemption state: requests and their processing history."""
    requests = [
        tuple(row)
        for row in catalog.connection.execute(
            "SELECT * FROM exemption_requests ORDER BY id"
        )
    ]
    events = [
        tuple(row)
        for row in catalog.connection.execute(
            "SELECT request_id, seq, occurred_at, actor, action, reason, "
            "from_status, to_status FROM exemption_events "
            "ORDER BY request_id, seq"
        )
    ]
    return requests, events


def select_app(report: dict) -> dict:
    (entry,) = [
        impact
        for impact in report["impacts"]
        if impact["component"]["name"] == APP
    ]
    return entry


def select_lib(report: dict) -> dict:
    (entry,) = [
        impact
        for impact in report["impacts"]
        if impact["component"]["name"] == LIB
    ]
    return entry


class RiskReportStateContractTests(unittest.TestCase):
    """Each saved state reads back as one complete, self-consistent report."""

    def setUp(self) -> None:
        self.catalog = build_catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def report(self, evaluated_at: str = EVAL_AT) -> dict:
        return self.catalog.risk_report(
            service=SERVICE, evaluated_at=evaluated_at
        )

    def test_before_update_both_impacts_high_and_request_pending(self) -> None:
        self.assertEqual(self.report(), BEFORE_UPDATE)
        app = select_app(self.report())
        self.assertEqual(app["severity"], "high")
        self.assertFalse(app["exempted"])
        self.assertEqual(app["exemption_request"], REQUEST_ID)
        self.assertEqual(app["not_exempt_reason"], PENDING_REASON)

    def test_source_update_raises_both_impacts_while_still_pending(self) -> None:
        upgrade_source(self.catalog)
        report = self.report()
        self.assertEqual(report, UPDATED_PENDING)
        # Both records move to critical together; the request is untouched
        # and still linked as pending.
        self.assertEqual(
            [impact["severity"] for impact in report["impacts"]],
            ["critical", "critical"],
        )
        self.assertEqual(report["unhandled_component_count"], 2)
        self.assertEqual(report["highest_severity"], "critical")
        app = select_app(report)
        self.assertFalse(app["exempted"])
        self.assertEqual(app["not_exempt_reason"], PENDING_REASON)

    def test_approval_exempts_only_the_application_impact(self) -> None:
        upgrade_source(self.catalog)
        approve(self.catalog)
        report = self.report()
        self.assertEqual(report, APPROVED)
        # Both records stay; only the application's indirect one is exempted.
        self.assertEqual(report["impact_count"], 2)
        self.assertEqual(report["unhandled_component_count"], 1)
        self.assertEqual(report["highest_severity"], "critical")
        app = select_app(report)
        self.assertTrue(app["exempted"])
        self.assertEqual(app["exemption_request"], REQUEST_ID)
        self.assertIsNone(app["not_exempt_reason"])
        lib = select_lib(report)
        self.assertFalse(lib["exempted"])
        self.assertIsNone(lib["exemption_request"])
        self.assertIsNone(lib["not_exempt_reason"])

    def test_approval_saves_the_critical_level_in_force_at_decision(self) -> None:
        upgrade_source(self.catalog)
        approved = approve(self.catalog)
        # The level saved with the approval is the current critical one,
        # never the high level the request was submitted under.
        self.assertEqual(approved["approved_severity"], "critical")
        detail = self.catalog.get_exemption(REQUEST_ID)
        self.assertEqual(detail["status"], "approved")
        self.assertEqual(detail["approved_severity"], "critical")
        self.assertEqual(detail["applicant"], "alice")
        self.assertEqual(detail["approver"], "bob")
        self.assertEqual(detail["scope"], expected_scope())
        # The detail carries exactly the submission and approval events.
        self.assertEqual(
            [
                (event["action"], event["actor"],
                 event["from_status"], event["to_status"])
                for event in detail["events"]
            ],
            [
                ("request", "alice", None, "pending"),
                ("approve", "bob", "pending", "approved"),
            ],
        )

    def test_evaluation_moment_only_judges_the_term(self) -> None:
        upgrade_source(self.catalog)
        approve(self.catalog)
        # A moment before the recorded approval instant but inside the term:
        # the saved approval state governs, so the record is exempted.
        early = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVAL_BEFORE_DECISION
        )
        self.assertTrue(select_app(early)["exempted"])
        self.assertEqual(early["unhandled_component_count"], 1)

        # A moment past the term: the same saved approval no longer covers
        # the record, and the report says why.
        late = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVAL_AFTER_EXPIRY
        )
        app = select_app(late)
        self.assertFalse(app["exempted"])
        self.assertEqual(app["exemption_request"], REQUEST_ID)
        self.assertEqual(app["not_exempt_reason"], EXPIRED_REASON)
        self.assertEqual(late["unhandled_component_count"], 2)
        self.assertEqual(late["highest_severity"], "critical")
        # The saved approval itself is never rewritten by the evaluation.
        detail = self.catalog.get_exemption(REQUEST_ID)
        self.assertEqual(detail["status"], "approved")
        self.assertEqual(detail["approved_severity"], "critical")


class RiskReportReadOnlyTests(unittest.TestCase):
    """Report queries never modify request state, level or history."""

    def setUp(self) -> None:
        self.catalog = build_catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def test_report_issues_only_reads_and_releases_its_snapshot(self) -> None:
        statements: list[str] = []
        self.catalog.connection.set_trace_callback(statements.append)
        try:
            self.catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
            self.catalog.risk_report(evaluated_at=EVAL_AT)
        finally:
            self.catalog.connection.set_trace_callback(None)

        normalized = [" ".join(s.split()).upper() for s in statements]
        for statement in normalized:
            self.assertTrue(
                statement.startswith(("SELECT", "BEGIN", "ROLLBACK")),
                f"risk report issued a non-read statement: {statement}",
            )
        self.assertNotIn("COMMIT", normalized)
        self.assertEqual(
            normalized.count("BEGIN"), normalized.count("ROLLBACK")
        )
        self.assertFalse(self.catalog.connection.in_transaction)

    def test_reports_leave_exemption_data_untouched_in_every_state(self) -> None:
        before = exemption_data(self.catalog)
        self.catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
        self.assertEqual(exemption_data(self.catalog), before)

        upgrade_source(self.catalog)
        self.catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
        self.assertEqual(exemption_data(self.catalog), before)

        approve(self.catalog)
        saved = exemption_data(self.catalog)
        for evaluated_at in (EVAL_AT, EVAL_BEFORE_DECISION, EVAL_AFTER_EXPIRY):
            self.catalog.risk_report(service=SERVICE, evaluated_at=evaluated_at)
            self.catalog.risk_report(evaluated_at=evaluated_at)
        # Neither the status, the saved critical level nor the history moved.
        self.assertEqual(exemption_data(self.catalog), saved)
        detail = self.catalog.get_exemption(REQUEST_ID)
        self.assertEqual(detail["status"], "approved")
        self.assertEqual(detail["approved_severity"], "critical")
        self.assertEqual(
            [event["action"] for event in detail["events"]],
            ["request", "approve"],
        )
        self.assertFalse(self.catalog.connection.in_transaction)


class RiskReportInterleavedSaveTests(unittest.TestCase):
    """Saves landing while a report is read are seen whole or not at all.

    The reader runs in WAL mode so the second connection's commits are not
    blocked by the read snapshot. A trace barrier releases the writer only
    once the report's impact reads have finished and the exemption-request
    read is about to run, then holds the reader until the saves have
    committed: the two report halves provably straddle the commit. Without
    one read snapshot the report would stitch the pre-save impacts to the
    post-save approval - a ``high`` application impact exempted by the
    ``critical`` approval. Querying only after all saves could never catch
    that mixture.
    """

    def _run_interleaved(self, writer_saves, prepare=None) -> tuple:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        database = str(Path(directory.name, "catalog.db"))
        catalog = Catalog(database)
        self.addCleanup(catalog.close)
        catalog.connection.execute("PRAGMA journal_mode=WAL")
        seed_catalog(catalog)
        if prepare is not None:
            prepare(catalog)

        proceed = threading.Event()
        committed = threading.Event()
        errors: list[BaseException] = []

        def save() -> None:
            proceed.wait(30)
            other = Catalog(database)
            try:
                writer_saves(other)
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
            if (
                not fired["done"]
                and normalized.startswith("SELECT ROWID AS RID")
                and "FROM EXEMPTION_REQUESTS" in normalized
            ):
                fired["done"] = True
                catalog.connection.set_trace_callback(None)
                proceed.set()
                # The reader blocks here until the other user's saves have
                # committed, so the exemption read provably races them.
                self.assertTrue(committed.wait(30))

        catalog.connection.set_trace_callback(barrier)
        try:
            report = catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
        finally:
            catalog.connection.set_trace_callback(None)
            # Release the writer even when the read failed before reaching
            # the barrier, so no save thread outlives the temporary directory.
            proceed.set()

        thread.join(30)
        self.assertFalse(thread.is_alive())
        # Writer errors are meaningful only once the interleave really fired.
        self.assertTrue(fired["done"], "the interleave barrier never fired")
        self.assertTrue(committed.wait(15))
        self.assertEqual(errors, [])
        return report, catalog

    def test_update_and_approval_during_read_show_pre_update_state(self) -> None:
        def saves(other: Catalog) -> None:
            upgrade_source(other)
            approve(other)

        report, catalog = self._run_interleaved(saves)

        # The snapshot opened before either save committed, so the whole
        # report answers for the pre-update state: both impacts high, the
        # application linked to its still-pending request.
        self.assertEqual(report, BEFORE_UPDATE)
        self.assertIn(report, (BEFORE_UPDATE, UPDATED_PENDING, APPROVED))
        app = select_app(report)
        lib = select_lib(report)
        # The forbidden mixture: a high application impact exempted through
        # the critical approval saved mid-read.
        self.assertFalse(app["severity"] == "high" and app["exempted"])
        # Source, flags, paths and reasons belong to that same state.
        self.assertEqual(app["severity"], lib["severity"])
        self.assertEqual(app["source"], OSV_SOURCE)
        self.assertFalse(app["direct"])
        self.assertTrue(lib["direct"])
        self.assertEqual(
            app["path"], [identity(APP), identity(LIB)]
        )
        self.assertEqual(app["not_exempt_reason"], PENDING_REASON)
        self.assertFalse(catalog.connection.in_transaction)

        # After the interleaved read a fresh report shows the saved new
        # state: both impacts critical, only the application exempted.
        later = catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
        self.assertEqual(later, APPROVED)
        # The saves themselves stored the critical level and exactly the
        # submission and approval events.
        detail = catalog.get_exemption(REQUEST_ID)
        self.assertEqual(detail["status"], "approved")
        self.assertEqual(detail["approved_severity"], "critical")
        self.assertEqual(
            [event["action"] for event in detail["events"]],
            ["request", "approve"],
        )

    def test_approval_during_read_after_update_shows_updated_pending_state(
        self,
    ) -> None:
        def saves(other: Catalog) -> None:
            approve(other)

        # The source replacement has already committed; only the approval
        # lands inside the report's read window.
        report, catalog = self._run_interleaved(saves, prepare=upgrade_source)

        # One complete intermediate state: both impacts critical, the
        # application still linked to the pending request, nothing exempted.
        self.assertEqual(report, UPDATED_PENDING)
        self.assertEqual(report["unhandled_component_count"], 2)
        self.assertEqual(report["highest_severity"], "critical")
        app = select_app(report)
        self.assertFalse(app["exempted"])
        self.assertEqual(app["exemption_request"], REQUEST_ID)
        self.assertEqual(app["not_exempt_reason"], PENDING_REASON)
        self.assertFalse(catalog.connection.in_transaction)

        # A later report on the same Catalog sees the completed approval.
        later = catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
        self.assertEqual(later, APPROVED)
        detail = catalog.get_exemption(REQUEST_ID)
        self.assertEqual(detail["approved_severity"], "critical")
        self.assertEqual(
            [event["action"] for event in detail["events"]],
            ["request", "approve"],
        )


class CliRiskReportContractTests(unittest.TestCase):
    """The risk-report CLI prints exactly the Python query result."""

    def test_cli_report_matches_python_result_after_update_and_approval(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)
            upgrade_source(catalog)
            approve(catalog)
            expected = catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
            catalog.close()

            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(
                    [
                        "--database", database,
                        "risk-report",
                        "--service", SERVICE,
                        "--at", EVAL_AT,
                    ]
                )
            self.assertEqual(status, 0)
            self.assertEqual(stderr.getvalue(), "")
            report = json.loads(stdout.getvalue())
            self.assertEqual(report, expected)
            self.assertEqual(report, APPROVED)


if __name__ == "__main__":
    unittest.main()
