"""Regression tests for an exemption approval failing *during* its save.

An approval is the one operation that has to persist two things together:

1. the decision result - the request becomes ``approved`` and gains the
   approver, decision time, note and the risk level in force at approval;
2. the processing history - one ``approve`` event recording the actor,
   timestamp, note and the pending -> approved transition.

The business-rule failures (unknown id, non-pending state, expired term,
applicant approving their own request, target impact gone at approval time)
all reject *before* either write. These tests cover the other half of the
contract: a request whose every approval precondition holds, and that then
hits a database error in one of the three save phases -

1. saving the decision result (``UPDATE exemption_requests``);
2. saving the approval history (``INSERT INTO exemption_events``);
3. the final commit that makes the decision and its history durable.

A failure in any of the three phases must roll the whole approval back
atomically. The request must never be left showing as approved while its
history is missing, and the risk report must never have deducted the risk
without a complete approval behind it. Concretely, after any such failure:

* the call raises a database error, never returns an approved record;
* the request is still ``pending`` with its scope, applicant, reason,
  submission time and expiry unchanged, and no approver / decision time /
  note / approved risk level left behind;
* the history keeps only the events that genuinely completed before it -
  here the single ``request`` event;
* the risk report keeps its pre-approval business result: the target impact
  is still unexempted, linked to the same pending request and described as
  awaiting approval; source, severity and dependency path are unchanged, as
  are the unhandled-component count and highest severity;
* a same-id vulnerability provided by a *different* source, with its own
  independent request, is completely unaffected - the failure and any
  exemption effect never cross sources on the vulnerability id alone.

A final class covers the normal, fault-free approval: complete decision
fields, one new history event with the right before/after status, the
exemption applied to exactly the requested (indirect, application-level)
impact - it never also exempts the directly hit library - while components
that still carry an unexempted impact keep counting. Existing request,
decision, query, report and scope rules stay compatible.
"""

import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from supply_guard.catalog import Catalog, format_timestamp
from supply_guard.cli import main

SERVICE = "api"
# The specified source the request is about, and a second source providing
# the same vulnerability id independently.
SOURCE = "nvd"
OTHER_SOURCE = "ghsa"
CVE = "CVE-2026-8001"
REQUEST_ID = "EXM-2026-8001"
OTHER_REQUEST_ID = "EXM-2026-8002"

# The application depends on a vulnerable library; the request targets the
# application's *indirect* impact, never the direct hit on the library.
APP_VERSION = "1.0.0"
LIB_VERSION = "3.0.0"

APPLICANT = "alice"
OTHER_APPLICANT = "carol"
APPROVER = "bob"
APPROVAL_NOTE = "compensating controls verified"
REQUEST_REASON = "egress proxy mitigates the transitive library exposure"
OTHER_REASON = "track the same id arriving from the other feed"

# Every decision/evaluation instant is strictly inside the exemption term,
# so term expiry can never explain any result in these tests.
SUBMITTED_AT = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
OTHER_SUBMITTED_AT = datetime(2026, 2, 1, 0, 0, tzinfo=timezone.utc)
DECIDED_AT = datetime(2026, 3, 1, 0, 0, tzinfo=timezone.utc)
EXPIRES_AT = "2026-12-31T23:59:59+00:00"
EVAL_AT = "2026-06-01T00:00:00+00:00"


def osv_record(source_severity):
    return [
        {
            "id": CVE,
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "lib"},
                    "versions": [LIB_VERSION],
                }
            ],
            "database_specific": {"severity": source_severity},
        }
    ]


# Write errors injected at each approval save phase. The triggers live in the
# same database the approval writes to, so the failure goes through SQLite
# exactly like a real disk/constraint error: the statement fails and the
# surrounding approval transaction must roll back.

# Phase 1: persisting the decision result fails. The WHEN clause restricts
# the fault to a row actually leaving ``pending`` (the approval UPDATE), so
# reads and any unrelated statement are unaffected.
DECISION_SAVE_FAILURE_TRIGGER = """
CREATE TRIGGER fail_decision_save
BEFORE UPDATE ON exemption_requests
WHEN EXISTS (
        SELECT 1 FROM exemption_requests
        WHERE id = NEW.id AND status = 'pending'
      )
BEGIN
    SELECT RAISE(ABORT, 'injected decision-save write error');
END
"""

# Phase 2: the decision result UPDATE has already run inside the transaction
# when persisting the approval history fails.
HISTORY_SAVE_FAILURE_TRIGGER = """
CREATE TRIGGER fail_history_save
BEFORE INSERT ON exemption_events
WHEN NEW.action = 'approve'
BEGIN
    SELECT RAISE(ABORT, 'injected history-save write error');
END
"""


def build_catalog(database: str | Path) -> Catalog:
    """Create the pending-approval scenario shared by every regression case.

    Service ``api`` registers an application depending on ``lib`` 3.0.0. Two
    OSV sources both provide the same vulnerability id for the pinned
    library - the specified source ``nvd`` rates it ``high`` and the
    independent source ``ghsa`` rates it ``medium`` - so the application
    carries two indirect records (one per source) and the library two direct
    records. Two pending, unexpired requests target the application's
    indirect impact from each source separately. The target request has been
    submitted normally by ``alice``; ``bob`` (a different user) is the
    approver used by every test.
    """
    catalog = Catalog(database)
    catalog.add_component(SERVICE, "pypi", "app", APP_VERSION)
    catalog.add_component(SERVICE, "pypi", "lib", LIB_VERSION)
    catalog.add_dependency(
        SERVICE, "pypi", "app", APP_VERSION,
        SERVICE, "pypi", "lib", LIB_VERSION,
    )
    catalog.import_osv(SOURCE, osv_record("high"))
    catalog.import_osv(OTHER_SOURCE, osv_record("medium"))
    catalog.request_exemption(
        REQUEST_ID,
        SERVICE, "pypi", "app", APP_VERSION,
        CVE, "lib", SOURCE,
        applicant=APPLICANT,
        reason=REQUEST_REASON,
        expires_at=EXPIRES_AT,
        submitted_at=SUBMITTED_AT,
    )
    catalog.request_exemption(
        OTHER_REQUEST_ID,
        SERVICE, "pypi", "app", APP_VERSION,
        CVE, "lib", OTHER_SOURCE,
        applicant=OTHER_APPLICANT,
        reason=OTHER_REASON,
        expires_at=EXPIRES_AT,
        submitted_at=OTHER_SUBMITTED_AT,
    )
    return catalog


def target_scope():
    return {
        "service": SERVICE,
        "ecosystem": "pypi",
        "name": "app",
        "version": APP_VERSION,
        "vulnerability": CVE,
        "matched_name": "lib",
        "source": SOURCE,
    }


def find_entry(report, component_name, source):
    """The one report record for a component/vulnerability/source triple."""
    matches = [
        entry for entry in report["impacts"]
        if entry["component"]["service"] == SERVICE
        and entry["component"]["name"] == component_name
        and entry["vulnerability"] == CVE
        and entry["source"] == source
    ]
    assert len(matches) == 1, (
        f"expected exactly one {component_name}/{CVE}/source={source} "
        f"record, got {len(matches)}"
    )
    return matches[0]


def request_row(catalog, request_id):
    """The raw stored request row, so no column can be checked by omission."""
    row = catalog.connection.execute(
        "SELECT * FROM exemption_requests WHERE id = ?", (request_id,)
    ).fetchone()
    assert row is not None
    return row


def event_actions(catalog, request_id):
    return [
        str(row[0])
        for row in catalog.connection.execute(
            "SELECT action FROM exemption_events WHERE request_id = ? "
            "ORDER BY seq",
            (request_id,),
        )
    ]


class _ApprovalStateAssertions:
    """Post-failure contract checks shared by the rollback test classes."""

    def _assert_target_still_pristine_pending(self, catalog, snapshot):
        # The failed call must never be readable back as an approved record.
        record = catalog.get_exemption(REQUEST_ID)
        self.assertEqual(record["status"], "pending")
        self.assertEqual(record["scope"], target_scope())
        self.assertEqual(record["applicant"], APPLICANT)
        self.assertEqual(record["reason"], REQUEST_REASON)
        self.assertEqual(record["created_at"], format_timestamp(SUBMITTED_AT))
        self.assertEqual(record["expires_at"], snapshot["target_expires_at"])
        # No residue of a decision that did not fully complete.
        self.assertIsNone(record["decided_at"])
        self.assertIsNone(record["approver"])
        self.assertIsNone(record["decision_note"])
        self.assertIsNone(record["approved_severity"])
        self.assertIsNone(record["revoked_at"])
        self.assertIsNone(record["revoker"])
        self.assertIsNone(record["revoke_note"])

        row = request_row(catalog, REQUEST_ID)
        self.assertEqual(str(row["status"]), "pending")
        self.assertIsNone(row["decided_at"])
        self.assertIsNone(row["approver"])
        self.assertIsNone(row["decision_note"])
        self.assertIsNone(row["approved_severity"])

        # History keeps only the events that genuinely completed before the
        # failed approval: the single submission event, unchanged.
        self.assertEqual(len(record["events"]), 1)
        event = record["events"][0]
        self.assertEqual(event["seq"], 1)
        self.assertEqual(event["action"], "request")
        self.assertEqual(event["actor"], APPLICANT)
        self.assertEqual(event["reason"], REQUEST_REASON)
        self.assertIsNone(event["from_status"])
        self.assertEqual(event["to_status"], "pending")
        self.assertEqual(event["at"], format_timestamp(SUBMITTED_AT))
        self.assertEqual(event_actions(catalog, REQUEST_ID), ["request"])
        self.assertEqual(
            catalog.connection.execute(
                "SELECT COUNT(*) FROM exemption_events WHERE request_id = ?",
                (REQUEST_ID,),
            ).fetchone()[0],
            1,
        )
        return record

    def _assert_other_request_untouched(self, catalog):
        # The same vulnerability id from another source has its own request;
        # a save failure on the nvd approval must never reach it.
        record = catalog.get_exemption(OTHER_REQUEST_ID)
        self.assertEqual(record["status"], "pending")
        self.assertEqual(record["scope"]["source"], OTHER_SOURCE)
        self.assertEqual(record["applicant"], OTHER_APPLICANT)
        self.assertEqual(record["reason"], OTHER_REASON)
        self.assertIsNone(record["approver"])
        self.assertIsNone(record["decided_at"])
        self.assertIsNone(record["decision_note"])
        self.assertIsNone(record["approved_severity"])
        self.assertEqual(event_actions(catalog, OTHER_REQUEST_ID), ["request"])

    def _assert_report_keeps_pre_approval_result(self, catalog, snapshot):
        report = catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
        # Byte-for-byte identical to the report taken before the failed save.
        self.assertEqual(report, snapshot["risk_report"])
        self.assertEqual(
            catalog.impact(service=SERVICE), snapshot["impact"]
        )

        # The application's target (nvd) impact is still unexempted and links
        # the same pending request as still awaiting approval.
        target = find_entry(report, "app", SOURCE)
        self.assertFalse(target["exempted"])
        self.assertEqual(target["exemption_request"], REQUEST_ID)
        self.assertEqual(target["not_exempt_reason"], "豁免申请尚在待审批")
        self.assertEqual(target["source"], SOURCE)
        self.assertEqual(target["severity"], "high")
        self.assertEqual(target["severity_basis"], "declared")
        self.assertFalse(target["direct"])
        self.assertEqual(target["matched_conditions"], [f"=={LIB_VERSION}"])
        self.assertEqual(
            [(node["name"], node["version"]) for node in target["path"]],
            [("app", APP_VERSION), ("lib", LIB_VERSION)],
        )

        # The directly hit library is unaffected business-wise as well.
        direct = find_entry(report, "lib", SOURCE)
        self.assertTrue(direct["direct"])
        self.assertFalse(direct["exempted"])
        self.assertIsNone(direct["exemption_request"])
        self.assertEqual(direct["severity"], "high")

        # The other source's same-id impact and its own request stay exactly
        # as they were: still pending-linked, still medium, never marked with
        # the failed approval's outcome or exempted by id alone.
        other_indirect = find_entry(report, "app", OTHER_SOURCE)
        self.assertFalse(other_indirect["exempted"])
        self.assertEqual(
            other_indirect["exemption_request"], OTHER_REQUEST_ID
        )
        self.assertEqual(
            other_indirect["not_exempt_reason"], "豁免申请尚在待审批"
        )
        self.assertEqual(other_indirect["severity"], "medium")
        self.assertEqual(other_indirect["source"], OTHER_SOURCE)
        other_direct = find_entry(report, "lib", OTHER_SOURCE)
        self.assertFalse(other_direct["exempted"])
        self.assertIsNone(other_direct["exemption_request"])
        self.assertEqual(other_direct["severity"], "medium")

        # Four records (two components x two sources); both components still
        # carry an unexempted record, and nvd's high remains the highest.
        self.assertEqual(report["impact_count"], 4)
        self.assertEqual(report["unhandled_component_count"], 2)
        self.assertEqual(report["highest_severity"], "high")
        self.assertFalse(any(i["exempted"] for i in report["impacts"]))

    def _take_snapshot(self, catalog):
        target = catalog.get_exemption(REQUEST_ID)
        return {
            "target_expires_at": target["expires_at"],
            "impact": catalog.impact(service=SERVICE),
            "risk_report": catalog.risk_report(
                service=SERVICE, evaluated_at=EVAL_AT
            ),
            "other_request": catalog.get_exemption(OTHER_REQUEST_ID),
        }


class ApprovalSaveFailureRollbackTests(_ApprovalStateAssertions, unittest.TestCase):
    """A save error in either write phase fails the approval atomically."""

    def _run_failure_scenario(self, phase, trigger):
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)

            # Every approval precondition holds before the save is faulted:
            # submitted normally, the source still provides the
            # vulnerability, the dependency path still exists, the approver
            # is not the applicant, and the term has not lapsed.
            self.assertEqual(
                catalog.get_exemption(REQUEST_ID)["status"], "pending"
            )
            self.assertEqual(
                catalog.get_exemption(REQUEST_ID)["applicant"], APPLICANT
            )
            self.assertNotEqual(APPROVER, APPLICANT)
            self.assertLess(DECIDED_AT, datetime(2026, 12, 31, 23, 59, 59,
                                                 tzinfo=timezone.utc))

            snapshot = self._take_snapshot(catalog)
            self._assert_report_keeps_pre_approval_result(catalog, snapshot)

            catalog.connection.execute(trigger)

            statements = []
            catalog.connection.set_trace_callback(statements.append)
            try:
                with self.assertRaises(sqlite3.Error) as caught:
                    catalog.approve_exemption(
                        REQUEST_ID, APPROVER, APPROVAL_NOTE,
                        decided_at=DECIDED_AT,
                    )
            finally:
                catalog.connection.set_trace_callback(None)
            # A save-stage database error, not a business-rule ValueError:
            # the request passed every precondition and reached the write.
            self.assertNotIsInstance(caught.exception, ValueError)
            self.assertEqual(type(caught.exception), sqlite3.IntegrityError)

            normalized = [s.strip() for s in statements]
            self.assertTrue(
                any(s == "BEGIN IMMEDIATE" for s in normalized)
            )
            # The decision result UPDATE was attempted in both phases.
            self.assertTrue(
                any(s.startswith("UPDATE exemption_requests") for s in normalized),
                f"{phase}: decision result save was never attempted",
            )

            if phase == "decision-save":
                # The decision UPDATE failed first: the history phase never
                # ran at all.
                self.assertFalse(
                    any(
                        s.startswith("INSERT INTO exemption_events")
                        for s in normalized
                    )
                )
            else:
                # The decision UPDATE ran, then saving the approval history
                # was attempted and failed.
                self.assertTrue(
                    any(
                        "FROM exemption_events" in s
                        for s in normalized
                        if s.startswith("SELECT")
                    )
                )
                self.assertTrue(
                    any(
                        s.startswith("INSERT INTO exemption_events")
                        for s in normalized
                    ),
                    f"{phase}: approval history save was never attempted",
                )

            # The whole partial approval rolled back and was never committed.
            self.assertIn("ROLLBACK", normalized)
            self.assertNotIn("COMMIT", normalized)

            # Same connection: still a pristine pending request, the other
            # source's request untouched, and the report shows the risk was
            # never deducted.
            self._assert_target_still_pristine_pending(catalog, snapshot)
            self._assert_other_request_untouched(catalog)
            self._assert_report_keeps_pre_approval_result(catalog, snapshot)
            self.assertEqual(
                catalog.get_exemption(OTHER_REQUEST_ID),
                snapshot["other_request"],
            )
            self.assertFalse(catalog.connection.in_transaction)
            catalog.close()

            # Durable rollback: a reopened file database shows identical
            # state (the injected trigger persists in the schema, exactly
            # like a real constraint would).
            reopened = Catalog(database)
            self._assert_target_still_pristine_pending(reopened, snapshot)
            self._assert_other_request_untouched(reopened)
            self._assert_report_keeps_pre_approval_result(reopened, snapshot)

            # With the fault removed the very same request is still
            # approvable: the failed attempt neither wedged it nor left a
            # half-saved approval. The approval records the current nvd high
            # and the history gains exactly one event at seq 2.
            reopened.connection.execute(
                "DROP TRIGGER IF EXISTS fail_decision_save"
            )
            reopened.connection.execute(
                "DROP TRIGGER IF EXISTS fail_history_save"
            )
            approved = reopened.approve_exemption(
                REQUEST_ID, APPROVER, APPROVAL_NOTE, decided_at=DECIDED_AT
            )
            self.assertEqual(approved["status"], "approved")
            self.assertEqual(approved["approver"], APPROVER)
            self.assertEqual(approved["decision_note"], APPROVAL_NOTE)
            self.assertEqual(approved["approved_severity"], "high")
            self.assertEqual(
                approved["decided_at"], format_timestamp(DECIDED_AT)
            )
            self.assertEqual(
                [event["action"] for event in approved["events"]],
                ["request", "approve"],
            )
            self.assertEqual([event["seq"] for event in approved["events"]],
                             [1, 2])
            decision_event = approved["events"][1]
            self.assertEqual(decision_event["actor"], APPROVER)
            self.assertEqual(decision_event["reason"], APPROVAL_NOTE)
            self.assertEqual(decision_event["from_status"], "pending")
            self.assertEqual(decision_event["to_status"], "approved")
            self.assertEqual(
                decision_event["at"], format_timestamp(DECIDED_AT)
            )
            # The other source's request is still its own pending workflow.
            self._assert_other_request_untouched(reopened)
            reopened.close()

    def test_decision_result_save_failure_rolls_back_the_approval(self) -> None:
        self._run_failure_scenario(
            "decision-save", DECISION_SAVE_FAILURE_TRIGGER
        )

    def test_history_save_failure_rolls_back_the_approval(self) -> None:
        self._run_failure_scenario(
            "history-save", HISTORY_SAVE_FAILURE_TRIGGER
        )


class FinalCommitFailureRollbackTests(_ApprovalStateAssertions, unittest.TestCase):
    """A database error at the final COMMIT fails the approval atomically.

    The decision UPDATE and the approval-history INSERT have both run inside
    the write transaction when SQLite rejects the commit itself - the case
    named in the contract is a file database whose writer lock is momentarily
    held by another read connection (SQLITE_BUSY). Until the commit succeeds
    those writes are only an open, uncommitted transaction: on the same
    connection they would otherwise read back as a completed approval that
    never became durable, and the connection would stay unable to commit
    anything until it was closed and reopened. The commit phase therefore
    needs the same rollback protection as the two statement phases.
    """

    def _open_blocking_reader(self, database):
        """Hold a SHARED read lock that blocks the writer's COMMIT upgrade.

        A SHARED lock coexists with the approval transaction's RESERVED lock,
        so the BEGIN/UPDATE/INSERT phases all run; only the final upgrade to
        an EXCLUSIVE lock at COMMIT is rejected with SQLITE_BUSY - exactly
        the file-database-held-by-a-reader scenario. The short busy timeouts
        only bound how long the failed commit waits; the lock stays held
        until the test releases it, so the result is deterministic.
        """
        reader = sqlite3.connect(database)
        reader.execute("PRAGMA busy_timeout = 50")
        reader.execute("BEGIN")
        reader.execute(
            "SELECT COUNT(*) FROM exemption_requests"
        ).fetchone()
        return reader

    def test_final_commit_failure_rolls_back_and_catalog_stays_usable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)
            catalog.connection.execute("PRAGMA busy_timeout = 50")
            snapshot = self._take_snapshot(catalog)

            reader = self._open_blocking_reader(database)
            statements = []
            catalog.connection.set_trace_callback(statements.append)
            try:
                with self.assertRaises(sqlite3.Error) as caught:
                    catalog.approve_exemption(
                        REQUEST_ID, APPROVER, APPROVAL_NOTE,
                        decided_at=DECIDED_AT,
                    )
            finally:
                catalog.connection.set_trace_callback(None)

            # The original database error reaches the caller, never an
            # approved record and never a business-rule ValueError.
            self.assertEqual(type(caught.exception), sqlite3.OperationalError)
            self.assertNotIsInstance(caught.exception, ValueError)
            self.assertEqual(str(caught.exception), "database is locked")

            normalized = [s.strip() for s in statements]
            self.assertIn("BEGIN IMMEDIATE", normalized)
            # Both save statements ran inside the transaction; the failure is
            # specifically the durability step that follows them.
            self.assertTrue(
                any(s.startswith("UPDATE exemption_requests") for s in normalized)
            )
            self.assertTrue(
                any(s.startswith("INSERT INTO exemption_events") for s in normalized)
            )
            commit_index = normalized.index("COMMIT")
            rollback_indexes = [
                index for index, statement in enumerate(normalized)
                if statement == "ROLLBACK"
            ]
            # COMMIT was attempted, rejected, and then rolled back.
            self.assertTrue(rollback_indexes)
            self.assertGreater(min(rollback_indexes), commit_index)

            # No half-open transaction is left behind on the same connection.
            self.assertFalse(catalog.connection.in_transaction)

            # Using the very same Catalog object: pristine pending request,
            # the other source's request untouched, and the report byte-for-
            # byte identical to before the failed approval. These reads run
            # while the blocking reader still holds its lock.
            self._assert_target_still_pristine_pending(catalog, snapshot)
            self._assert_other_request_untouched(catalog)
            self._assert_report_keeps_pre_approval_result(catalog, snapshot)
            self.assertEqual(
                catalog.get_exemption(OTHER_REQUEST_ID),
                snapshot["other_request"],
            )
            reader.rollback()
            reader.close()

            # Durable rollback through a freshly opened file database.
            reopened = Catalog(database)
            self._assert_target_still_pristine_pending(reopened, snapshot)
            self._assert_other_request_untouched(reopened)
            self._assert_report_keeps_pre_approval_result(reopened, snapshot)
            reopened.close()

            # Once the database accepts writes again, the ORIGINAL directory
            # object keeps working - it must not require close/reopen to shed
            # the failed approval - and a retry saves the complete approval,
            # adding exactly one approve event.
            approved = catalog.approve_exemption(
                REQUEST_ID, APPROVER, APPROVAL_NOTE, decided_at=DECIDED_AT
            )
            self.assertEqual(approved["status"], "approved")
            self.assertEqual(approved["approver"], APPROVER)
            self.assertEqual(approved["decision_note"], APPROVAL_NOTE)
            self.assertEqual(approved["approved_severity"], "high")
            self.assertEqual(
                approved["decided_at"], format_timestamp(DECIDED_AT)
            )
            self.assertEqual(
                [event["action"] for event in approved["events"]],
                ["request", "approve"],
            )
            self.assertEqual(
                [event["seq"] for event in approved["events"]], [1, 2]
            )

            # The report moves together with the successful approval: the
            # requested indirect impact is exempted, the other source's same-
            # id record stays pending/unexempted, and the direct library hit
            # was never part of this scope.
            report = catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
            target = find_entry(report, "app", SOURCE)
            self.assertTrue(target["exempted"])
            self.assertEqual(target["exemption_request"], REQUEST_ID)
            self.assertIsNone(target["not_exempt_reason"])
            other_indirect = find_entry(report, "app", OTHER_SOURCE)
            self.assertFalse(other_indirect["exempted"])
            self.assertEqual(
                other_indirect["exemption_request"], OTHER_REQUEST_ID
            )
            direct = find_entry(report, "lib", SOURCE)
            self.assertFalse(direct["exempted"])
            self.assertEqual(report["impact_count"], 4)
            self.assertEqual(report["unhandled_component_count"], 2)
            self.assertEqual(report["highest_severity"], "high")
            self._assert_other_request_untouched(catalog)

            catalog.close()
            durable = Catalog(database)
            self.assertEqual(
                durable.get_exemption(REQUEST_ID), approved
            )
            self.assertEqual(
                durable.risk_report(service=SERVICE, evaluated_at=EVAL_AT),
                report,
            )
            durable.close()


class BusinessRejectionContrastTests(unittest.TestCase):
    """Pre-save business rejections must not be mistaken for save failures.

    A request the applicant tries to self-approve is rejected *before* either
    save statement runs (only the transaction's read/lock phase executes), so
    it contrasts with the injected save failures above, where the UPDATE /
    history INSERT demonstrably ran and were rolled back.
    """

    def test_self_approval_reaches_neither_save_statement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)
            statements = []
            catalog.connection.set_trace_callback(statements.append)
            try:
                with self.assertRaises(ValueError):
                    catalog.approve_exemption(
                        REQUEST_ID, APPLICANT, "self approval"
                    )
            finally:
                catalog.connection.set_trace_callback(None)
            normalized = [s.strip() for s in statements]
            self.assertFalse(
                any(s.startswith("UPDATE exemption_requests") for s in normalized)
            )
            self.assertFalse(
                any(s.startswith("INSERT INTO exemption_events") for s in normalized)
            )
            record = catalog.get_exemption(REQUEST_ID)
            self.assertEqual(record["status"], "pending")
            self.assertIsNone(record["approver"])
            self.assertEqual(event_actions(catalog, REQUEST_ID), ["request"])
            catalog.close()


class ApprovalSuccessPreservedTests(unittest.TestCase):
    """The fault-free approval result and exemption scope stay compatible."""

    def _normal_approval(self, catalog: Catalog) -> dict:
        return catalog.approve_exemption(
            REQUEST_ID, APPROVER, APPROVAL_NOTE, decided_at=DECIDED_AT
        )

    def test_approval_persists_result_and_history_together(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)

            approved = self._normal_approval(catalog)
            self.assertEqual(approved["status"], "approved")
            self.assertEqual(approved["scope"], target_scope())
            self.assertEqual(approved["applicant"], APPLICANT)
            self.assertEqual(approved["reason"], REQUEST_REASON)
            self.assertEqual(
                approved["created_at"], format_timestamp(SUBMITTED_AT)
            )
            self.assertEqual(
                approved["expires_at"], "2026-12-31T23:59:59.000000Z"
            )
            # Complete decision fields, including the risk level in force at
            # approval (the specified source's current high).
            self.assertEqual(approved["approver"], APPROVER)
            self.assertEqual(approved["decision_note"], APPROVAL_NOTE)
            self.assertEqual(
                approved["decided_at"], format_timestamp(DECIDED_AT)
            )
            self.assertEqual(approved["approved_severity"], "high")

            # Exactly one new history event with the right transition.
            self.assertEqual(len(approved["events"]), 2)
            self.assertEqual(
                [event["action"] for event in approved["events"]],
                ["request", "approve"],
            )
            self.assertEqual(
                [event["seq"] for event in approved["events"]], [1, 2]
            )
            decision = approved["events"][1]
            self.assertEqual(decision["actor"], APPROVER)
            self.assertEqual(decision["reason"], APPROVAL_NOTE)
            self.assertEqual(decision["from_status"], "pending")
            self.assertEqual(decision["to_status"], "approved")
            self.assertEqual(decision["at"], format_timestamp(DECIDED_AT))

            report_before = catalog.risk_report(
                service=SERVICE, evaluated_at=EVAL_AT
            )
            request_before = catalog.get_exemption(REQUEST_ID)
            catalog.close()

            # The result is durable and deterministic across reopen.
            reopened = Catalog(database)
            self.assertEqual(
                reopened.get_exemption(REQUEST_ID), request_before
            )
            self.assertEqual(
                reopened.risk_report(service=SERVICE, evaluated_at=EVAL_AT),
                report_before,
            )
            catalog = reopened

            # Only the requested indirect impact is exempted; approving the
            # application-level impact never exempts the directly hit library.
            target = find_entry(report_before, "app", SOURCE)
            self.assertTrue(target["exempted"])
            self.assertEqual(target["exemption_request"], REQUEST_ID)
            self.assertIsNone(target["not_exempt_reason"])
            self.assertFalse(target["direct"])
            self.assertEqual(target["severity"], "high")
            self.assertEqual(
                [(node["name"], node["version"]) for node in target["path"]],
                [("app", APP_VERSION), ("lib", LIB_VERSION)],
            )
            direct = find_entry(report_before, "lib", SOURCE)
            self.assertTrue(direct["direct"])
            self.assertFalse(direct["exempted"])
            self.assertIsNone(direct["exemption_request"])

            # The other source's same-id impact and request are independent:
            # still pending-linked and unexempted despite the nvd approval.
            other_indirect = find_entry(report_before, "app", OTHER_SOURCE)
            self.assertFalse(other_indirect["exempted"])
            self.assertEqual(
                other_indirect["exemption_request"], OTHER_REQUEST_ID
            )
            self.assertEqual(
                other_indirect["not_exempt_reason"], "豁免申请尚在待审批"
            )
            self.assertEqual(other_indirect["severity"], "medium")
            other_direct = find_entry(report_before, "lib", OTHER_SOURCE)
            self.assertFalse(other_direct["exempted"])
            self.assertIsNone(other_direct["exemption_request"])

            # app still carries the unexempted ghsa record and lib its two
            # direct hits: both components stay unhandled, highest still high.
            self.assertEqual(report_before["impact_count"], 4)
            self.assertEqual(
                report_before["unhandled_component_count"], 2
            )
            self.assertEqual(report_before["highest_severity"], "high")
            exempted = [
                (entry["component"]["name"], entry["source"])
                for entry in report_before["impacts"]
                if entry["exempted"]
            ]
            self.assertEqual(exempted, [("app", SOURCE)])

            # The other request stayed a separate pending workflow.
            other = catalog.get_exemption(OTHER_REQUEST_ID)
            self.assertEqual(other["status"], "pending")
            self.assertEqual(other["scope"]["source"], OTHER_SOURCE)
            self.assertEqual(
                [event["action"] for event in other["events"]], ["request"]
            )
            self.assertEqual(
                [r["id"] for r in catalog.list_exemptions(status="approved")],
                [REQUEST_ID],
            )
            # Only the other source's request stays pending.
            self.assertEqual(
                [r["id"] for r in catalog.list_exemptions(status="pending")],
                [OTHER_REQUEST_ID],
            )
            catalog.close()

    def test_cli_approval_reports_the_approved_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            setup = build_catalog(database)
            setup.close()

            output = io.StringIO()
            with redirect_stdout(output):
                status = main([
                    "--database", database,
                    "approve-exemption", REQUEST_ID,
                    "--handler", APPROVER,
                    "--note", APPROVAL_NOTE,
                ])
            self.assertEqual(status, 0)
            printed = json.loads(output.getvalue())
            self.assertEqual(printed["status"], "approved")
            self.assertEqual(printed["approver"], APPROVER)
            self.assertEqual(printed["approved_severity"], "high")
            self.assertEqual(
                [event["action"] for event in printed["events"]],
                ["request", "approve"],
            )

            catalog = Catalog(database)
            record = catalog.get_exemption(REQUEST_ID)
            self.assertEqual(record["status"], "approved")
            self.assertEqual(
                [event["action"] for event in record["events"]],
                ["request", "approve"],
            )
            # The other source's request is untouched through the CLI path.
            self.assertEqual(
                catalog.get_exemption(OTHER_REQUEST_ID)["status"], "pending"
            )
            catalog.close()


if __name__ == "__main__":
    unittest.main()
