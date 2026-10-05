"""Regression tests: an approval result and its history are saved together.

Approving a pending exemption request performs two saves in one write
transaction:

1. the decision result (status, approver, decision time, note and the risk
   level recorded at approval) is written onto the request row;
2. one ``approve`` event is appended to the request's processing history.

The scenarios here pin an OSV-imported, named-source vulnerability. The
application ``app`` is only affected *indirectly* (it depends on the directly
hit library through ``web``); the same vulnerability id is also imported from
a second source, so the request's seven-field scope (component, vulnerability
id, matched package, source) is what separates the two records. A request is
submitted for the application's impact under the first source and is still
pending, the source still provides the vulnerability, the dependency path
still exists, the approver is not the applicant, and the request has not
expired at approval time.

Under those preconditions an approval must succeed atomically or fail
atomically. A failure while saving either the decision result or the history
event must surface as an error - never as a successfully returned approved
record - and leave the request pending with only its genuinely completed
history; the risk report must keep its pre-approval business result. The
same vulnerability id from another source, with its own independent request,
must never inherit the failure or any exemption effect.
"""

import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from supply_guard.catalog import Catalog, format_timestamp


SERVICE = "api"
LIB_SOURCE = "nvd"
OTHER_SOURCE = "ghsa"
VULN = "CVE-2026-9001"
LIB_REQUEST = "REQ-NVD-APP"
OTHER_REQUEST = "REQ-GHSA-APP"
EXPIRES = "2030-01-01T00:00:00+00:00"
SUBMITTED = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
DECIDED = datetime(2026, 6, 2, 9, 0, tzinfo=timezone.utc)
EVALUATED = datetime(2026, 6, 3, 9, 0, tzinfo=timezone.utc)


def osv_record(identifier, package="lib", severity="high", **affected):
    entry = {"package": {"ecosystem": "PyPI", "name": package}}
    entry.update(affected)
    return {
        "id": identifier,
        "affected": [entry],
        "database_specific": {"severity": severity},
    }


# Fires when the approval writes its decision result onto the target request
# row (the UPDATE inside _process_decision). Raising here simulates a
# save-stage failure for the result itself.
RESULT_SAVE_FAILURE_TRIGGER = """
CREATE TRIGGER fail_approval_result_save
BEFORE UPDATE OF status ON exemption_requests
WHEN OLD.id = 'REQ-NVD-APP' AND NEW.status = 'approved'
BEGIN
    SELECT RAISE(ABORT, 'injected approval-result save error');
END;
"""

# Fires when the approval appends its approve event, i.e. after the decision
# result UPDATE has already run inside the same transaction. Simulates a
# failure while saving this approval's history.
HISTORY_SAVE_FAILURE_TRIGGER = """
CREATE TRIGGER fail_approval_history_save
BEFORE INSERT ON exemption_events
WHEN NEW.request_id = 'REQ-NVD-APP' AND NEW.action = 'approve'
BEGIN
    SELECT RAISE(ABORT, 'injected approval-history save error');
END;
"""


def build_catalog(database: str = ":memory:") -> Catalog:
    """Directory and requests shared by every scenario.

    ``app -> web -> lib`` in service ``api``; the directly hit library is
    ``lib`` 1.0.0. The same vulnerability id is imported from two named
    sources (``nvd`` high, ``ghsa`` medium), each producing its own direct
    hit on lib and indirect hits on web and app. One pending request per
    source exists for the *application's* indirect impact.
    """
    catalog = Catalog(database)
    for name in ("app", "web", "lib"):
        catalog.add_component(SERVICE, "pypi", name, "1.0.0")
    catalog.add_dependency(
        SERVICE, "pypi", "app", "1.0.0", SERVICE, "pypi", "web", "1.0.0"
    )
    catalog.add_dependency(
        SERVICE, "pypi", "web", "1.0.0", SERVICE, "pypi", "lib", "1.0.0"
    )
    catalog.import_osv(
        LIB_SOURCE,
        [osv_record(VULN, package="lib", severity="high",
                    versions=["1.0.0"])],
    )
    catalog.import_osv(
        OTHER_SOURCE,
        [osv_record(VULN, package="lib", severity="medium",
                    versions=["1.0.0"])],
    )
    catalog.request_exemption(
        LIB_REQUEST, SERVICE, "pypi", "app", "1.0.0",
        VULN, "lib", LIB_SOURCE,
        "alice", "accept risk via egress proxy", EXPIRES,
        submitted_at=SUBMITTED,
    )
    catalog.request_exemption(
        OTHER_REQUEST, SERVICE, "pypi", "app", "1.0.0",
        VULN, "lib", OTHER_SOURCE,
        "carol", "tracked separately", EXPIRES,
        submitted_at=SUBMITTED,
    )
    return catalog


class ApprovalAtomicSaveFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = build_catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def find(self, entries, component_name, source, matched_name="lib"):
        matches = [
            entry for entry in entries
            if entry["component"]["service"] == SERVICE
            and entry["component"]["name"] == component_name
            and entry["vulnerability"] == VULN
            and entry["source"] == source
            and entry["matched_name"] == matched_name
        ]
        self.assertEqual(
            len(matches), 1,
            f"expected exactly one {component_name}/{VULN}/{source} record, "
            f"got {len(matches)}",
        )
        return matches[0]

    def assert_still_pristine_pending(self, request_id=LIB_REQUEST):
        record = self.catalog.get_exemption(request_id)
        self.assertEqual(record["status"], "pending")
        scope = record["scope"]
        self.assertEqual(
            (scope["service"], scope["ecosystem"], scope["name"],
             scope["version"], scope["vulnerability"],
             scope["matched_name"], scope["source"]),
            (SERVICE, "pypi", "app", "1.0.0", VULN, "lib", LIB_SOURCE),
        )
        self.assertEqual(record["applicant"], "alice")
        self.assertEqual(record["reason"], "accept risk via egress proxy")
        self.assertEqual(record["created_at"], format_timestamp(SUBMITTED))
        self.assertEqual(record["expires_at"], format_timestamp(
            datetime(2030, 1, 1, tzinfo=timezone.utc)
        ))
        # No decision residue of any kind.
        self.assertIsNone(record["approver"])
        self.assertIsNone(record["decided_at"])
        self.assertIsNone(record["decision_note"])
        self.assertIsNone(record["approved_severity"])
        self.assertIsNone(record["revoked_at"])
        self.assertIsNone(record["revoker"])
        self.assertIsNone(record["revoke_note"])
        # History holds only the genuinely completed submission event.
        self.assertEqual(len(record["events"]), 1)
        event = record["events"][0]
        self.assertEqual(event["action"], "request")
        self.assertEqual(event["actor"], "alice")
        self.assertEqual(event["reason"], "accept risk via egress proxy")
        self.assertIsNone(event["from_status"])
        self.assertEqual(event["to_status"], "pending")
        self.assertEqual(event["at"], format_timestamp(SUBMITTED))
        return record

    def assert_indirect_impact_unchanged(self, entry, source, severity):
        self.assertEqual(entry["source"], source)
        self.assertEqual(entry["matched_name"], "lib")
        self.assertEqual(entry["severity"], severity)
        self.assertFalse(entry["direct"])
        self.assertEqual(
            [node["name"] for node in entry["path"]], ["app", "web", "lib"]
        )
        self.assertEqual(entry["matched_conditions"], ["==1.0.0"])

    def assert_report_matches_pre_approval_business_result(self, before):
        report = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVALUATED
        )
        # Byte-for-byte the pre-approval report: counts, highest severity,
        # ordering, links and reasons are all reproduced.
        self.assertEqual(report, before)
        # The target impact is still unexempted and linked to its own pending
        # request with a still-pending reason.
        target = self.find(report["impacts"], "app", LIB_SOURCE)
        self.assert_indirect_impact_unchanged(target, LIB_SOURCE, "high")
        self.assertFalse(target["exempted"])
        self.assertEqual(target["exemption_request"], LIB_REQUEST)
        self.assertIn("待审批", target["not_exempt_reason"])
        # The directly hit library is not covered by the application's
        # request under any source.
        direct = self.find(report["impacts"], "lib", LIB_SOURCE)
        self.assertTrue(direct["direct"])
        self.assertFalse(direct["exempted"])
        self.assertIsNone(direct["exemption_request"])
        self.assertIsNone(direct["not_exempt_reason"])
        # The same id from the other source keeps its own impact, severity,
        # path and independent pending request: the failure never crossed
        # sources on the strength of the vulnerability id alone.
        other = self.find(report["impacts"], "app", OTHER_SOURCE)
        self.assert_indirect_impact_unchanged(other, OTHER_SOURCE, "medium")
        self.assertFalse(other["exempted"])
        self.assertEqual(other["exemption_request"], OTHER_REQUEST)
        self.assertIn("待审批", other["not_exempt_reason"])
        other_direct = self.find(report["impacts"], "lib", OTHER_SOURCE)
        self.assertTrue(other_direct["direct"])
        self.assertFalse(other_direct["exempted"])
        self.assertIsNone(other_direct["exemption_request"])
        # All six current records stay unexempted; three distinct components
        # remain unhandled and the highest level is unchanged.
        self.assertEqual(report["impact_count"], 6)
        self.assertEqual(report["unhandled_component_count"], 3)
        self.assertEqual(report["highest_severity"], "high")
        self.assertFalse(
            any(entry["exempted"] for entry in report["impacts"])
        )
        return report

    def run_failing_approval(self, trigger):
        """Drive one failed approval, returning the traced SQL statements."""
        before_request = self.catalog.get_exemption(LIB_REQUEST)
        before_other = self.catalog.get_exemption(OTHER_REQUEST)
        before_report = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVALUATED
        )

        statements: list[str] = []
        self.catalog.connection.set_trace_callback(statements.append)
        try:
            with self.assertRaises(sqlite3.Error) as caught:
                self.catalog.approve_exemption(
                    LIB_REQUEST, "bob", "controls verified",
                    decided_at=DECIDED,
                )
        finally:
            self.catalog.connection.set_trace_callback(None)
        # A save-stage database error: every approval precondition held, so
        # this must not be mistaken for a validation ValueError, and no
        # approved record is returned.
        self.assertNotIsInstance(caught.exception, ValueError)
        self.assertEqual(type(caught.exception), sqlite3.IntegrityError)

        normalized = [s.strip() for s in statements]
        self.assertIn("ROLLBACK", normalized)
        self.assertNotIn("COMMIT", normalized)
        return before_request, before_other, before_report, normalized

    def verify_failed_approval(self, trigger):
        (
            before_request, before_other, before_report, statements
        ) = self.run_failing_approval(trigger)

        # The approval really started writing before it failed.
        self.assertTrue(
            any(
                s.startswith("UPDATE exemption_requests") for s in statements
            ),
            "decision result update never ran",
        )

        # The stored request is the exact pre-approval record.
        self.assertEqual(
            self.catalog.get_exemption(LIB_REQUEST), before_request
        )
        self.assert_still_pristine_pending()
        # The other source's independent request and history are untouched.
        self.assertEqual(
            self.catalog.get_exemption(OTHER_REQUEST), before_other
        )
        other = self.catalog.get_exemption(OTHER_REQUEST)
        self.assertEqual(other["status"], "pending")
        self.assertEqual(
            [event["action"] for event in other["events"]], ["request"]
        )
        self.assertIsNone(other["approver"])

        self.assert_report_matches_pre_approval_business_result(before_report)

    def test_result_save_failure_rolls_back_whole_approval(self) -> None:
        self.catalog.connection.execute(RESULT_SAVE_FAILURE_TRIGGER)
        self.verify_failed_approval(RESULT_SAVE_FAILURE_TRIGGER)

    def test_history_save_failure_rolls_back_result_and_history(self) -> None:
        self.catalog.connection.execute(HISTORY_SAVE_FAILURE_TRIGGER)
        (
            _before_request, _before_other, _before_report, statements
        ) = self.run_failing_approval(HISTORY_SAVE_FAILURE_TRIGGER)
        # In this variant the result UPDATE had already succeeded inside the
        # transaction when the history INSERT failed; both must roll back.
        self.assertTrue(
            any(s.startswith("INSERT INTO exemption_events") for s in statements),
            "approval history insert never ran",
        )
        self.assertEqual(
            self.catalog.get_exemption(LIB_REQUEST), _before_request
        )
        self.assert_still_pristine_pending()
        self.assertEqual(
            self.catalog.get_exemption(OTHER_REQUEST), _before_other
        )
        self.assert_report_matches_pre_approval_business_result(_before_report)

    def test_failed_approval_is_durable_after_reopen(self) -> None:
        # The rollback must be durable, not merely invisible on the same
        # connection: a reopened database shows the identical pending state
        # and pre-approval report.
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)
            before_report = catalog.risk_report(
                service=SERVICE, evaluated_at=EVALUATED
            )
            catalog.connection.execute(RESULT_SAVE_FAILURE_TRIGGER)
            with self.assertRaises(sqlite3.IntegrityError):
                catalog.approve_exemption(
                    LIB_REQUEST, "bob", "controls verified",
                    decided_at=DECIDED,
                )
            catalog.connection.execute(
                "DROP TRIGGER IF EXISTS fail_approval_result_save"
            )
            catalog.close()

            reopened = Catalog(database)
            record = reopened.get_exemption(LIB_REQUEST)
            self.assertEqual(record["status"], "pending")
            self.assertIsNone(record["approver"])
            self.assertIsNone(record["approved_severity"])
            self.assertEqual(
                [event["action"] for event in record["events"]], ["request"]
            )
            self.assertEqual(
                reopened.risk_report(
                    service=SERVICE, evaluated_at=EVALUATED
                ),
                before_report,
            )
            # Nothing was left half-locked: after the failure the request can
            # still be approved normally once the fault is gone.
            approved = reopened.approve_exemption(
                LIB_REQUEST, "bob", "controls verified", decided_at=DECIDED
            )
            self.assertEqual(approved["status"], "approved")
            reopened.close()

    def test_successful_approval_saves_result_and_history_together(self) -> None:
        # No fault: the indirect app impact under nvd is approved atomically.
        approved = self.catalog.approve_exemption(
            LIB_REQUEST, "bob", "controls verified", decided_at=DECIDED
        )
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["approver"], "bob")
        self.assertEqual(approved["decision_note"], "controls verified")
        self.assertEqual(approved["decided_at"], format_timestamp(DECIDED))
        self.assertEqual(approved["approved_severity"], "high")
        self.assertEqual(
            [event["action"] for event in approved["events"]],
            ["request", "approve"],
        )
        decision = approved["events"][1]
        self.assertEqual(decision["actor"], "bob")
        self.assertEqual(decision["reason"], "controls verified")
        self.assertEqual(decision["from_status"], "pending")
        self.assertEqual(decision["to_status"], "approved")
        self.assertEqual(decision["at"], format_timestamp(DECIDED))
        # Scope, applicant, reason and term are unchanged by the decision.
        scope = approved["scope"]
        self.assertEqual(
            (scope["name"], scope["matched_name"], scope["source"]),
            ("app", "lib", LIB_SOURCE),
        )
        self.assertEqual(approved["applicant"], "alice")
        self.assertEqual(
            approved["expires_at"], format_timestamp(
                datetime(2030, 1, 1, tzinfo=timezone.utc)
            )
        )

        report = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVALUATED
        )
        # Only the application's nvd indirect record is exempted.
        target = self.find(report["impacts"], "app", LIB_SOURCE)
        self.assert_indirect_impact_unchanged(target, LIB_SOURCE, "high")
        self.assertTrue(target["exempted"])
        self.assertEqual(target["exemption_request"], LIB_REQUEST)
        self.assertIsNone(target["not_exempt_reason"])
        self.assertEqual(
            [
                (entry["component"]["name"], entry["source"])
                for entry in report["impacts"]
                if entry["exempted"]
            ],
            [("app", LIB_SOURCE)],
        )
        # Approving the application's indirect impact does not exempt the
        # directly hit library; it keeps participating in the counts.
        direct = self.find(report["impacts"], "lib", LIB_SOURCE)
        self.assertFalse(direct["exempted"])
        self.assertIsNone(direct["exemption_request"])
        # The other source's impact and its independent pending request are
        # exactly as before: still pending, still unexempted, and the app
        # still counts as unhandled through that route.
        other = self.find(report["impacts"], "app", OTHER_SOURCE)
        self.assert_indirect_impact_unchanged(other, OTHER_SOURCE, "medium")
        self.assertFalse(other["exempted"])
        self.assertEqual(other["exemption_request"], OTHER_REQUEST)
        self.assertIn("待审批", other["not_exempt_reason"])
        other_request = self.catalog.get_exemption(OTHER_REQUEST)
        self.assertEqual(other_request["status"], "pending")
        self.assertEqual(
            [event["action"] for event in other_request["events"]],
            ["request"],
        )
        # app (via ghsa), web and lib each still carry at least one
        # unexempted record; the exempted nvd/app record counts for neither.
        self.assertEqual(report["impact_count"], 6)
        self.assertEqual(report["unhandled_component_count"], 3)
        self.assertEqual(report["highest_severity"], "high")

        # Existing query inputs/outputs and status filters stay compatible.
        self.assertEqual(
            [request["id"] for request in self.catalog.list_exemptions(
                status="approved"
            )],
            [LIB_REQUEST],
        )
        pending = {
            request["id"]
            for request in self.catalog.list_exemptions(status="pending")
        }
        self.assertEqual(pending, {OTHER_REQUEST})
        self.assertEqual(
            self.catalog.get_exemption(LIB_REQUEST)["status"], "approved"
        )


if __name__ == "__main__":
    unittest.main()
