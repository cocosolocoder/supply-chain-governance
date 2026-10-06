"""Regression coverage for viewing one exemption request by id.

``Catalog.get_exemption`` and the ``exemption-show`` CLI command answer one
question: the detail of a single request id must present one *saved* state
whole. While another process approves, rejects or revokes that very request,
a read can land before or after the save, but status, handler, decision
time, note, approved severity and the event history always belong to the
same instant.

Guarantees covered here:

* a pending request's detail carries only the submission event and no
  decision fields; an approved detail adds the approval information and
  event; a revoked detail keeps the original approval information and adds
  the revocation information and event;
* a decision (approve/reject/revoke) another process saves while a detail is
  being read is observed either wholly or not at all — never a pending row
  with an approval event or an approved row with a revocation event, and
  never a success detail with missing history;
* an earlier query may show the older complete state, but a later query on
  the same Catalog sees the already-saved new state — old details are not
  cached;
* the query is read-only: it adds no events, changes no status and leaves no
  transaction open, and expired requests or requests whose target impact
  disappeared are still returned exactly as saved, with their history;
* inside a caller-owned transaction the query shares that transaction's
  view (including its own uncommitted changes) without committing or
  rolling it back; a read failure surfaces as a database error, leaves no
  half-open transaction and the same Catalog stays usable;
* empty and unknown ids keep erroring clearly;
* the CLI ``exemption-show`` output is exactly the Python query result.
"""

import contextlib
import io
import json
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import main


def osv_record(identifier, package="lib", severity="high", **affected):
    entry = {"package": {"ecosystem": "PyPI", "name": package}}
    entry.update(affected)
    record = {"id": identifier, "affected": [entry]}
    if severity is not None:
        record["database_specific"] = {"severity": severity}
    return record


DECISION_FIELDS = (
    "decided_at",
    "approver",
    "decision_note",
    "approved_severity",
)
REVOKE_FIELDS = ("revoked_at", "revoker", "revoke_note")


class ExemptionShowFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name, "catalog.db"))
        self.catalog = Catalog(self.database)
        self.catalog.add_component("api", "pypi", "app", "1.0.0")
        self.catalog.add_component("api", "pypi", "web", "1.0.0")
        self.catalog.add_component("api", "pypi", "lib", "1.0.0")
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "web", "1.0.0"
        )
        self.catalog.add_dependency(
            "api", "pypi", "web", "1.0.0", "api", "pypi", "lib", "1.0.0"
        )
        self.catalog.add_vulnerability("CVE-MAN", "lib", "high")
        self.future = "2030-01-01T00:00:00+00:00"

    def tearDown(self) -> None:
        self.catalog.close()
        self.directory.cleanup()

    def request(self, request_id="REQ-1", *, vulnerability="CVE-MAN",
                source=None, matched_name="lib", name="lib"):
        return self.catalog.request_exemption(
            request_id, "api", "pypi", name, "1.0.0",
            vulnerability, matched_name, source,
            applicant="alice",
            reason="mitigated",
            expires_at=self.future,
        )

    def snapshot(self):
        requests = [
            tuple(row) for row in self.catalog.connection.execute(
                "SELECT * FROM exemption_requests ORDER BY id"
            )
        ]
        events = [
            tuple(row) for row in self.catalog.connection.execute(
                "SELECT request_id, seq, occurred_at, actor, action, reason, "
                "from_status, to_status FROM exemption_events "
                "ORDER BY request_id, seq"
            )
        ]
        return requests, events

    def assertActions(self, record, actions):
        self.assertEqual(
            [event["action"] for event in record["events"]], actions
        )
        self.assertEqual(
            [event["seq"] for event in record["events"]],
            list(range(1, len(actions) + 1)),
        )

    def assertNoDecisionFields(self, record):
        for field in DECISION_FIELDS + REVOKE_FIELDS:
            self.assertIsNone(record[field], f"{field} 不应有值")


class SavedStateShapeTests(ExemptionShowFixture):
    """Each career stage reads back as one coherent saved state."""

    def test_pending_detail_has_submission_only_and_empty_decision_fields(self):
        self.request()
        record = self.catalog.get_exemption("REQ-1")
        self.assertEqual(record["id"], "REQ-1")
        self.assertEqual(record["status"], "pending")
        self.assertNoDecisionFields(record)
        self.assertActions(record, ["request"])
        event = record["events"][0]
        self.assertEqual(event["actor"], "alice")
        self.assertEqual(event["reason"], "mitigated")
        self.assertIsNone(event["from_status"])
        self.assertEqual(event["to_status"], "pending")

    def test_approved_detail_carries_approval_information_and_event(self):
        self.request()
        when = datetime(2026, 5, 1, tzinfo=timezone.utc)
        self.catalog.approve_exemption(
            "REQ-1", "bob", "controls verified", decided_at=when
        )
        record = self.catalog.get_exemption("REQ-1")
        self.assertEqual(record["status"], "approved")
        self.assertEqual(record["approver"], "bob")
        self.assertEqual(record["decision_note"], "controls verified")
        self.assertEqual(
            record["decided_at"], "2026-05-01T00:00:00.000000Z"
        )
        self.assertEqual(record["approved_severity"], "high")
        self.assertIsNone(record["revoked_at"])
        self.assertIsNone(record["revoker"])
        self.assertIsNone(record["revoke_note"])
        self.assertActions(record, ["request", "approve"])
        decision = record["events"][1]
        self.assertEqual(decision["actor"], "bob")
        self.assertEqual(decision["reason"], "controls verified")
        self.assertEqual(decision["from_status"], "pending")
        self.assertEqual(decision["to_status"], "approved")

    def test_rejected_detail_carries_reject_information_and_event(self):
        self.request()
        self.catalog.reject_exemption("REQ-1", "bob", "fix instead")
        record = self.catalog.get_exemption("REQ-1")
        self.assertEqual(record["status"], "rejected")
        self.assertEqual(record["approver"], "bob")
        self.assertEqual(record["decision_note"], "fix instead")
        self.assertIsNone(record["approved_severity"])
        self.assertActions(record, ["request", "reject"])

    def test_revoked_detail_keeps_approval_and_adds_revocation(self):
        self.request()
        self.catalog.approve_exemption("REQ-1", "bob", "controls verified")
        self.catalog.revoke_exemption(
            "REQ-1", "carol", "control removed"
        )
        record = self.catalog.get_exemption("REQ-1")
        self.assertEqual(record["status"], "revoked")
        # The original approval information stays part of the saved detail.
        self.assertEqual(record["approver"], "bob")
        self.assertEqual(record["decision_note"], "controls verified")
        self.assertEqual(record["approved_severity"], "high")
        self.assertIsNotNone(record["decided_at"])
        # Revocation information is present in full as well.
        self.assertEqual(record["revoker"], "carol")
        self.assertEqual(record["revoke_note"], "control removed")
        self.assertIsNotNone(record["revoked_at"])
        self.assertActions(record, ["request", "approve", "revoke"])

    def test_history_contains_only_events_of_the_requested_id(self):
        self.request("REQ-1")
        # A distinct scope so both requests can legitimately coexist.
        self.catalog.add_vulnerability("CVE-OTHER", "lib", "low")
        self.request("REQ-2", vulnerability="CVE-OTHER")
        self.catalog.approve_exemption("REQ-1", "bob", "first")
        self.catalog.reject_exemption("REQ-2", "carol", "second")
        first = self.catalog.get_exemption("REQ-1")
        second = self.catalog.get_exemption("REQ-2")
        self.assertActions(first, ["request", "approve"])
        self.assertActions(second, ["request", "reject"])
        self.assertTrue(
            all(event["actor"] in {"alice", "bob"}
                for event in first["events"])
        )
        self.assertTrue(
            all(event["actor"] in {"alice", "carol"}
                for event in second["events"])
        )


class ConcurrentSaveSnapshotTests(ExemptionShowFixture):
    """A save landing while one id is shown can never mix two states.

    The reader runs in WAL mode so a writer's commit is not blocked by the
    read. A trace barrier releases a second Catalog's full decision save
    only when the detail read reaches its second SELECT (the history read),
    i.e. strictly after the request-row read has finished. With separate
    per-statement reads the two reads would straddle the save; one read
    snapshot pins both to a single saved instant.
    """

    def setUp(self) -> None:
        super().setUp()
        self.catalog.connection.execute("PRAGMA journal_mode=WAL")

    def _start_concurrent_save(self, decision, request_id="REQ-1"):
        proceed = threading.Event()
        committed = threading.Event()
        errors: list[BaseException] = []

        def save() -> None:
            proceed.wait(30)
            other = Catalog(self.database)
            try:
                if decision == "approve":
                    other.approve_exemption(request_id, "bob", "concurrent")
                elif decision == "reject":
                    other.reject_exemption(request_id, "bob", "concurrent")
                else:
                    other.revoke_exemption(request_id, "carol", "concurrent")
            except BaseException as exc:  # report any save failure
                errors.append(exc)
            finally:
                other.close()
                committed.set()

        thread = threading.Thread(target=save)
        thread.start()

        seen = {"selects": 0}

        def barrier(sql) -> None:
            if sql.lstrip().upper().startswith("SELECT"):
                seen["selects"] += 1
                if seen["selects"] == 2:
                    self.catalog.connection.set_trace_callback(None)
                    proceed.set()
                    committed.wait(30)

        self.catalog.connection.set_trace_callback(barrier)
        return thread, committed, errors

    def _assert_saved(self, thread, committed, errors):
        self.assertTrue(committed.wait(15), "并发处理未能在两次读取之间提交")
        thread.join()
        self.assertEqual(errors, [])

    def test_approve_landing_between_reads_shows_one_coherent_state(self):
        self.request()
        thread, committed, errors = self._start_concurrent_save("approve")
        record = self.catalog.get_exemption("REQ-1")
        self.assertFalse(self.catalog.connection.in_transaction)
        self._assert_saved(thread, committed, errors)

        # Pinned to the pre-save instant: still pending, decision fields
        # empty, history containing the submission only — never the new
        # approval event stitched to the old pending row.
        self.assertEqual(record["status"], "pending")
        self.assertNoDecisionFields(record)
        self.assertActions(record, ["request"])

        # A follow-up query on the same Catalog sees the saved result.
        later = self.catalog.get_exemption("REQ-1")
        self.assertEqual(later["status"], "approved")
        self.assertEqual(later["approver"], "bob")
        self.assertEqual(later["decision_note"], "concurrent")
        self.assertEqual(later["approved_severity"], "high")
        self.assertActions(later, ["request", "approve"])

    def test_reject_landing_between_reads_shows_one_coherent_state(self):
        self.request()
        thread, committed, errors = self._start_concurrent_save("reject")
        record = self.catalog.get_exemption("REQ-1")
        self._assert_saved(thread, committed, errors)
        self.assertEqual(record["status"], "pending")
        self.assertNoDecisionFields(record)
        self.assertActions(record, ["request"])

        later = self.catalog.get_exemption("REQ-1")
        self.assertEqual(later["status"], "rejected")
        self.assertEqual(later["approver"], "bob")
        self.assertEqual(later["decision_note"], "concurrent")
        self.assertActions(later, ["request", "reject"])

    def test_revoke_landing_between_reads_keeps_one_coherent_state(self):
        self.request()
        self.catalog.approve_exemption("REQ-1", "bob", "first")
        thread, committed, errors = self._start_concurrent_save("revoke")
        record = self.catalog.get_exemption("REQ-1")
        self._assert_saved(thread, committed, errors)

        # Pre-save instant: still approved, no revocation fields or event,
        # approval information intact.
        self.assertEqual(record["status"], "approved")
        self.assertEqual(record["approver"], "bob")
        self.assertEqual(record["decision_note"], "first")
        self.assertEqual(record["approved_severity"], "high")
        for field in REVOKE_FIELDS:
            self.assertIsNone(record[field])
        self.assertActions(record, ["request", "approve"])

        # Post-save detail keeps the approval and adds the complete revoke.
        later = self.catalog.get_exemption("REQ-1")
        self.assertEqual(later["status"], "revoked")
        self.assertEqual(later["approver"], "bob")
        self.assertEqual(later["approved_severity"], "high")
        self.assertEqual(later["revoker"], "carol")
        self.assertEqual(later["revoke_note"], "concurrent")
        self.assertActions(later, ["request", "approve", "revoke"])


class ReadOnlyAndStalenessTests(ExemptionShowFixture):
    """Showing a request never mutates, judges, repairs or caches it."""

    def test_show_changes_nothing_and_leaves_no_transaction(self):
        self.request()
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        self.catalog.revoke_exemption("REQ-1", "bob", "undone")
        before = self.snapshot()
        for _ in range(3):
            self.catalog.get_exemption("REQ-1")
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.catalog.connection.in_transaction)

    def test_later_query_sees_saved_decision_without_reopening(self):
        self.request()
        first = self.catalog.get_exemption("REQ-1")
        self.assertEqual(first["status"], "pending")

        writer = Catalog(self.database)
        writer.approve_exemption("REQ-1", "bob", "from next process")
        writer.close()

        # The same Catalog object must not keep serving the stale detail.
        second = self.catalog.get_exemption("REQ-1")
        self.assertEqual(second["status"], "approved")
        self.assertEqual(second["decision_note"], "from next process")
        self.assertActions(second, ["request", "approve"])

    def test_expired_pending_request_is_returned_as_saved(self):
        self.catalog.request_exemption(
            "REQ-1", "api", "pypi", "lib", "1.0.0", "CVE-MAN", "lib", None,
            "alice", "reason", "2026-02-01T00:00:00+00:00",
            submitted_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        record = self.catalog.get_exemption("REQ-1")
        # Expiry never rewrites the saved status: it is still pending, with
        # its submission history and no decision fields.
        self.assertEqual(record["status"], "pending")
        self.assertNoDecisionFields(record)
        self.assertActions(record, ["request"])

    def test_expired_approved_request_is_returned_with_approval_intact(self):
        self.catalog.request_exemption(
            "REQ-1", "api", "pypi", "lib", "1.0.0", "CVE-MAN", "lib", None,
            "alice", "reason", "2026-02-01T00:00:00+00:00",
            submitted_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        self.catalog.approve_exemption(
            "REQ-1", "bob", "ok",
            decided_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        record = self.catalog.get_exemption("REQ-1")
        self.assertEqual(record["status"], "approved")
        self.assertEqual(record["approver"], "bob")
        self.assertEqual(record["approved_severity"], "high")
        self.assertActions(record, ["request", "approve"])

    def test_detail_survives_when_target_impact_disappears(self):
        # Request the indirect impact on app, then remove the dependency so
        # the impact no longer exists: the saved request and its history
        # stay queryable and are not re-judged or repaired.
        self.catalog.request_exemption(
            "REQ-1", "api", "pypi", "app", "1.0.0", "CVE-MAN", "lib", None,
            "alice", "reason", self.future,
        )
        self.catalog.remove_dependency(
            "api", "pypi", "web", "1.0.0", "api", "pypi", "lib", "1.0.0"
        )
        record = self.catalog.get_exemption("REQ-1")
        self.assertEqual(record["status"], "pending")
        self.assertEqual(record["scope"]["name"], "app")
        self.assertActions(record, ["request"])

    def test_detail_survives_when_osv_source_is_cleared(self):
        self.catalog.import_osv(
            "nvd",
            [osv_record("CVE-OSV", package="lib", versions=["1.0.0"])],
        )
        self.request("REQ-1", vulnerability="CVE-OSV", source="nvd")
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        self.catalog.import_osv("nvd", [])
        record = self.catalog.get_exemption("REQ-1")
        self.assertEqual(record["status"], "approved")
        self.assertEqual(record["scope"]["source"], "nvd")
        self.assertEqual(record["approved_severity"], "high")
        self.assertActions(record, ["request", "approve"])

    def test_empty_and_unknown_ids_raise_value_error(self):
        self.request()
        for empty in ("", "   "):
            with self.subTest(empty=empty):
                with self.assertRaises(ValueError):
                    self.catalog.get_exemption(empty)
        with self.assertRaises(ValueError):
            self.catalog.get_exemption("REQ-NOPE")
        # The failed lookups leave no transaction behind.
        self.assertFalse(self.catalog.connection.in_transaction)


class CallerTransactionAndFailureTests(ExemptionShowFixture):
    """Caller transactions are respected; read errors surface cleanly."""

    def test_show_inside_caller_transaction_sees_uncommitted_request(self):
        self.request()
        connection = self.catalog.connection
        connection.execute("BEGIN")
        try:
            connection.execute(
                """
                INSERT INTO exemption_requests(
                    id, service, ecosystem, name, version, vulnerability,
                    matched_name, source, created_at, applicant, reason,
                    expires_at, status
                ) VALUES (
                    'REQ-TMP', 'api', 'pypi', 'web', '1.0.0', 'CVE-MAN',
                    'lib', NULL, '2026-09-01T00:00:00.000000Z', 'alice',
                    'uncommitted', '2030-09-01T00:00:00.000000Z', 'pending'
                )
                """
            )
            connection.execute(
                """
                INSERT INTO exemption_events(
                    request_id, seq, occurred_at, actor, action, reason,
                    from_status, to_status
                ) VALUES (
                    'REQ-TMP', 1, '2026-09-01T00:00:00.000000Z', 'alice',
                    'request', 'uncommitted', NULL, 'pending'
                )
                """
            )
            record = self.catalog.get_exemption("REQ-TMP")
            self.assertEqual(record["status"], "pending")
            self.assertActions(record, ["request"])
            # The query must not end, commit or roll back the caller's tx.
            self.assertTrue(connection.in_transaction)
        finally:
            connection.rollback()
        with self.assertRaises(ValueError):
            self.catalog.get_exemption("REQ-TMP")
        self.assertFalse(connection.in_transaction)

    def test_show_inside_caller_transaction_sees_uncommitted_decision(self):
        self.request()
        connection = self.catalog.connection
        connection.execute("BEGIN")
        try:
            connection.execute(
                """
                UPDATE exemption_requests
                SET status = 'approved',
                    decided_at = '2026-09-02T00:00:00.000000Z',
                    approver = 'bob', decision_note = 'uncommitted',
                    approved_severity = 'high'
                WHERE id = 'REQ-1'
                """
            )
            connection.execute(
                """
                INSERT INTO exemption_events(
                    request_id, seq, occurred_at, actor, action, reason,
                    from_status, to_status
                ) VALUES (
                    'REQ-1', 2, '2026-09-02T00:00:00.000000Z', 'bob',
                    'approve', 'uncommitted', 'pending', 'approved'
                )
                """
            )
            record = self.catalog.get_exemption("REQ-1")
            self.assertEqual(record["status"], "approved")
            self.assertEqual(record["approver"], "bob")
            self.assertEqual(record["approved_severity"], "high")
            self.assertActions(record, ["request", "approve"])
            self.assertTrue(connection.in_transaction)
        finally:
            connection.rollback()
        # Rolling the caller's changes back restores the saved pending view.
        rolled_back = self.catalog.get_exemption("REQ-1")
        self.assertEqual(rolled_back["status"], "pending")
        self.assertActions(rolled_back, ["request"])
        self.assertFalse(connection.in_transaction)

    def test_read_error_fails_the_show_but_leaves_a_usable_catalog(self):
        self.request()
        armed = {"select_started": False, "fired": False}

        def arm(sql) -> None:
            normalized = " ".join(sql.split()).upper()
            if normalized.startswith("SELECT * FROM EXEMPTION_REQUESTS"):
                armed["select_started"] = True

        def interrupt_once() -> int:
            if armed["select_started"] and not armed["fired"]:
                armed["fired"] = True
                self.catalog.connection.interrupt()
            return 0

        connection = self.catalog.connection
        connection.set_trace_callback(arm)
        connection.set_progress_handler(interrupt_once, 1)
        try:
            with self.assertRaises(sqlite3.Error):
                self.catalog.get_exemption("REQ-1")
        finally:
            connection.set_progress_handler(None, 0)
            connection.set_trace_callback(None)

        # No half-open snapshot is left and the same Catalog still works;
        # no row or history event was altered by the failed read.
        self.assertFalse(connection.in_transaction)
        record = self.catalog.get_exemption("REQ-1")
        self.assertEqual(record["status"], "pending")
        self.assertActions(record, ["request"])


class CliParityTests(ExemptionShowFixture):
    """exemption-show is the same feature as the Python query."""

    def _run_cli(self, *args):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(["--database", self.database, *args])
        return code, buffer.getvalue()

    def test_cli_show_matches_python_result(self):
        self.request()
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        code, output = self._run_cli("exemption-show", "REQ-1")
        self.assertEqual(code, 0)
        self.assertEqual(
            json.loads(output), self.catalog.get_exemption("REQ-1")
        )

    def test_cli_unknown_and_empty_id_fail(self):
        code, _ = self._run_cli("exemption-show", "REQ-NOPE")
        self.assertEqual(code, 1)
        code, _ = self._run_cli("exemption-show", "")
        self.assertEqual(code, 1)

    def test_cli_revoked_detail_is_coherent(self):
        self.request()
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        self.catalog.revoke_exemption("REQ-1", "carol", "undone")
        code, output = self._run_cli("exemption-show", "REQ-1")
        self.assertEqual(code, 0)
        record = json.loads(output)
        self.assertEqual(record["status"], "revoked")
        self.assertEqual(record["approver"], "bob")
        self.assertEqual(record["revoker"], "carol")
        self.assertEqual(
            [event["action"] for event in record["events"]],
            ["request", "approve", "revoke"],
        )


if __name__ == "__main__":
    unittest.main()
