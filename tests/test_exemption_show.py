"""Regression coverage for viewing one exemption request by id.

``exemption-show`` / ``Catalog.get_exemption`` assembles a detail from two
reads: the request row and that request's event history. When another
process approves, rejects or revokes the very same request between those
two reads, the detail used to contradict itself - a still-pending row
paired with the freshly saved approval event, or an approved row already
carrying a revocation event. These tests pin the required business
result without changing the entry point or the output structure:

* the detail always reflects ONE saved state: status, handler/timestamp/
  note, approved risk level, revocation fields and the ordered event
  history belong to the same instant - either the pre-decision state
  (submission history only, decision fields empty) or the post-decision
  state (its information and events whole);
* a later query sees the already saved new result; nothing is cached
  across calls, and no open transaction is left behind;
* the query is strictly read-only - it never adds events, changes a
  status, re-judges an expired request or re-checks whether the target
  impact still exists; an expired request and one whose vulnerability
  impact has disappeared are returned with their saved content and
  history;
* history stays ordered by seq and scoped to the queried id - events of
  other requests never leak in and no event is lost when the status
  changes;
* empty and unknown ids keep raising a clear error;
* inside a caller-owned transaction the detail shares that transaction's
  view (including its own uncommitted changes) without committing or
  rolling it back; a database error while reading the row or history
  fails the whole query - never a success detail missing its history -
  and the same Catalog object stays usable afterwards;
* the CLI ``exemption-show`` is the same query: identical JSON, same
  errors.
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


FUTURE_EXPIRY = "2030-01-01T00:00:00+00:00"
T1 = datetime(2026, 1, 1, tzinfo=timezone.utc)

_EXPECTED_FIELDS = (
    "id",
    "scope",
    "applicant",
    "reason",
    "created_at",
    "expires_at",
    "status",
    "decided_at",
    "approver",
    "decision_note",
    "approved_severity",
    "revoked_at",
    "revoker",
    "revoke_note",
    "events",
)


def osv_record(identifier, package="lib", severity="high", versions=None):
    record = {
        "id": identifier,
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": package},
                "versions": versions or ["1.0.0"],
            }
        ],
    }
    if severity is not None:
        record["database_specific"] = {"severity": severity}
    return record


def event_actions(record):
    return [event["action"] for event in record["events"]]


def event_seqs(record):
    return [event["seq"] for event in record["events"]]


def assert_detail_coherent(testcase, record):
    """Status, decision fields and history must describe one saved state."""
    testcase.assertEqual(set(record), set(_EXPECTED_FIELDS))
    status = record["status"]
    if status == "pending":
        # A pending detail carries the submission alone: no decision fields,
        # never a decision/revocation event stitched onto the old row.
        testcase.assertIsNone(record["decided_at"])
        testcase.assertIsNone(record["approver"])
        testcase.assertIsNone(record["decision_note"])
        testcase.assertIsNone(record["approved_severity"])
        testcase.assertIsNone(record["revoked_at"])
        testcase.assertIsNone(record["revoker"])
        testcase.assertIsNone(record["revoke_note"])
        testcase.assertEqual(event_actions(record), ["request"])
        testcase.assertEqual(event_seqs(record), [1])
    elif status == "approved":
        testcase.assertIsNotNone(record["decided_at"])
        testcase.assertEqual(record["approver"], "bob")
        testcase.assertEqual(record["decision_note"], "concurrent")
        testcase.assertEqual(record["approved_severity"], "high")
        testcase.assertIsNone(record["revoked_at"])
        testcase.assertIsNone(record["revoker"])
        testcase.assertIsNone(record["revoke_note"])
        testcase.assertEqual(event_actions(record), ["request", "approve"])
        testcase.assertEqual(event_seqs(record), [1, 2])
    elif status == "rejected":
        testcase.assertIsNotNone(record["decided_at"])
        testcase.assertEqual(record["approver"], "bob")
        testcase.assertEqual(record["decision_note"], "concurrent")
        testcase.assertIsNone(record["approved_severity"])
        testcase.assertIsNone(record["revoked_at"])
        testcase.assertIsNone(record["revoker"])
        testcase.assertIsNone(record["revoke_note"])
        testcase.assertEqual(event_actions(record), ["request", "reject"])
        testcase.assertEqual(event_seqs(record), [1, 2])
    else:
        testcase.assertEqual(status, "revoked")
        # Revocation keeps the original approval information whole and adds
        # the revocation fields and its event after the approval history.
        testcase.assertIsNotNone(record["decided_at"])
        testcase.assertEqual(record["approver"], "bob")
        testcase.assertEqual(record["decision_note"], "first approval")
        testcase.assertEqual(record["approved_severity"], "high")
        testcase.assertIsNotNone(record["revoked_at"])
        testcase.assertEqual(record["revoker"], "carol")
        testcase.assertEqual(record["revoke_note"], "concurrent")
        testcase.assertEqual(
            event_actions(record), ["request", "approve", "revoke"]
        )
        testcase.assertEqual(event_seqs(record), [1, 2, 3])


class ExemptionShowFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()
        self.catalog.add_component("api", "pypi", "lib", "1.0.0")
        # Two distinct vulnerabilities let two live requests occupy distinct
        # scopes within one fixture.
        self.catalog.add_vulnerability("CVE-1", "lib", "high")
        self.catalog.add_vulnerability("CVE-2", "lib", "high")

    def tearDown(self) -> None:
        self.catalog.close()

    def request(self, request_id="REQ-1", **overrides):
        values = dict(
            request_id=request_id,
            service="api",
            ecosystem="pypi",
            name="lib",
            version="1.0.0",
            vulnerability="CVE-1",
            matched_name="lib",
            source=None,
            applicant="alice",
            reason="mitigated",
            expires_at=FUTURE_EXPIRY,
        )
        values.update(overrides)
        return self.catalog.request_exemption(**values)

    def snapshot_tables(self):
        requests = [
            tuple(row) for row in self.catalog.connection.execute(
                "SELECT id, service, ecosystem, name, version, vulnerability, "
                "matched_name, source, created_at, applicant, reason, "
                "expires_at, status, decided_at, approver, decision_note, "
                "approved_severity, revoked_at, revoker, revoke_note "
                "FROM exemption_requests ORDER BY id"
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


class DetailShapeAndHistoryTests(ExemptionShowFixture):
    """The saved detail is returned whole whatever the world looks like."""

    def test_pending_detail_has_submission_history_and_empty_decision_fields(
        self,
    ) -> None:
        self.request()
        record = self.catalog.get_exemption("REQ-1")
        assert_detail_coherent(self, record)
        self.assertEqual(record["id"], "REQ-1")
        self.assertEqual(record["status"], "pending")
        self.assertEqual(
            record["scope"],
            {
                "service": "api",
                "ecosystem": "pypi",
                "name": "lib",
                "version": "1.0.0",
                "vulnerability": "CVE-1",
                "matched_name": "lib",
                "source": None,
            },
        )
        (event,) = record["events"]
        self.assertEqual(event["actor"], "alice")
        self.assertEqual(event["reason"], "mitigated")
        self.assertIsNone(event["from_status"])
        self.assertEqual(event["to_status"], "pending")
        self.assertEqual(event["at"], record["created_at"])

    def test_approved_and_rejected_details_pair_decision_with_history(self) -> None:
        self.request("REQ-A")
        self.catalog.approve_exemption(
            "REQ-A", "bob", "ok",
            decided_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
        )
        approved = self.catalog.get_exemption("REQ-A")
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["approver"], "bob")
        self.assertEqual(approved["approved_severity"], "high")
        self.assertEqual(event_actions(approved), ["request", "approve"])

        self.request("REQ-R", vulnerability="CVE-2")
        self.catalog.reject_exemption(
            "REQ-R", "bob", "no",
            decided_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
        )
        rejected = self.catalog.get_exemption("REQ-R")
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(rejected["approver"], "bob")
        self.assertIsNone(rejected["approved_severity"])
        self.assertEqual(event_actions(rejected), ["request", "reject"])

    def test_revoked_detail_keeps_approval_and_adds_revocation(self) -> None:
        self.request()
        self.catalog.approve_exemption("REQ-1", "bob", "first approval")
        self.catalog.revoke_exemption("REQ-1", "carol", "control gone")
        record = self.catalog.get_exemption("REQ-1")
        self.assertEqual(record["status"], "revoked")
        # Original approval information survives the revocation.
        self.assertEqual(record["approver"], "bob")
        self.assertEqual(record["decision_note"], "first approval")
        self.assertEqual(record["approved_severity"], "high")
        self.assertIsNotNone(record["decided_at"])
        # Revocation information and event are present in full.
        self.assertEqual(record["revoker"], "carol")
        self.assertEqual(record["revoke_note"], "control gone")
        self.assertIsNotNone(record["revoked_at"])
        self.assertEqual(
            event_actions(record), ["request", "approve", "revoke"]
        )
        self.assertEqual(event_seqs(record), [1, 2, 3])

    def test_history_is_scoped_to_the_queried_id_and_ordered_by_seq(self) -> None:
        self.request("REQ-A")
        self.catalog.approve_exemption("REQ-A", "bob", "ok")
        self.catalog.revoke_exemption("REQ-A", "carol", "gone")
        # A separate request (distinct scope) keeps an independent history.
        self.request("REQ-B", vulnerability="CVE-2")
        detail_a = self.catalog.get_exemption("REQ-A")
        detail_b = self.catalog.get_exemption("REQ-B")
        self.assertEqual(event_seqs(detail_a), [1, 2, 3])
        self.assertEqual(event_seqs(detail_b), [1])
        self.assertEqual(event_actions(detail_b), ["request"])
        for event in detail_b["events"]:
            self.assertNotIn(event["action"], ("approve", "reject", "revoke"))

    def test_empty_and_unknown_ids_are_clear_errors(self) -> None:
        self.request()
        for bad in ("", "   "):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(ValueError, "申请编号不能为空"):
                    self.catalog.get_exemption(bad)
        with self.assertRaisesRegex(ValueError, "未知申请编号: NOPE"):
            self.catalog.get_exemption("NOPE")
        # A failed lookup harms neither the data nor the Catalog.
        record = self.catalog.get_exemption("REQ-1")
        self.assertEqual(record["id"], "REQ-1")

    def test_show_is_read_only_and_leaves_no_open_transaction(self) -> None:
        self.request()
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        before = self.snapshot_tables()
        for _ in range(3):
            detail = self.catalog.get_exemption("REQ-1")
            self.assertEqual(event_actions(detail), ["request", "approve"])
            self.assertFalse(self.catalog.connection.in_transaction)
        self.assertEqual(self.snapshot_tables(), before)

    def test_expired_requests_are_returned_saved_without_re_judging(self) -> None:
        # A pending request whose term has lapsed is still shown as saved.
        self.request(
            submitted_at=T1, expires_at="2026-02-01T00:00:00+00:00"
        )
        expired_pending = self.catalog.get_exemption("REQ-1")
        self.assertEqual(expired_pending["status"], "pending")
        self.assertEqual(event_actions(expired_pending), ["request"])

        # The scope frees at REQ-1's expiry, so a later same-scope request is
        # legal; approve it and let its term lapse as well.
        self.request(
            "REQ-2", submitted_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
            expires_at="2026-04-01T00:00:00+00:00",
        )
        self.catalog.approve_exemption(
            "REQ-2", "bob", "ok",
            decided_at=datetime(2026, 3, 2, tzinfo=timezone.utc),
        )
        expired_approved = self.catalog.get_exemption("REQ-2")
        self.assertEqual(expired_approved["status"], "approved")
        self.assertEqual(event_actions(expired_approved),
                         ["request", "approve"])

    def test_detail_survives_the_target_impact_disappearing(self) -> None:
        self.catalog.import_osv(
            "nvd", [osv_record("CVE-OSV", severity="high")]
        )
        self.request(vulnerability="CVE-OSV", source="nvd")
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        approved_before = self.catalog.get_exemption("REQ-1")
        self.assertEqual(approved_before["approved_severity"], "high")

        # Replacing the source removes that OSV vulnerability impact (the
        # manual CVE-1 impact is unrelated); the request is not re-evaluated
        # or trimmed on read.
        self.assertEqual(self.catalog.import_osv("nvd", []), 0)
        self.assertFalse(
            any(record["vulnerability"] == "CVE-OSV"
                for record in self.catalog.impact(service="api"))
        )
        detail = self.catalog.get_exemption("REQ-1")
        self.assertEqual(detail["status"], "approved")
        self.assertEqual(detail["approver"], "bob")
        self.assertEqual(detail["approved_severity"], "high")
        self.assertEqual(
            detail["scope"]["vulnerability"], "CVE-OSV"
        )
        self.assertEqual(detail["scope"]["source"], "nvd")
        self.assertEqual(event_actions(detail), ["request", "approve"])

        # A pending request whose scope vanishes is likewise kept intact.
        self.catalog.import_osv(
            "nvd", [osv_record("CVE-OSV-2", severity="low")]
        )
        self.request("REQ-2", vulnerability="CVE-OSV-2", source="nvd")
        self.catalog.import_osv("nvd", [])
        pending = self.catalog.get_exemption("REQ-2")
        self.assertEqual(pending["status"], "pending")
        self.assertEqual(event_actions(pending), ["request"])


class ConcurrentDecisionSnapshotTests(unittest.TestCase):
    """A decision saved while one detail is read lands wholly or not at all.

    The other process is a second Catalog connection on a WAL file
    database that runs the full decision save (status row and history
    event in one committed transaction). A trace barrier releases the
    writer only after the detail's request-row read has finished, so the
    save commits strictly before the detail reads the history. Without a
    shared snapshot that produces the contradictory detail (old row + new
    event); with one, the detail answers for a single saved instant.
    """

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name, "catalog.db"))
        self.catalog = Catalog(self.database)
        self.catalog.connection.execute("PRAGMA journal_mode=WAL")
        self.catalog.add_component("api", "pypi", "lib", "1.0.0")
        self.catalog.add_vulnerability("CVE-1", "lib", "high")
        self.catalog.add_vulnerability("CVE-2", "lib", "high")

    def tearDown(self) -> None:
        self.catalog.close()
        self.directory.cleanup()

    def _request(self, request_id="REQ-1"):
        return self.catalog.request_exemption(
            request_id, "api", "pypi", "lib", "1.0.0", "CVE-1", "lib", None,
            applicant="alice", reason="mitigated", expires_at=FUTURE_EXPIRY,
        )

    def _start_concurrent_save(self, decision, *, note="concurrent"):
        """Commit one complete decision save right before the history read."""
        proceed = threading.Event()
        committed = threading.Event()
        errors: list[BaseException] = []

        def save() -> None:
            proceed.wait(30)
            other = Catalog(self.database)
            try:
                if decision == "approve":
                    other.approve_exemption("REQ-1", "bob", note)
                elif decision == "reject":
                    other.reject_exemption("REQ-1", "bob", note)
                else:
                    other.revoke_exemption("REQ-1", "carol", note)
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

    def _assert_save_landed(self, thread, committed, errors) -> None:
        self.assertTrue(committed.wait(15), "并发处理未能在两次读取之间提交")
        thread.join()
        self.assertEqual(errors, [])

    def test_pending_detail_seen_whole_when_approval_lands_between_reads(
        self,
    ) -> None:
        self._request()
        thread, committed, errors = self._start_concurrent_save("approve")
        detail = self.catalog.get_exemption("REQ-1")
        self.assertFalse(self.catalog.connection.in_transaction)
        self._assert_save_landed(thread, committed, errors)

        # The read snapshot was pinned before the save committed, so the
        # detail is the coherent pre-save state - never pending with an
        # approval event or half-filled decision fields.
        assert_detail_coherent(self, detail)
        self.assertEqual(detail["status"], "pending")

        # The next query sees the already saved approval, whole.
        after = self.catalog.get_exemption("REQ-1")
        assert_detail_coherent(self, after)
        self.assertEqual(after["status"], "approved")
        self.assertEqual(after["approver"], "bob")
        self.assertEqual(after["decision_note"], "concurrent")
        self.assertEqual(after["approved_severity"], "high")

    def test_pending_detail_seen_whole_when_rejection_lands_between_reads(
        self,
    ) -> None:
        self._request()
        thread, committed, errors = self._start_concurrent_save("reject")
        detail = self.catalog.get_exemption("REQ-1")
        self.assertFalse(self.catalog.connection.in_transaction)
        self._assert_save_landed(thread, committed, errors)

        assert_detail_coherent(self, detail)
        self.assertEqual(detail["status"], "pending")

        after = self.catalog.get_exemption("REQ-1")
        assert_detail_coherent(self, after)
        self.assertEqual(after["status"], "rejected")
        self.assertEqual(after["decision_note"], "concurrent")
        self.assertIsNone(after["approved_severity"])

    def test_approved_detail_seen_whole_when_revocation_lands_between_reads(
        self,
    ) -> None:
        self._request()
        self.catalog.approve_exemption("REQ-1", "bob", "first approval")
        thread, committed, errors = self._start_concurrent_save(
            "revoke", note="concurrent"
        )
        detail = self.catalog.get_exemption("REQ-1")
        self.assertFalse(self.catalog.connection.in_transaction)
        self._assert_save_landed(thread, committed, errors)

        # Either saved instant is acceptable, but the detail must never pair
        # the approved row with a revocation event (or vice versa): the
        # pre-save approval note stays with the two-event approved state.
        if detail["status"] == "approved":
            self.assertEqual(detail["approver"], "bob")
            self.assertEqual(detail["decision_note"], "first approval")
            self.assertEqual(detail["approved_severity"], "high")
            self.assertIsNone(detail["revoked_at"])
            self.assertIsNone(detail["revoker"])
            self.assertIsNone(detail["revoke_note"])
            self.assertEqual(
                event_actions(detail), ["request", "approve"]
            )
            self.assertEqual(event_seqs(detail), [1, 2])
        else:
            self.assertEqual(detail["status"], "revoked")
            assert_detail_coherent(self, detail)

        after = self.catalog.get_exemption("REQ-1")
        assert_detail_coherent(self, after)
        self.assertEqual(after["status"], "revoked")
        # The original approval remains part of the saved detail.
        self.assertEqual(after["approver"], "bob")
        self.assertEqual(after["decision_note"], "first approval")
        self.assertEqual(after["approved_severity"], "high")
        self.assertEqual(after["revoker"], "carol")
        self.assertEqual(after["revoke_note"], "concurrent")

    def test_each_detail_only_carries_events_of_its_own_id(self) -> None:
        # While REQ-1 is approved mid-read, REQ-2 stays pending; the REQ-1
        # detail must never show REQ-2's submission and vice versa.
        self._request("REQ-1")
        self.catalog.request_exemption(
            "REQ-2", "api", "pypi", "lib", "1.0.0", "CVE-2", "lib", None,
            applicant="alice", reason="other", expires_at=FUTURE_EXPIRY,
        )
        thread, committed, errors = self._start_concurrent_save("approve")
        detail = self.catalog.get_exemption("REQ-1")
        self._assert_save_landed(thread, committed, errors)
        for event in detail["events"]:
            self.assertIn(event["action"], ("request", "approve"))
            self.assertIn(event["reason"], ("mitigated", "concurrent"))
        other = self.catalog.get_exemption("REQ-2")
        self.assertEqual(other["status"], "pending")
        self.assertEqual(event_actions(other), ["request"])
        self.assertEqual(other["events"][0]["reason"], "other")


class ShowTransactionAndFailureTests(ExemptionShowFixture):
    """Caller transactions are respected and read errors surface cleanly."""

    def test_show_inside_caller_transaction_sees_its_uncommitted_rows(self) -> None:
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
                    'REQ-TMP', 'api', 'pypi', 'lib', '1.0.0', 'CVE-1',
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
            detail = self.catalog.get_exemption("REQ-TMP")
            self.assertEqual(detail["status"], "pending")
            self.assertEqual(detail["reason"], "uncommitted")
            self.assertEqual(event_actions(detail), ["request"])
            # The query must not end, commit or roll back the caller's tx.
            self.assertTrue(connection.in_transaction)
        finally:
            connection.rollback()
        with self.assertRaisesRegex(ValueError, "未知申请编号: REQ-TMP"):
            self.catalog.get_exemption("REQ-TMP")

    def test_show_inside_caller_transaction_sees_its_uncommitted_update(self) -> None:
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
            detail = self.catalog.get_exemption("REQ-1")
            # Row and history both read through the caller's own view.
            self.assertEqual(detail["status"], "approved")
            self.assertEqual(detail["decision_note"], "uncommitted")
            self.assertEqual(event_actions(detail), ["request", "approve"])
            self.assertTrue(connection.in_transaction)
        finally:
            # The caller, not the query, decides to withdraw the change.
            connection.rollback()
        withdrawn = self.catalog.get_exemption("REQ-1")
        self.assertEqual(withdrawn["status"], "pending")
        self.assertIsNone(withdrawn["decision_note"])
        self.assertEqual(event_actions(withdrawn), ["request"])

    def test_caller_transaction_survives_an_unknown_id_lookup(self) -> None:
        self.request()
        connection = self.catalog.connection
        connection.execute("BEGIN")
        try:
            with self.assertRaisesRegex(ValueError, "未知申请编号: MISSING"):
                self.catalog.get_exemption("MISSING")
            self.assertTrue(connection.in_transaction)
        finally:
            connection.rollback()
        self.assertFalse(connection.in_transaction)

    def test_read_error_fails_the_detail_but_leaves_a_usable_catalog(self) -> None:
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

        # No half-open snapshot is left, the connection is reusable, and the
        # next read returns the complete detail including history.
        self.assertFalse(connection.in_transaction)
        detail = self.catalog.get_exemption("REQ-1")
        self.assertEqual(detail["id"], "REQ-1")
        self.assertEqual(detail["status"], "pending")
        self.assertEqual(event_actions(detail), ["request"])

    def test_empty_id_validation_does_not_open_a_transaction(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.get_exemption("   ")
        self.assertFalse(self.catalog.connection.in_transaction)


class CliShowParityTests(unittest.TestCase):
    """The CLI exemption-show is exactly the Python detail query."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name, "catalog.db"))
        catalog = Catalog(self.database)
        catalog.add_component("api", "pypi", "lib", "1.0.0")
        catalog.add_vulnerability("CVE-1", "lib", "high")
        catalog.add_vulnerability("CVE-2", "lib", "high")
        catalog.request_exemption(
            "REQ-1", "api", "pypi", "lib", "1.0.0", "CVE-1", "lib", None,
            "alice", "mitigated", FUTURE_EXPIRY,
        )
        catalog.approve_exemption("REQ-1", "bob", "ok")
        catalog.request_exemption(
            "REQ-2", "api", "pypi", "lib", "1.0.0", "CVE-2", "lib", None,
            "alice", "waiting", FUTURE_EXPIRY,
        )
        catalog.close()

    def tearDown(self) -> None:
        self.directory.cleanup()

    def run_cli_show(self, request_id):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            code = main(
                ["--database", self.database, "exemption-show", request_id]
            )
        return code, stdout.getvalue(), stderr.getvalue()

    def test_cli_output_equals_python_detail(self) -> None:
        catalog = Catalog(self.database)
        self.addCleanup(catalog.close)
        for request_id in ("REQ-1", "REQ-2"):
            with self.subTest(request_id=request_id):
                code, output, errors = self.run_cli_show(request_id)
                self.assertEqual(code, 0)
                self.assertEqual(errors, "")
                self.assertEqual(
                    json.loads(output), catalog.get_exemption(request_id)
                )

    def test_cli_unknown_and_empty_ids_fail_with_an_error(self) -> None:
        for request_id in ("NOPE", ""):
            with self.subTest(request_id=request_id):
                code, output, errors = self.run_cli_show(request_id)
                self.assertEqual(code, 1)
                self.assertEqual(output, "")
                self.assertTrue(errors.startswith("error: "))


if __name__ == "__main__":
    unittest.main()
