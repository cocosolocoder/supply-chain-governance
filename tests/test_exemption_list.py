"""Regression coverage for the exemption-request list business result.

The list answers one question: when requests are viewed by approval status,
the application content and the processing history always belong to the same
request id. These tests pin that result for both entry points —
``Catalog.list_exemptions`` and the ``exemption-list`` CLI command — without
changing the query entry points or the output structure.

Guarantees covered here:

* the unfiltered list and each status view (``pending``/``approved``/
  ``rejected``/``revoked``) return exactly the requests saved with that
  status;
* ordering is submission time newest first, request id ascending at an equal
  submission instant — filtered or not;
* each result keeps the full scope, applicant, reason, submission/expiry and
  existing decision/revocation fields, and matches ``get_exemption`` exactly;
* history starts with the submission event and then follows, in order, only
  events that actually happened to that request — never trimmed by the
  filter, never missing the submission, never carrying another request's
  events;
* easily confused requests stay independent: one manual registration and
  different OSV sources for the same component/vulnerability, plus an expired
  old request and a later new id for the very same scope;
* different processing careers are reflected separately (submit-only
  pending, rejected, approved-then-revoked);
* expiry never rewrites a saved status (an approved-but-expired request
  still shows under ``approved``), and an old request never disappears
  because a newer request for the same scope exists;
* empty catalog / no match returns ``[]``;
* listing mutates nothing — statuses, decision info and histories are
  identical before and after, with no extra history events;
* CLI and Python are the same feature: the same scopes, order and history;
* an illegal CLI status value keeps being rejected.

A final class pins the concurrent contract: another process saving an
approval, rejection, revocation or a brand-new request while a list is
reading must never split one saved state across the request read and the
history read — membership, status, notes and history always come from the
same instant; a read error aborts the whole list; and a caller-managed
transaction (including its uncommitted writes) is respected instead of
committed or rolled back by the query.
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


def osv_record(identifier, package="lib", severity=None, **affected):
    entry = {"package": {"ecosystem": "PyPI", "name": package}}
    entry.update(affected)
    record = {"id": identifier, "affected": [entry]}
    if severity is not None:
        record["database_specific"] = {"severity": severity}
    return record


# Fixed instants so an equal-instant tie and the expired/renewed pair can be
# built deterministically; all stored timestamps canonicalize to UTC strings.
T1 = datetime(2026, 1, 1, tzinfo=timezone.utc)
T2 = datetime(2026, 2, 1, tzinfo=timezone.utc)
T3 = datetime(2026, 3, 1, tzinfo=timezone.utc)
T4 = datetime(2026, 4, 1, tzinfo=timezone.utc)
T5 = datetime(2026, 7, 1, tzinfo=timezone.utc)

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


class ExemptionListFixture(unittest.TestCase):
    """Build requests through the real public API, never raw SQL.

    Layout (``api``): ``app -> web -> lib`` and ``worker/lib``; ``lib`` is hit
    by a manual vulnerability and by ``CVE-SAME`` arriving from two OSV
    sources (``nvd`` and ``ghsa``) plus a manual entry under the same id, so
    the same component + vulnerability can be requested three ways that must
    never merge.
    """

    def setUp(self) -> None:
        self.catalog = Catalog()
        for name in ("app", "web", "lib"):
            self.catalog.add_component("api", "pypi", name, "1.0.0")
        self.catalog.add_component("worker", "pypi", "lib", "1.0.0")
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "web", "1.0.0"
        )
        self.catalog.add_dependency(
            "api", "pypi", "web", "1.0.0", "api", "pypi", "lib", "1.0.0"
        )
        self.catalog.add_vulnerability("CVE-MAN", "lib", "high")
        for source, severity in (("nvd", "low"), ("ghsa", "medium")):
            self.catalog.import_osv(
                source,
                [osv_record("CVE-SAME", package="lib", severity=severity,
                            versions=["1.0.0"])],
            )
        self.catalog.add_vulnerability("CVE-SAME", "lib", "critical")
        self.future = "2030-01-01T00:00:00+00:00"

    def tearDown(self) -> None:
        self.catalog.close()

    def request(self, request_id, **overrides):
        values = dict(
            request_id=request_id,
            service="api",
            ecosystem="pypi",
            name="lib",
            version="1.0.0",
            vulnerability="CVE-MAN",
            matched_name="lib",
            source=None,
            applicant="alice",
            reason="mitigated",
            expires_at=self.future,
        )
        values.update(overrides)
        return self.catalog.request_exemption(**values)

    @staticmethod
    def ids(records):
        return [record["id"] for record in records]

    def snapshot(self):
        """Everything a status list is allowed to read but not change."""
        requests = [
            tuple(row[column] for column in (
                "id", "status", "created_at", "applicant", "reason",
                "expires_at", "decided_at", "approver", "decision_note",
                "approved_severity", "revoked_at", "revoker", "revoke_note",
            ))
            for row in self.catalog.connection.execute(
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

    def assertQueryLeavesStateUnchanged(self, *list_calls):
        before = self.snapshot()
        results = [call() for call in list_calls]
        self.assertEqual(self.snapshot(), before)
        return results

    def assertRecordEqualsShow(self, record):
        self.assertEqual(
            set(record), set(_EXPECTED_FIELDS),
            "列表结果必须保留现有输出结构，不增删字段",
        )
        self.assertEqual(record, self.catalog.get_exemption(record["id"]))


class ListFilteringAndShapeTests(ExemptionListFixture):
    """Who appears in each view, and what a result row contains."""

    def test_empty_catalog_lists_nothing_for_every_view(self) -> None:
        fresh = Catalog()
        self.addCleanup(fresh.close)
        self.assertEqual(fresh.list_exemptions(), [])
        for status in ("pending", "approved", "rejected", "revoked"):
            with self.subTest(status=status):
                self.assertEqual(fresh.list_exemptions(status=status), [])

    def test_no_match_for_status_returns_empty_list(self) -> None:
        self.request("REQ-P")
        # A pending catalog has no approved/rejected/revoked rows.
        for status in ("approved", "rejected", "revoked"):
            with self.subTest(status=status):
                self.assertEqual(self.catalog.list_exemptions(status=status),
                                 [])

    def test_submit_only_pending_keeps_submission_history(self) -> None:
        self.request("REQ-P")
        self.request("REQ-A", name="web", matched_name="lib")
        self.catalog.approve_exemption("REQ-A", "bob", "approve note")

        (pending,) = self.catalog.list_exemptions(status="pending")
        self.assertEqual(pending["id"], "REQ-P")
        self.assertIsNone(pending["decided_at"])
        self.assertIsNone(pending["approver"])
        self.assertIsNone(pending["decision_note"])
        self.assertIsNone(pending["approved_severity"])
        self.assertIsNone(pending["revoked_at"])
        self.assertIsNone(pending["revoker"])
        self.assertIsNone(pending["revoke_note"])
        # An undecided request has exactly one history event: the submission.
        (event,) = pending["events"]
        self.assertEqual(event["action"], "request")
        self.assertIsNone(event["from_status"])
        self.assertEqual(event["to_status"], "pending")
        self.assertEqual(event["actor"], "alice")
        self.assertEqual(event["reason"], "mitigated")
        self.assertEqual(event["at"], pending["created_at"])
        self.assertRecordEqualsShow(pending)

    def test_status_views_partition_full_list_by_saved_status(self) -> None:
        self.request("REQ-P1", submitted_at=T1)
        self.request("REQ-P2", name="web", matched_name="lib", submitted_at=T2)
        self.request("REQ-A1", name="app", matched_name="lib", submitted_at=T3)
        self.catalog.approve_exemption(
            "REQ-A1", "bob", "a1",
            decided_at=datetime(2026, 3, 2, tzinfo=timezone.utc),
        )
        self.request("REQ-A2", service="worker", submitted_at=T1)
        self.catalog.approve_exemption(
            "REQ-A2", "carol", "a2",
            decided_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        self.catalog.revoke_exemption(
            "REQ-A2", "carol", "rev a2",
            revoked_at=datetime(2026, 1, 3, tzinfo=timezone.utc),
        )
        self.request(
            "REQ-R1", vulnerability="CVE-SAME", matched_name="lib",
            submitted_at=T2,
        )
        self.catalog.reject_exemption(
            "REQ-R1", "bob", "r1",
            decided_at=datetime(2026, 2, 2, tzinfo=timezone.utc),
        )
        self.request(
            "REQ-R2", vulnerability="CVE-SAME", source="nvd",
            submitted_at=T3,
        )
        self.catalog.reject_exemption(
            "REQ-R2", "bob", "r2",
            decided_at=datetime(2026, 3, 2, tzinfo=timezone.utc),
        )

        everything = self.catalog.list_exemptions()
        by_status = {
            status: self.catalog.list_exemptions(status=status)
            for status in ("pending", "approved", "rejected", "revoked")
        }
        # The four views partition the full list by the currently saved
        # status: every request appears exactly once, nothing missing or
        # duplicated.
        partitioned = sorted(
            record["id"]
            for records in by_status.values() for record in records
        )
        self.assertEqual(partitioned, sorted(self.ids(everything)))
        self.assertEqual(len(partitioned), len(everything))
        for status, records in by_status.items():
            with self.subTest(status=status):
                self.assertTrue(
                    all(record["status"] == status for record in records)
                )
        self.assertEqual(self.ids(by_status["pending"]), ["REQ-P2", "REQ-P1"])
        self.assertEqual(self.ids(by_status["approved"]), ["REQ-A1"])
        self.assertEqual(self.ids(by_status["rejected"]),
                         ["REQ-R2", "REQ-R1"])
        self.assertEqual(self.ids(by_status["revoked"]), ["REQ-A2"])

    def test_approved_expired_request_stays_in_approved_view(self) -> None:
        # Expiry never rewrites a saved approval status.
        self.request(
            "REQ-EXPIRED",
            expires_at="2026-06-01T00:00:00+00:00",
            submitted_at=T1,
        )
        self.catalog.approve_exemption(
            "REQ-EXPIRED", "bob", "ok",
            decided_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        approved = self.catalog.list_exemptions(status="approved")
        self.assertEqual(self.ids(approved), ["REQ-EXPIRED"])
        self.assertEqual(approved[0]["status"], "approved")
        # Its term ended but its content/history are intact.
        self.assertEqual(
            [event["action"] for event in approved[0]["events"]],
            ["request", "approve"],
        )
        self.assertIn(approved[0], self.catalog.list_exemptions())
        for other in ("pending", "rejected", "revoked"):
            with self.subTest(other=other):
                self.assertEqual(self.catalog.list_exemptions(status=other),
                                 [])

    def test_revoked_request_keeps_full_content_decision_and_history(self) -> None:
        self.request("REQ-1", reason="full content check", submitted_at=T1)
        self.catalog.approve_exemption(
            "REQ-1", "bob", "approve note",
            decided_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        self.catalog.revoke_exemption(
            "REQ-1", "carol", "revoke note",
            revoked_at=datetime(2026, 1, 3, tzinfo=timezone.utc),
        )

        (record,) = self.catalog.list_exemptions(status="revoked")
        self.assertEqual(record["scope"], {
            "service": "api",
            "ecosystem": "pypi",
            "name": "lib",
            "version": "1.0.0",
            "vulnerability": "CVE-MAN",
            "matched_name": "lib",
            "source": None,
        })
        self.assertEqual(record["applicant"], "alice")
        self.assertEqual(record["reason"], "full content check")
        self.assertEqual(record["created_at"], "2026-01-01T00:00:00.000000Z")
        self.assertEqual(record["expires_at"], "2030-01-01T00:00:00.000000Z")
        self.assertEqual(record["status"], "revoked")
        self.assertEqual(record["approver"], "bob")
        self.assertEqual(record["decision_note"], "approve note")
        self.assertEqual(record["approved_severity"], "high")
        self.assertEqual(record["revoker"], "carol")
        self.assertEqual(record["revoke_note"], "revoke note")
        self.assertIsNotNone(record["decided_at"])
        self.assertIsNotNone(record["revoked_at"])
        self.assertRecordEqualsShow(record)

    def test_rejected_request_keeps_full_content_and_history(self) -> None:
        self.request(
            "REQ-R", name="web", matched_name="lib",
            applicant="dave", reason="cannot upgrade",
            submitted_at=T2,
        )
        self.catalog.reject_exemption(
            "REQ-R", "bob", "fix instead",
            decided_at=datetime(2026, 2, 2, tzinfo=timezone.utc),
        )
        (record,) = self.catalog.list_exemptions(status="rejected")
        self.assertEqual(record["scope"]["name"], "web")
        self.assertEqual(record["scope"]["matched_name"], "lib")
        self.assertEqual(record["applicant"], "dave")
        self.assertEqual(record["reason"], "cannot upgrade")
        self.assertEqual(record["approver"], "bob")
        self.assertEqual(record["decision_note"], "fix instead")
        self.assertIsNone(record["approved_severity"])
        self.assertIsNone(record["revoked_at"])
        self.assertEqual(record["created_at"], "2026-02-01T00:00:00.000000Z")
        self.assertRecordEqualsShow(record)


class ListOrderingTests(ExemptionListFixture):
    """Newest submission first; id ascending at one instant."""

    def test_newest_submission_first(self) -> None:
        self.request("REQ-1", submitted_at=T1)
        self.request("REQ-2", name="web", matched_name="lib", submitted_at=T2)
        self.request("REQ-3", name="app", matched_name="lib", submitted_at=T3)
        self.assertEqual(
            self.ids(self.catalog.list_exemptions()),
            ["REQ-3", "REQ-2", "REQ-1"],
        )

    def test_equal_submission_instant_sorts_id_ascending(self) -> None:
        # Three distinct scopes submitted at the very same instant must order
        # by id, never by insertion sequence.
        self.request("REQ-C", name="app", matched_name="lib", submitted_at=T1)
        self.request("REQ-A", submitted_at=T1)
        self.request("REQ-B", name="web", matched_name="lib", submitted_at=T1)
        self.assertEqual(
            self.ids(self.catalog.list_exemptions()),
            ["REQ-A", "REQ-B", "REQ-C"],
        )

    def test_ordering_with_interleaved_times_and_ties(self) -> None:
        self.request("REQ-T1A", submitted_at=T1)
        self.request("REQ-T2Z", name="web", matched_name="lib",
                     submitted_at=T2)
        self.request("REQ-T2A", name="app", matched_name="lib",
                     submitted_at=T2)
        self.request("REQ-T3M", service="worker", submitted_at=T3)
        self.assertEqual(
            self.ids(self.catalog.list_exemptions()),
            ["REQ-T3M", "REQ-T2A", "REQ-T2Z", "REQ-T1A"],
        )

    def test_filtered_order_keeps_same_rule(self) -> None:
        # T1: REQ-A pending (app), REQ-B rejected (web); T2: REQ-C pending
        # (worker); T3: four approvals on four distinct scopes at the same
        # submission instant. Each view keeps newest-first with id ascending
        # at ties, merely dropping the rows whose saved status does not match.
        self.request("REQ-A", name="app", matched_name="lib", submitted_at=T1)
        self.request("REQ-B", name="web", matched_name="lib", submitted_at=T1)
        self.catalog.reject_exemption(
            "REQ-B", "bob", "no",
            decided_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        self.request("REQ-C", service="worker", submitted_at=T2)
        approved_at_t3 = (
            ("REQ-D", {}),
            ("REQ-E", {"vulnerability": "CVE-SAME", "matched_name": "lib"}),
            ("REQ-F", {"vulnerability": "CVE-SAME", "source": "nvd"}),
            ("REQ-G", {"vulnerability": "CVE-SAME", "source": "ghsa"}),
        )
        for request_id, scope in approved_at_t3:
            self.request(request_id, submitted_at=T3, **scope)
            self.catalog.approve_exemption(
                request_id, "bob", "ok",
                decided_at=datetime(2026, 3, 2, tzinfo=timezone.utc),
            )

        self.assertEqual(
            self.ids(self.catalog.list_exemptions(status="approved")),
            ["REQ-D", "REQ-E", "REQ-F", "REQ-G"],
        )
        self.assertEqual(
            self.ids(self.catalog.list_exemptions(status="pending")),
            ["REQ-C", "REQ-A"],
        )
        self.assertEqual(
            self.ids(self.catalog.list_exemptions(status="rejected")),
            ["REQ-B"],
        )
        self.assertEqual(
            self.catalog.list_exemptions(status="revoked"), []
        )
        # The unfiltered list interleaves every status under the same rule.
        self.assertEqual(
            self.ids(self.catalog.list_exemptions()),
            ["REQ-D", "REQ-E", "REQ-F", "REQ-G", "REQ-C", "REQ-A", "REQ-B"],
        )


class ListHistoryAttachmentTests(ExemptionListFixture):
    """Content and history of each row belong to exactly one request id."""

    def test_history_is_complete_per_status_not_trimmed_to_filter(self) -> None:
        # An approved-then-revoked request lives in the revoked view, yet its
        # history must still start at submission and include the approval —
        # filtering must not reduce history to "revoke" events only.
        self.request("REQ-1")
        self.catalog.approve_exemption("REQ-1", "bob", "approve note")
        self.catalog.revoke_exemption("REQ-1", "carol", "revoke note")
        (revoked,) = self.catalog.list_exemptions(status="revoked")
        actions = [(event["seq"], event["action"], event["actor"],
                    event["reason"], event["from_status"],
                    event["to_status"]) for event in revoked["events"]]
        self.assertEqual(actions, [
            (1, "request", "alice", "mitigated", None, "pending"),
            (2, "approve", "bob", "approve note", "pending", "approved"),
            (3, "revoke", "carol", "revoke note", "approved", "revoked"),
        ])
        # The approved view is empty precisely because the saved status is
        # revoked — but the approval event still belongs to this request.
        self.assertEqual(self.catalog.list_exemptions(status="approved"), [])

        # A rejected request in its view likewise keeps request + rejection,
        # not just the rejection.
        self.request("REQ-2", name="web", matched_name="lib")
        self.catalog.reject_exemption("REQ-2", "bob", "deny")
        (rejected,) = self.catalog.list_exemptions(status="rejected")
        self.assertEqual(
            [event["action"] for event in rejected["events"]],
            ["request", "reject"],
        )
        self.assertEqual(rejected["events"][-1]["to_status"], "rejected")
        self.assertEqual(rejected["events"][-1]["from_status"], "pending")

    def test_histories_of_distinct_requests_never_cross(self) -> None:
        # Three requests with deliberately interleaved event timestamps and
        # different careers; each listed row must carry only its own events.
        self.request("REQ-P", submitted_at=T1)
        self.request("REQ-R", name="web", matched_name="lib", submitted_at=T2)
        self.catalog.reject_exemption(
            "REQ-R", "bob", "r-note",
            decided_at=datetime(2026, 2, 5, tzinfo=timezone.utc),
        )
        self.request("REQ-V", name="app", matched_name="lib", submitted_at=T3)
        self.catalog.approve_exemption(
            "REQ-V", "carol", "v-approve",
            decided_at=datetime(2026, 3, 5, tzinfo=timezone.utc),
        )
        self.catalog.revoke_exemption(
            "REQ-V", "carol", "v-revoke",
            revoked_at=datetime(2026, 3, 6, tzinfo=timezone.utc),
        )

        rows = {row["id"]: row for row in self.catalog.list_exemptions()}
        # Full event tuples — seq, time, actor, action, note and before/after
        # status — so an event from another request (different actor, note,
        # timestamp or transition) can never be mistaken for this row's own.
        expected = {
            "REQ-P": [
                (1, "2026-01-01T00:00:00.000000Z", "alice", "request",
                 "mitigated", None, "pending"),
            ],
            "REQ-R": [
                (1, "2026-02-01T00:00:00.000000Z", "alice", "request",
                 "mitigated", None, "pending"),
                (2, "2026-02-05T00:00:00.000000Z", "bob", "reject",
                 "r-note", "pending", "rejected"),
            ],
            "REQ-V": [
                (1, "2026-03-01T00:00:00.000000Z", "alice", "request",
                 "mitigated", None, "pending"),
                (2, "2026-03-05T00:00:00.000000Z", "carol", "approve",
                 "v-approve", "pending", "approved"),
                (3, "2026-03-06T00:00:00.000000Z", "carol", "revoke",
                 "v-revoke", "approved", "revoked"),
            ],
        }
        for request_id, tuples in expected.items():
            self.assertEqual(
                [
                    (event["seq"], event["at"], event["actor"],
                     event["action"], event["reason"], event["from_status"],
                     event["to_status"])
                    for event in rows[request_id]["events"]
                ],
                tuples,
            )
        # Every row's first event is its own submission at its own created
        # instant — a cross-attachment would mismatch this pairing.
        for request_id, row in rows.items():
            self.assertEqual(
                (row["events"][0]["action"], row["events"][0]["at"]),
                ("request", row["created_at"]),
            )
        # And the exact same attachment holds through every status filter.
        for status in ("pending", "rejected", "revoked"):
            for row in self.catalog.list_exemptions(status=status):
                self.assertRecordEqualsShow(row)

    def test_all_listed_records_equal_single_fetch_including_events(self) -> None:
        self.request("REQ-1")
        self.request("REQ-2", name="web", matched_name="lib")
        self.catalog.approve_exemption("REQ-2", "bob", "ok")
        self.request("REQ-3", name="app", matched_name="lib")
        self.catalog.reject_exemption("REQ-3", "bob", "no")
        for status in (None, "pending", "approved", "rejected", "revoked"):
            with self.subTest(status=status):
                for row in self.catalog.list_exemptions(status=status):
                    self.assertRecordEqualsShow(row)


class ConfusableRequestTests(ExemptionListFixture):
    """Scopes that look alike must never merge content or share history."""

    def test_same_component_and_vulnerability_three_sources_stay_apart(self) -> None:
        # Manual registration, nvd and ghsa all name lib + CVE-SAME.
        self.request("REQ-MAN", vulnerability="CVE-SAME", matched_name="lib")
        self.request("REQ-NVD", vulnerability="CVE-SAME", source="nvd")
        self.request("REQ-GHSA", vulnerability="CVE-SAME", source="ghsa")
        all_rows = {
            row["id"]: row for row in self.catalog.list_exemptions()
        }
        self.assertEqual(sorted(all_rows), ["REQ-GHSA", "REQ-MAN", "REQ-NVD"])
        self.assertIsNone(all_rows["REQ-MAN"]["scope"]["source"])
        self.assertEqual(all_rows["REQ-NVD"]["scope"]["source"], "nvd")
        self.assertEqual(all_rows["REQ-GHSA"]["scope"]["source"], "ghsa")
        # Three independent submissions, no shared history whatsoever.
        for request_id in ("REQ-MAN", "REQ-NVD", "REQ-GHSA"):
            with self.subTest(request_id=request_id):
                (event,) = all_rows[request_id]["events"]
                self.assertEqual(event["action"], "request")

        # Give them different careers; filtering still separates them.
        self.catalog.approve_exemption("REQ-NVD", "bob", "low risk")
        self.catalog.reject_exemption("REQ-GHSA", "bob", "no")
        approved = {
            row["id"]: row for row in
            self.catalog.list_exemptions(status="approved")
        }
        self.assertEqual(set(approved), {"REQ-NVD"})
        self.assertEqual(
            [event["action"] for event in approved["REQ-NVD"]["events"]],
            ["request", "approve"],
        )
        self.assertEqual(
            approved["REQ-NVD"]["approved_severity"], "low",
        )
        rejected = self.catalog.list_exemptions(status="rejected")
        self.assertEqual(self.ids(rejected), ["REQ-GHSA"])
        self.assertEqual(
            [event["action"] for event in rejected[0]["events"]],
            ["request", "reject"],
        )
        pending = self.catalog.list_exemptions(status="pending")
        self.assertEqual(self.ids(pending), ["REQ-MAN"])
        # The manual request never inherited the OSV approval severity.
        self.assertIsNone(pending[0]["approved_severity"])

    def test_expired_old_request_and_new_same_scope_request_coexist(self) -> None:
        # An old request for a scope expires (approved, term ended); a later
        # new-id request is submitted for exactly the same scope. Both rows
        # must remain visible with their own content and history.
        self.request(
            "REQ-OLD",
            expires_at="2026-06-01T00:00:00+00:00",
            submitted_at=T1,
        )
        self.catalog.approve_exemption(
            "REQ-OLD", "bob", "old approval",
            decided_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        self.request(
            "REQ-NEW",
            expires_at="2030-06-01T00:00:00+00:00",
            submitted_at=T5,
        )

        rows = {
            row["id"]: row for row in self.catalog.list_exemptions()
        }
        self.assertEqual(set(rows), {"REQ-OLD", "REQ-NEW"})
        # Newest first: the later submission leads; the expired one is still
        # present instead of disappearing when the new request arrived.
        self.assertEqual(
            self.ids(self.catalog.list_exemptions()),
            ["REQ-NEW", "REQ-OLD"],
        )
        old = rows["REQ-OLD"]
        self.assertEqual(old["status"], "approved")
        self.assertEqual(old["expires_at"], "2026-06-01T00:00:00.000000Z")
        self.assertEqual(old["decision_note"], "old approval")
        self.assertEqual(
            [event["action"] for event in old["events"]],
            ["request", "approve"],
        )
        new = rows["REQ-NEW"]
        self.assertEqual(new["status"], "pending")
        self.assertEqual(new["expires_at"], "2030-06-01T00:00:00.000000Z")
        self.assertIsNone(new["approver"])
        self.assertEqual(
            [event["action"] for event in new["events"]], ["request"]
        )
        # Status views keep both: the expired approval is still "approved".
        self.assertEqual(
            self.ids(self.catalog.list_exemptions(status="approved")),
            ["REQ-OLD"],
        )
        self.assertEqual(
            self.ids(self.catalog.list_exemptions(status="pending")),
            ["REQ-NEW"],
        )
        # Scopes are the same seven fields; only the ids and careers differ.
        self.assertEqual(old["scope"], new["scope"])

    def test_expired_pending_old_request_remains_after_replacement(self) -> None:
        # Same story with an old request that simply expired while pending
        # (rejected implicitly by time, not by a decision): it stays pending
        # in storage and remains listed alongside the replacement.
        self.request(
            "REQ-OLD",
            expires_at="2026-02-01T00:00:00+00:00",
            submitted_at=T1,
        )
        self.request(
            "REQ-NEW",
            expires_at="2030-01-01T00:00:00+00:00",
            submitted_at=T4,
        )
        pending = self.catalog.list_exemptions(status="pending")
        self.assertEqual(self.ids(pending), ["REQ-NEW", "REQ-OLD"])
        by_id = {row["id"]: row for row in pending}
        self.assertEqual(
            [event["action"] for event in by_id["REQ-OLD"]["events"]],
            ["request"],
        )
        self.assertEqual(
            [event["action"] for event in by_id["REQ-NEW"]["events"]],
            ["request"],
        )


class ListDoesNotMutateTests(ExemptionListFixture):
    """Querying never alters statuses, decision info or history."""

    def test_listing_views_add_no_events_and_change_nothing(self) -> None:
        self.request("REQ-P", submitted_at=T1)
        self.request("REQ-A", name="web", matched_name="lib", submitted_at=T2)
        self.catalog.approve_exemption("REQ-A", "bob", "ok")
        self.request("REQ-R", name="app", matched_name="lib", submitted_at=T3)
        self.catalog.reject_exemption("REQ-R", "bob", "no")
        self.request("REQ-V", service="worker", submitted_at=T4)
        self.catalog.approve_exemption("REQ-V", "carol", "ok")
        self.catalog.revoke_exemption("REQ-V", "carol", "back")

        calls = [lambda: self.catalog.list_exemptions()] + [
            lambda status=status: self.catalog.list_exemptions(status=status)
            for status in ("pending", "approved", "rejected", "revoked")
        ]
        # Run every view twice; repeated queries must remain side-effect free.
        self.assertQueryLeavesStateUnchanged(*(calls + calls))

        # Explicitly, the event count is exactly one submission per request
        # plus the recorded decisions — nothing added by listing.
        event_count = self.catalog.connection.execute(
            "SELECT COUNT(*) FROM exemption_events"
        ).fetchone()[0]
        # 4 submissions + 1 approve + 1 reject + 1 approve + 1 revoke = 8.
        self.assertEqual(event_count, 8)

    def test_empty_queries_do_not_mutate(self) -> None:
        calls = [lambda: self.catalog.list_exemptions()] + [
            lambda status=status: self.catalog.list_exemptions(status=status)
            for status in ("pending", "approved", "rejected", "revoked")
        ]
        results = self.assertQueryLeavesStateUnchanged(*calls)
        for result in results:
            self.assertEqual(result, [])

    def test_repeated_queries_return_identical_results(self) -> None:
        self.request("REQ-1", submitted_at=T1)
        self.request("REQ-2", name="web", matched_name="lib", submitted_at=T2)
        self.catalog.approve_exemption("REQ-2", "bob", "ok")
        for status in (None, "pending", "approved"):
            first = self.catalog.list_exemptions(status=status)
            second = self.catalog.list_exemptions(status=status)
            self.assertEqual(first, second)


class CliParityTests(unittest.TestCase):
    """The CLI list and the Python query are the same business function."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name, "catalog.db"))
        catalog = Catalog(self.database)
        for name in ("app", "web", "lib"):
            catalog.add_component("api", "pypi", name, "1.0.0")
        catalog.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "web", "1.0.0"
        )
        catalog.add_dependency(
            "api", "pypi", "web", "1.0.0", "api", "pypi", "lib", "1.0.0"
        )
        catalog.add_vulnerability("CVE-MAN", "lib", "high")
        catalog.import_osv(
            "nvd",
            [osv_record("CVE-OSV", package="lib", severity="low",
                        versions=["1.0.0"])],
        )
        catalog.request_exemption(
            "REQ-P", "api", "pypi", "lib", "1.0.0", "CVE-OSV", "lib", "nvd",
            "alice", "pending one", "2030-01-01T00:00:00+00:00",
            submitted_at=T1,
        )
        catalog.request_exemption(
            "REQ-A", "api", "pypi", "web", "1.0.0", "CVE-MAN", "lib", None,
            "alice", "approved one", "2030-01-01T00:00:00+00:00",
            submitted_at=T2,
        )
        catalog.approve_exemption("REQ-A", "bob", "approve note")
        catalog.request_exemption(
            "REQ-R", "api", "pypi", "app", "1.0.0", "CVE-MAN", "lib", None,
            "alice", "rejected one", "2030-01-01T00:00:00+00:00",
            submitted_at=T3,
        )
        catalog.reject_exemption("REQ-R", "bob", "reject note")
        catalog.request_exemption(
            "REQ-V", "api", "pypi", "lib", "1.0.0", "CVE-MAN", "lib", None,
            "alice", "revoked one", "2030-01-01T00:00:00+00:00",
            submitted_at=T4,
        )
        catalog.approve_exemption("REQ-V", "carol", "approve to revoke")
        catalog.revoke_exemption("REQ-V", "carol", "revoke note")
        catalog.close()

    def tearDown(self) -> None:
        self.directory.cleanup()

    def run_cli_list(self, *extra):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            code = main(["--database", self.database, "exemption-list",
                         *extra])
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(code, 0)
        return json.loads(stdout.getvalue())

    def test_cli_matches_python_for_every_view(self) -> None:
        catalog = Catalog(self.database)
        self.addCleanup(catalog.close)
        for status in (None, "pending", "approved", "rejected", "revoked"):
            with self.subTest(status=status):
                cli_records = self.run_cli_list(
                    *() if status is None else ("--status", status)
                )
                py_records = catalog.list_exemptions(status=status)
                # Same scopes, same order, same full content and history.
                self.assertEqual(cli_records, py_records)
                self.assertEqual(
                    [record["id"] for record in cli_records],
                    [record["id"] for record in py_records],
                )

    def test_cli_unfiltered_order_and_status_subsets(self) -> None:
        all_records = self.run_cli_list()
        self.assertEqual(
            [row["id"] for row in all_records],
            ["REQ-V", "REQ-R", "REQ-A", "REQ-P"],
        )
        approved = self.run_cli_list("--status", "approved")
        self.assertEqual([row["id"] for row in approved], ["REQ-A"])
        # The CLI row carries the request's complete history, including the
        # source-scoped scope, and the revoke career shows all three events.
        revoked = self.run_cli_list("--status", "revoked")
        self.assertEqual([row["id"] for row in revoked], ["REQ-V"])
        self.assertEqual(
            [event["action"] for event in revoked[0]["events"]],
            ["request", "approve", "revoke"],
        )
        pending = self.run_cli_list("--status", "pending")
        self.assertEqual(
            pending[0]["scope"]["vulnerability"], "CVE-OSV"
        )
        self.assertEqual(pending[0]["scope"]["source"], "nvd")
        self.assertEqual(
            [event["action"] for event in pending[0]["events"]],
            ["request"],
        )

    def test_cli_empty_views_emit_empty_json_array(self) -> None:
        # Only the four fixture statuses exist one each; build a fresh empty
        # database to check the empty-array output of every view.
        with tempfile.TemporaryDirectory() as empty_dir:
            empty_db = str(Path(empty_dir, "catalog.db"))
            Catalog(empty_db).close()

            def run_empty(*extra):
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), \
                        contextlib.redirect_stderr(stderr):
                    code = main(["--database", empty_db, "exemption-list",
                                 *extra])
                self.assertEqual(code, 0)
                self.assertEqual(stderr.getvalue(), "")
                return json.loads(stdout.getvalue())

            self.assertEqual(run_empty(), [])
            for status in ("pending", "approved", "rejected", "revoked"):
                self.assertEqual(run_empty("--status", status), [])

    def test_cli_illegal_status_value_is_rejected(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as context:
                main(["--database", self.database, "exemption-list",
                      "--status", "expired"])
        self.assertNotEqual(context.exception.code, 0)
        self.assertIn("invalid choice", stderr.getvalue())
        self.assertIn("expired", stderr.getvalue())
        # Nothing was printed as a list and the stored data is untouched.
        self.assertEqual(stdout.getvalue(), "")
        catalog = Catalog(self.database)
        self.addCleanup(catalog.close)
        self.assertEqual(
            [row["id"] for row in catalog.list_exemptions()],
            ["REQ-V", "REQ-R", "REQ-A", "REQ-P"],
        )
        # Every legal value still works after the rejected invocation.
        for status in ("pending", "approved", "rejected", "revoked"):
            stdout2 = io.StringIO()
            with contextlib.redirect_stdout(stdout2):
                code = main(["--database", self.database, "exemption-list",
                             "--status", status])
            self.assertEqual(code, 0)
            self.assertTrue(stdout2.getvalue().strip().startswith("["))


class ConcurrentSnapshotTests(unittest.TestCase):
    """Content, status, notes and history always come from one saved instant.

    Another process saving an approval, rejection, revocation or a brand-new
    request while the list is reading must never split a single saved state
    across the request selection and the history read. The interleave is
    reproduced deterministically: the database runs in WAL so a second
    connection can commit while this connection keeps a snapshot open, and a
    trace callback fires the competing save at the exact statement that used
    to be the second, independent read.
    """

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name, "catalog.db"))
        self.catalog = Catalog(self.database)
        # WAL is what makes the read-commit-read interleaving possible: a
        # concurrent writer commits while the list connection holds its read
        # snapshot. In the default rollback journal that scenario is simply
        # blocked, so WAL is required to exercise the snapshot contract.
        self.catalog.connection.execute("PRAGMA journal_mode=WAL").fetchone()
        for name in ("app", "web", "lib"):
            self.catalog.add_component("api", "pypi", name, "1.0.0")
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

    def request(self, catalog, request_id, submitted_at=None, **overrides):
        values = dict(
            request_id=request_id,
            service="api",
            ecosystem="pypi",
            name="lib",
            version="1.0.0",
            vulnerability="CVE-MAN",
            matched_name="lib",
            source=None,
            applicant="alice",
            reason="mitigated",
            expires_at=self.future,
        )
        values.update(overrides)
        if submitted_at is not None:
            values["submitted_at"] = submitted_at
        return catalog.request_exemption(**values)

    def writer_catalog(self) -> Catalog:
        writer = Catalog(self.database)
        self.addCleanup(writer.close)
        return writer

    def list_with_save_between_reads(self, write_action, status):
        """Run the list while another process saves between its two reads.

        The competing write commits immediately before the history read is
        executed - the exact boundary where application content and history
        used to come from two different saved states.
        """
        writer = self.writer_catalog()
        fired = []

        def tracer(statement: str) -> None:
            if not fired and "exemption_events AS e" in statement:
                fired.append(True)
                write_action(writer)

        self.catalog.connection.set_trace_callback(tracer)
        try:
            result = self.catalog.list_exemptions(status=status)
        finally:
            self.catalog.connection.set_trace_callback(None)
        self.assertTrue(fired, "交错必须恰好发生在历史读取语句之前")
        return result

    @staticmethod
    def assertRecordCoherent(testcase, record, status, actions):
        """Status, notes and history describe one and the same saved state."""
        testcase.assertEqual(record["status"], status)
        event_actions = [event["action"] for event in record["events"]]
        testcase.assertEqual(event_actions, actions)
        # History always starts with the request, at the submission instant.
        testcase.assertEqual(record["events"][0]["action"], "request")
        testcase.assertEqual(record["events"][0]["at"], record["created_at"])
        # The final history transition lands exactly on the displayed
        # status; an old row attached to newer history fails this pairing.
        testcase.assertEqual(record["events"][-1]["to_status"], status)
        for earlier, later in zip(record["events"], record["events"][1:]):
            testcase.assertEqual(later["from_status"], earlier["to_status"])

    def test_approval_between_reads_keeps_pending_view_at_old_state(self) -> None:
        self.request(self.catalog, "REQ-A", submitted_at=T1)
        self.request(self.catalog, "REQ-P", name="web", matched_name="lib",
                     submitted_at=T2)
        rows = self.list_with_save_between_reads(
            lambda w: w.approve_exemption("REQ-A", "bob", "approve note"),
            status="pending",
        )
        # Pinned before the save: REQ-A is still selected, still pending, and
        # carries no approval residue; the other pending row is unaffected.
        by_id = {row["id"]: row for row in rows}
        self.assertEqual(set(by_id), {"REQ-A", "REQ-P"})
        self.assertRecordCoherent(self, by_id["REQ-A"], "pending", ["request"])
        self.assertIsNone(by_id["REQ-A"]["decision_note"])
        self.assertIsNone(by_id["REQ-A"]["approver"])
        self.assertRecordCoherent(self, by_id["REQ-P"], "pending", ["request"])
        # A later query sees the completed approval whole.
        self.assertEqual(
            [row["id"] for row in self.catalog.list_exemptions(status="pending")],
            ["REQ-P"],
        )
        approved = {
            row["id"]: row
            for row in self.catalog.list_exemptions(status="approved")
        }
        self.assertEqual(set(approved), {"REQ-A"})
        self.assertEqual(
            [event["action"] for event in approved["REQ-A"]["events"]],
            ["request", "approve"],
        )
        self.assertEqual(approved["REQ-A"]["decision_note"], "approve note")

    def test_rejection_between_reads_keeps_pending_view_at_old_state(self) -> None:
        self.request(self.catalog, "REQ-R", submitted_at=T1)
        rows = self.list_with_save_between_reads(
            lambda w: w.reject_exemption("REQ-R", "bob", "reject note"),
            status="pending",
        )
        (record,) = rows
        self.assertRecordCoherent(self, record, "pending", ["request"])
        self.assertIsNone(record["decision_note"])
        later = {
            row["id"]: row
            for row in self.catalog.list_exemptions(status="rejected")
        }
        self.assertEqual(set(later), {"REQ-R"})
        self.assertEqual(
            [event["action"] for event in later["REQ-R"]["events"]],
            ["request", "reject"],
        )

    def test_revocation_between_reads_keeps_approved_view_at_old_state(
        self,
    ) -> None:
        self.request(self.catalog, "REQ-V", submitted_at=T1)
        self.catalog.approve_exemption("REQ-V", "bob", "approve note")
        rows = self.list_with_save_between_reads(
            lambda w: w.revoke_exemption("REQ-V", "carol", "revoke note"),
            status="approved",
        )
        (record,) = rows
        self.assertRecordCoherent(
            self, record, "approved", ["request", "approve"]
        )
        self.assertEqual(record["decision_note"], "approve note")
        self.assertIsNone(record["revoke_note"])
        later = {
            row["id"]: row
            for row in self.catalog.list_exemptions(status="revoked")
        }
        self.assertEqual(set(later), {"REQ-V"})
        self.assertEqual(
            [event["action"] for event in later["REQ-V"]["events"]],
            ["request", "approve", "revoke"],
        )
        self.assertEqual(
            self.catalog.list_exemptions(status="approved"), []
        )

    def test_unfiltered_list_never_mixes_old_row_with_new_history(self) -> None:
        self.request(self.catalog, "REQ-A", submitted_at=T1)
        rows = self.list_with_save_between_reads(
            lambda w: w.approve_exemption("REQ-A", "bob", "approve note"),
            status=None,
        )
        # Pre-decision snapshot: still pending, decision note absent, and the
        # approve event is not grafted onto the old row.
        (record,) = rows
        self.assertRecordCoherent(self, record, "pending", ["request"])
        self.assertIsNone(record["decision_note"])
        self.assertIsNone(record["approver"])

        # A subsequent unfiltered query sees the saved approval as a whole.
        later = {row["id"]: row for row in self.catalog.list_exemptions()}
        self.assertEqual(later["REQ-A"]["status"], "approved")
        self.assertEqual(later["REQ-A"]["decision_note"], "approve note")
        self.assertEqual(
            [event["action"] for event in later["REQ-A"]["events"]],
            ["request", "approve"],
        )

    def test_request_entering_selection_between_reads_cannot_break_list(
        self,
    ) -> None:
        # A second request enters the pending selection while the list reads.
        # The old second read then returned an event for an id the first read
        # never selected, which made list construction fail outright; and in
        # unfiltered views its event could attach to nothing.
        self.request(self.catalog, "REQ-P", submitted_at=T1)

        def submit(writer: Catalog) -> None:
            self.request(
                writer, "REQ-NEW", name="web", matched_name="lib",
                submitted_at=T2,
            )

        rows = self.list_with_save_between_reads(submit, status="pending")
        # Pinned to the pre-save snapshot: the request that entered
        # mid-read is neither listed nor has its history pulled in.
        self.assertEqual([row["id"] for row in rows], ["REQ-P"])
        self.assertRecordCoherent(self, rows[0], "pending", ["request"])

        later = self.catalog.list_exemptions(status="pending")
        self.assertEqual([row["id"] for row in later], ["REQ-NEW", "REQ-P"])
        self.assertEqual(
            [event["action"] for event in later[0]["events"]], ["request"]
        )

    def test_request_entering_approved_view_between_reads_is_wholesale(
        self,
    ) -> None:
        # Symmetric entering case for the approved view: a decision lands
        # while that view is reading. A second, already approved request
        # makes sure the history read still runs; the snapshot may exclude
        # the new request (pre-save) or include it together with both its
        # events, but never include it with history stripped.
        self.request(self.catalog, "REQ-KEPT", name="web", matched_name="lib",
                     submitted_at=T1)
        self.catalog.approve_exemption("REQ-KEPT", "bob", "kept note")
        self.request(self.catalog, "REQ-A", submitted_at=T2)

        rows = self.list_with_save_between_reads(
            lambda w: w.approve_exemption("REQ-A", "bob", "approve note"),
            status="approved",
        )
        # Read began before the save: only the previously approved request
        # is in the snapshot; the new approval is not half-present.
        by_id = {row["id"]: row for row in rows}
        self.assertEqual(set(by_id), {"REQ-KEPT"})
        self.assertRecordCoherent(
            self, by_id["REQ-KEPT"], "approved", ["request", "approve"]
        )
        # The completed approval is visible to the very next query, with
        # its full history.
        later = {
            row["id"]: row
            for row in self.catalog.list_exemptions(status="approved")
        }
        self.assertEqual(set(later), {"REQ-KEPT", "REQ-A"})
        self.assertEqual(
            [event["action"] for event in later["REQ-A"]["events"]],
            ["request", "approve"],
        )
        self.assertEqual(later["REQ-A"]["decision_note"], "approve note")

    def _raw_exemption_state(self):
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

    def _deny_reads_of(self, table: str):
        def authorizer(kind, arg1, _arg2, _db, _source):
            if kind == sqlite3.SQLITE_READ and arg1 == table:
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        self.catalog.connection.set_authorizer(authorizer)

    def test_database_error_on_either_read_reports_failure_and_stays_usable(
        self,
    ) -> None:
        self.request(self.catalog, "REQ-P", submitted_at=T1)
        self.request(self.catalog, "REQ-A", name="web", matched_name="lib",
                     submitted_at=T2)
        self.catalog.approve_exemption("REQ-A", "bob", "ok")
        for failing_table in ("exemption_requests", "exemption_events"):
            with self.subTest(failing_read=failing_table):
                before = self._raw_exemption_state()
                self._deny_reads_of(failing_table)
                try:
                    for status in (None, "pending", "approved"):
                        with self.assertRaises(sqlite3.Error):
                            self.catalog.list_exemptions(status=status)
                        # The failed read never leaves an open transaction
                        # behind on the shared connection.
                        self.assertFalse(
                            self.catalog.connection.in_transaction
                        )
                finally:
                    self.catalog.connection.set_authorizer(None)
                # No half list, no writes: the same connection keeps serving
                # complete results and the stored data is untouched.
                self.assertEqual(self._raw_exemption_state(), before)
                self.assertEqual(
                    [row["id"] for row in
                     self.catalog.list_exemptions(status="pending")],
                    ["REQ-P"],
                )

    def _insert_uncommitted_request(self, request_id="REQ-TX") -> None:
        self.catalog.connection.execute("BEGIN")
        self.catalog.connection.execute(
            """
            INSERT INTO exemption_requests(
                id, service, ecosystem, name, version, vulnerability,
                matched_name, source, created_at, applicant, reason,
                expires_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id, "api", "pypi", "app", "1.0.0", "CVE-MAN", "lib",
                None, "2026-05-01T00:00:00.000000Z", "alice", "uncommitted",
                "2030-01-01T00:00:00.000000Z", "pending",
            ),
        )
        self.catalog.connection.execute(
            """
            INSERT INTO exemption_events(
                request_id, seq, occurred_at, actor, action, reason,
                from_status, to_status
            ) VALUES (?, 1, ?, ?, 'request', ?, NULL, 'pending')
            """,
            (
                request_id, "2026-05-01T00:00:00.000000Z", "alice",
                "uncommitted",
            ),
        )

    def test_list_inside_caller_transaction_uses_caller_visible_state(self) -> None:
        self.request(self.catalog, "REQ-P", submitted_at=T1)
        self._insert_uncommitted_request()
        self.assertTrue(self.catalog.connection.in_transaction)
        try:
            for status in (None, "pending"):
                with self.subTest(status=status):
                    rows = self.catalog.list_exemptions(status=status)
                    self.assertIn("REQ-TX", [row["id"] for row in rows])
                    tx_row = next(row for row in rows if row["id"] == "REQ-TX")
                    self.assertEqual(tx_row["status"], "pending")
                    self.assertEqual(
                        [event["action"] for event in tx_row["events"]],
                        ["request"],
                    )
                    # The query neither committed nor rolled the caller's
                    # transaction back.
                    self.assertTrue(
                        self.catalog.connection.in_transaction
                    )
            # Another connection still cannot see the uncommitted request.
            other = sqlite3.connect(self.database)
            self.addCleanup(other.close)
            self.assertEqual(
                other.execute(
                    "SELECT COUNT(*) FROM exemption_requests WHERE id = 'REQ-TX'"
                ).fetchone()[0],
                0,
            )
        finally:
            self.catalog.connection.rollback()
        self.assertFalse(self.catalog.connection.in_transaction)
        # The caller rolled back; later queries no longer include REQ-TX and
        # the connection works normally.
        self.assertEqual(
            [row["id"] for row in self.catalog.list_exemptions()],
            ["REQ-P"],
        )

    def test_read_error_inside_caller_transaction_preserves_caller_tx(self) -> None:
        self.request(self.catalog, "REQ-P", submitted_at=T1)
        self._insert_uncommitted_request()
        self._deny_reads_of("exemption_events")
        try:
            with self.assertRaises(sqlite3.Error):
                self.catalog.list_exemptions(status="pending")
            # The caller's transaction is still open with its writes intact;
            # the query must not have committed or rolled it back.
            self.assertTrue(self.catalog.connection.in_transaction)
            self.assertEqual(
                self.catalog.connection.execute(
                    "SELECT reason FROM exemption_requests WHERE id = 'REQ-TX'"
                ).fetchone()[0],
                "uncommitted",
            )
            other = sqlite3.connect(self.database)
            self.addCleanup(other.close)
            self.assertEqual(
                other.execute(
                    "SELECT COUNT(*) FROM exemption_requests WHERE id = 'REQ-TX'"
                ).fetchone()[0],
                0,
            )
        finally:
            self.catalog.connection.set_authorizer(None)
            self.catalog.connection.rollback()
        self.assertEqual(
            [row["id"] for row in self.catalog.list_exemptions(status="pending")],
            ["REQ-P"],
        )


if __name__ == "__main__":
    unittest.main()
