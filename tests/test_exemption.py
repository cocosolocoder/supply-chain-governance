import json
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


class ExemptionFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()
        # api: app -> web -> lib ; lib is directly hit (manual + OSV).
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
        self.catalog.import_osv(
            "nvd",
            [osv_record("CVE-OSV", package="lib", severity="low",
                        versions=["1.0.0"])],
        )
        self.future = "2030-01-01T00:00:00+00:00"

    def tearDown(self) -> None:
        self.catalog.close()

    def request(self, request_id="REQ-1", **overrides):
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


class RequestValidationTests(ExemptionFixture):
    def test_request_for_live_impact_is_stored_pending(self) -> None:
        record = self.request()
        self.assertEqual(record["status"], "pending")
        self.assertEqual(record["scope"]["source"], None)
        self.assertEqual(record["events"][0]["action"], "request")
        self.assertEqual(record["events"][0]["from_status"], None)
        self.assertEqual(record["events"][0]["to_status"], "pending")
        self.assertEqual(record["events"][0]["actor"], "alice")

    def test_named_osv_source_identified(self) -> None:
        record = self.request(
            "REQ-OSV", vulnerability="CVE-OSV", source="nvd"
        )
        self.assertEqual(record["scope"]["source"], "nvd")
        self.assertEqual(record["status"], "pending")

    def test_target_must_exist(self) -> None:
        with self.assertRaises(ValueError):
            self.request(name="ghost")
        with self.assertRaises(ValueError):
            self.request(service="billing")
        # Another component of the same service is a different version scope.
        with self.assertRaises(ValueError):
            self.request(version="2.0.0")
        with self.assertRaises(ValueError):
            self.request(vulnerability="CVE-NOPE")
        with self.assertRaises(ValueError):
            self.request(matched_name="other")
        # A different source is a different scope that does not exist.
        with self.assertRaises(ValueError):
            self.request(source="other-source")
        # The OSV record is not the manual one and vice versa.
        with self.assertRaises(ValueError):
            self.request(vulnerability="CVE-MAN", source="nvd")
        with self.assertRaises(ValueError):
            self.request(vulnerability="CVE-OSV")
        # No request row is left behind.
        self.assertEqual(self.catalog.list_exemptions(), [])

    def test_empty_fields_rejected(self) -> None:
        for field, value in [
            ("request_id", " "),
            ("service", " "),
            ("ecosystem", " "),
            ("name", " "),
            ("version", " "),
            ("vulnerability", " "),
            ("matched_name", " "),
            ("applicant", " "),
            ("reason", " "),
        ]:
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    self.request(**{field: value})

    def test_expiry_rules(self) -> None:
        with self.assertRaises(ValueError):
            self.request(expires_at="not-a-time")
        with self.assertRaises(ValueError):
            # Naive timestamp has no timezone.
            self.request(expires_at="2030-01-01T00:00:00")
        submitted = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with self.assertRaises(ValueError):
            self.request(
                expires_at="2026-01-01T00:00:00+00:00",
                submitted_at=submitted,
            )
        with self.assertRaises(ValueError):
            self.request(
                expires_at="2025-12-31T23:59:59+00:00",
                submitted_at=submitted,
            )
        # Exactly one instant later is accepted.
        record = self.request(
            expires_at="2026-01-01T00:00:01+00:00",
            submitted_at=submitted,
        )
        self.assertEqual(record["status"], "pending")

    def test_idempotent_retry_returns_original(self) -> None:
        first = self.request()
        second = self.request()
        self.assertEqual(first, second)
        rows = self.catalog.connection.execute(
            "SELECT COUNT(*) FROM exemption_requests"
        ).fetchone()[0]
        events = self.catalog.connection.execute(
            "SELECT COUNT(*) FROM exemption_events"
        ).fetchone()[0]
        self.assertEqual(rows, 1)
        self.assertEqual(events, 1)

    def test_same_id_different_content_rejected_and_kept(self) -> None:
        self.request()
        with self.assertRaises(ValueError):
            self.request(reason="changed reason")
        with self.assertRaises(ValueError):
            self.request(name="web")
        # Original record and its single event survive.
        record = self.catalog.get_exemption("REQ-1")
        self.assertEqual(record["reason"], "mitigated")
        self.assertEqual(len(record["events"]), 1)

    def test_one_live_request_per_scope(self) -> None:
        self.request()
        with self.assertRaises(ValueError):
            self.request(request_id="REQ-2")
        # A rejected request frees the scope.
        self.catalog.reject_exemption("REQ-1", "bob", "no")
        self.request(request_id="REQ-2")

    def test_distinct_scopes_are_independent(self) -> None:
        self.request()  # api lib manual
        self.request("REQ-W", name="web", vulnerability="CVE-MAN",
                     matched_name="lib")
        self.request("REQ-SVC", service="worker")
        self.request("REQ-OSV", vulnerability="CVE-OSV", source="nvd")
        self.assertEqual(len(self.catalog.list_exemptions()), 4)
        # Approving the direct hit does not exempt dependent components.
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        report = self.catalog.risk_report()
        by = {
            (i["component"]["service"], i["component"]["name"],
             i["vulnerability"], i["source"]): i
            for i in report["impacts"]
        }
        self.assertTrue(by[("api", "lib", "CVE-MAN", None)]["exempted"])
        self.assertFalse(by[("api", "web", "CVE-MAN", None)]["exempted"])
        self.assertFalse(by[("api", "app", "CVE-MAN", None)]["exempted"])


class DecisionTests(ExemptionFixture):
    def test_approve_records_severity_and_history(self) -> None:
        self.request()
        record = self.catalog.approve_exemption("REQ-1", "bob", "agreed")
        self.assertEqual(record["status"], "approved")
        self.assertEqual(record["approver"], "bob")
        self.assertEqual(record["decision_note"], "agreed")
        self.assertEqual(record["approved_severity"], "high")
        self.assertEqual([e["action"] for e in record["events"]],
                         ["request", "approve"])
        decision = record["events"][1]
        self.assertEqual(decision["from_status"], "pending")
        self.assertEqual(decision["to_status"], "approved")
        self.assertEqual(decision["actor"], "bob")
        self.assertEqual(decision["reason"], "agreed")
        self.assertIsNotNone(decision["at"])

    def test_reject_terminal(self) -> None:
        self.request()
        record = self.catalog.reject_exemption("REQ-1", "bob", "no way")
        self.assertEqual(record["status"], "rejected")
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("REQ-1", "bob", "late")
        with self.assertRaises(ValueError):
            self.catalog.reject_exemption("REQ-1", "bob", "again")
        with self.assertRaises(ValueError):
            self.catalog.revoke_exemption("REQ-1", "bob", "x")

    def test_only_pending_can_be_decided(self) -> None:
        self.request()
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("REQ-1", "carol", "again")
        with self.assertRaises(ValueError):
            self.catalog.reject_exemption("REQ-1", "carol", "again")

    def test_applicant_cannot_self_approve(self) -> None:
        self.request()
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("REQ-1", "alice", "self")
        # Still pending.
        self.assertEqual(self.catalog.get_exemption("REQ-1")["status"], "pending")
        # Self-rejection is allowed (not an approval conflict), different scope.
        self.request("REQ-2", name="web", matched_name="lib")
        self.catalog.reject_exemption("REQ-2", "alice", "withdraw")

    def test_empty_handler_and_note_rejected(self) -> None:
        self.request()
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("REQ-1", " ", "ok")
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("REQ-1", "bob", "  ")

    def test_unknown_id_errors(self) -> None:
        for operation in (
            self.catalog.approve_exemption,
            self.catalog.reject_exemption,
            self.catalog.revoke_exemption,
        ):
            with self.subTest(operation=operation.__name__):
                with self.assertRaises(ValueError):
                    operation("NOPE", "bob", "note")

    def test_decision_after_expiry_rejected_and_kept(self) -> None:
        submitted = datetime(2026, 1, 1, tzinfo=timezone.utc)
        expiry = "2026-02-01T00:00:00+00:00"
        self.request(expires_at=expiry, submitted_at=submitted)
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption(
                "REQ-1", "bob", "late",
                decided_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
            )
        record = self.catalog.get_exemption("REQ-1")
        self.assertEqual(record["status"], "pending")
        self.assertEqual(len(record["events"]), 1)
        # Just before expiry is accepted.
        self.catalog.approve_exemption(
            "REQ-1", "bob", "in time",
            decided_at=datetime(2026, 1, 31, 23, 59, 59, tzinfo=timezone.utc),
        )

    def test_approve_requires_target_to_still_exist(self) -> None:
        self.request()
        # Remove the dependency-free manual hit by clearing the vuln via a
        # fresh identical observation is not possible; instead withdraw impact
        # by deleting the component through catalog replacement. Simulate
        # disappearance with OSV source withdrawal on an OSV-scoped request.
        self.request("REQ-OSV", vulnerability="CVE-OSV", source="nvd")
        self.catalog.import_osv("nvd", [])
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("REQ-OSV", "bob", "gone")
        self.assertEqual(
            self.catalog.get_exemption("REQ-OSV")["status"], "pending"
        )

    def test_revoke_rules(self) -> None:
        self.request()
        with self.assertRaises(ValueError):
            self.catalog.revoke_exemption("REQ-1", "bob", "too soon")
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        with self.assertRaises(ValueError):
            self.catalog.revoke_exemption("REQ-1", " ", "x")
        with self.assertRaises(ValueError):
            self.catalog.revoke_exemption("REQ-1", "bob", " ")
        record = self.catalog.revoke_exemption("REQ-1", "carol", "rollback")
        self.assertEqual(record["status"], "revoked")
        self.assertEqual(record["revoker"], "carol")
        actions = [e["action"] for e in record["events"]]
        self.assertEqual(actions, ["request", "approve", "revoke"])
        with self.assertRaises(ValueError):
            self.catalog.revoke_exemption("REQ-1", "carol", "again")
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("REQ-1", "carol", "reopen")

    def test_cannot_revoke_after_expiry_instant(self) -> None:
        submitted = datetime(2026, 1, 1, tzinfo=timezone.utc)
        expiry = "2026-02-01T00:00:00+00:00"
        self.request(expires_at=expiry, submitted_at=submitted)
        self.catalog.approve_exemption(
            "REQ-1", "bob", "ok",
            decided_at=submitted,
        )
        with self.assertRaises(ValueError):
            self.catalog.revoke_exemption(
                "REQ-1", "bob", "late",
                revoked_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
            )

    def test_revoking_frees_scope_for_new_request(self) -> None:
        self.request()
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        with self.assertRaises(ValueError):
            self.request(request_id="REQ-2")
        self.catalog.revoke_exemption("REQ-1", "bob", "reconsider")
        self.request(request_id="REQ-2")


class SeverityEscalationTests(ExemptionFixture):
    def test_exemption_stops_when_severity_outgrows_approval(self) -> None:
        self.request()
        self.catalog.approve_exemption("REQ-1", "bob", "ok")  # approved: high
        report = self.catalog.risk_report(service="api")
        (lib,) = [i for i in report["impacts"]
                  if i["component"]["name"] == "lib"
                  and i["vulnerability"] == "CVE-MAN"]
        self.assertTrue(lib["exempted"])

        # Raise the manual observation to critical.
        self.catalog.add_vulnerability("CVE-MAN", "lib", "critical")
        report = self.catalog.risk_report(service="api")
        (lib,) = [i for i in report["impacts"]
                  if i["component"]["name"] == "lib"
                  and i["vulnerability"] == "CVE-MAN"]
        self.assertFalse(lib["exempted"])
        self.assertEqual(lib["exemption_request"], "REQ-1")
        self.assertIn("超出审批范围", lib["not_exempt_reason"])

        # Equal rank still covered; a lower rank stays covered.
        self.catalog.add_vulnerability("CVE-MAN", "lib", "high")
        self.assertTrue(
            next(i for i in self.catalog.risk_report(service="api")["impacts"]
                 if i["component"]["name"] == "lib"
                 and i["vulnerability"] == "CVE-MAN")["exempted"]
        )


class RiskReportTests(ExemptionFixture):
    def by(self, report, name, vulnerability="CVE-MAN", source=None,
           service="api"):
        matches = [
            i for i in report["impacts"]
            if i["component"]["name"] == name
            and i["component"]["service"] == service
            and i["vulnerability"] == vulnerability
            and i["source"] == source
        ]
        (match,) = matches
        return match

    def test_report_shape_and_path(self) -> None:
        report = self.catalog.risk_report()
        self.assertEqual(report["highest_severity"], "high")
        self.assertEqual(report["unhandled_component_count"], 4)
        app = self.by(report, "app")
        self.assertFalse(app["direct"])
        self.assertEqual(
            [n["name"] for n in app["path"]], ["app", "web", "lib"]
        )
        lib = self.by(report, "lib")
        self.assertTrue(lib["direct"])
        self.assertEqual([n["name"] for n in lib["path"]], ["lib"])

    def test_exempted_record_excluded_from_counts(self) -> None:
        self.request()
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        report = self.catalog.risk_report()
        # lib's manual record exempted; lib still appears via OSV, and app/web
        # still have the manual record.
        self.assertTrue(self.by(report, "lib", "CVE-MAN")["exempted"])
        self.assertFalse(self.by(report, "lib", "CVE-OSV", "nvd")["exempted"])
        # 4 distinct components still carry at least one unexempted record.
        self.assertEqual(report["unhandled_component_count"], 4)
        # Exempting the OSV low record too does not change the highest (high).
        self.request("REQ-OSV", vulnerability="CVE-OSV", source="nvd")
        self.catalog.approve_exemption("REQ-OSV", "bob", "ok")
        report = self.catalog.risk_report()
        self.assertEqual(report["highest_severity"], "high")

    def test_highest_and_count_null_when_fully_exempted(self) -> None:
        # Single component, single vuln: fully exempted report.
        catalog = Catalog()
        catalog.add_component("s", "pypi", "only", "1.0.0")
        catalog.add_vulnerability("CVE-1", "only", "low")
        catalog.request_exemption(
            "R", "s", "pypi", "only", "1.0.0", "CVE-1", "only", None,
            "a", "r", self.future,
        )
        catalog.approve_exemption("R", "b", "ok")
        report = catalog.risk_report()
        self.assertEqual(report["unhandled_component_count"], 0)
        self.assertIsNone(report["highest_severity"])
        self.assertEqual(report["impact_count"], 1)
        self.assertTrue(report["impacts"][0]["exempted"])
        catalog.close()

    def test_service_filter(self) -> None:
        report = self.catalog.risk_report(service="api")
        self.assertTrue(all(
            i["component"]["service"] == "api" for i in report["impacts"]
        ))
        self.assertEqual(report["service"], "api")
        self.assertEqual(
            self.catalog.risk_report(service="nope")["impact_count"], 0
        )

    def test_sorting_is_stable(self) -> None:
        at = "2027-01-01T00:00:00+00:00"
        first = self.catalog.risk_report(evaluated_at=at)
        second = self.catalog.risk_report(evaluated_at=at)
        self.assertEqual(first, second)
        keys = [
            (i["component"]["service"], i["component"]["ecosystem"],
             i["component"]["name"], i["component"]["version"],
             i["vulnerability"], i["matched_name"], i["source"] or "")
            for i in first["impacts"]
        ]
        self.assertEqual(keys, sorted(keys))

    def test_evaluated_at_controls_only_the_term(self) -> None:
        expiry = "2030-06-01T00:00:00+00:00"
        self.request(expires_at=expiry)
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        # Before expiry instant: covered.
        before = self.catalog.risk_report(
            evaluated_at="2030-05-31T23:59:59+00:00"
        )
        self.assertTrue(self.by(before, "lib")["exempted"])
        # At/after expiry instant: not covered, reason states expiry.
        at = self.catalog.risk_report(
            evaluated_at="2030-06-01T00:00:00+00:00"
        )
        entry = self.by(at, "lib")
        self.assertFalse(entry["exempted"])
        self.assertEqual(entry["exemption_request"], "REQ-1")
        self.assertIn("到期", entry["not_exempt_reason"])
        # Timezone offset is normalized to the same UTC instant.
        shifted = self.catalog.risk_report(
            evaluated_at="2030-06-01T08:00:00+08:00"
        )
        self.assertFalse(self.by(shifted, "lib")["exempted"])

    def test_pending_link_shown(self) -> None:
        self.request()
        report = self.catalog.risk_report()
        entry = self.by(report, "lib")
        self.assertFalse(entry["exempted"])
        self.assertEqual(entry["exemption_request"], "REQ-1")
        self.assertIn("待审批", entry["not_exempt_reason"])

    def test_disappearance_removes_impact_but_keeps_history(self) -> None:
        self.request("REQ-OSV", vulnerability="CVE-OSV", source="nvd")
        self.catalog.approve_exemption("REQ-OSV", "bob", "ok")
        self.catalog.import_osv("nvd", [])  # withdraw the OSV record
        report = self.catalog.risk_report()
        self.assertFalse(any(
            i["vulnerability"] == "CVE-OSV" for i in report["impacts"]
        ))
        record = self.catalog.get_exemption("REQ-OSV")
        self.assertEqual(record["status"], "approved")
        self.assertEqual(len(record["events"]), 2)

    def test_reappearing_impact_resumes_exemption(self) -> None:
        self.request("REQ-OSV", vulnerability="CVE-OSV", source="nvd")
        self.catalog.approve_exemption("REQ-OSV", "bob", "ok")
        self.catalog.import_osv("nvd", [])
        self.catalog.import_osv(
            "nvd", [osv_record("CVE-OSV", package="lib", severity="low",
                               versions=["1.0.0"])]
        )
        entry = self.by(
            self.catalog.risk_report(), "lib", "CVE-OSV", "nvd"
        )
        self.assertTrue(entry["exempted"])
        self.assertEqual(entry["exemption_request"], "REQ-OSV")

    def test_latest_dependency_path_is_shown(self) -> None:
        # Add a shorter path app -> lib; the request scope (lib direct) is
        # unchanged but dependent records reflect the new path.
        self.request()
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "lib", "1.0.0"
        )
        app = self.by(self.catalog.risk_report(), "app")
        self.assertEqual([n["name"] for n in app["path"]], ["app", "lib"])
        # The request's stored scope is untouched.
        self.assertEqual(
            self.catalog.get_exemption("REQ-1")["scope"]["name"], "lib"
        )


class PersistenceAndConcurrencyTests(unittest.TestCase):
    def test_persists_across_reopen_and_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory, "catalog.db")
            catalog = Catalog(database)
            catalog.add_component("api", "pypi", "lib", "1.0.0")
            catalog.add_vulnerability("CVE-1", "lib", "high")
            catalog.request_exemption(
                "REQ-1", "api", "pypi", "lib", "1.0.0", "CVE-1", "lib", None,
                "alice", "reason", "2030-01-01T00:00:00+00:00",
            )
            catalog.approve_exemption("REQ-1", "bob", "ok")
            first = catalog.risk_report(
                evaluated_at="2027-01-01T00:00:00+00:00"
            )
            catalog.close()

            reopened = Catalog(database)
            record = reopened.get_exemption("REQ-1")
            self.assertEqual(record["status"], "approved")
            self.assertEqual(len(record["events"]), 2)
            second = reopened.risk_report(
                evaluated_at="2027-01-01T00:00:00+00:00"
            )
            self.assertEqual(first, second)
            reopened.close()

    def test_existing_database_keeps_working(self) -> None:
        # A database created before exemptions existed (no exemption tables)
        # migrates transparently.
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory, "catalog.db")
            catalog = Catalog(database)
            catalog.add_component("api", "pypi", "lib", "1.0.0")
            catalog.add_vulnerability("CVE-1", "lib", "high")
            catalog.close()

            reopened = Catalog(database)
            reopened.request_exemption(
                "REQ-1", "api", "pypi", "lib", "1.0.0", "CVE-1", "lib", None,
                "alice", "reason", "2030-01-01T00:00:00+00:00",
            )
            self.assertEqual(
                reopened.get_exemption("REQ-1")["status"], "pending"
            )
            reopened.close()

    def test_concurrent_decisions_accept_one_change(self) -> None:
        import sqlite3
        import threading

        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory, "catalog.db")
            catalog = Catalog(database)
            catalog.add_component("api", "pypi", "lib", "1.0.0")
            catalog.add_vulnerability("CVE-1", "lib", "high")
            catalog.request_exemption(
                "REQ-1", "api", "pypi", "lib", "1.0.0", "CVE-1", "lib", None,
                "alice", "reason", "2030-01-01T00:00:00+00:00",
            )
            catalog.close()

            outcomes: list[str] = []

            def decide(handler: str) -> None:
                local = Catalog(database)
                try:
                    local.approve_exemption("REQ-1", handler, "concurrent")
                    outcomes.append("approved")
                except ValueError:
                    outcomes.append("rejected")
                finally:
                    local.close()

            t1 = threading.Thread(target=decide, args=("bob",))
            t2 = threading.Thread(target=decide, args=("carol",))
            t1.start(); t2.start()
            t1.join(); t2.join()

            self.assertEqual(sorted(outcomes), ["approved", "rejected"])
            check = Catalog(database)
            record = check.get_exemption("REQ-1")
            self.assertEqual(record["status"], "approved")
            self.assertEqual(len(record["events"]), 2)
            check.close()


class CliTests(unittest.TestCase):
    def test_full_cli_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))

            def run(*args):
                return main(["--database", database, *args])

            self.assertEqual(run("add-component", "api", "pypi", "lib", "1"), 0)
            self.assertEqual(
                run("add-vulnerability", "CVE-1", "lib", "high"), 0
            )
            self.assertEqual(
                run(
                    "request-exemption", "REQ-1",
                    "api", "pypi", "lib", "1", "CVE-1", "lib",
                    "--applicant", "alice",
                    "--reason", "mitigated",
                    "--expires-at", "2030-01-01T00:00:00+00:00",
                ),
                0,
            )
            self.assertEqual(
                run("approve-exemption", "REQ-1",
                    "--handler", "alice", "--note", "self"),
                1,
            )
            self.assertEqual(
                run("approve-exemption", "REQ-1",
                    "--handler", "bob", "--note", "ok"),
                0,
            )
            self.assertEqual(run("exemption-show", "REQ-1"), 0)
            self.assertEqual(run("exemption-list"), 0)
            self.assertEqual(run("exemption-list", "--status", "approved"), 0)
            self.assertEqual(
                run("risk-report", "--service", "api",
                    "--at", "2027-01-01T00:00:00+00:00"),
                0,
            )
            self.assertEqual(
                run("revoke-exemption", "REQ-1",
                    "--handler", "bob", "--note", "rollback"),
                0,
            )

    def test_cli_naive_expiry_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            main(["--database", database, "add-component",
                  "api", "pypi", "lib", "1"])
            main(["--database", database, "add-vulnerability",
                  "CVE-1", "lib", "high"])
            code = main([
                "--database", database, "request-exemption", "REQ-1",
                "api", "pypi", "lib", "1", "CVE-1", "lib",
                "--applicant", "alice", "--reason", "x",
                "--expires-at", "2030-01-01T00:00:00",
            ])
            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
