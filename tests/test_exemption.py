import json
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import main


FUTURE = "2099-01-01T00:00:00+00:00"
PAST = "2000-01-01T00:00:00+00:00"
EVAL_AT = "2050-01-01T00:00:00+00:00"


class ExemptionApplyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()
        self.catalog.add_component("api", "pypi", "fastapi", "0.115.0")
        self.catalog.add_vulnerability("CVE-1", "fastapi", "medium")

    def tearDown(self) -> None:
        self.catalog.close()

    def test_apply_creates_pending_application(self) -> None:
        result = self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "planned upgrade", FUTURE,
        )
        self.assertEqual(result["application_no"], "EX-1")
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["applicant"], "alice")
        self.assertEqual(result["risk_level"], None)
        self.assertEqual(result["source"], "")

    def test_apply_with_named_osv_source(self) -> None:
        self.catalog.import_osv("osv-src", [
            {"id": "CVE-2", "affected": [
                {"package": {"ecosystem": "PyPI", "name": "flask"},
                 "versions": ["1.0.0"]}
            ]}
        ])
        self.catalog.add_component("api", "pypi", "flask", "1.0.0")
        result = self.catalog.apply_exemption(
            "EX-2", "api", "pypi", "flask", "1.0.0",
            "CVE-2", "flask", "osv-src", "alice", "reason", FUTURE,
        )
        self.assertEqual(result["source"], "osv-src")

    def test_apply_idempotent_returns_original(self) -> None:
        kwargs = dict(
            application_no="EX-1", service="api", ecosystem="pypi",
            name="fastapi", version="0.115.0", vulnerability_id="CVE-1",
            matched_name="fastapi", source=None, applicant="alice",
            reason="planned upgrade", expires_at=FUTURE,
        )
        first = self.catalog.apply_exemption(**kwargs)
        second = self.catalog.apply_exemption(**kwargs)
        self.assertEqual(first["id"] if "id" in first else first["application_no"],
                         second["application_no"])
        self.assertEqual(first["created_at"], second["created_at"])
        self.assertEqual(first["status"], second["status"])

    def test_same_number_different_content_rejected(self) -> None:
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )
        with self.assertRaises(ValueError):
            self.catalog.apply_exemption(
                "EX-1", "api", "pypi", "fastapi", "0.115.0",
                "CVE-1", "fastapi", None, "bob", "different reason", FUTURE,
            )

    def test_target_must_exist(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.apply_exemption(
                "EX-1", "api", "pypi", "ghost", "1.0.0",
                "CVE-1", "ghost", None, "alice", "reason", FUTURE,
            )

    def test_empty_fields_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.apply_exemption(
                "", "api", "pypi", "fastapi", "0.115.0",
                "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
            )
        with self.assertRaises(ValueError):
            self.catalog.apply_exemption(
                "EX-1", "", "pypi", "fastapi", "0.115.0",
                "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
            )
        with self.assertRaises(ValueError):
            self.catalog.apply_exemption(
                "EX-1", "api", "pypi", "fastapi", "0.115.0",
                "CVE-1", "fastapi", None, "", "reason", FUTURE,
            )
        with self.assertRaises(ValueError):
            self.catalog.apply_exemption(
                "EX-1", "api", "pypi", "fastapi", "0.115.0",
                "CVE-1", "fastapi", None, "alice", "", FUTURE,
            )

    def test_invalid_timestamp_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.apply_exemption(
                "EX-1", "api", "pypi", "fastapi", "0.115.0",
                "CVE-1", "fastapi", None, "alice", "reason", "not-a-time",
            )

    def test_naive_timestamp_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.apply_exemption(
                "EX-1", "api", "pypi", "fastapi", "0.115.0",
                "CVE-1", "fastapi", None, "alice", "reason",
                "2099-01-01T00:00:00",
            )

    def test_expiry_must_be_in_future(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.apply_exemption(
                "EX-1", "api", "pypi", "fastapi", "0.115.0",
                "CVE-1", "fastapi", None, "alice", "reason", PAST,
            )

    def test_scope_blocking_unexpired_pending(self) -> None:
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )
        with self.assertRaises(ValueError):
            self.catalog.apply_exemption(
                "EX-2", "api", "pypi", "fastapi", "0.115.0",
                "CVE-1", "fastapi", None, "bob", "reason", FUTURE,
            )

    def test_scope_blocking_unexpired_approved(self) -> None:
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )
        self.catalog.approve_exemption("EX-1", "bob", "ok")
        with self.assertRaises(ValueError):
            self.catalog.apply_exemption(
                "EX-2", "api", "pypi", "fastapi", "0.115.0",
                "CVE-1", "fastapi", None, "carol", "reason", FUTURE,
            )

    def test_expired_application_does_not_block(self) -> None:
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )
        # Manually expire the application.
        self.catalog.connection.execute(
            "UPDATE exemptions SET expires_at = '2020-01-01T00:00:00+00:00' "
            "WHERE application_no = 'EX-1'"
        )
        self.catalog.connection.commit()
        result = self.catalog.apply_exemption(
            "EX-2", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "bob", "reason", FUTURE,
        )
        self.assertEqual(result["application_no"], "EX-2")

    def test_rejected_application_does_not_block(self) -> None:
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )
        self.catalog.reject_exemption("EX-1", "bob", "no")
        result = self.catalog.apply_exemption(
            "EX-2", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "carol", "reason", FUTURE,
        )
        self.assertEqual(result["application_no"], "EX-2")

    def test_different_version_separate_application(self) -> None:
        self.catalog.add_component("api", "pypi", "fastapi", "0.116.0")
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )
        result = self.catalog.apply_exemption(
            "EX-2", "api", "pypi", "fastapi", "0.116.0",
            "CVE-1", "fastapi", None, "bob", "reason", FUTURE,
        )
        self.assertEqual(result["application_no"], "EX-2")

    def test_different_service_separate_application(self) -> None:
        self.catalog.add_component("web", "pypi", "fastapi", "0.115.0")
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )
        result = self.catalog.apply_exemption(
            "EX-2", "web", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "bob", "reason", FUTURE,
        )
        self.assertEqual(result["application_no"], "EX-2")

    def test_different_source_separate_application(self) -> None:
        self.catalog.import_osv("osv-a", [
            {"id": "CVE-2", "affected": [
                {"package": {"ecosystem": "PyPI", "name": "fastapi"},
                 "versions": ["0.115.0"]}
            ]}
        ])
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )
        result = self.catalog.apply_exemption(
            "EX-2", "api", "pypi", "fastapi", "0.115.0",
            "CVE-2", "fastapi", "osv-a", "bob", "reason", FUTURE,
        )
        self.assertEqual(result["application_no"], "EX-2")


class ExemptionApproveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()
        self.catalog.add_component("api", "pypi", "fastapi", "0.115.0")
        self.catalog.add_vulnerability("CVE-1", "fastapi", "medium")
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )

    def tearDown(self) -> None:
        self.catalog.close()

    def test_approve_succeeds(self) -> None:
        result = self.catalog.approve_exemption("EX-1", "bob", "approved")
        self.assertEqual(result["status"], "approved")
        self.assertEqual(result["risk_level"], "medium")

    def test_self_approval_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("EX-1", "alice", "self approve")

    def test_empty_operator_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("EX-1", "  ", "ok")

    def test_empty_reason_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("EX-1", "bob", "")

    def test_unknown_application_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("EX-999", "bob", "ok")

    def test_approve_rejected_application_fails(self) -> None:
        self.catalog.reject_exemption("EX-1", "bob", "no")
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("EX-1", "carol", "ok")

    def test_approve_revoked_application_fails(self) -> None:
        self.catalog.approve_exemption("EX-1", "bob", "ok")
        self.catalog.revoke_exemption("EX-1", "carol", "revoked")
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("EX-1", "dave", "ok")

    def test_approve_expired_application_fails(self) -> None:
        self.catalog.reject_exemption("EX-1", "bob", "clear")
        self.catalog.apply_exemption(
            "EX-2", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )
        self.catalog.connection.execute(
            "UPDATE exemptions SET expires_at = '2020-01-01T00:00:00+00:00' "
            "WHERE application_no = 'EX-2'"
        )
        self.catalog.connection.commit()
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("EX-2", "bob", "ok")

    def test_approve_when_target_gone_fails(self) -> None:
        self.catalog.remove_dependency(
            "api", "pypi", "fastapi", "0.115.0",
            "api", "pypi", "fastapi", "0.115.0",
        )
        # Removing a self-dependency is a no-op; delete the component instead.
        self.catalog.connection.execute("PRAGMA foreign_keys = ON")
        self.catalog.connection.execute(
            "DELETE FROM components WHERE service = 'api' AND name = 'fastapi'"
        )
        self.catalog.connection.commit()
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("EX-1", "bob", "ok")

    def test_risk_level_saved_at_approval(self) -> None:
        self.catalog.add_vulnerability("CVE-1", "fastapi", "high")
        result = self.catalog.approve_exemption("EX-1", "bob", "ok")
        self.assertEqual(result["risk_level"], "high")


class ExemptionRejectRevokeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()
        self.catalog.add_component("api", "pypi", "fastapi", "0.115.0")
        self.catalog.add_vulnerability("CVE-1", "fastapi", "medium")
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )

    def tearDown(self) -> None:
        self.catalog.close()

    def test_reject_succeeds(self) -> None:
        result = self.catalog.reject_exemption("EX-1", "bob", "no")
        self.assertEqual(result["status"], "rejected")

    def test_reject_approved_fails(self) -> None:
        self.catalog.approve_exemption("EX-1", "bob", "ok")
        with self.assertRaises(ValueError):
            self.catalog.reject_exemption("EX-1", "carol", "no")

    def test_reject_revoked_fails(self) -> None:
        self.catalog.approve_exemption("EX-1", "bob", "ok")
        self.catalog.revoke_exemption("EX-1", "carol", "revoked")
        with self.assertRaises(ValueError):
            self.catalog.reject_exemption("EX-1", "dave", "no")

    def test_revoke_succeeds(self) -> None:
        self.catalog.approve_exemption("EX-1", "bob", "ok")
        result = self.catalog.revoke_exemption("EX-1", "carol", "revoked")
        self.assertEqual(result["status"], "revoked")

    def test_revoke_pending_fails(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.revoke_exemption("EX-1", "bob", "revoked")

    def test_revoke_rejected_fails(self) -> None:
        self.catalog.reject_exemption("EX-1", "bob", "no")
        with self.assertRaises(ValueError):
            self.catalog.revoke_exemption("EX-1", "carol", "revoked")

    def test_revoke_expired_fails(self) -> None:
        self.catalog.reject_exemption("EX-1", "bob", "clear")
        self.catalog.apply_exemption(
            "EX-2", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )
        self.catalog.connection.execute(
            "UPDATE exemptions SET expires_at = '2020-01-01T00:00:00+00:00' "
            "WHERE application_no = 'EX-2'"
        )
        self.catalog.connection.commit()
        # Cannot approve an expired one, so revoke also fails since it stays pending.
        with self.assertRaises(ValueError):
            self.catalog.revoke_exemption("EX-2", "bob", "revoked")


class ExemptionHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()
        self.catalog.add_component("api", "pypi", "fastapi", "0.115.0")
        self.catalog.add_vulnerability("CVE-1", "fastapi", "medium")

    def tearDown(self) -> None:
        self.catalog.close()

    def test_history_records_full_flow(self) -> None:
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "initial reason", FUTURE,
        )
        self.catalog.approve_exemption("EX-1", "bob", "approved")
        self.catalog.revoke_exemption("EX-1", "carol", "revoked")
        history = self.catalog.exemption_history("EX-1")
        self.assertEqual(len(history), 3)
        self.assertEqual(history[0]["action"], "applied")
        self.assertEqual(history[0]["operator"], "alice")
        self.assertEqual(history[0]["from_status"], "")
        self.assertEqual(history[0]["to_status"], "pending")
        self.assertEqual(history[1]["action"], "approved")
        self.assertEqual(history[1]["operator"], "bob")
        self.assertEqual(history[1]["from_status"], "pending")
        self.assertEqual(history[1]["to_status"], "approved")
        self.assertEqual(history[2]["action"], "revoked")
        self.assertEqual(history[2]["operator"], "carol")
        self.assertEqual(history[2]["from_status"], "approved")
        self.assertEqual(history[2]["to_status"], "revoked")

    def test_history_unknown_application_returns_empty(self) -> None:
        self.assertEqual(self.catalog.exemption_history("EX-999"), [])


class RiskReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()
        self.catalog.add_component("api", "pypi", "fastapi", "0.115.0")
        self.catalog.add_vulnerability("CVE-1", "fastapi", "medium")

    def tearDown(self) -> None:
        self.catalog.close()

    def test_report_no_exemption(self) -> None:
        report = self.catalog.risk_report(evaluation_at=EVAL_AT)
        self.assertEqual(len(report["impacts"]), 1)
        impact = report["impacts"][0]
        self.assertFalse(impact["exempt"])
        self.assertIsNone(impact["application_no"])
        self.assertEqual(impact["reason"], "无豁免申请")
        self.assertEqual(report["summary"]["unexempted_components"], 1)
        self.assertEqual(report["summary"]["highest_severity"], "medium")

    def test_report_approved_exemption_is_exempt(self) -> None:
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )
        self.catalog.approve_exemption("EX-1", "bob", "ok")
        report = self.catalog.risk_report(evaluation_at=EVAL_AT)
        impact = report["impacts"][0]
        self.assertTrue(impact["exempt"])
        self.assertEqual(impact["application_no"], "EX-1")
        self.assertIsNone(impact["reason"])
        self.assertEqual(report["summary"]["unexempted_components"], 0)
        self.assertIsNone(report["summary"]["highest_severity"])

    def test_report_pending_reason(self) -> None:
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )
        report = self.catalog.risk_report(evaluation_at=EVAL_AT)
        impact = report["impacts"][0]
        self.assertFalse(impact["exempt"])
        self.assertEqual(impact["reason"], "审批中")

    def test_report_rejected_reason(self) -> None:
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )
        self.catalog.reject_exemption("EX-1", "bob", "no")
        report = self.catalog.risk_report(evaluation_at=EVAL_AT)
        impact = report["impacts"][0]
        self.assertFalse(impact["exempt"])
        self.assertEqual(impact["reason"], "已拒绝")

    def test_report_revoked_reason(self) -> None:
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )
        self.catalog.approve_exemption("EX-1", "bob", "ok")
        self.catalog.revoke_exemption("EX-1", "carol", "revoked")
        report = self.catalog.risk_report(evaluation_at=EVAL_AT)
        impact = report["impacts"][0]
        self.assertFalse(impact["exempt"])
        self.assertEqual(impact["reason"], "已撤销")

    def test_report_expired_reason(self) -> None:
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )
        # Manually expire and approve the application.
        self.catalog.connection.execute(
            "UPDATE exemptions SET expires_at = '2020-01-01T00:00:00+00:00', "
            "status = 'approved', risk_level = 'medium' "
            "WHERE application_no = 'EX-1'"
        )
        self.catalog.connection.commit()
        report = self.catalog.risk_report(evaluation_at=EVAL_AT)
        impact = report["impacts"][0]
        self.assertFalse(impact["exempt"])
        self.assertEqual(impact["reason"], "已过期")

    def test_report_risk_level_exceeded(self) -> None:
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )
        self.catalog.approve_exemption("EX-1", "bob", "ok")
        self.catalog.add_vulnerability("CVE-1", "fastapi", "critical")
        report = self.catalog.risk_report(evaluation_at=EVAL_AT)
        impact = report["impacts"][0]
        self.assertFalse(impact["exempt"])
        self.assertEqual(impact["reason"], "超出审批范围")

    def test_report_risk_level_equal_still_exempt(self) -> None:
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )
        self.catalog.approve_exemption("EX-1", "bob", "ok")
        report = self.catalog.risk_report(evaluation_at=EVAL_AT)
        self.assertTrue(report["impacts"][0]["exempt"])

    def test_report_service_filter(self) -> None:
        self.catalog.add_component("web", "pypi", "fastapi", "0.115.0")
        report = self.catalog.risk_report(service="web", evaluation_at=EVAL_AT)
        self.assertEqual(len(report["impacts"]), 1)
        self.assertEqual(report["impacts"][0]["component"]["service"], "web")

    def test_report_stable_sorting(self) -> None:
        self.catalog.add_component("api", "pypi", "zeta", "1.0.0")
        self.catalog.add_component("api", "pypi", "alpha", "1.0.0")
        self.catalog.add_vulnerability("CVE-2", "zeta", "low")
        self.catalog.add_vulnerability("CVE-3", "alpha", "high")
        report = self.catalog.risk_report(evaluation_at=EVAL_AT)
        names = [i["component"]["name"] for i in report["impacts"]]
        self.assertEqual(names, sorted(names))

    def test_report_evaluation_at_affects_expiry(self) -> None:
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason",
            "2050-06-01T00:00:00+00:00",
        )
        self.catalog.approve_exemption("EX-1", "bob", "ok")
        before = self.catalog.risk_report(
            evaluation_at="2050-01-01T00:00:00+00:00"
        )
        after = self.catalog.risk_report(
            evaluation_at="2050-07-01T00:00:00+00:00"
        )
        self.assertTrue(before["impacts"][0]["exempt"])
        self.assertFalse(after["impacts"][0]["exempt"])
        self.assertEqual(after["impacts"][0]["reason"], "已过期")

    def test_report_preserves_impact_fields(self) -> None:
        report = self.catalog.risk_report(evaluation_at=EVAL_AT)
        impact = report["impacts"][0]
        self.assertIn("source", impact)
        self.assertIn("severity", impact)
        self.assertIn("direct", impact)
        self.assertIn("path", impact)
        self.assertIn("component", impact)
        self.assertIn("vulnerability", impact)
        self.assertIn("matched_name", impact)

    def test_report_does_not_modify_history(self) -> None:
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "fastapi", "0.115.0",
            "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
        )
        self.catalog.approve_exemption("EX-1", "bob", "ok")
        history_before = self.catalog.exemption_history("EX-1")
        self.catalog.risk_report(evaluation_at=EVAL_AT)
        self.catalog.risk_report(evaluation_at=EVAL_AT)
        history_after = self.catalog.exemption_history("EX-1")
        self.assertEqual(history_before, history_after)


class ExemptionScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()
        self.catalog.add_component("api", "pypi", "app", "1.0.0")
        self.catalog.add_component("api", "pypi", "lib", "1.0.0")
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "lib", "1.0.0"
        )
        self.catalog.add_vulnerability("CVE-1", "lib", "high")

    def tearDown(self) -> None:
        self.catalog.close()

    def test_exempt_direct_hit_does_not_exempt_dependents(self) -> None:
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "lib", "1.0.0",
            "CVE-1", "lib", None, "alice", "reason", FUTURE,
        )
        self.catalog.approve_exemption("EX-1", "bob", "ok")
        report = self.catalog.risk_report(evaluation_at=EVAL_AT)
        by_name = {i["component"]["name"]: i for i in report["impacts"]}
        self.assertTrue(by_name["lib"]["exempt"])
        self.assertFalse(by_name["app"]["exempt"])
        self.assertEqual(by_name["app"]["reason"], "无豁免申请")

    def test_exempt_independent_component(self) -> None:
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "app", "1.0.0",
            "CVE-1", "lib", None, "alice", "reason", FUTURE,
        )
        self.catalog.approve_exemption("EX-1", "bob", "ok")
        report = self.catalog.risk_report(evaluation_at=EVAL_AT)
        by_name = {i["component"]["name"]: i for i in report["impacts"]}
        self.assertFalse(by_name["lib"]["exempt"])
        self.assertTrue(by_name["app"]["exempt"])

    def test_impact_reappears_exemption_reapplies(self) -> None:
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "app", "1.0.0",
            "CVE-1", "lib", None, "alice", "reason", FUTURE,
        )
        self.catalog.approve_exemption("EX-1", "bob", "ok")
        # Remove the dependency so the indirect impact disappears.
        self.catalog.remove_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "lib", "1.0.0"
        )
        report = self.catalog.risk_report(evaluation_at=EVAL_AT)
        self.assertEqual(len(report["impacts"]), 1)
        self.assertEqual(report["impacts"][0]["component"]["name"], "lib")
        # Re-add the dependency; the exemption should apply again.
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "lib", "1.0.0"
        )
        report = self.catalog.risk_report(evaluation_at=EVAL_AT)
        by_name = {i["component"]["name"]: i for i in report["impacts"]}
        self.assertTrue(by_name["app"]["exempt"])

    def test_dependency_path_change_keeps_scope(self) -> None:
        # Remove the direct app -> lib dependency so the only path is through web.
        self.catalog.remove_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "lib", "1.0.0"
        )
        self.catalog.add_component("api", "pypi", "web", "1.0.0")
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "web", "1.0.0"
        )
        self.catalog.add_dependency(
            "api", "pypi", "web", "1.0.0", "api", "pypi", "lib", "1.0.0"
        )
        self.catalog.apply_exemption(
            "EX-1", "api", "pypi", "app", "1.0.0",
            "CVE-1", "lib", None, "alice", "reason", FUTURE,
        )
        self.catalog.approve_exemption("EX-1", "bob", "ok")
        report = self.catalog.risk_report(evaluation_at=EVAL_AT)
        app_impact = next(
            i for i in report["impacts"] if i["component"]["name"] == "app"
        )
        self.assertEqual(
            [n["name"] for n in app_impact["path"]], ["app", "web", "lib"]
        )


class ExemptionPersistenceTests(unittest.TestCase):
    def test_data_persists_across_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory, "catalog.db")
            catalog = Catalog(database)
            catalog.add_component("api", "pypi", "fastapi", "0.115.0")
            catalog.add_vulnerability("CVE-1", "fastapi", "medium")
            catalog.apply_exemption(
                "EX-1", "api", "pypi", "fastapi", "0.115.0",
                "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
            )
            catalog.approve_exemption("EX-1", "bob", "ok")
            catalog.close()

            reopened = Catalog(database)
            report = reopened.risk_report(evaluation_at=EVAL_AT)
            self.assertTrue(report["impacts"][0]["exempt"])
            self.assertEqual(report["impacts"][0]["application_no"], "EX-1")
            history = reopened.exemption_history("EX-1")
            self.assertEqual(len(history), 2)
            reopened.close()

    def test_same_data_and_time_consistent_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory, "catalog.db")
            catalog = Catalog(database)
            catalog.add_component("api", "pypi", "fastapi", "0.115.0")
            catalog.add_vulnerability("CVE-1", "fastapi", "medium")
            catalog.apply_exemption(
                "EX-1", "api", "pypi", "fastapi", "0.115.0",
                "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
            )
            catalog.approve_exemption("EX-1", "bob", "ok")
            first = catalog.risk_report(evaluation_at=EVAL_AT)
            catalog.close()

            reopened = Catalog(database)
            second = reopened.risk_report(evaluation_at=EVAL_AT)
            self.assertEqual(first, second)
            reopened.close()

    def test_existing_database_without_exemption_tables(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory, "catalog.db")
            catalog = Catalog(database)
            catalog.add_component("api", "pypi", "fastapi", "0.115.0")
            catalog.add_vulnerability("CVE-1", "fastapi", "medium")
            catalog.close()
            # Reopen — the new tables should be created automatically.
            reopened = Catalog(database)
            report = reopened.risk_report(evaluation_at=EVAL_AT)
            self.assertFalse(report["impacts"][0]["exempt"])
            reopened.close()


class ExemptionConcurrencyTests(unittest.TestCase):
    def test_two_concurrent_approvals_one_wins(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = Catalog(database)
            catalog.add_component("api", "pypi", "fastapi", "0.115.0")
            catalog.add_vulnerability("CVE-1", "fastapi", "medium")
            catalog.apply_exemption(
                "EX-1", "api", "pypi", "fastapi", "0.115.0",
                "CVE-1", "fastapi", None, "alice", "reason", FUTURE,
            )
            catalog.close()

            results = []
            errors = []

            def approve(operator: str) -> None:
                conn = Catalog(database)
                try:
                    result = conn.approve_exemption("EX-1", operator, "ok")
                    results.append(result["status"])
                except ValueError as error:
                    errors.append(str(error))
                finally:
                    conn.close()

            barrier = threading.Barrier(2)

            def worker(operator: str) -> None:
                barrier.wait()
                approve(operator)

            t1 = threading.Thread(target=worker, args=("bob",))
            t2 = threading.Thread(target=worker, args=("carol",))
            t1.start()
            t2.start()
            t1.join()
            t2.join()

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0], "approved")
            self.assertEqual(len(errors), 1)


class ExemptionCliTests(unittest.TestCase):
    def test_full_cli_flow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            self.assertEqual(
                main(["--database", database, "add-component",
                      "api", "pypi", "fastapi", "0.115.0"]),
                0,
            )
            self.assertEqual(
                main(["--database", database, "add-vulnerability",
                      "CVE-1", "fastapi", "medium"]),
                0,
            )
            self.assertEqual(
                main([
                    "--database", database, "apply-exemption",
                    "--application-no", "EX-1",
                    "--service", "api", "--ecosystem", "pypi",
                    "--name", "fastapi", "--version", "0.115.0",
                    "--vulnerability", "CVE-1", "--matched-name", "fastapi",
                    "--applicant", "alice", "--reason", "planned upgrade",
                    "--expires-at", FUTURE,
                ]),
                0,
            )
            self.assertEqual(
                main([
                    "--database", database, "approve-exemption",
                    "--application-no", "EX-1",
                    "--operator", "bob", "--reason", "approved",
                ]),
                0,
            )
            self.assertEqual(
                main(["--database", database, "risk-report"]), 0
            )
            self.assertEqual(
                main([
                    "--database", database, "exemption-history",
                    "--application-no", "EX-1",
                ]),
                0,
            )
            self.assertEqual(
                main(["--database", database, "list-exemptions"]), 0
            )

    def test_self_approval_cli_returns_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            self.assertEqual(
                main(["--database", database, "add-component",
                      "api", "pypi", "fastapi", "0.115.0"]),
                0,
            )
            self.assertEqual(
                main(["--database", database, "add-vulnerability",
                      "CVE-1", "fastapi", "medium"]),
                0,
            )
            self.assertEqual(
                main([
                    "--database", database, "apply-exemption",
                    "--application-no", "EX-1",
                    "--service", "api", "--ecosystem", "pypi",
                    "--name", "fastapi", "--version", "0.115.0",
                    "--vulnerability", "CVE-1", "--matched-name", "fastapi",
                    "--applicant", "alice", "--reason", "reason",
                    "--expires-at", FUTURE,
                ]),
                0,
            )
            self.assertEqual(
                main([
                    "--database", database, "approve-exemption",
                    "--application-no", "EX-1",
                    "--operator", "alice", "--reason", "self",
                ]),
                1,
            )


if __name__ == "__main__":
    unittest.main()
